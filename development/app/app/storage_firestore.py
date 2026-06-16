"""Firestore storage backend (durable, for Cloud Run).

Mirrors the storage_sqlite interface exactly (same function names, dict returns, json-string complex
fields, float timestamps) so the service/main callers are unchanged. Pure storage — the db.py facade
applies feed-key encryption.

Design decisions (see the verify-durable-state workflow):
- FLAT top-level collections (tenants, flagged_users, scan_runs, audit_log), each doc carries tenant_id —
  closest match to the SQLite interface (global ids, get_x(id) by doc id).
- Queries use ONLY a single-field where(tenant_id==X) (auto-indexed) + Python-side sort/filter, to avoid
  composite-index requirements (the emulator does NOT flag missing composite indexes; this sidesteps the
  emulator-green-but-prod-fails trap entirely — fine for the small per-tenant data volume here).
- tenant doc id = customer_id (natural key); returned dict "id" == "customer_id".
- flagged doc id = sha1(tenant_id|email)[:24] hex → deterministic (idempotent upsert) AND url-safe (the
  email can't break the /flagged/{id}/remediate path).
- Ambient ADC auth on Cloud Run (same runtime SA as DWD). FIRESTORE_EMULATOR_HOST makes tests billing-free.
"""
from __future__ import annotations

import hashlib
import json
import time

from google.api_core.exceptions import AlreadyExists, FailedPrecondition
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from .config import settings
from .storage_base import DuplicateTenantError


def _ok_id(x) -> bool:
    """A Firestore document id can't contain '/' (path separator) or NUL and can't be empty. A user-supplied
    id (e.g. POST /tenants/switch, /flagged/{id}/...) that does would RAISE deep in the client (500) instead
    of cleanly returning None like the sqlite backend's _int(). Guard the by-id reads to keep parity."""
    s = str(x)
    return bool(s) and "/" not in s and "\x00" not in s and len(s) <= 1500

_TENANTS = "tenants"
_FLAGGED = "flagged_users"
_SCANS = "scan_runs"
_AUDIT = "audit_log"
_AUDIT_HEADS = "audit_heads"   # per-tenant {seq, head} for atomic chained append
_APPROVALS = "approvals"

_client = None


def _db():
    global _client
    if _client is None:
        # No credentials/project args: ADC resolves the Cloud Run runtime SA via the metadata server.
        # FIRESTORE_EMULATOR_HOST (if set) overrides with AnonymousCredentials + a dummy project.
        _client = firestore.Client(project=settings.project_id or None)
    return _client


def _by_tenant(coll, tenant_id):
    return _db().collection(coll).where(filter=FieldFilter("tenant_id", "==", tenant_id)).stream()


def _flagged_id(tenant_id, email):
    return hashlib.sha1(f"{tenant_id}|{email}".encode()).hexdigest()[:24]


def init_schema():
    # Firestore is schemaless — nothing to create. Touch the client to fail fast on misconfig.
    _db()


# ---------- tenants ----------
def tenant_exists(customer_id) -> bool:
    if not _ok_id(customer_id):
        return False
    return _db().collection(_TENANTS).document(str(customer_id)).get().exists


def _tenant_doc(snap):
    if not snap.exists:
        return None
    d = snap.to_dict()
    d["id"] = snap.id          # id == customer_id
    d["customer_id"] = snap.id
    d.setdefault("quarantine_group", "")
    d.setdefault("auto_baseline_at", 0)
    d.setdefault("admin_subject", "")        # MSSP backfill: pre-change docs read '' -> global fallback
    d.setdefault("service_account", "")
    return d


def get_tenant(tenant_id):
    if not _ok_id(tenant_id):
        return None
    return _tenant_doc(_db().collection(_TENANTS).document(str(tenant_id)).get())


def first_tenant():
    docs = list(_db().collection(_TENANTS).order_by("created_at").limit(1).stream())
    return _tenant_doc(docs[0]) if docs else None


def list_tenants():
    out = [_tenant_doc(s) for s in _db().collection(_TENANTS).stream()]
    return sorted([t for t in out if t], key=lambda t: t.get("created_at", 0))


def create_tenant(customer_id, name, verified_domains, feed_base, feed_company_id,
                  feed_api_key, feed_start_date, admin_subject="", service_account=""):
    """feed_api_key is ALREADY encrypted by the db facade. Raises DuplicateTenantError on dup.
    admin_subject/service_account are MSSP per-org identity (default '' = inherit the global config)."""
    ref = _db().collection(_TENANTS).document(str(customer_id))
    doc = {
        "customer_id": customer_id, "name": name,
        "verified_domains": json.dumps(verified_domains), "feed_base": feed_base,
        "feed_company_id": feed_company_id, "feed_api_key": feed_api_key,
        "feed_start_date": feed_start_date, "enabled_actions": json.dumps([]),
        "quarantine_group": "", "auto_baseline_at": 0, "feed_lookback_days": 0, "feed_high_water": "",
        "admin_subject": admin_subject, "service_account": service_account, "created_at": time.time(),
    }
    try:
        # create() (NOT set()) is atomic: it fails if the doc already exists, so two concurrent creates of
        # the same customer_id can't both pass an exists-check and silently overwrite each other (parity with
        # the sqlite UNIQUE(customer_id) constraint).
        ref.create(doc)
    except AlreadyExists:
        raise DuplicateTenantError(customer_id)
    return customer_id


def update_tenant(tenant_id, **fields):
    if not fields:
        return
    _db().collection(_TENANTS).document(str(tenant_id)).update(dict(fields))


# ---------- flagged users ----------
def upsert_flagged(tenant_id, email, sources, lookup_status, now, socradar_refs=None):
    """UNION sources + socradar_refs on conflict (ADR-0001 #3: a streamed scan upserts the same email from
    separate sources/pages). The per-tenant scan lease guarantees a single writer."""
    fid = _flagged_id(tenant_id, email)
    new_refs = list(socradar_refs or [])
    ref = _db().collection(_FLAGGED).document(fid)
    snap = ref.get()
    if snap.exists:
        d = snap.to_dict() or {}
        merged_sources = sorted(set(sources) | set(json.loads(d.get("sources") or "[]")))
        old_refs = json.loads(d.get("socradar_refs") or "[]")
        merged_refs = old_refs + [r for r in new_refs if r not in old_refs]
        # don't let a TRANSIENT blip (error_*) downgrade an already-found user (would block remediation).
        ls = "found" if (d.get("lookup_status") == "found" and str(lookup_status).startswith("error_")) else lookup_status
        ref.update({"sources": json.dumps(merged_sources), "lookup_status": ls,
                    "last_seen": now, "socradar_refs": json.dumps(merged_refs)})
    else:
        ref.set({"id": fid, "tenant_id": tenant_id, "email": email,
                 "sources": json.dumps(sorted(set(sources))), "lookup_status": lookup_status,
                 "status": "open", "first_seen": now, "last_seen": now, "remediated_at": None,
                 "socradar_refs": json.dumps(new_refs), "socradar_close_status": None})
    return fid


def set_close_status(flagged_id, status_json):
    _db().collection(_FLAGGED).document(str(flagged_id)).update({"socradar_close_status": status_json})


def _flagged_doc(snap):
    if not snap.exists:
        return None
    d = snap.to_dict()
    d["id"] = snap.id
    return d


def list_flagged(tenant_id, status=None):
    rows = [_flagged_doc(s) for s in _by_tenant(_FLAGGED, tenant_id)]
    rows = [r for r in rows if r and (status is None or r.get("status") == status)]
    return sorted(rows, key=lambda r: r.get("last_seen", 0), reverse=True)


def get_flagged(flagged_id):
    if not _ok_id(flagged_id):
        return None
    return _flagged_doc(_db().collection(_FLAGGED).document(str(flagged_id)).get())


def get_flagged_for_tenant(flagged_id, tenant_id):
    """MSSP isolation: return the flagged user only if it belongs to tenant_id (else None)."""
    d = get_flagged(flagged_id)
    return d if d and str(d.get("tenant_id")) == str(tenant_id) else None


def mark_remediated(flagged_id, now):
    ref = _db().collection(_FLAGGED).document(str(flagged_id))

    @firestore.transactional
    def _mark(tx):
        snap = ref.get(transaction=tx)
        # atomic read-check-write (parity with sqlite's `UPDATE ... WHERE status!='partial'`): don't clobber
        # a 'partial' (a prior action's unconfirmed post-state) — or a missing doc — back to 'remediated'.
        if not snap.exists or snap.to_dict().get("status") == "partial":
            return
        tx.update(ref, {"status": "remediated", "remediated_at": now})
    _mark(_db().transaction())


def set_flagged_status(flagged_id, status):
    _db().collection(_FLAGGED).document(str(flagged_id)).update({"status": status})


def flagged_counts(tenant_id):
    counts: dict[str, int] = {}
    for s in _by_tenant(_FLAGGED, tenant_id):
        st = (s.to_dict() or {}).get("status", "open")
        counts[st] = counts.get(st, 0) + 1
    return counts


# ---------- scan runs ----------
def start_scan(tenant_id, now):
    ref = _db().collection(_SCANS).document()
    ref.set({"id": ref.id, "tenant_id": tenant_id, "started_at": now, "finished_at": None,
             "totals": None, "found_count": 0, "unique_emails": 0, "error": None,
             "status": "running", "cursor": None, "window_start": None, "heartbeat": now})
    return ref.id


def finish_scan(scan_id, now, totals=None, found=0, unique=0, error=None, status=None):
    st = status or ("error" if error else "done")
    _db().collection(_SCANS).document(str(scan_id)).update({
        "finished_at": now, "totals": json.dumps(totals or {}),
        "found_count": found, "unique_emails": unique, "error": error, "status": st})


def claim_or_resume_scan(tenant_id, now, lease_ttl, window_start):
    """Single-flight per tenant under a Firestore TRANSACTION (atomic read-check-write — two workers cannot
    both create/claim the same tenant's scan; same pattern as mark_remediated). Status is filtered
    client-side off a single-field tenant_id query, so NO composite index is needed. Returns (scan_id,
    cursor, mode)."""
    coll = _db().collection(_SCANS)
    q = coll.where(filter=FieldFilter("tenant_id", "==", tenant_id))
    out = {}

    @firestore.transactional
    def _claim(tx):
        rows = [(s.reference, s.to_dict() or {}) for s in q.stream(transaction=tx)]
        active = sorted([rd for rd in rows if rd[1].get("status") in ("running", "paused")],
                        key=lambda rd: rd[1].get("started_at", 0), reverse=True)
        if active:
            ref, d = active[0]
            if d.get("status") == "running" and now - (d.get("heartbeat") or 0) < lease_ttl:
                out.clear()
                out["mode"] = "busy"
                return
            tx.update(ref, {"status": "running", "heartbeat": now})   # paused handoff OR stale zombie
            out.clear()
            out.update(scan_id=ref.id, cursor=d.get("cursor"), mode="resume")
            return
        new_ref = coll.document()
        tx.set(new_ref, {"id": new_ref.id, "tenant_id": tenant_id, "started_at": now, "finished_at": None,
                         "totals": None, "found_count": 0, "unique_emails": 0, "error": None,
                         "status": "running", "cursor": None, "window_start": window_start, "heartbeat": now})
        out.clear()
        out.update(scan_id=new_ref.id, cursor=None, mode="new")

    _claim(_db().transaction())
    return out.get("scan_id"), out.get("cursor"), out.get("mode")


def pause_scan(scan_id, now, cursor):
    _db().collection(_SCANS).document(str(scan_id)).update(
        {"status": "paused", "heartbeat": now, "cursor": cursor})


def scan_heartbeat(scan_id, now, cursor=None, totals=None, found=None, unique=None):
    upd = {"heartbeat": now}
    if cursor is not None:
        upd["cursor"] = cursor
    if totals is not None:
        upd["totals"] = json.dumps(totals)
    if found is not None:
        upd["found_count"] = found
    if unique is not None:
        upd["unique_emails"] = unique
    _db().collection(_SCANS).document(str(scan_id)).update(upd)


def get_active_scan(tenant_id):
    running = [s.to_dict() | {"id": s.id} for s in _by_tenant(_SCANS, tenant_id)
               if (s.to_dict() or {}).get("status") == "running"]
    return max(running, key=lambda r: r.get("started_at", 0)) if running else None


def last_scan(tenant_id):
    runs = [s.to_dict() | {"id": s.id} for s in _by_tenant(_SCANS, tenant_id)]
    if not runs:
        return None
    return max(runs, key=lambda r: r.get("started_at", 0))


def recent_scans(tenant_id, limit=20):
    runs = [s.to_dict() | {"id": s.id} for s in _by_tenant(_SCANS, tenant_id)
            if (s.to_dict() or {}).get("finished_at")]
    return sorted(runs, key=lambda r: r.get("started_at", 0), reverse=True)[:limit]


# ---------- audit (hash chain computed by the db facade; appended ATOMICALLY here) ----------
def append_audit(tenant_id, actor, action, result, target_email, detail, ts, compute):
    """Atomic chained append via a per-tenant head doc (seq + head hash) in a transaction, so concurrent
    appends serialize. `compute(prev, seq) -> entry_hash`. Returns (entry_hash, seq)."""
    head_ref = _db().collection(_AUDIT_HEADS).document(str(tenant_id))
    audit_ref = _db().collection(_AUDIT).document()

    @firestore.transactional
    def _append(tx):
        snap = head_ref.get(transaction=tx)
        cur = snap.to_dict() if snap.exists else {}
        prev = cur.get("head")
        seq = (cur.get("seq") or 0) + 1
        eh = compute(prev, seq)
        tx.set(audit_ref, {"id": audit_ref.id, "tenant_id": tenant_id, "ts": ts, "actor": actor,
                           "action": action, "target_email": target_email, "result": result,
                           "detail": detail, "seq": seq, "prev_hash": prev, "entry_hash": eh})
        tx.set(head_ref, {"seq": seq, "head": eh})
        return eh, seq
    return _append(_db().transaction())


def list_audit_chain(tenant_id):
    rows = [s.to_dict() | {"id": s.id} for s in _by_tenant(_AUDIT, tenant_id)]
    # legacy (seq missing) first, then by seq
    return sorted(rows, key=lambda r: (r.get("seq") is not None, r.get("seq") or 0, r.get("ts", 0)))


def count_auto_actions_since(tenant_id, since_ts):
    rows = [s.to_dict() for s in _by_tenant(_AUDIT, tenant_id)]
    return sum(1 for r in rows if (r.get("ts") or 0) >= since_ts
               and str(r.get("action", "")).startswith("auto:") and r.get("result") == "ok")


# ---------- approvals (two-person rule) ----------
def create_approval(tenant_id, flagged_id, email, action, requester, now):
    ref = _db().collection(_APPROVALS).document()
    ref.set({"id": ref.id, "tenant_id": tenant_id, "flagged_id": str(flagged_id), "email": email,
             "action": action, "requester": requester, "state": "pending", "approver": None,
             "created_at": now, "decided_at": None})
    return ref.id


def get_approval(approval_id):
    if not _ok_id(approval_id):
        return None
    snap = _db().collection(_APPROVALS).document(str(approval_id)).get()
    return (snap.to_dict() | {"id": snap.id}) if snap.exists else None


def list_approvals(tenant_id, state=None):
    rows = [s.to_dict() | {"id": s.id} for s in _by_tenant(_APPROVALS, tenant_id)]
    rows = [r for r in rows if state is None or r.get("state") == state]
    return sorted(rows, key=lambda r: r.get("created_at", 0), reverse=True)


def set_approval_state(approval_id, state, approver, now, expect=None):
    ref = _db().collection(_APPROVALS).document(str(approval_id))
    if expect is None:
        ref.update({"state": state, "approver": approver, "decided_at": now})
        return True

    @firestore.transactional
    def _cas(tx):
        snap = ref.get(transaction=tx)
        if not snap.exists or snap.to_dict().get("state") != expect:
            return False
        tx.update(ref, {"state": state, "approver": approver, "decided_at": now})
        return True
    return _cas(_db().transaction())


def list_audit(tenant_id, limit=200):
    # audit_log grows unbounded — prefer an indexed, LIMITED read (composite index tenant_id + ts desc)
    # so a /audit view never scans the whole collection (cost discipline). Falls back to a bounded
    # full-read + Python sort if that composite index isn't created in the project yet.
    coll = _db().collection(_AUDIT)
    try:
        q = (coll.where(filter=FieldFilter("tenant_id", "==", tenant_id))
                 .order_by("ts", direction=firestore.Query.DESCENDING).limit(limit))
        return [s.to_dict() | {"id": s.id} for s in q.stream()]
    except FailedPrecondition:  # composite index missing — graceful fallback
        rows = [s.to_dict() | {"id": s.id} for s in _by_tenant(_AUDIT, tenant_id)]
        return sorted(rows, key=lambda r: r.get("ts", 0), reverse=True)[:limit]
