"""Storage facade — picks the backend (sqlite|firestore) and applies feed-key encryption at the boundary.

Callers (service.py, main.py) import `db` and use the same function names as before. The backend is
chosen by settings.storage_backend; feed keys are encrypted on write / decrypted on read here (one place),
so both backends store ciphertext and stay encryption-agnostic.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time

from . import crypto
from .config import settings
from .storage_base import DuplicateTenantError  # re-exported for main.py: `except db.DuplicateTenantError`

_audit_log = logging.getLogger("socradar.audit")   # mirrors every audit row off-box (Cloud Logging)

if settings.storage_backend == "firestore":
    from . import storage_firestore as _b
else:
    from . import storage_sqlite as _b

__all__ = ["DuplicateTenantError", "init_db", "ensure_default_tenant", "get_tenant", "first_tenant",
           "list_tenants", "create_tenant", "update_tenant", "upsert_flagged", "list_flagged",
           "get_flagged", "mark_remediated", "set_flagged_status", "set_close_status", "flagged_counts",
           "start_scan", "finish_scan", "last_scan", "recent_scans", "audit", "list_audit",
           "verify_audit_chain",
           "count_auto_actions_since", "create_approval", "get_approval", "list_approvals",
           "set_approval_state"]


def _decrypt_tenant(t):
    if t and t.get("feed_api_key"):
        t["feed_api_key"] = crypto.dec(t["feed_api_key"])
    return t


# ---------- lifecycle ----------
def init_db():
    _b.init_schema()
    ensure_default_tenant()


def ensure_default_tenant():
    """Seed the single bootstrap tenant from env if none exists. Feed key stored encrypted."""
    if _b.tenant_exists(settings.default_customer_id):
        return
    _b.create_tenant(
        settings.default_customer_id, settings.default_domain or "Default tenant",
        [settings.default_domain], settings.feed_base, settings.feed_company_id,
        crypto.enc(settings.feed_api_key), settings.feed_start_date)


# ---------- tenants (encryption boundary) ----------
def get_tenant(tenant_id):
    return _decrypt_tenant(_b.get_tenant(tenant_id))


def first_tenant():
    return _decrypt_tenant(_b.first_tenant())


def list_tenants():
    return [_decrypt_tenant(t) for t in _b.list_tenants()]


def create_tenant(customer_id, name, verified_domains, feed_base, feed_company_id,
                  feed_api_key, feed_start_date, admin_subject="", service_account=""):
    # admin_subject/service_account are identifiers (not secrets) -> stored plaintext, NOT through crypto.
    return _b.create_tenant(customer_id, name, verified_domains, feed_base, feed_company_id,
                            crypto.enc(feed_api_key), feed_start_date,
                            admin_subject=admin_subject, service_account=service_account)


def update_tenant(tenant_id, **fields):
    if "feed_api_key" in fields:
        fields["feed_api_key"] = crypto.enc(fields["feed_api_key"])
    _b.update_tenant(tenant_id, **fields)


# ---------- pass-through (no encryption) ----------
def upsert_flagged(tenant_id, email, sources, lookup_status, now, socradar_refs=None):
    return _b.upsert_flagged(tenant_id, email, sources, lookup_status, now, socradar_refs)


def set_close_status(flagged_id, status_json):
    _b.set_close_status(flagged_id, status_json)


def list_flagged(tenant_id, status=None):
    return _b.list_flagged(tenant_id, status)


def get_flagged(flagged_id):
    return _b.get_flagged(flagged_id)


def get_flagged_for_tenant(flagged_id, tenant_id):
    return _b.get_flagged_for_tenant(flagged_id, tenant_id)


def mark_remediated(flagged_id, now):
    _b.mark_remediated(flagged_id, now)


def set_flagged_status(flagged_id, status):
    _b.set_flagged_status(flagged_id, status)


def flagged_counts(tenant_id):
    return _b.flagged_counts(tenant_id)


def start_scan(tenant_id, now):
    return _b.start_scan(tenant_id, now)


def finish_scan(scan_id, now, totals=None, found=0, unique=0, error=None):
    _b.finish_scan(scan_id, now, totals=totals, found=found, unique=unique, error=error)


def last_scan(tenant_id):
    return _b.last_scan(tenant_id)


def recent_scans(tenant_id, limit=20):
    return _b.recent_scans(tenant_id, limit)


def _entry_hash(prev_hash, payload: dict) -> str:
    """Keyed (HMAC-SHA256) when audit_hmac_key is set — a row-writer without the OFF-BOX key cannot forge a
    valid chain. Falls back to plain SHA-256 if no key (tamper-evident vs an external verifier, but not
    forgery-proof — see settings.audit_hmac_key)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    msg = ((prev_hash or "") + canonical).encode()
    if settings.audit_hmac_key:
        return hmac.new(settings.audit_hmac_key.encode(), msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


def _chain_payload(tenant_id, seq, ts, actor, action, result, target_email, detail) -> dict:
    return {"tenant_id": str(tenant_id), "seq": seq, "ts": ts, "actor": actor, "action": action,
            "target_email": target_email, "result": result, "detail": detail}


def audit(tenant_id, actor, action, result, target_email=None, detail=None):
    """Tamper-evident append. The per-tenant hash chain (prev_hash + monotonic seq, HMAC-keyed) is read +
    computed + written ATOMICALLY in the backend (no read-compute-write race → no false tamper alarms), and
    every row is also emitted to stdout, which Cloud Run captures to Cloud Logging off-box. A row edit or a
    tail/middle deletion breaks the chain or the seq run (verify_audit_chain detects it)."""
    ts = time.time()

    def compute(prev, seq):
        return _entry_hash(prev, _chain_payload(tenant_id, seq, ts, actor, action,
                                                result, target_email, detail))
    eh, seq = _b.append_audit(tenant_id, actor, action, result, target_email, detail, ts, compute)
    _audit_log.info("audit %s/%s/%s seq=%s", tenant_id, action, result, seq,
                    extra={"audit": {"tenant_id": str(tenant_id), "seq": seq, "action": action,
                                     "result": result, "target_email": target_email, "entry_hash": eh}})


def verify_audit_chain(tenant_id) -> dict:
    """Recompute the chain in seq order; detect edits (hash mismatch), seq gaps (deletion), and re-ordering.
    Legacy pre-chain rows (prev_hash AND entry_hash both NULL) are skipped without forging the running prev."""
    rows = _b.list_audit_chain(tenant_id)
    prev, expect_seq = None, None
    for i, r in enumerate(rows):
        if r.get("prev_hash") is None and r.get("entry_hash") is None:
            continue   # unchained legacy row (pre-migration) — not part of the chain
        seq = r.get("seq")
        if expect_seq is not None and seq != expect_seq:
            return {"ok": False, "reason": "seq_gap", "broken_at": i, "count": len(rows)}
        payload = _chain_payload(r["tenant_id"], seq, r["ts"], r["actor"], r["action"],
                                 r["result"], r.get("target_email"), r.get("detail"))
        if r.get("prev_hash") != prev or r.get("entry_hash") != _entry_hash(prev, payload):
            return {"ok": False, "reason": "hash_mismatch", "broken_at": i, "count": len(rows)}
        prev = r["entry_hash"]
        expect_seq = seq + 1
    return {"ok": True, "count": len(rows)}


def count_auto_actions_since(tenant_id, since_ts):
    return _b.count_auto_actions_since(tenant_id, since_ts)


def create_approval(tenant_id, flagged_id, email, action, requester, now=None):
    return _b.create_approval(tenant_id, flagged_id, email, action, requester, now or time.time())


def get_approval(approval_id):
    return _b.get_approval(approval_id)


def list_approvals(tenant_id, state=None):
    return _b.list_approvals(tenant_id, state)


def set_approval_state(approval_id, state, approver, now=None, expect=None):
    """Returns True if the state was changed. With expect set, it's a compare-and-swap (only flips when the
    current state == expect) — prevents two concurrent approvals double-executing the same request."""
    return _b.set_approval_state(approval_id, state, approver, now or time.time(), expect)


def list_audit(tenant_id, limit=200):
    return _b.list_audit(tenant_id, limit)
