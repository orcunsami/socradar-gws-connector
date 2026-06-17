"""SQLite storage backend (local default; ephemeral on Cloud Run /tmp).

Pure storage — encryption of the feed key is applied by the db.py facade, NOT here. All reads return
plain dicts (uniform with the Firestore backend); ids are integers (autoincrement). Defensive int casts
let string ids from routes/session flow in unchanged.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager

from .config import settings
from .storage_base import DuplicateTenantError

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    verified_domains TEXT NOT NULL,
    feed_base TEXT NOT NULL,
    feed_company_id TEXT NOT NULL,
    feed_api_key TEXT NOT NULL,
    feed_start_date TEXT NOT NULL,
    enabled_actions TEXT NOT NULL DEFAULT '[]',
    quarantine_group TEXT NOT NULL DEFAULT '',
    auto_baseline_at REAL NOT NULL DEFAULT 0,     -- never-auto-on-first-scan: 0=baseline not set yet
    admin_subject TEXT NOT NULL DEFAULT '',       -- MSSP: per-org super-admin to impersonate; '' = use global config
    service_account TEXT NOT NULL DEFAULT '',     -- MSSP: per-org DWD SA override; '' = use the shared global SA
    feed_lookback_days INTEGER NOT NULL DEFAULT 0, -- rolling feed window preset (today-N); 0 = use the fixed feed_start_date
    feed_high_water TEXT NOT NULL DEFAULT '',      -- incremental: next startDate (last fully-scanned discovery date); '' = backfill from scratch
    scan_interval TEXT NOT NULL DEFAULT 'off',     -- auto-scan cadence: off|30m|1h|6h|daily (scheduler ticks; per-tenant due-check gates it)
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS flagged_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    sources TEXT NOT NULL,
    lookup_status TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    remediated_at REAL,
    socradar_refs TEXT NOT NULL DEFAULT '[]',     -- json [{source,id}] for closing the SOCRadar alarm
    socradar_close_status TEXT,                   -- write-back outcome (json per-source) after remediation
    UNIQUE(tenant_id, email)
);
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    totals TEXT,
    found_count INTEGER DEFAULT 0,
    unique_emails INTEGER DEFAULT 0,
    error TEXT,
    status TEXT NOT NULL DEFAULT 'done',           -- running | done | error (lease: 'running' + stale heartbeat = reclaimable)
    cursor TEXT,                                    -- json {source: next_page, done:[sources]} for crash/budget resume
    window_start TEXT,                             -- the startDate this scan paged from (resume re-derives the SAME window)
    heartbeat REAL                                 -- last progress write; a 'running' row past the lease TTL is a zombie to reclaim
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_email TEXT,
    result TEXT NOT NULL,
    detail TEXT,
    seq INTEGER,                                  -- per-tenant monotonic sequence (deletion/reorder detection)
    prev_hash TEXT,                               -- tamper-evident hash chain (per tenant)
    entry_hash TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    flagged_id TEXT NOT NULL,
    email TEXT NOT NULL,
    action TEXT NOT NULL,
    requester TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',        -- pending | executed | rejected
    approver TEXT,
    created_at REAL NOT NULL,
    decided_at REAL
);
"""


@contextmanager
def conn():
    c = sqlite3.connect(settings.db_path)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def _int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def init_schema():
    with conn() as c:
        c.executescript(SCHEMA)
        cols = [r["name"] for r in c.execute("PRAGMA table_info(tenants)").fetchall()]
        if "quarantine_group" not in cols:
            c.execute("ALTER TABLE tenants ADD COLUMN quarantine_group TEXT NOT NULL DEFAULT ''")
        if "auto_baseline_at" not in cols:
            c.execute("ALTER TABLE tenants ADD COLUMN auto_baseline_at REAL NOT NULL DEFAULT 0")
        # MSSP per-org identity (backward-compat: existing rows get '' -> the connector falls back to the
        # global config admin_subject/service_account, so a live single-org DB is unaffected).
        if "admin_subject" not in cols:
            c.execute("ALTER TABLE tenants ADD COLUMN admin_subject TEXT NOT NULL DEFAULT ''")
        if "service_account" not in cols:
            c.execute("ALTER TABLE tenants ADD COLUMN service_account TEXT NOT NULL DEFAULT ''")
        if "feed_lookback_days" not in cols:
            c.execute("ALTER TABLE tenants ADD COLUMN feed_lookback_days INTEGER NOT NULL DEFAULT 0")
        if "feed_high_water" not in cols:
            c.execute("ALTER TABLE tenants ADD COLUMN feed_high_water TEXT NOT NULL DEFAULT ''")
        if "scan_interval" not in cols:
            c.execute("ALTER TABLE tenants ADD COLUMN scan_interval TEXT NOT NULL DEFAULT 'off'")
        scols = [r["name"] for r in c.execute("PRAGMA table_info(scan_runs)").fetchall()]
        if "status" not in scols:
            # existing finished rows are 'done'; an unfinished legacy row stays NULL->treated as not-running
            c.execute("ALTER TABLE scan_runs ADD COLUMN status TEXT NOT NULL DEFAULT 'done'")
        for col, ddl in (("cursor", "cursor TEXT"), ("window_start", "window_start TEXT"), ("heartbeat", "heartbeat REAL")):
            if col not in scols:
                c.execute(f"ALTER TABLE scan_runs ADD COLUMN {ddl}")
        fcols = [r["name"] for r in c.execute("PRAGMA table_info(flagged_users)").fetchall()]
        if "socradar_refs" not in fcols:
            c.execute("ALTER TABLE flagged_users ADD COLUMN socradar_refs TEXT NOT NULL DEFAULT '[]'")
        if "socradar_close_status" not in fcols:
            c.execute("ALTER TABLE flagged_users ADD COLUMN socradar_close_status TEXT")
        acols = [r["name"] for r in c.execute("PRAGMA table_info(audit_log)").fetchall()]
        if "seq" not in acols:
            c.execute("ALTER TABLE audit_log ADD COLUMN seq INTEGER")
        if "prev_hash" not in acols:
            c.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
        if "entry_hash" not in acols:
            c.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")


# ---------- tenants ----------
def tenant_exists(customer_id) -> bool:
    with conn() as c:
        return c.execute("SELECT 1 FROM tenants WHERE customer_id=?", (customer_id,)).fetchone() is not None


def get_tenant(tenant_id):
    tid = _int(tenant_id)
    if tid is None:
        return None
    with conn() as c:
        r = c.execute("SELECT * FROM tenants WHERE id=?", (tid,)).fetchone()
        return dict(r) if r else None


def first_tenant():
    with conn() as c:
        r = c.execute("SELECT * FROM tenants ORDER BY id LIMIT 1").fetchone()
        return dict(r) if r else None


def list_tenants():
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM tenants ORDER BY id").fetchall()]


def create_tenant(customer_id, name, verified_domains, feed_base, feed_company_id,
                  feed_api_key, feed_start_date, admin_subject="", service_account=""):
    """feed_api_key is ALREADY encrypted by the db facade. Raises DuplicateTenantError on dup customer_id.
    admin_subject/service_account are MSSP per-org identity (KEYWORD args, default '' = inherit the global
    config — keeps the 7-positional-arg callers and single-org behavior unchanged)."""
    with conn() as c:
        try:
            cur = c.execute(
                """INSERT INTO tenants
                   (customer_id, name, verified_domains, feed_base, feed_company_id, feed_api_key,
                    feed_start_date, enabled_actions, admin_subject, service_account, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (customer_id, name, json.dumps(verified_domains), feed_base, feed_company_id,
                 feed_api_key, feed_start_date, json.dumps([]), admin_subject, service_account, time.time()))
            return cur.lastrowid
        except sqlite3.IntegrityError as e:
            raise DuplicateTenantError(customer_id) from e


def update_tenant(tenant_id, **fields):
    tid = _int(tenant_id)
    if not fields or tid is None:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    with conn() as c:
        c.execute(f"UPDATE tenants SET {cols} WHERE id=?", (*fields.values(), tid))


# ---------- flagged users ----------
def upsert_flagged(tenant_id, email, sources, lookup_status, now, socradar_refs=None):
    """Read-merge upsert under BEGIN IMMEDIATE (serialized like append_audit). On conflict it UNIONs sources
    and socradar_refs instead of last-writer-wins (ADR-0001 #3: a streamed scan processes botnet/pii/vip in
    separate pages/invocations, so the same email must accumulate its sources, not clobber the prior one).
    Leaves status + first_seen untouched (a rescan must not reset a remediated finding or its detection time).
    The per-tenant scan lease guarantees a single writer; BEGIN IMMEDIATE serializes any incidental overlap."""
    tid = _int(tenant_id)
    new_sources = set(sources)
    new_refs = list(socradar_refs or [])
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        ex = c.execute("SELECT id, sources, socradar_refs, lookup_status FROM flagged_users "
                       "WHERE tenant_id=? AND email=?", (tid, email)).fetchone()
        if ex:
            merged_sources = sorted(new_sources | set(json.loads(ex["sources"] or "[]")))
            old_refs = json.loads(ex["socradar_refs"] or "[]")
            merged_refs = old_refs + [r for r in new_refs if r not in old_refs]
            # don't let a TRANSIENT blip (error_*) un-'find' an already-found user (it would block remediation
            # at the lookup_status!='found' gate). A definitive not_found/permission_denied still updates.
            ls = "found" if (ex["lookup_status"] == "found" and str(lookup_status).startswith("error_")) else lookup_status
            c.execute("UPDATE flagged_users SET sources=?, lookup_status=?, last_seen=?, socradar_refs=? WHERE id=?",
                      (json.dumps(merged_sources), ls, now, json.dumps(merged_refs), ex["id"]))
            return ex["id"]
        cur = c.execute(
            """INSERT INTO flagged_users
                 (tenant_id, email, sources, lookup_status, status, first_seen, last_seen, socradar_refs)
               VALUES (?,?,?,?, 'open', ?,?,?)""",
            (tid, email, json.dumps(sorted(new_sources)), lookup_status, now, now, json.dumps(new_refs)))
        return cur.lastrowid


def set_close_status(flagged_id, status_json):
    fid = _int(flagged_id)
    if fid is None:
        return
    with conn() as c:
        c.execute("UPDATE flagged_users SET socradar_close_status=? WHERE id=?", (status_json, fid))


def list_flagged(tenant_id, status=None):
    tid = _int(tenant_id)
    q = "SELECT * FROM flagged_users WHERE tenant_id=?"
    args = [tid]
    if status:
        q += " AND status=?"
        args.append(status)
    q += " ORDER BY last_seen DESC"
    with conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def get_flagged(flagged_id):
    fid = _int(flagged_id)
    if fid is None:
        return None
    with conn() as c:
        r = c.execute("SELECT * FROM flagged_users WHERE id=?", (fid,)).fetchone()
        return dict(r) if r else None


def get_flagged_for_tenant(flagged_id, tenant_id):
    """MSSP isolation: fetch a flagged user ONLY if it belongs to tenant_id. A bare flagged-id is a
    cross-org handle in a multi-tenant deployment — every by-id mutate path must scope by tenant."""
    fid, tid = _int(flagged_id), _int(tenant_id)
    if fid is None or tid is None:
        return None
    with conn() as c:
        r = c.execute("SELECT * FROM flagged_users WHERE id=? AND tenant_id=?", (fid, tid)).fetchone()
        return dict(r) if r else None


def mark_remediated(flagged_id, now):
    fid = _int(flagged_id)
    if fid is None:
        return
    with conn() as c:
        # don't clobber a 'partial' (a prior action's unconfirmed post-state) back to 'remediated' —
        # under-claim is the safe direction (honesty invariant). Operator clears partial manually.
        c.execute("UPDATE flagged_users SET status='remediated', remediated_at=? WHERE id=? AND status!='partial'",
                  (now, fid))


def set_flagged_status(flagged_id, status):
    fid = _int(flagged_id)
    if fid is None:
        return
    with conn() as c:
        c.execute("UPDATE flagged_users SET status=? WHERE id=?", (status, fid))


def flagged_counts(tenant_id):
    tid = _int(tenant_id)
    with conn() as c:
        rows = c.execute("SELECT status, COUNT(*) n FROM flagged_users WHERE tenant_id=? GROUP BY status",
                         (tid,)).fetchall()
    return {r["status"]: r["n"] for r in rows}


# ---------- scan runs ----------
def start_scan(tenant_id, now):
    tid = _int(tenant_id)
    with conn() as c:
        cur = c.execute("INSERT INTO scan_runs (tenant_id, started_at, status, heartbeat) VALUES (?,?, 'running', ?)",
                        (tid, now, now))
        return cur.lastrowid


def finish_scan(scan_id, now, totals=None, found=0, unique=0, error=None, status=None):
    st = status or ("error" if error else "done")
    with conn() as c:
        c.execute("""UPDATE scan_runs SET finished_at=?, totals=?, found_count=?, unique_emails=?, error=?, status=?
                     WHERE id=?""",
                  (now, json.dumps(totals or {}), found, unique, error, st, _int(scan_id)))


def claim_or_resume_scan(tenant_id, now, lease_ttl, window_start):
    """Single-flight per tenant (ADR-0001 lease). Returns (scan_id, cursor_json_or_None, mode):
    - 'busy'   : a 'running' row with a LIVE heartbeat (now-heartbeat < lease_ttl) — a worker is mid-scan.
    - 'resume' : a 'paused' row (a budget self-continuation handoff) OR a 'running' row past the lease TTL
                 (a zombie from a crash/SIGKILL/timeout) -> reclaim + resume from cursor.
    - 'new'    : no active scan -> create a fresh 'running' row."""
    tid = _int(tenant_id)
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT id, cursor, heartbeat, status FROM scan_runs "
                        "WHERE tenant_id=? AND status IN ('running','paused') ORDER BY id DESC LIMIT 1",
                        (tid,)).fetchone()
        if row:
            if row["status"] == "running" and now - (row["heartbeat"] or 0) < lease_ttl:
                return None, None, "busy"
            # paused (deliberate handoff) OR stale 'running' (zombie) -> take ownership + resume
            c.execute("UPDATE scan_runs SET status='running', heartbeat=? WHERE id=?", (now, row["id"]))
            return row["id"], row["cursor"], "resume"
        cur = c.execute("INSERT INTO scan_runs (tenant_id, started_at, status, heartbeat, window_start) "
                        "VALUES (?,?, 'running', ?, ?)", (tid, now, now, window_start))
        return cur.lastrowid, None, "new"


def pause_scan(scan_id, now, cursor):
    """Budget self-continuation: checkpoint + hand off. status='paused' so the NEXT invocation resumes it
    (a fresh-heartbeat 'running' would be mistaken for an active worker and refused as 'busy')."""
    with conn() as c:
        c.execute("UPDATE scan_runs SET status='paused', heartbeat=?, cursor=? WHERE id=?",
                  (now, cursor, _int(scan_id)))


def scan_heartbeat(scan_id, now, cursor=None, totals=None, found=None, unique=None):
    """Progress write during a long scan: refresh the lease heartbeat + (optionally) the resume cursor and the
    running tallies, so a reclaimed zombie resumes with accurate counts."""
    sets, args = ["heartbeat=?"], [now]
    if cursor is not None:
        sets.append("cursor=?"); args.append(cursor)
    if totals is not None:
        sets.append("totals=?"); args.append(json.dumps(totals))
    if found is not None:
        sets.append("found_count=?"); args.append(found)
    if unique is not None:
        sets.append("unique_emails=?"); args.append(unique)
    args.append(_int(scan_id))
    with conn() as c:
        c.execute(f"UPDATE scan_runs SET {', '.join(sets)} WHERE id=?", args)


def get_active_scan(tenant_id):
    tid = _int(tenant_id)
    with conn() as c:
        r = c.execute("SELECT * FROM scan_runs WHERE tenant_id=? AND status='running' ORDER BY id DESC LIMIT 1",
                      (tid,)).fetchone()
        return dict(r) if r else None


def last_scan(tenant_id):
    tid = _int(tenant_id)
    with conn() as c:
        r = c.execute("SELECT * FROM scan_runs WHERE tenant_id=? ORDER BY id DESC LIMIT 1", (tid,)).fetchone()
        return dict(r) if r else None


def recent_scans(tenant_id, limit=20):
    """Most recent FINISHED scans (newest first) — for metrics + anomaly baseline."""
    tid = _int(tenant_id)
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM scan_runs WHERE tenant_id=? AND finished_at IS NOT NULL "
            # order by started_at (id as a deterministic tie-break) to MATCH the firestore backend, so the
            # /tasks/scan due-check picks the same "most recent finished scan" on either store.
            "ORDER BY started_at DESC, id DESC LIMIT ?", (tid, limit)).fetchall()]


# ---------- audit (hash chain computed by the db facade; appended ATOMICALLY here) ----------
def append_audit(tenant_id, actor, action, result, target_email, detail, ts, compute):
    """Atomic chained append: read chain head (prev_hash + max seq) and INSERT in ONE immediate
    transaction, so concurrent appends serialize (no read-compute-write race / false tamper alarm).
    `compute(prev, seq) -> entry_hash` is the facade's keyed hash. Returns (entry_hash, seq)."""
    tid = _int(tenant_id)
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        r = c.execute("SELECT entry_hash, seq FROM audit_log WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
                      (tid,)).fetchone()
        prev = r["entry_hash"] if r else None
        seq = (r["seq"] + 1) if r and r["seq"] is not None else 1
        eh = compute(prev, seq)
        c.execute("""INSERT INTO audit_log
                     (tenant_id, ts, actor, action, target_email, result, detail, seq, prev_hash, entry_hash)
                     VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (tid, ts, actor, action, target_email, result, detail, seq, prev, eh))
        return eh, seq


def count_auto_actions_since(tenant_id, since_ts):
    """Successful auto actions for this tenant since since_ts (circuit-breaker / rate-limit input)."""
    tid = _int(tenant_id)
    with conn() as c:
        r = c.execute("SELECT COUNT(*) n FROM audit_log WHERE tenant_id=? AND ts>=? "
                      "AND action LIKE 'auto:%' AND result='ok'", (tid, since_ts)).fetchone()
        return r["n"]


def list_audit(tenant_id, limit=200):
    tid = _int(tenant_id)
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM audit_log WHERE tenant_id=? ORDER BY id DESC LIMIT ?", (tid, limit)).fetchall()]


# ---------- approvals (two-person rule) ----------
def create_approval(tenant_id, flagged_id, email, action, requester, now):
    with conn() as c:
        cur = c.execute("""INSERT INTO approvals
            (tenant_id, flagged_id, email, action, requester, state, created_at)
            VALUES (?,?,?,?,?, 'pending', ?)""",
            (_int(tenant_id), str(flagged_id), email, action, requester, now))
        return cur.lastrowid


def get_approval(approval_id):
    aid = _int(approval_id)
    if aid is None:
        return None
    with conn() as c:
        r = c.execute("SELECT * FROM approvals WHERE id=?", (aid,)).fetchone()
        return dict(r) if r else None


def list_approvals(tenant_id, state=None):
    tid = _int(tenant_id)
    q, args = "SELECT * FROM approvals WHERE tenant_id=?", [tid]
    if state:
        q += " AND state=?"
        args.append(state)
    q += " ORDER BY id DESC"
    with conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def set_approval_state(approval_id, state, approver, now, expect=None):
    q = "UPDATE approvals SET state=?, approver=?, decided_at=? WHERE id=?"
    args = [state, approver, now, _int(approval_id)]
    if expect is not None:
        q += " AND state=?"          # compare-and-swap: only flips if still in the expected state
        args.append(expect)
    with conn() as c:
        cur = c.execute(q, args)
        return cur.rowcount == 1


def list_audit_chain(tenant_id):
    """All audit rows in chain order (seq, then id for legacy unchained rows)."""
    tid = _int(tenant_id)
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM audit_log WHERE tenant_id=? ORDER BY seq IS NULL DESC, seq ASC, id ASC",
            (tid,)).fetchall()]
