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
    error TEXT
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
    tid = _int(tenant_id)
    refs = json.dumps(socradar_refs or [])
    # Atomic upsert (single statement) — two concurrent scans of the same tenant must not race a
    # SELECT-then-INSERT into a UNIQUE(tenant_id,email) IntegrityError. On conflict we refresh
    # sources/lookup/last_seen/refs but DELIBERATELY leave status + first_seen untouched (a rescan must not
    # reset a remediated/partial finding or overwrite its original detection time).
    with conn() as c:
        row = c.execute(
            """INSERT INTO flagged_users
                 (tenant_id, email, sources, lookup_status, status, first_seen, last_seen, socradar_refs)
               VALUES (?,?,?,?, 'open', ?,?,?)
               ON CONFLICT(tenant_id, email) DO UPDATE SET
                 sources=excluded.sources, lookup_status=excluded.lookup_status,
                 last_seen=excluded.last_seen, socradar_refs=excluded.socradar_refs
               RETURNING id""",
            (tid, email, json.dumps(sorted(sources)), lookup_status, now, now, refs)).fetchone()
        return row["id"]


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
        cur = c.execute("INSERT INTO scan_runs (tenant_id, started_at) VALUES (?,?)", (tid, now))
        return cur.lastrowid


def finish_scan(scan_id, now, totals=None, found=0, unique=0, error=None):
    with conn() as c:
        c.execute("""UPDATE scan_runs SET finished_at=?, totals=?, found_count=?, unique_emails=?, error=?
                     WHERE id=?""",
                  (now, json.dumps(totals or {}), found, unique, error, _int(scan_id)))


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
            "ORDER BY id DESC LIMIT ?", (tid, limit)).fetchall()]


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
