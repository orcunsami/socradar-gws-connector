#!/usr/bin/env python3
"""Streaming scan ConnectorError RESUME (ADR-0001 Phase-2 review fix) — deterministic, no gcloud/network.

A mid-backfill feed error must KEEP the page checkpoint and RESUME on the next execution (not restart from
window_start, which would orphan hours of paging). A PERMANENT error (bad key / feed down) must NOT loop
forever — it finalizes 'error' after scan_max_stuck_resumes no-progress resumes. Run from the app dir."""
import importlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/resume.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0res"
os.environ["DEFAULT_DOMAIN"] = "corp.com"
os.environ["ADMIN_SUBJECT"] = "operator@corp.com"
os.environ["FEED_FULL_SCAN"] = "true"
os.environ["SCAN_MAX_STUCK_RESUMES"] = "2"

import app.config as cfg
importlib.reload(cfg)
import app.connector as connector
import app.db as db
importlib.reload(db)
import app.service as service
importlib.reload(service)

connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.lookup_user = lambda email, token: "found"

db.init_db()
A = db.first_tenant()
db.update_tenant(A["id"], verified_domains=json.dumps(["corp.com"]))
A = db.first_tenant()
# a 2nd tenant for the permanent-error case (per-tenant lease/cursor isolation)
db.create_tenant("C0dead", "Dead", ["corp.com"], "https://b", "1", "k", "2026-06-01")
B = [t for t in db.list_tenants() if t["customer_id"] == "C0dead"][0]

c = {}


def rec(e, a):
    return {"email": e, "source": None, "password_present": True, "alarm_id": a}


def emails(t):
    return sorted(r["email"] for r in db.list_flagged(t["id"]))


# ===== TRANSIENT: fail ONCE on botnet page2, then succeed on resume =====
TPAGES = [[rec("alice@corp.com", 1)], [rec("bob@corp.com", 2)], [rec("carol@corp.com", 3)]]
flaky = {"failed": False}


def transient_stream(base, cid, key, source, start_date, start_page=1, page_limit=None):
    if source != "botnet":
        return
    for i in range(start_page - 1, len(TPAGES)):
        if i == 1 and not flaky["failed"]:        # reaching page 2 the FIRST time -> a transient feed error
            flaky["failed"] = True
            raise connector.ConnectorError("feed 503 (transient)")
        yield i + 1, TPAGES[i], 3


connector.stream_source = transient_stream
r1 = service.run_scan(A, "tester")
c["transient: run1 not-ok but RESUMABLE (checkpoint kept)"] = (r1.get("ok") is False) and r1.get("resumable") is True
c["transient: run1 made progress (alice from page1 flagged)"] = emails(A) == ["alice@corp.com"]
c["transient: scan row left 'paused' (not 'error', not lost)"] = db.last_scan(A["id"])["status"] == "paused"
r2 = service.run_scan(A, "tester")
c["transient: run2 RESUMED to completion (not a restart)"] = r2.get("ok") is True
c["transient: full set after resume (alice+bob+carol)"] = emails(A) == ["alice@corp.com", "bob@corp.com", "carol@corp.com"]
c["transient: scan finalized 'done'"] = db.last_scan(A["id"])["status"] == "done"

# ===== PERMANENT: always fail on page1 -> give up after scan_max_stuck_resumes (=2) =====
def dead_stream(base, cid, key, source, start_date, start_page=1, page_limit=None):
    raise connector.ConnectorError("401 invalid API key (permanent)")
    yield  # noqa: unreachable — make it a generator


connector.stream_source = dead_stream
rb1 = service.run_scan(B, "tester")
c["permanent: 1st failure -> resumable (attempt 1/2)"] = rb1.get("resumable") is True
c["permanent: still 'paused' after attempt 1"] = db.last_scan(B["id"])["status"] == "paused"
rb2 = service.run_scan(B, "tester")
c["permanent: 2nd no-progress -> GIVE UP (not resumable)"] = not rb2.get("resumable")
c["permanent: scan finalized 'error' (no infinite loop)"] = db.last_scan(B["id"])["status"] == "error"
c["permanent: a finalized-error scan does NOT block a fresh scan"] = (
    db.claim_or_resume_scan(B["id"], __import__("time").time(), 1800, "2026-06-01")[2] == "new")

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print(f"RESULT: {'PASS' if ok else 'FAIL'} — {sum(c.values())}/{len(c)} resume checks")
sys.exit(0 if ok else 1)
