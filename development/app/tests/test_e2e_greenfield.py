#!/usr/bin/env python3
"""E2E GREENFIELD (ADR-0001 Phase 1+2) — from an empty DB through the FULL new streaming engine AND the
Cloud Run Job entrypoint: configure -> JOB scan (full coverage, no truncation) -> flag -> remediate ->
audit -> metrics -> an incremental DELTA scan picks up a NEW leak -> audit-chain intact -> job idempotent.
Deterministic, no gcloud/network. Run from the app dir: python3 tests/test_e2e_greenfield.py
"""
import datetime
import importlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/e2e.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0e2e"
os.environ["DEFAULT_DOMAIN"] = "acme.com"
os.environ["ADMIN_SUBJECT"] = "operator@acme.com"
os.environ["REMEDIATION_ADMINS"] = "operator@acme.com"
os.environ["FEED_FULL_SCAN"] = "true"
os.environ["APP_ENV"] = "dev"

import app.config as cfg
importlib.reload(cfg)
import app.connector as connector
import app.db as db
importlib.reload(db)
import app.service as service
importlib.reload(service)
import app.metrics as metrics
importlib.reload(metrics)
import app.job as job
importlib.reload(job)


def rec(email, aid):
    return {"email": email, "source": None, "password_present": True, "alarm_id": aid}


# mutable feed: multi-source, multi-page, incl. an out-of-domain email, a UNION email, and a SANITIZED-EMPTY
# vip page1 (keyword-only) followed by a real exec email on page2 (the silent-data-loss case).
PAGES = {
    "botnet": [[rec("alice@acme.com", 1), rec("ext@other.com", 2)], [rec("bob@acme.com", 3)]],
    "pii": [[rec("alice@acme.com", 90)]],
    "vip": [[], [rec("ceo@acme.com", 77)]],
}


def mock_stream(base, cid, key, source, start_date, start_page=1, page_limit=None):
    pages = PAGES.get(source, [])
    total = sum(len(p) for p in pages) + (1 if source == "vip" else 0)  # vip page1 had raw keyword-only records
    for i in range(start_page - 1, len(pages)):
        yield i + 1, pages[i], total


connector.stream_source = mock_stream
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.lookup_user = lambda email, token: "found"
connector.apply_action = lambda *a, **k: True
connector.is_admin = lambda email, token: False
connector.verify_action_effect = lambda *a, **k: "unverifiable"

c = {}


def flagged_emails(t):
    return sorted(r["email"] for r in db.list_flagged(t["id"]))


def has_audit(t, action=None, result=None, sub=None):
    for a in db.list_audit(t["id"], 300):
        if action and a["action"] != action:
            continue
        if result and a["result"] != result:
            continue
        if sub and sub.lower() not in (a.get("detail") or "").lower():
            continue
        return True
    return False


# ===== 1) greenfield config =====
db.init_db()                                  # seeds the default tenant (acme.com) from env
t = db.first_tenant()
db.update_tenant(t["id"], enabled_actions=json.dumps(["signout"]))
t = db.first_tenant()
c["greenfield: tenant seeded with verified domain acme.com"] = json.loads(t["verified_domains"]) == ["acme.com"]
c["greenfield: empty start (no flagged)"] = db.list_flagged(t["id"]) == []

# ===== 2) JOB scan (Cloud Run Job entrypoint, full coverage) =====
rc = job.run()                                # scans every tenant via the streaming engine, to completion
c["JOB: exit 0 (success)"] = rc == 0
t = db.first_tenant()
c["JOB full coverage: in-domain users flagged (ext@other dropped)"] = flagged_emails(t) == [
    "alice@acme.com", "bob@acme.com", "ceo@acme.com"]
c["JOB data-loss guard: ceo (vip page2 after sanitized-empty page1) flagged"] = (
    "ceo@acme.com" in flagged_emails(t))
alice = [r for r in db.list_flagged(t["id"]) if r["email"] == "alice@acme.com"][0]
c["JOB UNION sources: alice botnet+pii"] = sorted(json.loads(alice["sources"])) == ["botnet", "pii"]
c["JOB no truncation alert"] = not has_audit(t, action="feed_truncated")
c["JOB honest summary (full coverage)"] = has_audit(t, action="scan", result="ok", sub="full coverage")
c["JOB incremental high-water advanced"] = t["feed_high_water"] == datetime.date.today().isoformat()
last = db.last_scan(t["id"])
c["JOB scan row done"] = last["status"] == "done" and bool(last["finished_at"])

# ===== 3) remediate a flagged user =====
fid = alice["id"]
r = service.remediate(t, fid, "signout", "operator@acme.com")
c["remediate: signout ok"] = r.get("ok") is True
c["remediate: user -> remediated"] = db.get_flagged(fid)["status"] == "remediated"
c["remediate: audited (remediate:signout ok)"] = has_audit(t, action="remediate:signout", result="ok")

# ===== 4) metrics reflect the loop =====
m = metrics.compute(t["id"])
c["metrics: 3 flagged, coverage > 0"] = m["flagged_total"] == 3 and (m["coverage"] or 0) > 0
c["metrics: remediation success counted"] = (m["remediation_attempts"] or 0) >= 1

# ===== 5) incremental DELTA scan picks up a NEW leak =====
PAGES["botnet"][1].append(rec("newvictim@acme.com", 555))   # a new leak appears in the feed
rc2 = job.run()
t = db.first_tenant()
c["DELTA: rescan ok"] = rc2 == 0
c["DELTA: NEW leak picked up (newvictim flagged)"] = "newvictim@acme.com" in flagged_emails(t)
c["DELTA: old remediated user NOT reset to open (idempotent)"] = db.get_flagged(fid)["status"] == "remediated"

# ===== 6) audit chain intact (tamper-evident) =====
c["audit chain verifies (tamper-evident)"] = db.verify_audit_chain(t["id"]).get("ok") is True

# ===== 7) job is idempotent (re-run, no crash, no spurious new state) =====
before = len(db.list_flagged(t["id"]))
rc3 = job.run()
c["JOB idempotent: re-run exit 0"] = rc3 == 0
c["JOB idempotent: no phantom new flagged users"] = len(db.list_flagged(t["id"])) == before

# ===== 8) single-tenant TENANT_ID targeting works =====
c["JOB TENANT_ID targeting: known id scans, returns 0"] = job.run(str(t["id"])) == 0
c["JOB TENANT_ID targeting: unknown id -> exit 2"] = job.run("nope-not-a-tenant") == 2

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print(f"RESULT: {'PASS' if ok else 'FAIL'} — {sum(c.values())}/{len(c)} e2e-greenfield checks")
sys.exit(0 if ok else 1)
