#!/usr/bin/env python3
"""Auto-scan from Settings: the per-tenant scan_interval persists via Settings, and POST /tasks/scan honors
it (due-check) — a tenant is scanned ONLY when its interval has elapsed since its last finished scan; 'off'
is never auto-scanned; ?force=1 scans all regardless. No gcloud/feed. Run from the app dir."""
import os
import re
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DBP = tempfile.mktemp(suffix=".sqlite3")
os.environ.update(DB_PATH=DBP, DEFAULT_CUSTOMER_ID="C0as", DEFAULT_DOMAIN="ex.com", ALLOWED_DOMAIN="ex.com",
                  ADMIN_SUBJECT="o@ex.com", DEV_LOGIN="true", APP_ENV="dev", REMEDIATION_ADMINS="o@ex.com",
                  FEED_API_KEY="x", FEED_COMPANY_ID="1", SCAN_TRIGGER_TOKEN="tok", SECRET_KEY="x" * 32)

import importlib  # noqa: E402
import app.config as cfg  # noqa: E402
importlib.reload(cfg)
from app import db  # noqa: E402
import app.main as main  # noqa: E402
importlib.reload(main)
from fastapi.testclient import TestClient  # noqa: E402

db.init_db()

# mock run_scan: count the call + write a REAL finished scan row so the next due-check reads it
calls = []
def fake_run_scan(t, actor):
    calls.append((t["id"], actor))
    now = time.time()
    sid = db.start_scan(t["id"], now)
    db.finish_scan(sid, now, totals={}, found=0, unique=0, status="done")
    return {"ok": True, "actor": actor}
main.service.run_scan = fake_run_scan

cl = TestClient(main.app)
cl.get("/auth/login", follow_redirects=False)
CSRF = re.search(r'name="csrf" value="([^"]+)"', cl.get("/settings").text).group(1)
tid = db.first_tenant()["id"]

P = F = 0
def chk(name, cond):
    global P, F
    print(("  PASS: " if cond else "  FAIL: ") + name)
    if cond:
        P += 1
    else:
        F += 1


def tasks_scan(force=False):
    calls.clear()
    url = "/tasks/scan?force=1" if force else "/tasks/scan"
    body = cl.post(url, headers={"X-Scan-Token": "tok"}).json()
    return body, list(calls)


def backdate_last_scan(seconds_ago):
    con = sqlite3.connect(DBP)
    con.execute("UPDATE scan_runs SET finished_at=? WHERE tenant_id=?", (time.time() - seconds_ago, tid))
    con.commit(); con.close()


# 1) default is 'off'
chk("default scan_interval = off", (db.get_tenant(tid).get("scan_interval") or "off") == "off")

# 2) Settings persists scan_interval
t = db.get_tenant(tid)
cl.post("/settings", data={"verified_domains": "ex.com", "feed_base": t["feed_base"],
                           "feed_company_id": t["feed_company_id"], "feed_start_date": t["feed_start_date"],
                           "feed_lookback_days": "0", "scan_interval": "30m", "csrf": CSRF},
        follow_redirects=False)
chk("scan_interval persisted = 30m (via Settings)", db.get_tenant(tid)["scan_interval"] == "30m")

# 3) interval set + no prior scan -> DUE -> scanned
_, c = tasks_scan()
chk("interval set + no prior scan -> scanned", len(c) == 1 and c[0][1] == "scheduler")

# 4) just scanned -> within 30m -> NOT due -> skipped
body, c = tasks_scan()
chk("recently scanned -> not due -> skipped", len(c) == 0 and body["tenants"][str(tid)].get("due") is False)

# 5) last scan > 30m ago -> due -> scanned
backdate_last_scan(2000)   # 33 min ago
_, c = tasks_scan()
chk("interval elapsed (>30m) -> due -> scanned", len(c) == 1)

# 6) scan_interval = off -> NEVER auto-scanned (even with a very old scan)
db.update_tenant(tid, scan_interval="off")
backdate_last_scan(99999)
body, c = tasks_scan()
chk("scan_interval=off -> never auto-scanned", len(c) == 0 and body["tenants"][str(tid)].get("auto") == "off")

# 7) ?force=1 -> scans regardless of interval / off
_, c = tasks_scan(force=True)
chk("force=1 -> scans even when off", len(c) == 1)

# 8) invalid scan_interval coerced to 'off' by Settings validation
t = db.get_tenant(tid)
cl.post("/settings", data={"verified_domains": "ex.com", "feed_base": t["feed_base"],
                           "feed_company_id": t["feed_company_id"], "feed_start_date": t["feed_start_date"],
                           "feed_lookback_days": "0", "scan_interval": "5s", "csrf": CSRF},
        follow_redirects=False)
chk("invalid scan_interval -> coerced to off", db.get_tenant(tid)["scan_interval"] == "off")

print(f"\nRESULT: {'PASS' if F == 0 else 'FAIL'} — auto-scan schedule (interval persist + due-check + force) ({P} ok, {F} fail)")
sys.exit(0 if F == 0 else 1)
