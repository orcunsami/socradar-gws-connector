#!/usr/bin/env python3
"""When the feed WINDOW (lookback preset or custom start date) changes in Settings, the incremental
high-water mark must reset so the NEXT scan actually honors the new window (e.g. 'Last 1 year').
Regression for the silent-override bug: once a tenant had scanned, _effective_start_date() returned at
the high-water branch and a new lookback did nothing. Run from app dir: python3 tests/test_lookback_reset.py"""
import datetime
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/lookback_reset.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0def"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"
os.environ["REMEDIATION_ADMINS"] = "operator@example.com"
os.environ["FEED_START_DATE"] = "2026-06-01"

import importlib  # noqa: E402
import app.config as cfg  # noqa: E402
importlib.reload(cfg)
from app import db  # noqa: E402
import app.service as service  # noqa: E402
import app.main as main  # noqa: E402
importlib.reload(main)
from fastapi.testclient import TestClient  # noqa: E402

db.init_db()
cl = TestClient(main.app)
cl.get("/auth/login", follow_redirects=False)


def _csrf():
    html = cl.get("/settings").text
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""


def _post_settings(lookback, start_date=None, reset=False):
    t = db.get_tenant(tid)
    data = {
        "verified_domains": "example.com",
        "feed_base": t["feed_base"], "feed_company_id": t["feed_company_id"],
        "feed_start_date": start_date if start_date is not None else t["feed_start_date"],
        "feed_lookback_days": str(lookback), "quarantine_group": "", "csrf": _csrf(),
    }
    if reset:
        data["reset_backfill"] = "1"
    return cl.post("/settings", data=data, follow_redirects=False)


P = F = 0
def chk(name, cond):
    global P, F
    if cond:
        print(f"  PASS: {name}"); P += 1
    else:
        print(f"  FAIL: {name}"); F += 1


t = db.first_tenant(); tid = t["id"]
today = datetime.date.today()

# 1) simulate a completed scan -> high-water set to today (this is what service.py does at scan end)
db.update_tenant(tid, feed_high_water=today.isoformat())
sd = service._effective_start_date(db.get_tenant(tid))
chk("bug-state: high-water pins the start near today (not a year back)",
    sd >= (today - datetime.timedelta(days=30)).isoformat())

# 2) operator picks 'Last 30 days' (30 = largest preset) in Settings
r = _post_settings(30)
chk("settings POST returns 303", r.status_code == 303)
t = db.get_tenant(tid)
chk("lookback persisted = 30 (int)", t["feed_lookback_days"] == 30)
chk("high-water RESET to '' on window change", (t["feed_high_water"] or "") == "")

# 3) the NEXT scan now honors 'Last 30 days'
expected = (today - datetime.timedelta(days=30)).isoformat()
chk(f"effective start = today-30 ({expected})", service._effective_start_date(t) == expected)

# also: a value above the largest preset (e.g. 365) is NOT accepted via the form -> coerced to 0 (Custom date)
db.update_tenant(tid, feed_lookback_days=7)
_post_settings(365)
chk("365 rejected by the form -> coerced to 0 (no big-window preset)", db.get_tenant(tid)["feed_lookback_days"] == 0)

# 4) a fresh scan re-sets high-water; saving the SAME window must NOT wipe it (no spurious re-backfill)
db.update_tenant(tid, feed_lookback_days=30, feed_high_water=today.isoformat())
_post_settings(30)   # unchanged window
t = db.get_tenant(tid)
chk("high-water KEPT when window unchanged", (t["feed_high_water"] or "") == today.isoformat())

# 5) switching to a custom start date also resets high-water (custom date is a window change too)
_post_settings(0, start_date="2025-01-01")
t = db.get_tenant(tid)
chk("custom-date change also resets high-water", (t["feed_high_water"] or "") == "")
chk("effective start follows custom date when lookback=0", service._effective_start_date(t) == "2025-01-01")

# 6) the explicit "re-scan the full window" checkbox resets high-water even when the window is UNCHANGED
#    (this is the operator's escape hatch when the lookback is already the desired value but high-water pins it)
db.update_tenant(tid, feed_high_water=today.isoformat())
chk("precondition: high-water set again", (db.get_tenant(tid)["feed_high_water"] or "") == today.isoformat())
_post_settings(0, start_date="2025-01-01", reset=True)   # SAME window as #5, but tick the reset box
chk("reset_backfill checkbox clears high-water on unchanged window",
    (db.get_tenant(tid)["feed_high_water"] or "") == "")

print(f"\nRESULT: {'PASS' if F == 0 else 'FAIL'} — lookback/high-water reset on window change ({P} ok, {F} fail)")
sys.exit(0 if F == 0 else 1)
