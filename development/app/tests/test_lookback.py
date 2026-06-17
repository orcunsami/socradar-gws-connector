#!/usr/bin/env python3
"""Deterministic feed-lookback test — no gcloud, no network.
The PER-TENANT feed_lookback_days drives the window (0 -> fixed feed_start_date; >0 -> today-N). The
deploy-wide FEED_LOOKBACK_DAYS is SEEDED onto the bootstrap tenant at creation, NOT applied as a runtime
override — so an explicit "Custom date" (0) is never silently overridden by the global preset
(EXP-GOOGLE-0056 lookback-class bug). Run from the app dir."""
import datetime
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/lb.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0lb"
os.environ["FEED_FULL_SCAN"] = "false"   # this test mocks the legacy fetch_all_sources path
os.environ["DEFAULT_DOMAIN"] = "example.com"

from app import connector, db, service  # noqa: E402
from app.config import settings  # noqa: E402

c = {}
db.init_db()
t = db.first_tenant()
fsd = t["feed_start_date"]


def expect(days):
    return (datetime.date.today() - datetime.timedelta(days=days)).isoformat()


def set_lb(days):
    db.update_tenant(t["id"], feed_lookback_days=days, feed_high_water="")
    return db.get_tenant(t["id"])


# per-tenant feed_lookback_days drives the window
c["lookback=0 -> fixed feed_start_date"] = service._effective_start_date(set_lb(0)) == fsd
c["lookback=7 -> today-7 (last week)"] = service._effective_start_date(set_lb(7)) == expect(7)
c["lookback=30 -> today-30 (last month)"] = service._effective_start_date(set_lb(30)) == expect(30)

# a per-tenant 0 (Custom date) is NOT overridden by a global FEED_LOOKBACK_DAYS preset (the lookback-class bug)
settings.feed_lookback_days = 7
c["per-tenant 0 (Custom date) wins over global preset"] = service._effective_start_date(set_lb(0)) == fsd
settings.feed_lookback_days = 0

# run_scan passes the computed window to the feed
set_lb(30)
captured = {}
connector.fetch_all_sources = lambda b, cid, k, start: (captured.update({"start": start}) or ({}, {"botnet": 0, "pii": 0, "vip": 0}, {}, {}))
connector.get_dwd_token = lambda scopes, **kw: "tok"
service.run_scan(db.get_tenant(t["id"]), "test")
c["run_scan uses the lookback window"] = captured.get("start") == expect(30)

# the deploy-wide FEED_LOOKBACK_DAYS is SEEDED onto the bootstrap tenant at creation (so it still takes effect)
con = sqlite3.connect(os.environ["DB_PATH"]); con.execute("DELETE FROM tenants"); con.commit(); con.close()
settings.feed_lookback_days = 14
db.ensure_default_tenant()
seeded = db.first_tenant()
c["global FEED_LOOKBACK_DAYS seeds the bootstrap tenant at creation"] = bool(seeded) and seeded["feed_lookback_days"] == 14
settings.feed_lookback_days = 0

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — per-tenant lookback authoritative + global seeded at creation" if ok else "FAIL")
sys.exit(0 if ok else 1)
