#!/usr/bin/env python3
"""Deterministic feed-lookback test — no gcloud, no network.
Verifies feed_lookback_days: 0 -> fixed feed_start_date; >0 -> relative (today - N); and that run_scan
passes the computed window to the feed. Run from the app dir."""
import datetime
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/lb.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0lb"
os.environ["DEFAULT_DOMAIN"] = "example.com"

from app import connector, db, service  # noqa: E402
from app.config import settings  # noqa: E402

c = {}
db.init_db()
t = db.first_tenant()


def expect(days):
    return (datetime.date.today() - datetime.timedelta(days=days)).isoformat()


settings.feed_lookback_days = 0
c["lookback=0 -> fixed feed_start_date"] = service._effective_start_date(t) == t["feed_start_date"]
settings.feed_lookback_days = 7
c["lookback=7 -> today-7 (last week)"] = service._effective_start_date(t) == expect(7)
settings.feed_lookback_days = 30
c["lookback=30 -> today-30 (last month)"] = service._effective_start_date(t) == expect(30)

# run_scan passes the computed window to the feed
captured = {}
connector.fetch_all_sources = lambda b, cid, k, start: (captured.update({"start": start}) or ({}, {"botnet": 0, "pii": 0, "vip": 0}, {}, {}))
connector.get_dwd_token = lambda scopes, **kw: "tok"
service.run_scan(db.get_tenant(t["id"]), "test")
c["run_scan uses the lookback window"] = captured.get("start") == expect(30)

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — configurable feed lookback window verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
