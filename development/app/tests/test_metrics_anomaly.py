#!/usr/bin/env python3
"""Measure-what-matters metrics + behavioral anomaly detection. No gcloud/network. Run from the app dir."""
import importlib
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/ma.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0ma"
os.environ["FEED_FULL_SCAN"] = "false"   # this test mocks the legacy fetch_all_sources path
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"

import app.config as cfg
importlib.reload(cfg)
from app import connector, db, metrics, service
from app.config import settings

c = {}
db.init_db()
t = db.first_tenant()
db.update_tenant(t["id"], enabled_actions=json.dumps(["signout"]))

# --- METRICS: dwell, coverage, success ---
now = time.time()
f1 = db.upsert_flagged(t["id"], "a@example.com", {"botnet"}, "found", now - 3600, [1])  # detected 1h ago
db.mark_remediated(f1, now)                                                                # remediated now -> dwell ~3600s
db.upsert_flagged(t["id"], "b@example.com", {"pii"}, "found", now, [2])                   # open
db.audit(t["id"], "admin", "remediate:signout", "ok", "a@example.com")
db.audit(t["id"], "admin", "remediate:signout", "fail", "b@example.com")
m = metrics.compute(t["id"])
c["flagged total"] = m["flagged_total"] == 2
c["coverage = 50% (1 of 2 handled)"] = abs((m["coverage"] or 0) - 0.5) < 0.01
c["dwell p50 ~1h"] = m["dwell_seconds"]["p50"] and 3500 < m["dwell_seconds"]["p50"] < 3700
c["success rate 50% (1 ok / 2 attempts)"] = abs((m["remediation_success_rate"] or 0) - 0.5) < 0.01
c["audit integrity surfaced ok"] = m["audit_integrity"]["ok"] is True

# --- ANOMALY: baseline of small scans, then a spike suppresses auto ---
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.lookup_user = lambda e, tok: "found"
connector._api = lambda *a, **k: {}
settings.remediation_mode = "auto"
settings.auto_enabled_actions = "signout"
settings.auto_dry_run = False
settings.anomaly_spike_factor = 3.0
settings.anomaly_min_count = 5
settings.anomaly_baseline_scans = 5
# establish a baseline of small scans (1 found each) — also clears never-auto baseline after first
db.update_tenant(t["id"], auto_baseline_at=1.0)  # skip never-auto-first-scan gate for this test


def feed(emails):
    connector.fetch_all_sources = lambda *a, **k: ({e: {"botnet"} for e in emails},
                                                   {"botnet": len(emails), "pii": 0, "vip": 0}, {}, {})


for i in range(4):
    feed([f"base{i}@example.com"])     # 1 found each -> baseline median = 1
    service.run_scan(db.get_tenant(t["id"]), "scheduler")
# now a spike: 10 found (>> 3× median of 1, and >= min_count 5)
feed([f"spike{i}@example.com" for i in range(10)])
res = service.run_scan(db.get_tenant(t["id"]), "scheduler")
c["spike flagged as anomaly"] = res.get("anomaly") is True
c["anomaly audited"] = any(a["action"] == "anomaly_detected" for a in db.list_audit(t["id"]))
# auto-remediation SUPPRESSED on the anomalous scan -> spike users stay open
spike_remediated = [r for r in db.list_flagged(t["id"]) if r["email"].startswith("spike") and r["status"] == "remediated"]
c["auto SUPPRESSED on anomalous scan"] = len(spike_remediated) == 0
# a normal scan still auto-remediates (no anomaly)
feed(["normal@example.com"])
service.run_scan(db.get_tenant(t["id"]), "scheduler")
c["normal scan still auto-remediates"] = db.get_flagged([r for r in db.list_flagged(t["id"]) if r["email"] == "normal@example.com"][0]["id"])["status"] == "remediated"

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — metrics + anomaly detection verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
