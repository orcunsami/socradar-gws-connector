#!/usr/bin/env python3
"""Deterministic tests for: never-auto-on-first-scan baseline gate + tamper-evident hash-chain audit.
No gcloud/network. Run from the app dir."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/ba.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0ba"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"

from app import connector, db, service  # noqa: E402
from app.config import settings  # noqa: E402

c = {}
db.init_db()
t = db.first_tenant()
db.update_tenant(t["id"], enabled_actions=json.dumps(["signout"]))
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.lookup_user = lambda e, tok: "found"
connector._api = lambda *a, **k: {}
settings.remediation_mode = "auto"
settings.auto_enabled_actions = "signout"
settings.auto_dry_run = False
settings.auto_kill_switch = False
settings.auto_max_users_per_scan = 50
settings.auto_high_blast_actions = "suspend"
settings.auto_exclude_users = ""


def feed(email):
    connector.fetch_all_sources = lambda *a, **k: ({email: {"botnet"}}, {"botnet": 1, "pii": 0, "vip": 0}, {}, {})


# --- BASELINE GATE ---
# Scan #1 (first auto scan) must ONLY establish baseline, NOT remediate the backlog.
feed("backlog@example.com")
service.run_scan(db.get_tenant(t["id"]), "scheduler")
fu1 = [r for r in db.list_flagged(t["id"]) if r["email"] == "backlog@example.com"][0]
c["first auto scan -> baseline only, NO remediation"] = fu1["status"] != "remediated"
c["baseline_established audited"] = any(a["action"] == "baseline_established" for a in db.list_audit(t["id"]))
c["auto_baseline_at set"] = (db.get_tenant(t["id"]).get("auto_baseline_at") or 0) > 0

# Scan #2: a NEW finding (first_seen after baseline) IS auto-remediated.
time.sleep(0.01)
feed("fresh@example.com")
service.run_scan(db.get_tenant(t["id"]), "scheduler")
fu2 = [r for r in db.list_flagged(t["id"]) if r["email"] == "fresh@example.com"][0]
c["post-baseline finding IS auto-remediated"] = fu2["status"] == "remediated"
# the pre-baseline backlog user, still present, is NOT auto-remediated on scan #2 either
fu1b = db.get_flagged(fu1["id"])
c["pre-baseline backlog still NOT remediated"] = fu1b["status"] != "remediated"

# --- HASH-CHAIN AUDIT ---
v = db.verify_audit_chain(t["id"])
c["audit chain verifies OK"] = v["ok"] and v["count"] > 0
# tamper: edit a row's result directly in sqlite -> chain must break
from app.storage_sqlite import conn
with conn() as cx:
    rid = cx.execute("SELECT id FROM audit_log WHERE tenant_id=? ORDER BY id ASC LIMIT 1", (t["id"],)).fetchone()["id"]
    cx.execute("UPDATE audit_log SET result='tampered' WHERE id=?", (rid,))
v2 = db.verify_audit_chain(t["id"])
c["tamper DETECTED (chain breaks)"] = v2["ok"] is False and v2["broken_at"] == 0

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — baseline gate + tamper-evident audit verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
