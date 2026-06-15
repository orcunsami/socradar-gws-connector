#!/usr/bin/env python3
"""Post-state verification (A5) + scheduled audit-verify endpoint (A4). No gcloud/network. App dir."""
import importlib
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/ps.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0ps"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"
os.environ["SCAN_TRIGGER_TOKEN"] = "tok-secret"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"

import app.config as cfg
importlib.reload(cfg)
from app import connector, db, service

c = {}
db.init_db()
t = db.first_tenant()
db.update_tenant(t["id"], enabled_actions=json.dumps(["suspend", "signout"]))
connector.get_dwd_token = lambda scopes, **kw: "tok"

# --- A5: post-state confirmed (suspend really took) ---
connector.apply_action = lambda action, email, token, group=None: True
connector.verify_action_effect = lambda action, email, token, group=None: "confirmed" if action == "suspend" else "unverifiable"
fid = db.upsert_flagged(t["id"], "ok@example.com", {"botnet"}, "found", 1.0, [1])
r = service.remediate(db.get_tenant(t["id"]), fid, "suspend", "admin@example.com")
aud = db.list_audit(t["id"])
c["confirmed effect audited"] = any(a["action"] == "verify:suspend" and a["result"] == "confirmed" for a in aud)
c["confirmed -> stays remediated"] = db.get_flagged(fid)["status"] == "remediated"

# --- A5: action returns ok but state did NOT change -> 'failed' -> downgrade to partial ---
connector.verify_action_effect = lambda action, email, token, group=None: "failed"
fid2 = db.upsert_flagged(t["id"], "lie@example.com", {"botnet"}, "found", 1.0, [2])
service.remediate(db.get_tenant(t["id"]), fid2, "suspend", "admin@example.com")
c["failed post-state audited"] = any(a["action"] == "verify:suspend" and a["result"] == "failed" for a in db.list_audit(t["id"]))
c["failed post-state -> partial (not remediated)"] = db.get_flagged(fid2)["status"] == "partial"

# --- A5: unverifiable (signout = event) -> no verify row, stays remediated ---
connector.verify_action_effect = lambda action, email, token, group=None: "unverifiable"
fid3 = db.upsert_flagged(t["id"], "evt@example.com", {"botnet"}, "found", 1.0, [3])
service.remediate(db.get_tenant(t["id"]), fid3, "signout", "admin@example.com")
c["unverifiable -> no verify audit row"] = not any(a["action"] == "verify:signout" for a in db.list_audit(t["id"]))
c["unverifiable -> stays remediated"] = db.get_flagged(fid3)["status"] == "remediated"

# --- A4: scheduled audit-verify endpoint ---
import app.main as main
importlib.reload(main)
from fastapi.testclient import TestClient
cl = TestClient(main.app)
r = cl.post("/tasks/verify-audit", headers={"x-scan-token": "tok-secret"})
c["verify-audit ok with token"] = r.status_code == 200 and r.json().get("ok") is True
r = cl.post("/tasks/verify-audit", headers={"x-scan-token": "wrong"})
c["verify-audit 403 on bad token"] = r.status_code == 403
# tamper a row -> endpoint reports failure (502) + audits the integrity alert
from app.storage_sqlite import conn
with conn() as cx:
    row = cx.execute("SELECT id FROM audit_log WHERE tenant_id=? ORDER BY seq ASC LIMIT 1", (t["id"],)).fetchone()
    cx.execute("UPDATE audit_log SET result='tampered' WHERE id=?", (row["id"],))
r = cl.post("/tasks/verify-audit", headers={"x-scan-token": "tok-secret"})
c["verify-audit detects tamper (502)"] = r.status_code == 502 and r.json().get("ok") is False

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — post-state verify + scheduled audit-verify verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
