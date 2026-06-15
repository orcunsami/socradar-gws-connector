#!/usr/bin/env python3
"""Regression tests for the bug-hunt fixes (2026-06-13). Each guards a confirmed/real finding so it can't
silently come back. No gcloud/network. Run from the app dir: python3 tests/test_bughunt_fixes.py

Covered:
  1. settings_save: an empty verified_domains field keeps THIS tenant's domains, never the global
     default_domain (the confirmed P2 cross-tenant contamination path).
  2. approval reject is a CAS — an already-executed approval can't be overwritten as 'rejected'.
  3. semi-auto one-click returns an honest result: a cross-tenant id flashes rem_err, not rem_ok.
  4. metrics counts only the canonical 'remediate:*' rows — auto/approval wrappers no longer double-count.
  5. feed pagination doesn't stop after page 1 when the API omits total_data_count.
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/bughunt.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0def"
os.environ["DEFAULT_DOMAIN"] = "example.com"          # the GLOBAL default — must NOT leak into another tenant
os.environ["ADMIN_SUBJECT"] = "operator@example.com"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"
os.environ["REMEDIATION_ADMINS"] = "operator@example.com"

import importlib
import app.config as cfg  # noqa: E402
importlib.reload(cfg)
from app import connector, db, metrics  # noqa: E402
import app.main as main  # noqa: E402
importlib.reload(main)
from fastapi.testclient import TestClient  # noqa: E402

connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.apply_action = lambda *a, **k: True
connector.verify_action_effect = lambda *a, **k: "unverifiable"

db.init_db()

c = {}
cl = TestClient(main.app)
cl.get("/auth/login", follow_redirects=False)   # DEV_LOGIN sign-in

def _csrf():
    html = cl.get("/settings").text
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""

# org B (its own domain) + the default tenant (example.com)
tb = db.create_tenant("C0orgb", "Org B", ["orgb.com"], "https://x", "2", "k", "2026-01-01",
                      admin_subject="ceo@orgb.com")
db.update_tenant(tb, enabled_actions=json.dumps(["signout"]))
default_t = db.first_tenant()
db.update_tenant(default_t["id"], enabled_actions=json.dumps(["signout"]))
csrf = _csrf()

# === 1) settings_save empty domains MUST keep org B's domains, not backfill the global example.com ===
cl.post("/tenants/switch", data={"tenant_id": str(tb), "csrf": csrf}, follow_redirects=False)
csrf = _csrf()
cl.post("/settings", data={"verified_domains": "", "csrf": csrf}, follow_redirects=False)  # cleared field
domains_after = json.loads(db.get_tenant(tb)["verified_domains"])
c["settings empty-domains keeps tenant's own domains"] = domains_after == ["orgb.com"]
c["settings empty-domains does NOT backfill the global default_domain"] = "example.com" not in domains_after

# === 2) approval reject is a CAS: an executed approval can't be flipped to 'rejected' ===
aid = db.create_approval(tb, "1", "v@orgb.com", "suspend", "req@orgb.com")
db.set_approval_state(aid, "executed", "approver@orgb.com", expect="pending")   # it already ran
rejected_after_execute = db.set_approval_state(aid, "rejected", "other@orgb.com", expect="pending")
c["reject CAS: can't reject an already-executed approval"] = rejected_after_execute is False
c["reject CAS: executed state preserved"] = db.get_approval(aid)["state"] == "executed"

# === 3) semi-auto one-click on a CROSS-TENANT id is honest (rem_err, no mutation) ===
fa = db.upsert_flagged(default_t["id"], "victim@example.com", {"botnet"}, "found", 1.0)  # belongs to default
# active tenant is org B (switched above); apply-all a default-tenant id -> must refuse + report error
r = cl.post(f"/flagged/{fa}/auto-remediate",
            data={"exp_tenant": str(tb), "csrf": csrf}, follow_redirects=False)
c["one-click cross-tenant id -> rem_err (not fake success)"] = "rem_err" in r.headers.get("location", "")
c["one-click cross-tenant id did NOT mutate the other tenant's row"] = db.get_flagged(fa)["status"] == "open"

# === 4) metrics counts only 'remediate:*' — auto/approval wrappers don't double-count ===
mt = db.create_tenant("C0met", "Metrics", ["met.com"], "https://x", "3", "k", "2026-01-01")
# one logical auto action writes BOTH an 'auto:signout' wrapper and the canonical 'remediate:signout'
db.audit(mt, "auto", "auto:signout", "ok", "u@met.com")
db.audit(mt, "auto", "remediate:signout", "ok", "u@met.com")
m = metrics.compute(mt)
c["metrics: one action counted once (no auto/remediate double count)"] = m["remediation_attempts"] == 1
c["metrics: success rate not inflated"] = m["remediation_success_rate"] == 1.0

# === 5) feed pagination keeps paging when total_data_count is absent (no single-page stop) ===
pages = [
    {"is_success": True, "data": {"data": [{"email": f"a{i}@x.com"} for i in range(100)]}},  # 100, no total
    {"is_success": True, "data": {"data": [{"email": f"b{i}@x.com"} for i in range(30)]}},   # 30
    {"is_success": True, "data": {"data": []}},                                              # empty -> stop
]
seq = {"i": 0}
def fake_get(url, headers):
    r = pages[min(seq["i"], len(pages) - 1)]
    seq["i"] += 1
    return r
connector._get = fake_get
_recs, _total, processed, _trunc = connector.socradar_fetch("https://x", "1", "k", "botnet", "2026-01-01", limit=100)
c["feed pagination: total-missing still pages past page 1"] = processed == 130

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — bug-hunt fixes regression-guarded" if ok else "FAIL")
sys.exit(0 if ok else 1)
