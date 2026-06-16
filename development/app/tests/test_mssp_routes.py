#!/usr/bin/env python3
"""MSSP R3 (stale-tab guard) + edit-tenant (Settings admin_subject) + tenant_create validation.
Drives the real ASGI routes. No gcloud/network. Run from the app dir: python3 tests/test_mssp_routes.py"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/mssp_routes.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0def"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"
os.environ["REMEDIATION_ADMINS"] = "operator@example.com"

import importlib
import app.config as cfg  # noqa: E402
importlib.reload(cfg)
from app import connector, db  # noqa: E402
import app.main as main  # noqa: E402
importlib.reload(main)
from fastapi.testclient import TestClient  # noqa: E402

connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.apply_action = lambda *a, **k: True
connector.is_admin = lambda email, token: False   # non-admin target (admin-safeguard now fail-closed — GAP2)
connector.verify_action_effect = lambda *a, **k: "unverifiable"

db.init_db()   # startup event isn't fired without the TestClient context manager; init the schema directly

c = {}
cl = TestClient(main.app)
# DEV_LOGIN sign-in
cl.get("/auth/login", follow_redirects=False)

def _csrf():
    # the session csrf is minted on first GET; pull it from a rendered page via the hidden input
    html = cl.get("/settings").text
    import re
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""

# --- two tenants (default + org B) ---
tb = db.create_tenant("C0orgb", "Org B", ["orgb.com"], "https://x", "2", "k", "2026-01-01",
                      admin_subject="ceo@orgb.com")
db.update_tenant(tb, enabled_actions=json.dumps(["signout"]))
default_t = db.first_tenant()
db.update_tenant(default_t["id"], enabled_actions=json.dumps(["signout"]))
fa = db.upsert_flagged(default_t["id"], "victim@example.com", {"botnet"}, "found", 1.0)

csrf = _csrf()

# --- 1) tenant_create validation: admin_subject outside verified domains is rejected ---
r = cl.post("/tenants", data={"customer_id": "C0bad", "name": "Bad", "verified_domains": "bad.com",
            "feed_base": "https://x", "feed_company_id": "9", "feed_start_date": "2026-01-01",
            "admin_subject": "admin@other.com", "csrf": csrf}, follow_redirects=False)
c["tenant_create rejects admin_subject outside verified domains"] = "err=adminsub" in r.headers.get("location", "")

# --- 2) tenant_create accepts admin_subject inside verified domains ---
r = cl.post("/tenants", data={"customer_id": "C0good", "name": "Good", "verified_domains": "good.com",
            "feed_base": "https://x", "feed_company_id": "9", "feed_start_date": "2026-01-01",
            "admin_subject": "admin@good.com", "csrf": csrf}, follow_redirects=False)
c["tenant_create accepts valid admin_subject"] = "created=1" in r.headers.get("location", "")
def _by_cid(cid):
    return next((t for t in db.list_tenants() if t["customer_id"] == cid), None)
c["created tenant persisted admin_subject"] = (_by_cid("C0good") or {}).get("admin_subject") == "admin@good.com"

# --- 3) R3 stale-tab: remediate with exp_tenant != active tenant is rejected ---
# active tenant is the default (session has no tenant_id -> first_tenant). Post with a WRONG exp_tenant.
r = cl.post(f"/flagged/{fa}/remediate", data={"action": "signout", "exp_tenant": str(tb), "csrf": csrf},
            follow_redirects=False)
c["R3: remediate with stale exp_tenant rejected"] = "err=tenant" in r.headers.get("location", "")
c["R3: A's row untouched by stale-tab POST"] = db.get_flagged(fa)["status"] == "open"

# --- 4) R3: remediate with the CORRECT exp_tenant proceeds ---
r = cl.post(f"/flagged/{fa}/remediate", data={"action": "signout", "exp_tenant": str(default_t["id"]), "csrf": csrf},
            follow_redirects=False)
c["R3: remediate with correct exp_tenant proceeds"] = "rem_ok" in r.headers.get("location", "")

# --- 5) edit-tenant: Settings can set admin_subject (valid) and rejects an invalid one ---
# switch active tenant to org B first (sqlite tenant id is the int rowid)
cl.post("/tenants/switch", data={"tenant_id": str(tb), "csrf": csrf}, follow_redirects=False)
csrf = _csrf()
r = cl.post("/settings", data={"verified_domains": "orgb.com", "admin_subject": "newceo@orgb.com",
            "csrf": csrf}, follow_redirects=False)
c["edit-tenant: Settings sets admin_subject"] = db.get_tenant(tb)["admin_subject"] == "newceo@orgb.com"
r = cl.post("/settings", data={"verified_domains": "orgb.com", "admin_subject": "x@elsewhere.com",
            "csrf": csrf}, follow_redirects=False)
c["edit-tenant: rejects admin_subject outside verified domains"] = "err=adminsub" in r.headers.get("location", "")
c["edit-tenant: admin_subject unchanged after rejected save"] = db.get_tenant(tb)["admin_subject"] == "newceo@orgb.com"

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — MSSP routes (R3 stale-tab guard + edit-tenant + tenant_create validation)" if ok else "FAIL")
sys.exit(0 if ok else 1)
