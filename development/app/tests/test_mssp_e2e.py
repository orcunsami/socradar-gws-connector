#!/usr/bin/env python3
"""MSSP greenfield E2E: from an empty DB, through the real ASGI routes, stand up TWO orgs and prove the
full loop + cross-org isolation end to end. No gcloud/network. Run: python3 tests/test_mssp_e2e.py"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/mssp_e2e.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0mssp"          # the MSSP's own/primary tenant
os.environ["DEFAULT_DOMAIN"] = "mssp.com"
os.environ["ADMIN_SUBJECT"] = "operator@mssp.com"
os.environ["SERVICE_ACCOUNT"] = "connector@mssp-proj.iam.gserviceaccount.com"
os.environ["REMEDIATION_ADMINS"] = "operator@mssp.com"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"

import importlib
import app.config as cfg  # noqa: E402
importlib.reload(cfg)
from app import connector, db  # noqa: E402
import app.main as main  # noqa: E402
importlib.reload(main)
from fastapi.testclient import TestClient  # noqa: E402

# --- feed + Google mocks: each org's scan finds its OWN leaked user; capture the impersonated subject ---
FEED = {
    "C0orga": ({"alice@orga.com": {"botnet"}}, {"botnet": 1, "pii": 0, "vip": 0}, {"alice@orga.com": [11]}, {}),
    "C0orgb": ({"bob@orgb.com": {"pii"}}, {"botnet": 0, "pii": 1, "vip": 0}, {"bob@orgb.com": [22]}, {}),
}
def _fetch(base, company_id, api_key, start_date):
    return FEED.get(company_id, ({}, {}, {}, {}))
connector.fetch_all_sources = _fetch
MINTS = []
connector.get_dwd_token = lambda scopes, subject=None, service_account=None, **kw: (
    MINTS.append({"subject": subject, "sa": service_account}) or "tok")
connector.lookup_user = lambda email, token: "found"
connector.apply_action = lambda *a, **k: True
connector.verify_action_effect = lambda *a, **k: "unverifiable"

db.init_db()
c = {}
cl = TestClient(main.app)
cl.get("/auth/login", follow_redirects=False)   # DEV_LOGIN as operator@mssp.com

def csrf():
    import re
    m = re.search(r'name="csrf" value="([^"]+)"', cl.get("/tenants").text)
    return m.group(1) if m else ""

def cid_tenant(cid):
    return next((t for t in db.list_tenants() if t["customer_id"] == cid), None)

tok = csrf()

# === 1) onboard two customer orgs from scratch via the UI route ===
for cid, dom, admin, comp in [("C0orga", "orga.com", "ceo@orga.com", "C0orga"),
                              ("C0orgb", "orgb.com", "ceo@orgb.com", "C0orgb")]:
    r = cl.post("/tenants", data={"customer_id": cid, "name": cid, "verified_domains": dom,
                "feed_base": "https://x", "feed_company_id": comp, "feed_start_date": "2026-01-01",
                "admin_subject": admin, "csrf": tok}, follow_redirects=False)
c["onboarded org A + org B"] = cid_tenant("C0orga") is not None and cid_tenant("C0orgb") is not None
ta, tb = cid_tenant("C0orga"), cid_tenant("C0orgb")
# enable signout on both
db.update_tenant(ta["id"], enabled_actions=json.dumps(["signout"]))
db.update_tenant(tb["id"], enabled_actions=json.dumps(["signout"]))

# === 2) scan each org (switch active tenant, Run scan) — each impersonates ITS OWN admin ===
cl.post("/tenants/switch", data={"tenant_id": str(ta["id"]), "csrf": tok}, follow_redirects=False)
cl.post("/scan", data={"csrf": tok}, follow_redirects=False)
cl.post("/tenants/switch", data={"tenant_id": str(tb["id"]), "csrf": tok}, follow_redirects=False)
cl.post("/scan", data={"csrf": tok}, follow_redirects=False)
subs = [m["subject"] for m in MINTS]
c["scan A impersonated org A's admin"] = "ceo@orga.com" in subs
c["scan B impersonated org B's admin"] = "ceo@orgb.com" in subs
c["org A's flagged user found"] = any(f["email"] == "alice@orga.com" for f in db.list_flagged(ta["id"]))
c["org B's flagged user found"] = any(f["email"] == "bob@orgb.com" for f in db.list_flagged(tb["id"]))
c["org A's user NOT in org B's flagged list"] = not any(f["email"] == "alice@orga.com" for f in db.list_flagged(tb["id"]))

# === 3) remediate in org A (active = B now; switch back, act, with the stale-tab guard satisfied) ===
cl.post("/tenants/switch", data={"tenant_id": str(ta["id"]), "csrf": tok}, follow_redirects=False)
fa = [f for f in db.list_flagged(ta["id"]) if f["email"] == "alice@orga.com"][0]["id"]
r = cl.post(f"/flagged/{fa}/remediate", data={"action": "signout", "exp_tenant": str(ta["id"]), "csrf": tok},
            follow_redirects=False)
c["remediate in org A succeeded"] = "rem_ok" in r.headers.get("location", "")
c["org A's user marked remediated"] = db.get_flagged(fa)["status"] == "remediated"

# === 4) cross-org isolation: from org A's session, B's flagged id is rejected ===
fb = [f for f in db.list_flagged(tb["id"]) if f["email"] == "bob@orgb.com"][0]["id"]
before = db.get_flagged(fb)["status"]
# active tenant is A; posting B's id with exp_tenant=A (what a real stale page would send) -> remediate
# rejects it as not-in-this-tenant (service.remediate ownership chokepoint)
cl.post(f"/flagged/{fb}/remediate", data={"action": "signout", "exp_tenant": str(ta["id"]), "csrf": tok},
        follow_redirects=False)
c["org B's user untouched from org A's session"] = db.get_flagged(fb)["status"] == before == "open"

# === 5) audit chains are per-org and verify independently ===
va = db.verify_audit_chain(ta["id"])
vb = db.verify_audit_chain(tb["id"])
c["org A audit chain verifies"] = va.get("ok") is True
c["org B audit chain verifies"] = vb.get("ok") is True
c["org A audit has the remediation; org B does not"] = (
    any(r["action"] == "remediate:signout" and r["target_email"] == "alice@orga.com" for r in db.list_audit(ta["id"]))
    and not any(r.get("target_email") == "alice@orga.com" for r in db.list_audit(tb["id"])))

# === 6) backward-compat: the MSSP's own seeded default tenant inherits the GLOBAL identity ===
mssp_t = cid_tenant("C0mssp")
c["default tenant inherits global admin (blank per-tenant)"] = mssp_t["admin_subject"] == ""

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — MSSP greenfield E2E (two orgs onboarded -> scanned -> remediated -> isolated -> audited)" if ok else "FAIL")
sys.exit(0 if ok else 1)
