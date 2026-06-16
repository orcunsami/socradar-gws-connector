#!/usr/bin/env python3
"""MSSP Layer 2/3: per-tenant DWD impersonation + per-tenant operator-exclusion.
No gcloud/network. Run from the app dir: python3 tests/test_mssp_dwd.py"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/mssp_dwd.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0def"
os.environ["FEED_FULL_SCAN"] = "false"   # this test mocks the legacy fetch_all_sources path
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"     # the GLOBAL admin (single-org default)
os.environ["SERVICE_ACCOUNT"] = "global-sa@proj.iam.gserviceaccount.com"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"

import importlib
import app.config as cfg  # noqa: E402
importlib.reload(cfg)
from app import connector, db, service  # noqa: E402

c = {}
db.init_db()

# capture every token mint: (scopes, subject, service_account)
MINTS = []
connector.get_dwd_token = lambda scopes, subject=None, service_account=None, **kw: (
    MINTS.append({"scopes": list(scopes), "subject": subject, "sa": service_account}) or "tok")
connector.lookup_user = lambda email, token: "found"
connector.apply_action = lambda action, email, token, group=None: True
connector.verify_action_effect = lambda *a, **k: "unverifiable"
connector.fetch_all_sources = lambda *a, **k: ({}, {}, {}, {})  # no feed work; we drive remediate directly

# --- two MSSP orgs, each with its OWN super-admin ---
ta = db.create_tenant("C0orga", "Org A", ["orga.com"], "https://x", "1", "k", "2026-01-01",
                      admin_subject="ceo@orga.com", service_account="sa-a@proja.iam.gserviceaccount.com")
tb = db.create_tenant("C0orgb", "Org B", ["orgb.com"], "https://x", "2", "k", "2026-01-01",
                      admin_subject="ceo@orgb.com")  # no per-tenant SA -> inherits global SA
db.update_tenant(ta, enabled_actions=json.dumps(["signout"]))
db.update_tenant(tb, enabled_actions=json.dumps(["signout"]))

# --- remediate a normal user in each org; the minted token must carry THAT org's subject/SA ---
fa = db.upsert_flagged(ta, "victim@orga.com", {"botnet"}, "found", 1.0)
service.remediate(db.get_tenant(ta), fa, "signout", "soc@example.com")
mint_a = MINTS[-1]
c["org A impersonates org A admin"] = mint_a["subject"] == "ceo@orga.com"
c["org A uses org A's per-tenant SA"] = mint_a["sa"] == "sa-a@proja.iam.gserviceaccount.com"

fb = db.upsert_flagged(tb, "victim@orgb.com", {"pii"}, "found", 1.0)
service.remediate(db.get_tenant(tb), fb, "signout", "soc@example.com")
mint_b = MINTS[-1]
c["org B impersonates org B admin"] = mint_b["subject"] == "ceo@orgb.com"
c["org B (no per-tenant SA) falls back to GLOBAL SA"] = mint_b["sa"] == "global-sa@proj.iam.gserviceaccount.com"
c["org A subject NEVER used for org B"] = mint_b["subject"] != "ceo@orga.com"

# --- per-tenant operator-exclusion: each org's OWN admin is blocked; the other org's admin is normal ---
fb_admin = db.upsert_flagged(tb, "ceo@orgb.com", {"botnet"}, "found", 1.0)
r = service.remediate(db.get_tenant(tb), fb_admin, "signout", "soc@example.com")
c["org B's own super-admin is operator-excluded"] = (not r["ok"]) and "operator" in r["error"]

# ceo@orga.com is NOT org B's admin -> it would be a normal remediable user in org B (not auto-protected).
# (It's not in org B's verified domain, so it gets domain-blocked — proving the exclusion isn't what stops it.)
fb_other = db.upsert_flagged(tb, "ceo@orga.com", {"botnet"}, "found", 1.0)
r2 = service.remediate(db.get_tenant(tb), fb_other, "signout", "soc@example.com")
c["org A's admin is NOT operator-excluded in org B (domain-blocked instead)"] = (
    (not r2["ok"]) and "operator" not in r2["error"])

# --- single-org backward-compat: a tenant with blank admin_subject falls back to the GLOBAL ---
tc = db.create_tenant("C0single", "Single", ["example.com"], "https://x", "3", "k", "2026-01-01")  # no admin_subject
db.update_tenant(tc, enabled_actions=json.dumps(["signout"]))
fc = db.upsert_flagged(tc, "user@example.com", {"botnet"}, "found", 1.0)
service.remediate(db.get_tenant(tc), fc, "signout", "soc@example.com")
c["blank-admin tenant falls back to GLOBAL subject"] = MINTS[-1]["subject"] == "operator@example.com"
c["blank-SA tenant falls back to GLOBAL SA"] = MINTS[-1]["sa"] == "global-sa@proj.iam.gserviceaccount.com"

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — MSSP Layer 2/3 (per-tenant DWD impersonation + per-tenant operator-exclusion)" if ok else "FAIL")
sys.exit(0 if ok else 1)
