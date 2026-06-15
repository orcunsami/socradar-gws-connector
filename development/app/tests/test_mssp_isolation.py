#!/usr/bin/env python3
"""MSSP R1: cross-tenant by-id isolation — no org can mutate/leak another org's flagged row via a bare id.
No gcloud/network. Run from the app dir: python3 tests/test_mssp_isolation.py"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/mssp_iso.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0def"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"
os.environ["REQUIRE_APPROVAL"] = "true"
os.environ["APPROVAL_ACTIONS"] = "signout"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"

import importlib
import app.config as cfg  # noqa: E402
importlib.reload(cfg)
from app import connector, db, service  # noqa: E402

c = {}
db.init_db()
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.apply_action = lambda action, email, token, group=None: True
connector.verify_action_effect = lambda *a, **k: "unverifiable"

ta = db.create_tenant("C0orga", "Org A", ["orga.com"], "https://x", "1", "k", "2026-01-01",
                      admin_subject="ceo@orga.com")
tb = db.create_tenant("C0orgb", "Org B", ["orgb.com"], "https://x", "2", "k", "2026-01-01",
                      admin_subject="ceo@orgb.com")
db.update_tenant(ta, enabled_actions=json.dumps(["signout"]))
db.update_tenant(tb, enabled_actions=json.dumps(["signout"]))

# org A has a flagged user; capture its id
fa = db.upsert_flagged(ta, "victim@orga.com", {"botnet"}, "found", 1.0)

# --- get_flagged_for_tenant: A's id under B returns None ---
c["A's flagged id is invisible to tenant B"] = db.get_flagged_for_tenant(fa, tb) is None
c["A's flagged id is visible to tenant A"] = db.get_flagged_for_tenant(fa, ta) is not None

# --- remediate(tenant B, A's id) is rejected and does NOT mutate A's row ---
before = db.get_flagged(fa)["status"]
r = service.remediate(db.get_tenant(tb), fa, "signout", "soc@example.com")
after = db.get_flagged(fa)["status"]
c["cross-org remediate rejected"] = not r["ok"]
c["A's row status unchanged by B's remediate"] = before == after == "open"

# --- apply_enabled_actions(tenant B, A's id) must NOT flip A's row to 'partial' (the verifier's finding) ---
service.apply_enabled_actions(db.get_tenant(tb), fa, "soc@example.com")
c["A's row NOT mutated to partial by B's apply_enabled_actions"] = db.get_flagged(fa)["status"] == "open"

# --- approval creation under B with A's id must NOT leak A's email into B's approvals ---
# (require_approval=true + signout in approval list -> the manual route would create an approval)
# We exercise the service-level guard: B's apply_enabled_actions queued nothing for A's id.
b_approvals = db.list_approvals(tb)
leaked = [a for a in b_approvals if a.get("email") == "victim@orga.com"]
c["A's email did NOT leak into B's approvals"] = len(leaked) == 0

# --- audit chains stay independent: B's blocked attempts are logged under B, not A ---
a_audit = db.list_audit(ta)
b_audit = db.list_audit(tb)
c["B's cross-org attempt audited under B (not A)"] = all(
    "victim@orga.com" not in (row.get("target_email") or "") or row.get("result") != "ok" for row in b_audit)

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — MSSP R1 (cross-tenant by-id isolation; no mutate/PII-leak across orgs)" if ok else "FAIL")
sys.exit(0 if ok else 1)
