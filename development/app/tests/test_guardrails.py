#!/usr/bin/env python3
"""
Deterministic auto-remediation guardrail test — no gcloud, no live Google.
Tests guardrails.decide() per-gate in isolation + the run_scan auto wiring (manual=no-op, auto+dry-run=log
only, auto+execute=remediate) + semi-auto apply_enabled_actions. Run from the app dir.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "g.sqlite3")
os.environ["DEFAULT_CUSTOMER_ID"] = "C0g"
os.environ["FEED_FULL_SCAN"] = "false"   # this test mocks the legacy fetch_all_sources path
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"

from app import connector, db, guardrails, service  # noqa: E402
from app.config import settings  # noqa: E402

c = {}
FU = {"id": 1, "email": "victim@example.com", "status": "open"}


def reset():
    settings.remediation_mode = "auto"
    settings.auto_enabled_actions = "signout"
    settings.auto_dry_run = False
    settings.auto_kill_switch = False
    settings.auto_high_blast_actions = "suspend"
    settings.auto_max_users_per_scan = 5
    settings.auto_exclude_users = ""


# --- decide() per-gate ---
reset(); c["execute when allowed + not dry-run"] = guardrails.decide({}, FU, "signout", {"actioned": 0}) == guardrails.EXECUTE
reset(); settings.auto_dry_run = True; c["dry-run -> DRYRUN"] = guardrails.decide({}, FU, "signout", {"actioned": 0}) == guardrails.DRYRUN
reset(); c["not in allow-list -> skip"] = guardrails.decide({}, FU, "reset_password", {"actioned": 0}).startswith("skip:not_in_allowlist")
reset(); settings.auto_enabled_actions = "suspend"; c["suspend high-blast -> skip (never auto)"] = "high_blast" in guardrails.decide({}, FU, "suspend", {"actioned": 0})
reset(); c["operator excluded -> skip"] = "operator" in guardrails.decide({}, {"email": "operator@example.com", "status": "open"}, "signout", {"actioned": 0})
reset(); settings.auto_exclude_users = "victim@example.com"; c["VIP/break-glass exclude -> skip"] = "user_excluded" in guardrails.decide({}, FU, "signout", {"actioned": 0})
reset(); c["already remediated -> skip"] = "already" in guardrails.decide({}, {"email": "x@example.com", "status": "remediated"}, "signout", {"actioned": 0})
reset(); c["blast cap -> skip"] = "blast_cap" in guardrails.decide({}, FU, "signout", {"actioned": 5})
reset(); settings.auto_kill_switch = True; c["kill switch -> skip"] = "kill" in guardrails.decide({}, FU, "signout", {"actioned": 0})
settings.remediation_mode = "garbage"; c["invalid mode -> manual"] = guardrails.effective_mode() == "manual"

# --- run_scan auto wiring ---
db.init_db()
t = db.first_tenant()
db.update_tenant(t["id"], enabled_actions=json.dumps(["signout"]))
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.lookup_user = lambda e, tok: "found"
connector._api = lambda *a, **k: {}


def feed_for(email, aid):
    connector.fetch_all_sources = lambda *a, **k: ({email: {"botnet"}}, {"botnet": 1, "pii": 0, "vip": 0}, {email: [aid]}, {})


reset()
db.update_tenant(t["id"], auto_baseline_at=1.0)   # baseline already established (past) -> findings auto-eligible
settings.auto_dry_run = True
feed_for("victim@example.com", 111)
service.run_scan(db.get_tenant(t["id"]), "scheduler")
aud = db.list_audit(t["id"])
c["auto dry-run logged (no execute)"] = any(a["action"] == "auto:signout" and a["result"] == "dryrun" for a in aud)
fu = [r for r in db.list_flagged(t["id"]) if r["email"] == "victim@example.com"][0]
c["dry-run did NOT remediate"] = fu["status"] != "remediated"

reset()  # auto, not dry-run -> executes
feed_for("victim2@example.com", 222)
service.run_scan(db.get_tenant(t["id"]), "scheduler")
fu2 = [r for r in db.list_flagged(t["id"]) if r["email"] == "victim2@example.com"][0]
c["auto execute -> user remediated"] = fu2["status"] == "remediated"
c["auto execute logged ok"] = any(a["action"] == "auto:signout" and a["result"] == "ok" for a in db.list_audit(t["id"]))

settings.remediation_mode = "manual"  # manual -> no auto
feed_for("victim3@example.com", 333)
service.run_scan(db.get_tenant(t["id"]), "scheduler")
fu3 = [r for r in db.list_flagged(t["id"]) if r["email"] == "victim3@example.com"][0]
c["manual mode -> NO auto remediation"] = fu3["status"] != "remediated"

# --- semi-auto one-click ---
out = service.apply_enabled_actions(db.get_tenant(t["id"]), fu3["id"], "admin@example.com")
c["semi-auto applies enabled actions"] = ("signout", "ok") in out
c["semi-auto -> user remediated"] = db.get_flagged(fu3["id"])["status"] == "remediated"

# #4 partial: 2 enabled actions, one fails -> status 'partial' (not 'remediated')
db.update_tenant(t["id"], enabled_actions=json.dumps(["signout", "reset_password"]))
_orig = connector.apply_action
connector.apply_action = lambda action, email, token, group=None: action == "signout"   # signout ok, reset fails
db.upsert_flagged(t["id"], "victimP@example.com", {"botnet"}, "found", 1.0, [9])
fuP = [r for r in db.list_flagged(t["id"]) if r["email"] == "victimP@example.com"][0]
service.apply_enabled_actions(db.get_tenant(t["id"]), fuP["id"], "admin@example.com")
c["partial when an action fails (not 'remediated')"] = db.get_flagged(fuP["id"])["status"] == "partial"

# #3 per-user blast cap: cap=1, 2 found users, auto execute -> only 1 user remediated
reset()
settings.auto_max_users_per_scan = 1
connector.apply_action = lambda *a, **k: True
connector.fetch_all_sources = lambda *a, **k: (
    {"u1@example.com": {"botnet"}, "u2@example.com": {"botnet"}}, {"botnet": 2, "pii": 0, "vip": 0}, {}, {})
db.update_tenant(t["id"], enabled_actions=json.dumps(["signout"]))
service.run_scan(db.get_tenant(t["id"]), "scheduler")
remed = [r for r in db.list_flagged(t["id"]) if r["email"] in ("u1@example.com", "u2@example.com") and r["status"] == "remediated"]
c["per-user blast cap (1 of 2 auto-actioned)"] = len(remed) == 1
connector.apply_action = _orig

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — remediation_mode guardrails (manual/semi-auto/auto + gates) verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
