#!/usr/bin/env python3
"""Gap-fix verification (arastirma9 / EXP-GOOGLE-0046) — deterministic, no gcloud/network. Run from app dir.

Covers the 3 connector gaps the architecture review + code tie-break surfaced:
  GAP 2  admin-target safeguard must FAIL CLOSED + LOUD (old code failed OPEN on is_admin error/None)
  GAP 3  reset_password must auto-PAIR with revoke_tokens + revoke_asps (a bare reset leaves tokens alive)
  + an e2e greenfield run: scan -> flag -> remediate -> audit, end to end (mock connector).
"""
import importlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/gap.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0gap"
os.environ["FEED_FULL_SCAN"] = "false"   # the e2e here mocks the legacy fetch_all_sources path
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"
os.environ["APP_ENV"] = "dev"

import app.config as cfg
importlib.reload(cfg)
import app.connector as connector
import app.db as db
importlib.reload(db)
import app.service as service
importlib.reload(service)

# ---- mocks: no network. apply_action records the actions it was asked to run. ----
applied = []
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.apply_action = lambda action, email, token, group=None: (applied.append(action) or True)
ALL = ["signout", "reset_password", "suspend", "unsuspend", "disable_2sv",
       "revoke_tokens", "revoke_asps", "add_to_group", "remove_from_group"]

db.init_db()
t = db.first_tenant()
db.update_tenant(t["id"], enabled_actions=json.dumps(ALL))
t = db.first_tenant()   # re-read: the in-memory tenant row is a stale snapshot after update_tenant


def set_enabled(actions):
    """Update enabled_actions AND return a fresh tenant row (remediate reads the row it's handed)."""
    global t
    db.update_tenant(t["id"], enabled_actions=json.dumps(actions))
    t = db.first_tenant()
    return t


def new_victim(email):
    db.upsert_flagged(t["id"], email, {"botnet"}, "found", 1.0, [1])
    return [r for r in db.list_flagged(t["id"]) if r["email"] == email][0]["id"]


def has_audit(action=None, result=None, detail_sub=None):
    for a in db.list_audit(t["id"], 200):
        if action and a["action"] != action:
            continue
        if result and a["result"] != result:
            continue
        if detail_sub and detail_sub.lower() not in (a.get("detail") or "").lower():
            continue
        return True
    return False


c = {}

# ===== GAP 2 — admin-target safeguard FAIL CLOSED + LOUD =====
# 2a) target IS an admin -> refuse + alert-severity audit
connector.is_admin = lambda email, token: True
r = service.remediate(t, new_victim("admin1@example.com"), "signout", "tester")
c["admin target -> refused"] = (not r["ok"]) and r.get("admin_blocked") is True
c["admin block is LOUD (alert audit)"] = has_audit(result="alert", detail_sub="admin")

# 2b) is_admin INDETERMINATE (None) -> FAIL CLOSED (the regression: old code returned False here = fail-open)
connector.is_admin = lambda email, token: None
r = service.remediate(t, new_victim("maybe@example.com"), "signout", "tester")
c["is_admin None -> FAIL CLOSED (was fail-open)"] = (not r["ok"]) and r.get("admin_blocked") is True

# 2c) is_admin raises -> still FAIL CLOSED (indeterminate)
def _boom(email, token):
    raise RuntimeError("transient blip")
connector.is_admin = _boom
r = service.remediate(t, new_victim("blip@example.com"), "signout", "tester")
c["is_admin error -> FAIL CLOSED"] = (not r["ok"]) and r.get("admin_blocked") is True

# 2d) NON-admin -> proceeds normally
connector.is_admin = lambda email, token: False
applied.clear()
r = service.remediate(t, new_victim("user1@example.com"), "signout", "tester")
c["non-admin -> proceeds"] = r["ok"] and applied == ["signout"]

# ===== GAP 3 — reset_password auto-pairs with revoke_tokens + revoke_asps =====
connector.is_admin = lambda email, token: False
applied.clear()
r = service.remediate(t, new_victim("reset1@example.com"), "reset_password", "tester")
c["reset_password -> ok"] = r["ok"]
c["pairing: reset itself ran"] = "reset_password" in applied
c["pairing: revoke_tokens auto-ran"] = "revoke_tokens" in applied
c["pairing: revoke_asps auto-ran"] = "revoke_asps" in applied
c["pairing audited (paired:revoke_tokens)"] = has_audit(action="paired:revoke_tokens")

# 3b) pairing is SECURITY-MANDATED: runs even when revoke_tokens/asps are NOT tenant-enabled
set_enabled(["reset_password"])   # revoke disabled
applied.clear()
r = service.remediate(t, new_victim("reset2@example.com"), "reset_password", "tester")
c["pairing runs even when revoke NOT enabled"] = r["ok"] and "revoke_tokens" in applied and "revoke_asps" in applied
set_enabled(ALL)   # restore

# 3c) a non-paired action does NOT drag in revokes
applied.clear()
r = service.remediate(t, new_victim("susp1@example.com"), "suspend", "tester")
c["suspend does NOT auto-pair revokes"] = r["ok"] and applied == ["suspend"]

# 3d) pairing FAILURE -> NOT reported green (truthfulness, adversary-review finding): a failed token/ASP
# revoke = the open-ATO state pairing exists to close, so flag 'partial' + alert, don't claim full remediation.
def _fail_revokes(action, email, token, group=None):
    applied.append(action)
    return action not in ("revoke_tokens", "revoke_asps")   # reset ok, revokes FAIL
connector.apply_action = _fail_revokes
applied.clear()
pf = new_victim("resetfail@example.com")
r = service.remediate(t, pf, "reset_password", "tester")
c["pairing fail -> result.partial flagged"] = r.get("ok") and r.get("partial") is True
c["pairing fail -> NOT green (flagged 'partial')"] = db.get_flagged(pf)["status"] == "partial"
c["pairing fail -> alert audit (PAIRING INCOMPLETE)"] = has_audit(result="alert", detail_sub="PAIRING INCOMPLETE")
connector.apply_action = lambda action, email, token, group=None: (applied.append(action) or True)   # restore

# ===== disable_2sv security-downgrade semantics (Claude-web review) =====
connector.is_admin = lambda email, token: False
applied.clear()
r = service.remediate(t, new_victim("twosv@example.com"), "disable_2sv", "tester")
c["disable_2sv -> ok"] = r.get("ok") and "disable_2sv" in applied
c["disable_2sv -> loud DOWNGRADE alert audit"] = has_audit(action="remediate:disable_2sv", result="alert", detail_sub="DOWNGRADE")
c["disable_2sv is auto-FORBIDDEN (high-blast, never autonomous)"] = "disable_2sv" in cfg.settings.auto_high_blast_list

# ===== E2E GREENFIELD — scan -> flag -> remediate -> audit =====
connector.fetch_all_sources = lambda base, cid, key, sd: (
    {"e2e-victim@example.com": {"botnet"}},
    {"botnet": 1, "pii": 0, "vip": 0},
    {"e2e-victim@example.com": [99]},
    {"botnet": {"processed": 1, "total": 1, "truncated": False}})
connector.lookup_user = lambda email, token: "found"
connector.is_admin = lambda email, token: False
res = service.run_scan(t, "tester")
c["e2e scan ok, found=1"] = res.get("ok") and res.get("found") == 1
e2e_fid = [r for r in db.list_flagged(t["id"]) if r["email"] == "e2e-victim@example.com"][0]["id"]
applied.clear()
rr = service.remediate(t, e2e_fid, "signout", "tester")
c["e2e remediate ok"] = rr.get("ok") and "signout" in applied
c["e2e flagged -> remediated"] = db.get_flagged(e2e_fid)["status"] == "remediated"
c["e2e audited (remediate:signout ok)"] = has_audit(action="remediate:signout", result="ok")

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print(f"RESULT: {'PASS' if ok else 'FAIL'} — {sum(c.values())}/{len(c)} gap-fix checks")
sys.exit(0 if ok else 1)
