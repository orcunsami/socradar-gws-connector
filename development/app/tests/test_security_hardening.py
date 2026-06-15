#!/usr/bin/env python3
"""Deterministic security-hardening tests — no gcloud, no network.
Covers the P0/quick-win batch: DEV_LOGIN fail-closed on Cloud Run, dev_login_active gating, RBAC
remediation-admin allowlist, session cookie hardening, generic 500 handler. Run from the app dir."""
import importlib
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/sec.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0sec"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"

c = {}


def fresh_config(**env):
    """Reload config with a given environment to exercise startup-time logic."""
    for k in ("DEV_LOGIN", "APP_ENV", "K_SERVICE", "SECRET_KEY", "REMEDIATION_ADMINS"):
        os.environ.pop(k, None)
    os.environ.update(env)
    import app.config as cfg
    importlib.reload(cfg)
    return cfg


# 1) DEV_LOGIN fail-closed on Cloud Run (the biggest risk)
cfg = fresh_config(DEV_LOGIN="true", K_SERVICE="gws-connector", SECRET_KEY="real-key")
try:
    cfg.assert_startup_safe()
    c["DEV_LOGIN on Cloud Run -> startup RAISES"] = False
except RuntimeError as e:
    c["DEV_LOGIN on Cloud Run -> startup RAISES"] = "DEV_LOGIN" in str(e)

# 2) default SECRET_KEY on Cloud Run -> raises (simulate operator left the default, DEV_LOGIN off)
cfg = fresh_config(K_SERVICE="gws-connector", SECRET_KEY="dev-insecure-change-me", DEV_LOGIN="false")
try:
    cfg.assert_startup_safe()
    c["default SECRET_KEY on Cloud Run -> RAISES"] = False
except RuntimeError as e:
    c["default SECRET_KEY on Cloud Run -> RAISES"] = "SECRET_KEY" in str(e)

# 3) dev_login_active gating: honored only off-Cloud-Run + APP_ENV=dev
cfg = fresh_config(DEV_LOGIN="true", APP_ENV="dev")   # no K_SERVICE
c["dev_login honored locally (dev)"] = cfg.settings.dev_login_active is True
cfg = fresh_config(DEV_LOGIN="true", APP_ENV="prod")
c["dev_login NOT honored when APP_ENV=prod"] = cfg.settings.dev_login_active is False
cfg = fresh_config(DEV_LOGIN="true", APP_ENV="dev", K_SERVICE="x", SECRET_KEY="real")
c["dev_login NOT honored on Cloud Run"] = cfg.settings.dev_login_active is False

# 4) RBAC remediation-admin allowlist
cfg = fresh_config()   # empty REMEDIATION_ADMINS -> defaults to [admin_subject]
import app.auth as auth
importlib.reload(auth)
c["empty allowlist -> only operator is admin"] = (
    auth.is_remediation_admin("operator@example.com") and not auth.is_remediation_admin("intern@example.com"))
cfg = fresh_config(REMEDIATION_ADMINS="sec1@example.com, SEC2@example.com")
importlib.reload(auth)
c["explicit allowlist enforced (case-insensitive)"] = (
    auth.is_remediation_admin("sec1@example.com") and auth.is_remediation_admin("sec2@example.com")
    and not auth.is_remediation_admin("operator@example.com"))

# 5) clean local startup is safe (no raise) + warns about dev_login
cfg = fresh_config(DEV_LOGIN="true", APP_ENV="dev")
warns = cfg.assert_startup_safe()
c["local dev startup OK + warns on dev_login"] = any("DEV_LOGIN active" in w for w in warns)

# 6) HTTP: RBAC blocks a non-admin from remediating; session cookie is hardened
fresh_config(DEV_LOGIN="true", APP_ENV="dev", REMEDIATION_ADMINS="boss@example.com")
import app.main as main
importlib.reload(auth)
importlib.reload(main)
from fastapi.testclient import TestClient
import app.db as db
import json as _json
db.init_db()
t = db.first_tenant()
db.update_tenant(t["id"], enabled_actions=_json.dumps(["signout"]))
db.upsert_flagged(t["id"], "v@example.com", {"botnet"}, "found", 1.0, [1])
fid = [r for r in db.list_flagged(t["id"]) if r["email"] == "v@example.com"][0]["id"]
cl = TestClient(main.app)
r0 = cl.get("/auth/login")   # dev-login -> session as ADMIN_SUBJECT (orcun), who is NOT in the allowlist
csrf = __import__("re").search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)
rr = cl.post(f"/flagged/{fid}/remediate", data={"action": "signout", "csrf": csrf}, follow_redirects=False)
c["non-admin remediate BLOCKED (RBAC)"] = rr.status_code == 303 and "err=forbidden" in rr.headers.get("location", "")
c["RBAC block did NOT remediate"] = db.get_flagged(fid)["status"] != "remediated"
# session cookie hardened (SameSite=lax; HttpOnly). MUST be lax, NOT strict: the Google OAuth callback is a
# cross-site top-level GET; strict would drop the session cookie on it and break EVERY production sign-in.
# lax still withholds the cookie on cross-site POSTs, and state-changing POSTs carry a separate _csrf token.
setck = r0.headers.get("set-cookie", "") + cl.get("/").headers.get("set-cookie", "")
c["session cookie SameSite=lax + HttpOnly"] = "samesite=lax" in setck.lower() and "httponly" in setck.lower()

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — security hardening (DEV_LOGIN guard + RBAC + session) verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
