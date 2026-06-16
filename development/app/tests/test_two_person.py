#!/usr/bin/env python3
"""Two-person (four-eyes) approval — deterministic, no gcloud/network. Run from the app dir.
Verifies: high-blast action with require_approval queues instead of executing; a DIFFERENT admin approves
-> executes; the requester CANNOT approve their own request (four-eyes); reject works; flag off = direct."""
import importlib
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/tp.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0tp"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"
os.environ["REQUIRE_APPROVAL"] = "true"
os.environ["REMEDIATION_ADMINS"] = "alice@example.com,bob@example.com"

import app.config as cfg
importlib.reload(cfg)
import app.auth as auth
importlib.reload(auth)
import app.connector as connector
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.apply_action = lambda action, email, token, group=None: True
connector.is_admin = lambda email, token: False   # non-admin target (admin-safeguard now fail-closed — GAP2)
import app.db as db
importlib.reload(db)
import app.main as main
importlib.reload(main)
from fastapi.testclient import TestClient

c = {}
db.init_db()
t = db.first_tenant()
db.update_tenant(t["id"], enabled_actions=json.dumps(["suspend", "signout"]))
db.upsert_flagged(t["id"], "victim@example.com", {"botnet"}, "found", 1.0, [1])
fid = [r for r in db.list_flagged(t["id"]) if r["email"] == "victim@example.com"][0]["id"]


def client_as(email):
    """A TestClient whose dev-login session is forced to a specific admin email."""
    cl = TestClient(main.app)
    cl.get("/auth/login")  # sets session user = ADMIN_SUBJECT
    # override the session user email by monkeypatching auth.current_user for this client's requests
    return cl


# Force the "logged in" identity by monkeypatching current_user per phase (dev-login always = admin_subject).
_user = {"email": "alice@example.com"}
auth.current_user = lambda request: _user
main.auth.current_user = lambda request: _user

cl = TestClient(main.app)
csrf = re.search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)

# 1) high-blast suspend with approval ON -> queued, NOT executed
r = cl.post(f"/flagged/{fid}/remediate", data={"action": "suspend", "csrf": csrf}, follow_redirects=False)
c["high-blast queued (redirect to /approvals)"] = r.status_code == 303 and "/approvals" in r.headers.get("location", "")
c["suspend NOT executed yet"] = db.get_flagged(fid)["status"] != "remediated"
pend = db.list_approvals(t["id"], "pending")
c["pending approval created"] = len(pend) == 1 and pend[0]["action"] == "suspend"
ap_id = pend[0]["id"]

# 2) four-eyes: requester (alice) CANNOT approve her own
csrf = re.search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)
r = cl.post(f"/approvals/{ap_id}/approve", data={"csrf": csrf}, follow_redirects=False)
c["requester cannot self-approve (four-eyes)"] = "err=foureyes" in r.headers.get("location", "")
c["still not executed after self-approve attempt"] = db.get_flagged(fid)["status"] != "remediated"

# 3) a DIFFERENT admin (bob) approves -> executes
_user = {"email": "bob@example.com"}
csrf = re.search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)
r = cl.post(f"/approvals/{ap_id}/approve", data={"csrf": csrf}, follow_redirects=False)
c["second admin approve -> approved"] = "approved=1" in r.headers.get("location", "")
c["suspend NOW executed"] = db.get_flagged(fid)["status"] == "remediated"
c["approval state = executed"] = db.get_approval(ap_id)["state"] == "executed"

# 4) non-admin cannot approve
db.upsert_flagged(t["id"], "v2@example.com", {"botnet"}, "found", 1.0, [2])
fid2 = [r for r in db.list_flagged(t["id"]) if r["email"] == "v2@example.com"][0]["id"]
_user = {"email": "alice@example.com"}
csrf = re.search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)
cl.post(f"/flagged/{fid2}/remediate", data={"action": "suspend", "csrf": csrf}, follow_redirects=False)
ap2 = db.list_approvals(t["id"], "pending")[0]["id"]
_user = {"email": "intruder@example.com"}  # not in REMEDIATION_ADMINS
csrf = re.search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)
r = cl.post(f"/approvals/{ap2}/approve", data={"csrf": csrf}, follow_redirects=False)
c["non-admin cannot approve"] = "err=forbidden" in r.headers.get("location", "") and db.get_flagged(fid2)["status"] != "remediated"

# 5) reject works
_user = {"email": "bob@example.com"}
csrf = re.search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)
r = cl.post(f"/approvals/{ap2}/reject", data={"csrf": csrf}, follow_redirects=False)
c["reject -> rejected, never executed"] = db.get_approval(ap2)["state"] == "rejected" and db.get_flagged(fid2)["status"] != "remediated"

# 6) non-approval action (signout) executes directly even with approval ON
db.upsert_flagged(t["id"], "v3@example.com", {"botnet"}, "found", 1.0, [3])
fid3 = [r for r in db.list_flagged(t["id"]) if r["email"] == "v3@example.com"][0]["id"]
_user = {"email": "alice@example.com"}
csrf = re.search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)
cl.post(f"/flagged/{fid3}/remediate", data={"action": "signout", "csrf": csrf}, follow_redirects=False)
c["non-high-blast executes directly"] = db.get_flagged(fid3)["status"] == "remediated"

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — two-person (four-eyes) approval verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
