#!/usr/bin/env python3
"""unsuspend action (Entra enable_account parity): reverse of suspend. No gcloud/network. App dir."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import connector

c = {}

# --- registered as a non-destructive action, same scope as suspend, no new DWD scope ---
c["unsuspend in ACTIONS"] = "unsuspend" in connector.ACTIONS
c["unsuspend in _ACTION_FNS"] = "unsuspend" in connector._ACTION_FNS
c["unsuspend non-destructive"] = connector.ACTIONS["unsuspend"]["destructive"] is False
c["unsuspend reuses SCOPE_USER (no new scope)"] = connector.ACTIONS["unsuspend"]["scope"] == connector.SCOPE_USER
c["scope union unchanged (no admin re-auth)"] = connector.SCOPES_UNION == [
    connector.SCOPE_READONLY, connector.SCOPE_USER, connector.SCOPE_SECURITY, connector.SCOPE_GROUP]

# --- unsuspend_user sends PATCH {suspended: False} to the user resource ---
calls = []
connector._api = lambda method, url, token, body=None: (calls.append((method, url, body)) or {})
connector.unsuspend_user("user@example.com", "tok")
m, url, body = calls[-1]
c["PATCH method"] = m == "PATCH"
c["targets the user resource"] = url.endswith("/users/user%40example.com")
c["body sets suspended False"] = body == {"suspended": False}

# --- apply_action routes 'unsuspend' to unsuspend_user ---
calls.clear()
ok = connector.apply_action("unsuspend", "user@example.com", "tok")
c["apply_action returns True"] = ok is True
c["apply_action issued the PATCH"] = bool(calls) and calls[-1][2] == {"suspended": False}

# --- post-state verify: confirmed when suspended==False, failed when still True ---
connector._api = lambda method, url, token, body=None: {"suspended": False}
c["verify confirmed when restored"] = connector.verify_action_effect("unsuspend", "user@example.com", "tok") == "confirmed"
connector._api = lambda method, url, token, body=None: {"suspended": True}
c["verify failed when still suspended"] = connector.verify_action_effect("unsuspend", "user@example.com", "tok") == "failed"

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — unsuspend action verified (Entra enable_account parity)" if ok else "FAIL")
sys.exit(0 if ok else 1)
