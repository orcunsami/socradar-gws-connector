#!/usr/bin/env python3
"""
Deterministic remediation-action test — no gcloud, no live Google calls.

Mocks connector._api (records every Admin SDK call) + get_dwd_token (records the scope requested)
+ the directory lookup, then drives service.remediate for ALL 9 actions and asserts each issues the
correct HTTP method + endpoint + body + scope, and that gating (enabled toggle, operator exclusion,
quarantine-group requirement, idempotency) behaves. Run from the app dir:
    python3 tests/test_actions.py
"""
import json
import os
import sys
import tempfile
import urllib.error
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "t.sqlite3")
os.environ["DEFAULT_CUSTOMER_ID"] = "C0t"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"

from app import connector, db, service  # noqa: E402
from app.storage_sqlite import conn  # noqa: E402  (raw SQLite reset — this is a SQLite-backend test)

CALLS = []          # (method, url, body)
SCOPES = []         # scopes requested via get_dwd_token


def fake_api(method, url, token, body=None):
    CALLS.append((method, url, body))
    if method == "GET" and url.endswith("/tokens"):
        return {"items": [{"clientId": "client-abc"}]}
    if method == "GET" and url.endswith("/asps"):
        return {"items": [{"codeId": 7}]}
    return {}


def setup():
    db.init_db()
    connector._api = fake_api
    connector.get_dwd_token = lambda scopes, **kw: (SCOPES.append(scopes[0]) or "tok")
    t = db.first_tenant()
    db.update_tenant(t["id"], feed_api_key="x", quarantine_group="quarantine@example.com",
                     enabled_actions=json.dumps(list(connector.ACTIONS.keys())))
    # seed a found flagged user
    db.upsert_flagged(t["id"], "victim@example.com", {"botnet"}, "found", 1.0)
    return db.get_tenant(t["id"]), db.list_flagged(t["id"])[0]


EXPECT = {
    # action: (scope-suffix, [(method, url-substring, body-check)])
    "signout":           ("user.security", [("POST", "/victim@example.com/signOut", None)]),
    "reset_password":    ("directory.user", [("PATCH", "/users/victim@example.com",
                                              lambda b: b.get("changePasswordAtNextLogin") is True and "password" in b)]),
    "suspend":           ("directory.user", [("PATCH", "/users/victim@example.com", lambda b: b == {"suspended": True})]),
    "unsuspend":         ("directory.user", [("PATCH", "/users/victim@example.com", lambda b: b == {"suspended": False})]),
    "disable_2sv":       ("user.security", [("POST", "/twoStepVerification/turnOff", None)]),
    "revoke_tokens":     ("user.security", [("GET", "/tokens", None), ("DELETE", "/tokens/client-abc", None)]),
    "revoke_asps":       ("user.security", [("GET", "/asps", None), ("DELETE", "/asps/7", None)]),
    "add_to_group":      ("group.member", [("POST", "/groups/quarantine@example.com/members",
                                            lambda b: b == {"email": "victim@example.com", "role": "MEMBER"})]),
    "remove_from_group": ("group.member", [("DELETE", "/groups/quarantine@example.com/members/victim@example.com", None)]),
}


def check_action(tenant, fu, action):
    CALLS.clear(); SCOPES.clear()
    res = service.remediate(tenant, fu["id"], action, "admin@example.com")
    if not res.get("ok"):
        return False, f"remediate returned {res}"
    scope_suffix, expected_calls = EXPECT[action]
    if not SCOPES or scope_suffix not in SCOPES[0]:
        return False, f"scope mismatch: requested {SCOPES}, expected suffix {scope_suffix}"
    for method, sub, body_check in expected_calls:
        match = [c for c in CALLS if c[0] == method and sub in urllib.parse.unquote(c[1])]
        if not match:
            return False, f"missing call {method} ...{sub}; got {CALLS}"
        if callable(body_check) and not body_check(match[0][2] or {}):
            return False, f"body check failed for {method} {sub}: {match[0][2]}"
    return True, "ok"


def main():
    tenant, fu = setup()
    ok_all = True

    print("=== per-action contract (method/endpoint/scope/body) ===")
    for action in connector.ACTIONS:
        # reset the user's status to 'open' so each action can run
        with conn() as c:
            c.execute("UPDATE flagged_users SET status='open' WHERE id=?", (fu["id"],))
        ok, msg = check_action(tenant, fu, action)
        print(("  PASS  " if ok else "  FAIL  ") + f"{action:18s} {msg if not ok else ''}")
        ok_all = ok_all and ok

    print("\n=== gating ===")
    # operator excluded
    db.upsert_flagged(tenant["id"], "operator@example.com", {"botnet"}, "found", 1.0)
    op = [r for r in db.list_flagged(tenant["id"]) if r["email"] == "operator@example.com"][0]
    r = service.remediate(tenant, op["id"], "signout", "admin@example.com")
    g1 = (not r["ok"]) and "operator" in r["error"]
    print(("  PASS  " if g1 else "  FAIL  ") + "operator excluded from remediation")

    # action not enabled
    db.update_tenant(tenant["id"], enabled_actions=json.dumps([]))
    t2 = db.get_tenant(tenant["id"])
    with conn() as c:
        c.execute("UPDATE flagged_users SET status='open' WHERE id=?", (fu["id"],))
    r = service.remediate(t2, fu["id"], "signout", "admin@example.com")
    g2 = (not r["ok"]) and "not enabled" in r["error"]
    print(("  PASS  " if g2 else "  FAIL  ") + "disabled action blocked")

    # group action without quarantine group set
    db.update_tenant(tenant["id"], enabled_actions=json.dumps(["add_to_group"]), quarantine_group="")
    t3 = db.get_tenant(tenant["id"])
    with conn() as c:
        c.execute("UPDATE flagged_users SET status='open' WHERE id=?", (fu["id"],))
    r = service.remediate(t3, fu["id"], "add_to_group", "admin@example.com")
    g3 = (not r["ok"]) and "quarantine group" in r["error"]
    print(("  PASS  " if g3 else "  FAIL  ") + "group action blocked when no quarantine group")

    # idempotency: 409 on add -> success ; 404 on remove -> success
    def raise_409(method, url, token, body=None):
        raise urllib.error.HTTPError(url, 409, "exists", {}, None)
    connector._api = raise_409
    g4 = connector.add_to_group("x@example.com", "q@example.com", "tok") is True
    def raise_404(method, url, token, body=None):
        raise urllib.error.HTTPError(url, 404, "missing", {}, None)
    connector._api = raise_404
    g5 = connector.remove_from_group("x@example.com", "q@example.com", "tok") is True
    print(("  PASS  " if (g4 and g5) else "  FAIL  ") + "group add 409 / remove 404 = idempotent success")

    # cross-domain quarantine group rejected at remediation (not just at save)
    db.update_tenant(tenant["id"], enabled_actions=json.dumps(["add_to_group"]), quarantine_group="bad@evil.com")
    t4 = db.get_tenant(tenant["id"])
    with conn() as c:
        c.execute("UPDATE flagged_users SET status='open' WHERE id=?", (fu["id"],))
    r = service.remediate(t4, fu["id"], "add_to_group", "admin@example.com")
    g6 = (not r["ok"]) and "verified domains" in r["error"]
    print(("  PASS  " if g6 else "  FAIL  ") + "cross-domain quarantine group rejected")

    # non-HTTP error (timeout/DNS) -> clean False, not an unhandled crash/500
    def raise_urlerror(method, url, token, body=None):
        raise urllib.error.URLError("network down")
    connector._api = raise_urlerror
    try:
        g7 = connector.apply_action("signout", "x@example.com", "tok") is False
    except Exception:
        g7 = False
    print(("  PASS  " if g7 else "  FAIL  ") + "non-HTTP error -> clean False (no crash)")

    ok_all = ok_all and g1 and g2 and g3 and g4 and g5 and g6 and g7
    print("\nRESULT:", "PASS — all 9 actions + gating verified (no gcloud)" if ok_all else "FAIL")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
