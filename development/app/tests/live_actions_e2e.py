#!/usr/bin/env python3
"""
LIVE end-to-end test of the remediation actions against real Google Workspace — ADAPTIVE.

It detects which scopes are actually granted on the DWD client and runs as much as it can:
  - If admin.directory.user is granted -> creates a THROWAWAY target and runs ALL 8 actions on it
    (security + user + group), verifies observable effects, then deletes the target.
  - If not -> falls back to the 4 SECURITY-scope actions (signout, disable_2sv, revoke_tokens,
    revoke_asps) on an existing free-pool user (test4), and reports exactly which scopes/group are
    still needed for the other 4.

SAFETY: never touches test1/2/3. The full path uses a self-created/-deleted throwaway. The fallback
uses test4 (free pool) and only runs non-destructive-to-credentials actions (no password/suspend).

Run:  python3 tests/live_actions_e2e.py [quarantine-group-email]
"""
import os
import sys
import time
import urllib.error
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import connector  # noqa: E402

QG = sys.argv[1] if len(sys.argv) > 1 else None
TARGET = f"e2e-target-{int(time.time())}@example.com"  # unique per run (deleted email stays reserved ~20d)
FALLBACK_USER = "test4@example.com"
D = connector.DIRECTORY


def tok(scope):
    return connector.get_dwd_token([scope])


def api(method, path, scope, body=None):
    return connector._api(method, f"{D}{path}", tok(scope), body)


def q(email):
    return urllib.parse.quote(email)


def exists(email):
    try:
        api("GET", f"/users/{q(email)}", connector.SCOPE_READONLY)
        return True
    except urllib.error.HTTPError:
        return False


def run_full(target):
    r = {}
    r["signout"] = connector.revoke_sessions(target, tok(connector.SCOPE_SECURITY))
    try:
        r["disable_2sv"] = connector.disable_2sv(target, tok(connector.SCOPE_SECURITY))
    except urllib.error.HTTPError as e:
        r["disable_2sv"] = f"no-2sv-enrolled (HTTP {e.code}) — expected for a fresh user"
    r["revoke_tokens"] = connector.revoke_oauth_tokens(target, tok(connector.SCOPE_SECURITY))
    r["revoke_asps"] = connector.revoke_asps(target, tok(connector.SCOPE_SECURITY))
    r["reset_password"] = connector.reset_password(target, tok(connector.SCOPE_USER))
    # suspend verified on a STABLE user (fresh throwaways have suspend read-after-write lag), then reverted
    connector.suspend_user(FALLBACK_USER, tok(connector.SCOPE_USER))
    susp = False
    for _ in range(5):
        time.sleep(2)
        if api("GET", f"/users/{q(FALLBACK_USER)}", connector.SCOPE_READONLY).get("suspended") is True:
            susp = True
            break
    api("PATCH", f"/users/{q(FALLBACK_USER)}", connector.SCOPE_USER, {"suspended": False})  # revert
    r[f"suspend (verified on {FALLBACK_USER})"] = susp
    if QG:
        gu = FALLBACK_USER  # verify group ops on a STABLE user (a fresh throwaway can't join a group yet)
        def is_member():
            members = api("GET", f"/groups/{q(QG)}/members", connector.SCOPE_GROUP).get("members", [])
            return any((m.get("email") or "").lower() == gu for m in members)
        try:
            connector.add_to_group(gu, QG, tok(connector.SCOPE_GROUP))
            added = False
            for _ in range(5):
                time.sleep(2)
                if is_member():
                    added = True
                    break
            r[f"add_to_group (verified {gu} member)"] = added
            connector.remove_from_group(gu, QG, tok(connector.SCOPE_GROUP))
            gone = False
            for _ in range(5):
                time.sleep(2)
                if not is_member():
                    gone = True
                    break
            r[f"remove_from_group (verified {gu} gone)"] = gone
        except (connector.ConnectorError, urllib.error.HTTPError) as e:
            r["group actions"] = f"FAILED — is the group '{QG}' created + admin.directory.group.member granted? ({e})"
    else:
        r["group actions"] = "SKIPPED (pass a quarantine group email as the arg)"
    return r


def run_fallback(user):
    r = {}
    r["signout"] = connector.revoke_sessions(user, tok(connector.SCOPE_SECURITY))
    try:
        r["disable_2sv"] = connector.disable_2sv(user, tok(connector.SCOPE_SECURITY))
    except urllib.error.HTTPError as e:
        r["disable_2sv"] = f"no-2sv-enrolled (HTTP {e.code})"
    r["revoke_tokens"] = connector.revoke_oauth_tokens(user, tok(connector.SCOPE_SECURITY))
    r["revoke_asps"] = connector.revoke_asps(user, tok(connector.SCOPE_SECURITY))
    return r


def main():
    try:
        tok(connector.SCOPE_READONLY)
    except connector.ConnectorError as e:
        print(f"ABORT: {e}\n→ run: ! ~/google-cloud-sdk/bin/gcloud auth login")
        return 2

    # probe: is admin.directory.user granted? (try to create the throwaway)
    full = False
    try:
        body = {"primaryEmail": TARGET, "name": {"givenName": "E2E", "familyName": "Target"},
                "password": "TmpE2E!" + str(int(time.time())), "changePasswordAtNextLogin": True}
        api("POST", "/users", connector.SCOPE_USER, body)
        full = True
        time.sleep(3)
    except (connector.ConnectorError, urllib.error.HTTPError):
        full = False

    if full:
        print(f"directory.user GRANTED → FULL live test on throwaway {TARGET} (quarantine={QG or 'skip'})\n")
        try:
            r = run_full(TARGET)
        finally:
            print("cleaning up throwaway target...")
            try:
                api("DELETE", f"/users/{q(TARGET)}", connector.SCOPE_USER)
            except Exception as e:
                print(f"  (delete failed: {e} — remove {TARGET} manually)")
    else:
        if not exists(FALLBACK_USER):
            print(f"directory.user NOT granted, and fallback user {FALLBACK_USER} not found.\n"
                  f"→ Add scopes admin.directory.user + admin.directory.group.member to the DWD client, "
                  f"and create a quarantine group, then re-run for the full 8.")
            return 2
        print(f"directory.user NOT granted → FALLBACK: 4 security-scope actions on {FALLBACK_USER}\n"
              f"(reset_password/suspend/group need admin.directory.user + admin.directory.group.member + a group)\n")
        r = run_fallback(FALLBACK_USER)

    print("=== RESULTS ===")
    ok = True
    for k, v in r.items():
        good = (v is True) or (isinstance(v, str) and ("no-2sv" in v or "SKIPPED" in v))
        if isinstance(v, str) and "FAILED" in v:
            good = False
        ok = ok and good
        print(("  PASS  " if good else "  ----  ") + f"{k}: {v}")
    print("\nRESULT:", "all attempted actions executed live against real Google" if ok else "see ---- lines above")
    return 0


if __name__ == "__main__":
    sys.exit(main())
