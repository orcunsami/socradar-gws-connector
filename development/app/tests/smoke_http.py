#!/usr/bin/env python3
"""
HTTP smoke test — drives the running app end to end via urllib (no curl).
Starts uvicorn, dev-logs-in, runs a scan through the UI endpoint, reads /flagged.
Run from the app dir with the venv active:  python3 tests/smoke_http.py
"""
import http.cookiejar
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# this script imports `app.config` in-process (for the feed key) — put the app dir on sys.path like the
# other tests do, so it works regardless of the caller's cwd.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = "http://127.0.0.1:8080"


def opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def wait_health(op, tries=40):
    for _ in range(tries):
        try:
            r = op.open(BASE + "/healthz", timeout=3)
            if r.status == 200:
                return r.read().decode()
        except Exception:
            time.sleep(0.5)
    raise SystemExit("server did not become healthy")


def main():
    logf = open("/tmp/gws_uvicorn.log", "w")
    srv = subprocess.Popen([".venv/bin/uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8080"],
                           stdout=logf, stderr=subprocess.STDOUT)
    try:
        op = opener()
        print("health:", wait_health(op))

        # auth gate: / without login should redirect to /login
        try:
            html = op.open(BASE + "/").read().decode()
        except urllib.error.HTTPError as e:
            print("auth-gate ERROR", e.code, ":", e.read().decode()[:300])
            raise
        print("auth-gate ->", "login page" if "Sign in with Google" in html else "NOT gated (?)")

        # dev login -> dashboard
        dash = op.open(BASE + "/auth/login").read().decode()
        m = re.search(r'name="csrf" value="([^"]+)"', dash)
        if not m:
            print("FAIL: no csrf on dashboard"); return 1
        csrf = m.group(1)
        print("dev-login: ok, csrf:", csrf[:12] + "...")

        # run scan through the app endpoint
        data = urllib.parse.urlencode({"csrf": csrf}).encode()
        flagged = op.open(urllib.request.Request(BASE + "/scan", data=data, method="POST")).read().decode()

        emails = sorted(set(re.findall(r"test\d+@tandogan\.dev", flagged)))
        found = flagged.count('pill ok">found')
        print("flagged emails (by the app):", emails)
        print("found-in-directory pills:", found)

        # enable the signout action via Settings, then remediate one user through the UI
        op.open(urllib.request.Request(BASE + "/settings", method="POST", data=urllib.parse.urlencode(
            {"csrf": csrf, "verified_domains": "example.com", "enabled_actions": "signout"}).encode())).read()
        flg = op.open(BASE + "/flagged").read().decode()
        mid = re.search(r"/flagged/(\d+)/remediate", flg)
        remediated = False
        if mid:
            after = op.open(urllib.request.Request(BASE + f"/flagged/{mid.group(1)}/remediate", method="POST",
                data=urllib.parse.urlencode({"csrf": csrf, "action": "signout"}).encode())).read().decode()
            remediated = 'pill ok">remediated' in after
        print("remediation via UI (enable signout -> revoke one user):", "ok" if remediated else "NOT verified")

        # --- multi-tenant isolation (no External; second tenant scoped to a domain we don't own) ---
        from app.config import settings as cfg
        op.open(urllib.request.Request(BASE + "/tenants", method="POST", data=urllib.parse.urlencode({
            "csrf": csrf, "name": "Beta Corp (sim)", "customer_id": "C0betacorp",
            "verified_domains": "beta-corp.example", "feed_base": "https://preprod.socradar.com",
            "feed_company_id": "132", "feed_start_date": "2026-06-01",
            "feed_api_key": cfg.feed_api_key}).encode())).read()
        # tenant1 is active (no switch button); the first switch button is tenant2
        tpage = op.open(BASE + "/tenants").read().decode()
        tid2 = re.search(r'name="tenant_id" value="(\d+)"', tpage).group(1)
        op.open(urllib.request.Request(BASE + "/tenants/switch", method="POST",
            data=urllib.parse.urlencode({"csrf": csrf, "tenant_id": tid2}).encode())).read()
        # scan tenant2 (Beta Corp) against the SAME feed -> tandogan users are foreign -> filtered out
        f2 = op.open(urllib.request.Request(BASE + "/scan", method="POST",
            data=urllib.parse.urlencode({"csrf": csrf}).encode())).read().decode()
        t2_emails = sorted(set(re.findall(r"test\d+@tandogan\.dev", f2)))
        # switch back to tenant1 -> its data is intact and isolated
        tpage2 = op.open(BASE + "/tenants").read().decode()
        tid1 = re.search(r'name="tenant_id" value="(\d+)"', tpage2).group(1)
        op.open(urllib.request.Request(BASE + "/tenants/switch", method="POST",
            data=urllib.parse.urlencode({"csrf": csrf, "tenant_id": tid1}).encode())).read()
        f1 = op.open(BASE + "/flagged").read().decode()
        t1_emails = sorted(set(re.findall(r"test\d+@tandogan\.dev", f1)))
        isolated = (len(t2_emails) == 0) and (len(t1_emails) >= 3)
        print(f"multi-tenant: tenant2(Beta Corp) sees {t2_emails or 'NONE'} ; tenant1 still has {len(t1_emails)} ->",
              "ISOLATED" if isolated else "LEAK!")

        ok = len(emails) >= 3 and found >= 3 and remediated and isolated
        print("RESULT:", "PASS — scan + remediation + multi-tenant isolation, all via the UI" if ok else "CHECK")
        return 0 if ok else 1
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except Exception:
            srv.kill()


if __name__ == "__main__":
    sys.exit(main())
