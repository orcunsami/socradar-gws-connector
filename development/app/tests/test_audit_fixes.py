#!/usr/bin/env python3
"""Tests for the full-audit fix batch (P0/P1) + a single end-to-end flow. No gcloud/network. App dir.
Covers: connector resilience (no zombie scan, transient mapping), feed-truncation honesty, startup
fail-closed on no-sign-in, RBAC on /tenants, multi-action 'partial' not clobbered, /tasks/scan all-tenants,
and an E2E: feed -> domain filter -> lookup -> flag -> remediate -> close-alarm -> audit -> metrics."""
import importlib
import json
import os
import re
import sys
import tempfile
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/af.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0af"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"

import app.config as cfg
importlib.reload(cfg)
from app import connector, db, metrics, service
from app.config import settings, is_cloud_run

c = {}

# ---------- connector resilience: no zombie scan on an unexpected error ----------
db.init_db()
t = db.first_tenant()
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.fetch_all_sources = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))   # non-ConnectorError
res = service.run_scan(db.get_tenant(t["id"]), "x")
last = db.last_scan(t["id"])
c["unexpected error -> scan finished (no zombie row)"] = res.get("ok") is False and last.get("finished_at") is not None

# transient ConnectorError -> scan ok=False with error, row finished
connector.fetch_all_sources = lambda *a, **k: (_ for _ in ()).throw(connector.ConnectorError("network error"))
res = service.run_scan(db.get_tenant(t["id"]), "x")
c["transient error -> ok=False + finished"] = res.get("ok") is False and "network" in res.get("error", "")

# lookup_user maps a transient ConnectorError to error_transient (not not_found)
_orig_get = connector._get
connector._get = lambda *a, **k: (_ for _ in ()).throw(connector.ConnectorError("reset"))
c["lookup transient -> error_transient (not not_found)"] = connector.lookup_user("x@example.com", "tok") == "error_transient"
connector._get = _orig_get

# ---------- feed-truncation honesty ----------
settings.feed_max_pages = 1; settings.feed_page_limit = 2
calls = {"n": 0}
def fake_get(url, headers):
    calls["n"] += 1
    return {"is_success": True, "data": {"data": [{"email": f"u{calls['n']}@x.com"}, {"email": "v@x.com"}],
                                         "total_data_count": 100}}   # total 100 >> 1 page of 2
connector._get = fake_get
recs, total, processed, truncated = connector.socradar_fetch("b", "1", "k", "botnet", "2026-01-01")
c["truncation flagged when capped (total>processed)"] = truncated is True and total == 100 and processed == 2
connector._get = _orig_get
settings.feed_max_pages = 50; settings.feed_page_limit = 100

# ---------- startup fail-closed: prod + no OAuth + no dev_login = no sign-in method ----------
def fresh(**env):
    for k in ("DEV_LOGIN", "APP_ENV", "K_SERVICE", "SECRET_KEY", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"):
        os.environ.pop(k, None)
    os.environ.update(env)
    import app.config as m
    importlib.reload(m)
    return m
m = fresh(K_SERVICE="svc", SECRET_KEY="real", DEV_LOGIN="false")   # on Cloud Run, no oauth, no dev
try:
    m.assert_startup_safe()
    c["no sign-in method on Cloud Run -> startup RAISES"] = False
except RuntimeError as e:
    c["no sign-in method on Cloud Run -> startup RAISES"] = "sign-in" in str(e)
fresh()  # restore

# ---------- RBAC on /tenants (create + switch) ----------
os.environ["DEV_LOGIN"] = "true"; os.environ["APP_ENV"] = "dev"; os.environ["REMEDIATION_ADMINS"] = "boss@example.com"
importlib.reload(cfg)
import app.auth as auth
importlib.reload(auth)
import app.main as main
importlib.reload(main)
from fastapi.testclient import TestClient
db.init_db(); t = db.first_tenant()
_user = {"email": "intruder@example.com"}   # NOT a remediation admin
auth.current_user = main.auth.current_user = lambda r: _user
cl = TestClient(main.app)
csrf = re.search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)
r = cl.post("/tenants", data={"customer_id": "C0evil", "name": "Evil", "verified_domains": "evil.com",
            "feed_base": "https://x", "feed_company_id": "9", "feed_start_date": "2026-01-01", "csrf": csrf},
            follow_redirects=False)
c["RBAC: non-admin tenant_create blocked"] = "err=forbidden" in r.headers.get("location", "") and not any(
    x["customer_id"] == "C0evil" for x in db.list_tenants())
r = cl.post("/tenants/switch", data={"tenant_id": str(t["id"]), "csrf": csrf}, follow_redirects=False)
c["RBAC: non-admin tenant_switch blocked"] = "err=forbidden" in r.headers.get("location", "")

# ---------- multi-action 'partial' not clobbered by a later mark_remediated ----------
fid = db.upsert_flagged(t["id"], "p@example.com", {"botnet"}, "found", 1.0, [1])
db.set_flagged_status(fid, "partial")
db.mark_remediated(fid, 2.0)   # a later successful action must NOT un-partial
c["partial survives a later mark_remediated"] = db.get_flagged(fid)["status"] == "partial"

# ---------- /tasks/scan scans ALL tenants (headless, no session) ----------
os.environ["SCAN_TRIGGER_TOKEN"] = "tok"
importlib.reload(cfg); importlib.reload(main)
db.init_db()
db.create_tenant("C0two", "T2", ["two.com"], "https://x", "2", "k", "2026-01-01")
scanned = []
service.run_scan = lambda tenant, actor: (scanned.append(tenant["id"]) or {"ok": True, "actor": actor})
cl2 = TestClient(main.app)
rr = cl2.post("/tasks/scan", headers={"x-scan-token": "tok"})
c["/tasks/scan scans every tenant"] = rr.status_code == 200 and len(scanned) == len(db.list_tenants()) >= 2

# ---------- E2E: feed -> filter -> lookup -> flag -> remediate -> close -> audit -> metrics ----------
importlib.reload(cfg)
from app import service as svc2
importlib.reload(svc2)
import app.connector as conn2
conn2.get_dwd_token = lambda scopes, **kw: "tok"
conn2.lookup_user = lambda e, tok: "found"
conn2.apply_action = lambda action, email, token, group=None: True
conn2.verify_action_effect = lambda *a, **k: "confirmed"
closed = {"ids": None}
conn2.socradar_close_alarms = lambda base, cid, key, ids, **k: (closed.__setitem__("ids", ids) or {"ok": True, "message": "Resolved"})
conn2.fetch_all_sources = lambda *a, **k: (
    {"e2e@example.com": {"botnet"}, "foreign@other.com": {"pii"}},   # one in-domain, one foreign
    {"botnet": 1, "pii": 1, "vip": 0}, {"e2e@example.com": [555]},
    {"botnet": {"processed": 1, "total": 1, "truncated": False}})
# set flags on the LIVE settings object that svc2 actually reads (top-level `settings` is stale post-reload)
svc2.settings.close_socradar_alarm = True
svc2.settings.remediation_mode = "manual"; svc2.settings.require_approval = False
db.init_db(); te = db.first_tenant()
db.update_tenant(te["id"], enabled_actions=json.dumps(["signout"]))
scan = svc2.run_scan(db.get_tenant(te["id"]), "admin@example.com")
c["E2E scan: foreign skipped, 1 in-scope found"] = scan["found"] == 1 and scan["skipped_foreign"] == 1
fu = [r for r in db.list_flagged(te["id"]) if r["email"] == "e2e@example.com"][0]
rem = svc2.remediate(db.get_tenant(te["id"]), fu["id"], "signout", "admin@example.com")
c["E2E remediate ok"] = rem.get("ok") is True and db.get_flagged(fu["id"])["status"] == "remediated"
c["E2E close-the-loop fired (alarm id 555)"] = closed["ids"] == [555]
aud = [a["action"] for a in db.list_audit(te["id"])]
c["E2E audit trail (scan+remediate+close)"] = "scan" in aud and "remediate:signout" in aud and "socradar_close" in aud
mt = metrics.compute(te["id"])
c["E2E metrics: coverage + integrity"] = mt["counts"]["remediated"] == 1 and mt["audit_integrity"]["ok"] is True

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — audit-fix batch + E2E flow verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
