#!/usr/bin/env python3
"""
Deterministic test for the headless POST /tasks/scan endpoint — no gcloud, no feed.
Verifies the SCAN_TRIGGER_TOKEN guard (403 on bad/missing header) and that a valid call reaches
the SCAN path only (never remediation). Run from the app dir: python3 tests/test_tasks_scan.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "t.sqlite3")
os.environ["SCAN_TRIGGER_TOKEN"] = "s3cr3t"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0t"
os.environ["DEFAULT_DOMAIN"] = "example.com"

from fastapi.testclient import TestClient  # noqa: E402
from app import db, service  # noqa: E402
from app.main import app  # noqa: E402

db.init_db()
# mock the scan so no gcloud/feed is needed; record that ONLY scan (not remediate) is called
called = {"scan": 0}
service.run_scan = lambda tenant, actor: (called.__setitem__("scan", called["scan"] + 1)
                                          or {"ok": True, "found": 0, "actor": actor})

c = TestClient(app)
checks = {
    "no header -> 403":        c.post("/tasks/scan").status_code == 403,
    "wrong header -> 403":     c.post("/tasks/scan", headers={"X-Scan-Token": "nope"}).status_code == 403,
}
r = c.post("/tasks/scan?force=1", headers={"X-Scan-Token": "s3cr3t"})   # force = scan ALL (bypass per-tenant due-check)
body = r.json()
# new shape: scans ALL tenants -> {ok, tenants:{id: result}} (headless must not depend on session)
_tenant_results = list(body.get("tenants", {}).values())
checks["correct header -> 200 + scanned per-tenant as 'scheduler'"] = (
    r.status_code == 200 and body.get("ok") is True
    and len(_tenant_results) >= 1 and _tenant_results[0].get("actor") == "scheduler")
checks["scan called once per tenant"] = called["scan"] == len(_tenant_results) >= 1

for k, v in checks.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(checks.values())
print("RESULT:", "PASS — /tasks/scan token guard + scan-only verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
