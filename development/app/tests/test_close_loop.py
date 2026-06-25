#!/usr/bin/env python3
"""
Deterministic close-the-loop test — no live SOCRadar, no gcloud.
Close-by-alarm-id contract (Incident V4: POST /api/company/{id}/alarms/status/change {alarm_ids,status},
NO operator email — live-verified). Verifies the client body, best-effort never-raises, alarm
ids persisted at ingest, close-after-remediate + outcome recorded, decoupling, and opt-in gating.
"""
import json
import os
import sys
import tempfile
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "c.sqlite3")
os.environ["DEFAULT_CUSTOMER_ID"] = "C0c"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"
os.environ["CLOSE_SOCRADAR_ALARM"] = "true"

from app import connector, db, service  # noqa: E402
from app.config import settings  # noqa: E402

c = {}

# A) the close client builds the Incident-V4 body (alarm_ids + status=2, NO email), one endpoint
calls = []


def fake_req(url, data, headers, method="POST"):
    calls.append((url, json.loads(data.decode())))
    return {"is_success": True, "message": "Successfully updated ... to 'Resolved'"}


connector._req = fake_req
res = connector.socradar_close_alarms("https://platform.socradar.com", "132", "key", [111, 222])
c["endpoint = /alarms/status/change"] = len(calls) == 1 and "/api/company/132/alarms/status/change" in calls[0][0]
body = calls[0][1]
c["body alarm_ids"] = body.get("alarm_ids") == [111, 222]
c["body status=2 (RESOLVED)"] = body.get("status") == 2
c["NO email field"] = "email" not in body
c["client returns ok"] = res.get("ok") is True

# B) best-effort: never raises on network error
connector._req = lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("socradar down"))
r2 = connector.socradar_close_alarms("b", "132", "k", [1])
c["client never raises"] = isinstance(r2, dict) and r2.get("ok") is False

# C) wiring: alarm ids persisted at ingest + close called after remediate + outcome recorded
db.init_db()
connector._api = lambda *a, **k: {}
connector.get_dwd_token = lambda scopes, **kw: "tok"
t = db.first_tenant()
db.update_tenant(t["id"], enabled_actions=json.dumps(["signout"]))
db.upsert_flagged(t["id"], "victim@example.com", {"botnet"}, "found", 1.0, [999, 888])
fu = [r for r in db.list_flagged(t["id"]) if r["email"] == "victim@example.com"][0]
c["alarm ids persisted at ingest"] = json.loads(fu["socradar_refs"]) == [999, 888]
captured = {}
connector.socradar_close_alarms = lambda *a, **k: (captured.update({"called": True, "ids": a[3]}) or {"ok": True, "message": "ok"})
r = service.remediate(db.get_tenant(t["id"]), fu["id"], "signout", "admin@example.com")
c["remediate ok"] = r.get("ok") is True
c["close called after remediate"] = captured.get("called") is True
c["close got stored alarm ids"] = captured.get("ids") == [999, 888]
c["close status recorded"] = db.get_flagged(fu["id"]).get("socradar_close_status") is not None

# D) decoupled: a close that RAISES must not break the remediation result
db.upsert_flagged(t["id"], "victim3@example.com", {"botnet"}, "found", 1.0, [3])
fu3 = [r for r in db.list_flagged(t["id"]) if r["email"] == "victim3@example.com"][0]
connector.socradar_close_alarms = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
r3 = service.remediate(db.get_tenant(t["id"]), fu3["id"], "signout", "admin@example.com")
c["remediate ok despite close exception"] = r3.get("ok") is True

# E) opt-in OFF -> no close
settings.close_socradar_alarm = False
captured.clear()
db.upsert_flagged(t["id"], "victim2@example.com", {"botnet"}, "found", 1.0, [888])
fu2 = [r for r in db.list_flagged(t["id"]) if r["email"] == "victim2@example.com"][0]
connector.socradar_close_alarms = lambda *a, **k: (captured.update({"called": True}) or {"ok": True})
service.remediate(db.get_tenant(t["id"]), fu2["id"], "signout", "admin@example.com")
c["opt-in off -> no close"] = captured.get("called") is None
settings.close_socradar_alarm = True

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — close-the-loop (resolve SOCRadar alarm by id) verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
