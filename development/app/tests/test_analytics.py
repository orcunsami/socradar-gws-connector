#!/usr/bin/env python3
"""
Deterministic BigQuery analytics-exporter test — no real BigQuery, no billing.
Mocks the client and verifies: event() row shape; enabled() gating; success path builds rows + calls a
LOAD JOB with the right table; empty/disabled = no-op; and best-effort (client error -> False, never raises).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["ANALYTICS_BIGQUERY"] = "true"
os.environ["PROJECT_ID"] = "demo-proj"
os.environ["BIGQUERY_DATASET"] = "socradar"

from app import analytics  # noqa: E402

c = {}

# 1. event() row shape
e = analytics.event("flagged", "found", email="u@x.com", source="botnet", tenant_id="C0t", actor="a@x.com")
c["event_time is RFC3339 Z"] = e["event_time"].endswith("Z") and "T" in e["event_time"]
c["event keys complete"] = set(e) == {"event_time", "email", "source", "action", "result",
                                       "tenant_id", "actor", "details"}
c["tenant_id stringified"] = e["tenant_id"] == "C0t"

# 2. enabled()
c["enabled() true when on+project"] = analytics.enabled() is True

# 3. success path (mock client + skip table-ensure)
captured = {}


class FakeJob:
    errors = None

    def result(self):
        return None


class FakeClient:
    calls = 0

    def load_table_from_json(self, rows, table_id, job_config=None):
        FakeClient.calls += 1
        captured["rows"] = list(rows)
        captured["table"] = table_id
        return FakeJob()


analytics._client = FakeClient()
analytics._ensured = True            # skip real dataset/table creation
rows = [analytics.event("flagged", "found", email="u@x.com", tenant_id="C0t")]
c["write_events True on success"] = analytics.write_events(rows) is True
c["load job got the rows"] = captured.get("rows") == rows
c["table id correct"] = captured.get("table") == "demo-proj.socradar.flagged_events"

# 4. empty rows = no-op
c["empty rows -> False"] = analytics.write_events([]) is False

# 5. best-effort: client raises -> False (never propagates)
class BoomClient:
    def load_table_from_json(self, *a, **k):
        raise RuntimeError("bigquery unavailable")


analytics._client = BoomClient()
analytics._ensured = True
try:
    c["error swallowed -> False"] = analytics.write_events([analytics.event("x", "y")]) is False
except Exception:
    c["error swallowed -> False"] = False

# 6. disabled -> no-op, client NOT called
analytics.settings.analytics_bigquery = False
FakeClient.calls = 0
analytics._client = FakeClient()
c["disabled -> False"] = analytics.write_events([analytics.event("x", "y")]) is False
c["disabled -> client NOT called"] = FakeClient.calls == 0
analytics.settings.analytics_bigquery = True   # restore

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — BigQuery analytics exporter (mocked) verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
