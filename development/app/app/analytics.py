"""Optional BigQuery analytics export — the Azure-Workbook equivalent (#7).

Writes scan/remediation events to a BigQuery table for Looker Studio dashboards. Uses LOAD JOBS
(load_table_from_json), NOT streaming inserts, because the free BigQuery SANDBOX (no credit card, no
billing) supports load jobs but NOT streaming/DML — so the same code path is testable billing-free and
upgrades to a paid project unchanged.

BEST-EFFORT: every call is fully guarded and returns a bool. Analytics must NEVER break the connector —
if BigQuery is unavailable / lacks perms / hits a sandbox limit, the scan/remediation still succeeds.
Opt-in via settings.analytics_bigquery (default off). Ambient ADC auth on Cloud Run (same SA as DWD);
the SA needs roles/bigquery.dataEditor + roles/bigquery.jobUser.
"""
from __future__ import annotations

import datetime
import logging
import time

from .config import settings

log = logging.getLogger("gws.analytics")

_TABLE = "flagged_events"
_client = None
_ensured = False

# (name, type, mode) — keep in sync with the SchemaField build below
SCHEMA_FIELDS = [
    ("event_time", "TIMESTAMP", "REQUIRED"),
    ("email",      "STRING",    "NULLABLE"),   # VIP-feed users have no email (EXP-GOOGLE-0004)
    ("source",     "STRING",    "NULLABLE"),   # botnet/pii/vip (joined) or feed source
    ("action",     "STRING",    "REQUIRED"),   # flagged / remediate:signout / ...
    ("result",     "STRING",    "REQUIRED"),   # found/success/failed/blocked
    ("tenant_id",  "STRING",    "NULLABLE"),
    ("actor",      "STRING",    "NULLABLE"),   # admin who triggered
    ("details",    "STRING",    "NULLABLE"),
]


def enabled() -> bool:
    return bool(settings.analytics_bigquery and settings.project_id)


def _bq():
    global _client
    if _client is None:
        from google.cloud import bigquery
        _client = bigquery.Client(project=settings.project_id)
    return _client


def _table_id() -> str:
    return f"{settings.project_id}.{settings.bigquery_dataset}.{_TABLE}"


def _schema():
    from google.cloud import bigquery
    return [bigquery.SchemaField(n, t, mode=m) for n, t, m in SCHEMA_FIELDS]


def _ensure_table():
    global _ensured
    if _ensured:
        return
    from google.cloud import bigquery
    c = _bq()
    ds = bigquery.Dataset(f"{settings.project_id}.{settings.bigquery_dataset}")
    ds.location = settings.bigquery_location or "US"   # data residency: set to the deploy region (F3)
    c.create_dataset(ds, exists_ok=True)
    tbl = bigquery.Table(_table_id(), schema=_schema())
    tbl.time_partitioning = bigquery.TimePartitioning(field="event_time")
    c.create_table(tbl, exists_ok=True)
    _ensured = True


def event(action, result, *, email=None, source=None, tenant_id=None, actor=None, details=None, ts=None):
    """Build one analytics row (event_time as RFC3339 string for the BigQuery TIMESTAMP column)."""
    when = datetime.datetime.fromtimestamp(ts or time.time(), datetime.timezone.utc)
    return {"event_time": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "email": email, "source": source,
            "action": action, "result": result,
            "tenant_id": str(tenant_id) if tenant_id is not None else None,
            "actor": actor, "details": details}


def write_events(rows) -> bool:
    """Best-effort batched LOAD JOB (WRITE_APPEND). One job per call — callers batch per scan cycle.
    Returns True on success; never raises (BigQuery down / no perms / sandbox limit → False)."""
    if not enabled() or not rows:
        return False
    try:
        from google.cloud import bigquery
        _ensure_table()
        job = _bq().load_table_from_json(
            list(rows), _table_id(),
            job_config=bigquery.LoadJobConfig(
                schema=_schema(),
                write_disposition=bigquery.WriteDisposition.WRITE_APPEND))
        job.result()
        return not job.errors
    except Exception as e:                       # analytics must not break the connector
        log.warning("BigQuery analytics export failed (best-effort, ignored): %s", e)
        return False
