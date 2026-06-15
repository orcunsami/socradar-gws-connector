# Analytics — BigQuery + Looker Studio Dashboard (#7, the Azure-Workbook equivalent)

The connector optionally exports scan/remediation events to **BigQuery**; **Looker Studio** (free) reads
that table for a security-ops dashboard. Verified against primary docs (BigQuery sandbox, Looker Studio).

## What it gives you
A live dashboard of: flagged users over time, by source (botnet/pii/vip), remediation actions taken,
per tenant — the SOCRadar Workspace equivalent of Sentinel/Azure Workbooks.

## 1. Enable the export (connector side)
Deploy with `ANALYTICS_BIGQUERY=true` — the deploy script enables the BigQuery API and grants the runtime
SA `roles/bigquery.dataEditor` + `roles/bigquery.jobUser`. The app then writes one **load job per scan
cycle** to `PROJECT.socradar.flagged_events` (auto-created, time-partitioned on `event_time`).
```bash
ANALYTICS_BIGQUERY=true STORAGE_BACKEND=firestore PROJECT=your-gcp-project ... bash deploy/deploy-to-gcp.sh
```
- **LOAD JOBS, not streaming** → works in the free **BigQuery Sandbox** (no credit card, no billing), and
  upgrades to a paid project unchanged. (Streaming inserts + DML are NOT available in the sandbox.)
- **Best-effort:** if BigQuery is unavailable/over quota, the scan/remediation still succeeds (export just
  returns False). Analytics never breaks the connector.
- Table schema: `event_time, email, source, action, result, tenant_id, actor, details`.

## 2. Build the dashboard (Looker Studio — pure UI, ~15 min, no code)
Looker Studio is **free**; the BigQuery queries it issues are billable but a small ops table is effectively
**~$0** (on-demand $6.25/TiB, first 1 TiB/month free).

1. `lookerstudio.google.com` → **Create → Report** → **BigQuery** connector → **Authorize** (one-time OAuth).
2. Pick **Project → Dataset `socradar` → Table `flagged_events`** (or a Custom Query to pre-aggregate) → **Add**.
3. Drag-drop charts (all UI):

| Chart | Shows | Dimension / Metric |
|-------|-------|--------------------|
| Scorecard | total flagged / remediated | COUNT, COUNTIF(action LIKE 'remediate%') |
| Time series | flagged users over time | event_time (day) / COUNT DISTINCT email |
| Stacked column | by source botnet/pii/vip | day / breakdown=source / count |
| Pie | remediation actions taken | action / count |
| Detail table | email, source, action, result, event_time | — |

4. Add a **Date-range control** + a **Drop-down control on `tenant_id`** for an interactive per-tenant slice.
   ⚠️ The tenant drop-down is **presentation, NOT a security boundary** — for real isolation use one BQ
   table/dataset per Deploy-to-GCP install (single-tenant, matches the distribution model) or BQ row-level security.
5. **Share / schedule:** Share button (account/domain/link) or "Schedule email delivery" (recurring PDF to the SOC).

## 3. (Optional) productize one dashboard per tenant — Looker Studio Linking API
Build one master template report, then generate a per-tenant copy via URL (no manual rebuild):
```
https://lookerstudio.google.com/reporting/create?c.reportId=MASTER_ID&r.reportName=SOCRadar%20GWS%20-%20TENANT
  &ds.ds0.connector=bigQuery&ds.ds0.type=TABLE&ds.ds0.projectId=PROJECT
  &ds.ds0.datasetId=socradar&ds.ds0.tableId=flagged_events&ds.ds0.refreshFields=false
```

## Cost / cleanup
- Looker Studio = $0. BigQuery for this tiny table = effectively $0 (first 1 TiB/mo free). Sandbox tables
  auto-expire after 60 days (fine for dev; reset the default expiration after attaching billing for retention).
- Teardown removes the dataset/table when you delete the project resources (add `bq rm -r -d PROJECT:socradar`
  to a full decommission if billing was attached).
