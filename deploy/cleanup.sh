#!/usr/bin/env bash
#
# Teardown for the Deploy-to-GCP connector (cost discipline — Azure 5587 TL lesson).
# Cloud Run scales to zero, but the Artifact Registry build image still bills for storage.
#
# Usage:  PROJECT=my-gcp-project REGION=europe-west1 bash deploy/cleanup.sh
#
set -euo pipefail
GC="${GCLOUD:-gcloud}"
PROJECT="${PROJECT:?set PROJECT}"
REGION="${REGION:-europe-west1}"
SERVICE="gws-connector"

# Preflight: a dead/expired gcloud token makes every "delete ... 2>/dev/null || echo (no X)" below
# silently no-op AND falsely report a clean teardown while the resources keep billing. Caught live
# 2026-06-11 (token expired overnight -> cleanup printed "(no service)" for everything but nothing was
# deleted and billing stayed ON). Fail LOUD instead of pretending success.
if ! $GC auth print-access-token >/dev/null 2>&1; then
  echo "FATAL: gcloud is not authenticated (token dead/expired)."
  echo "Run:  gcloud auth login   then re-run this script."
  echo "Refusing to continue — a no-auth teardown reports fake success while resources keep billing."
  exit 1
fi

echo "==> Deleting Cloud Run service"
$GC run services delete "$SERVICE" --region="$REGION" --project="$PROJECT" --quiet 2>/dev/null || echo "   (no service)"

echo "==> Deleting Cloud Run JOB (Phase 2 scan job)"
$GC run jobs delete gws-scan-job --region="$REGION" --project="$PROJECT" --quiet 2>/dev/null || echo "   (no scan job)"

echo "==> Deleting feed key + audit-hmac secrets (irreversible — all versions)"
$GC secrets delete socradar-feed-key --project="$PROJECT" --quiet 2>/dev/null || echo "   (no feed secret)"
$GC secrets delete audit-hmac-key --project="$PROJECT" --quiet 2>/dev/null || echo "   (no audit-hmac secret)"

echo "==> Deleting build-image Artifact Registry repos (removes ALL build images + versions)"
# cloud-run-source-deploy = `gcloud run deploy --source` builds. gcr.io = the legacy gcr.io/PROJECT host
# (Terraform/Marketplace path uses a prebuilt image often pushed here via `gcloud builds submit --tag gcr.io/...`).
# Delete both; either may be absent depending on which deploy path was used.
for repo in cloud-run-source-deploy gcr.io; do
  $GC artifacts repositories delete "$repo" \
    --location="$REGION" --quiet --project="$PROJECT" 2>/dev/null \
    || echo "   (no $repo repo in $REGION)"
done
# gcr.io images may also live in the multi-region 'us'/'eu' AR mirror — remove if present.
for loc in us eu; do
  $GC artifacts repositories delete gcr.io --location="$loc" --quiet --project="$PROJECT" 2>/dev/null || true
done

echo "==> Deleting Cloud Scheduler jobs (the automated scan + the daily audit-verify triggers)"
for job in gws-scan gws-verify-audit gws-scan-job-trigger; do
  $GC scheduler jobs delete "$job" --location="$REGION" --quiet --project="$PROJECT" 2>/dev/null \
    || echo "   (no $job job)"
done

echo "==> Deleting the Cloud Build source-staging buckets ('run deploy --source' leaves these)"
PNUM="$($GC projects describe "$PROJECT" --format='value(projectNumber)' 2>/dev/null || true)"
for b in "run-sources-${PROJECT}-${REGION}" "run-sources-${PNUM}-${REGION}" "${PROJECT}_cloudbuild"; do
  [ -n "$b" ] && $GC storage rm -r "gs://${b}" --quiet 2>/dev/null || true
done

# Optional: unlink billing to return the project to its $0 / billingEnabled:false starting state.
if [ "${UNLINK_BILLING:-0}" = "1" ]; then
  echo "==> Unlinking billing (project -> billingEnabled:false)"
  $GC billing projects unlink "$PROJECT" 2>/dev/null || echo "   (unlink failed / already off)"
  echo "    (delete the \$10 budget too: gcloud billing budgets list --billing-account=... then ...delete)"
fi

# Optional CLEAN-SLATE: also wipe the DURABLE data (Firestore + BigQuery). OFF by default so a normal
# cost-teardown KEEPS the audit trail (durability). PURGE_DATA=1 makes it a true fresh start — use it for
# re-onboarding or a clean trial, so you never build on top of a previous run's leftover data.
if [ "${PURGE_DATA:-0}" = "1" ]; then
  echo "==> PURGE_DATA: wiping ALL Firestore data (tenants/flagged/scan/audit/approvals) — irreversible"
  $GC firestore bulk-delete \
    --collection-ids=tenants,flagged_users,scan_runs,audit_log,audit_heads,approvals \
    --database='(default)' --project="$PROJECT" --quiet 2>/dev/null \
    || echo "   (firestore bulk-delete skipped — no data / not a firestore deploy)"
  echo "==> PURGE_DATA: deleting the BigQuery analytics dataset (if any)"
  command -v bq >/dev/null 2>&1 && bq rm -r -f --dataset "$PROJECT:socradar" 2>/dev/null || echo "   (no BigQuery dataset / bq not installed)"
  echo "    NOTE: Firestore bulk-delete is ASYNC — give it a minute, then the connector re-bootstraps a fresh"
  echo "    default tenant (with the feed key from Secret Manager) on the next request. Clean slate, no re-enter."
fi

echo "==> NOTE: the runtime SA (gws-connector@$PROJECT...) and the DWD authorization are left in place"
echo "    (both are zero-cost IAM objects, and keeping them means you do NOT have to re-authorize DWD)."
echo "    Full decommission: delete the SA + remove the DWD client in admin.google.com."
echo "==> NOTE: durable data (Firestore/BigQuery) is kept by default. For a CLEAN SLATE re-run with PURGE_DATA=1:"
echo "      PROJECT=$PROJECT PURGE_DATA=1 bash deploy/cleanup.sh"
echo "Done."
