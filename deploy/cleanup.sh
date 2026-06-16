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

echo "==> NOTE: the runtime SA (gws-connector@$PROJECT...) and the DWD authorization are left in place"
echo "    (both are zero-cost IAM objects). Full decommission: delete the SA + remove the DWD client in admin.google.com."
echo "==> NOTE: if you deployed with STORAGE_BACKEND=firestore or ANALYTICS_BIGQUERY=true, the durable"
echo "    data stores are intentionally NOT auto-deleted (they may hold your audit trail). Remove manually:"
echo "      gcloud firestore databases delete '(default)' --project=$PROJECT --quiet"
echo "      bq rm -r -f --dataset $PROJECT:socradar"
echo "Done."
