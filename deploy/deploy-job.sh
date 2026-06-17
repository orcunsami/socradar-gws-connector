#!/usr/bin/env bash
#
# SOCRadar Google Workspace Connector — Phase 2 (ADR-0001): deploy the scan as a Cloud Run JOB.
#
# WHY a Job, not the Service: a Cloud Run *Service* request times out at 60 min, which is what forced the
# old 5,000-record (feed_max_pages) truncation. A Cloud Run *Job* has no request and runs to completion
# (task-timeout up to 7 days), so a full multi-month feed backfill is paged end-to-end with NO truncation.
# The streaming engine checkpoints a page cursor every page and a per-tenant lease guards single-flight, so a
# SIGTERM / task-timeout / crash RESUMES on the next execution (the scan row stays running/paused).
#
# Reuses the SA + Secret Manager secrets created by deploy-to-gcp.sh (run that first, or pass SA_EMAIL).
# A Job runs across separate executions, so its state MUST be durable across instances -> STORAGE_BACKEND
# defaults to firestore here (sqlite lives on a per-execution ephemeral /tmp and would lose the checkpoint).
#
# Usage:
#   PROJECT=my-gcp-project REGION=europe-west1 ADMIN_SUBJECT=connector-bot@customer.com \
#   DOMAIN=customer.com CUSTOMER_ID=my_customer FEED_COMPANY_ID=132 bash deploy/deploy-job.sh
#
set -euo pipefail

GC="${GCLOUD:-gcloud}"
PROJECT="${PROJECT:?set PROJECT (the customer GCP project id)}"
REGION="${REGION:-europe-west1}"
ADMIN_SUBJECT="${ADMIN_SUBJECT:?set ADMIN_SUBJECT (the Workspace admin to impersonate)}"
DOMAIN="${DOMAIN:?set DOMAIN (the customer Workspace primary domain)}"
CUSTOMER_ID="${CUSTOMER_ID:-my_customer}"
FEED_BASE="${FEED_BASE:-https://platform.socradar.com}"
FEED_COMPANY_ID="${FEED_COMPANY_ID:-}"
SA="${SA_EMAIL:-gws-connector@${PROJECT}.iam.gserviceaccount.com}"
STORAGE_BACKEND="${STORAGE_BACKEND:-firestore}"   # a multi-execution Job needs durable state (NOT sqlite/tmp)
JOB="gws-scan-job"
APP_DIR="$(cd "$(dirname "$0")/../development/app" && pwd)"

if [ "$STORAGE_BACKEND" = "sqlite" ]; then
  echo "⚠ STORAGE_BACKEND=sqlite on a Job is unsafe: each execution gets a fresh ephemeral /tmp, so the scan"
  echo "  cursor/lease/flagged state does NOT survive between executions (no resume). Use firestore for a Job."
fi

echo "==> [0/3] Enable APIs + Cloud Build permission (so this runs standalone, not only after deploy-to-gcp.sh)"
$GC services enable \
  run.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com \
  iamcredentials.googleapis.com admin.googleapis.com cloudbuild.googleapis.com cloudscheduler.googleapis.com \
  --project="$PROJECT"
PNUM="$($GC projects describe "$PROJECT" --format='value(projectNumber)')"
$GC projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:${PNUM}-compute@developer.gserviceaccount.com" \
  --role="roles/cloudbuild.builds.builder" --condition=None >/dev/null 2>&1 \
  || echo "    (could not grant cloudbuild.builds.builder — --source build may 403; run deploy-to-gcp.sh first or grant manually)"
# Preflight: the Job references these secrets at deploy time — fail early with a clear message if absent.
for sec in socradar-feed-key audit-hmac-key; do
  $GC secrets describe "$sec" --project="$PROJECT" >/dev/null 2>&1 \
    || { echo "FATAL: secret '$sec' not found. Run deploy/deploy-to-gcp.sh first (it creates the SA + secrets)."; exit 1; }
done
# Firestore backend (default for a Job): enable the API + a Native DB + grant the runtime SA datastore.user.
# (A Job is multi-execution; sqlite/tmp would lose the scan checkpoint between runs.) IAM can take a minute to
# propagate — the Job's --max-retries resumes past a first-run PermissionDenied (verified live 2026-06-16).
if [ "$STORAGE_BACKEND" = "firestore" ]; then
  $GC services enable firestore.googleapis.com --project="$PROJECT" 2>/dev/null || true
  $GC firestore databases create --location="$REGION" --project="$PROJECT" 2>/dev/null \
    || echo "    (Firestore DB already exists, or create it once: gcloud firestore databases create --location=$REGION)"
  $GC projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:$SA" --role="roles/datastore.user" --condition=None >/dev/null 2>&1 \
    && echo "    + datastore.user granted to $SA" \
    || echo "    (could not grant datastore.user — the firestore scan will 403 until granted)"
fi

echo "==> [1/3] Cloud Run JOB ($JOB) from source — same image, command 'python -m app.job'"
SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
( cd "$APP_DIR" && $GC run jobs deploy "$JOB" \
  --source=. --quiet --region="$REGION" --service-account="$SA" \
  --command="python" --args="-m,app.job" \
  --task-timeout="${TASK_TIMEOUT:-6h}" --max-retries="${MAX_RETRIES:-3}" \
  --set-secrets="FEED_API_KEY=socradar-feed-key:latest,AUDIT_HMAC_KEY=audit-hmac-key:latest" \
  --set-env-vars="^##^APP_ENV=prod##SERVICE_ACCOUNT=$SA##ADMIN_SUBJECT=$ADMIN_SUBJECT##ALLOWED_DOMAIN=$DOMAIN##DEFAULT_DOMAIN=$DOMAIN##DEFAULT_CUSTOMER_ID=$CUSTOMER_ID##FEED_BASE=$FEED_BASE##FEED_COMPANY_ID=$FEED_COMPANY_ID##FEED_FULL_SCAN=true##FEED_OVERLAP_DAYS=${FEED_OVERLAP_DAYS:-7}##SCAN_PAGES_PER_RUN=0##FEED_LOOKBACK_DAYS=${FEED_LOOKBACK_DAYS:-0}##FEED_START_DATE=${FEED_START_DATE:-2026-06-01}##SECRET_KEY=$SECRET_KEY##STORAGE_BACKEND=$STORAGE_BACKEND##DB_PATH=/tmp/app.sqlite3##PROJECT_ID=$PROJECT" \
  --project="$PROJECT" )

echo "==> [2/3] Cloud Scheduler -> trigger the Job (jobs:run) on a schedule (${SCAN_SCHEDULE:-*/30 * * * *})"
$GC services enable cloudscheduler.googleapis.com --project="$PROJECT" 2>/dev/null || true
# the scheduler SA needs run.invoker (jobs.run) on the project/job; reuse the runtime SA.
$GC projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:$SA" --role="roles/run.invoker" --condition=None >/dev/null 2>&1 \
  || echo "    (could not grant run.invoker — grant it so the scheduler can run the job)"
JOB_RUN_URI="https://${REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${PROJECT}/jobs/${JOB}:run"
$GC scheduler jobs delete gws-scan-job-trigger --location="$REGION" --project="$PROJECT" --quiet 2>/dev/null || true
$GC scheduler jobs create http gws-scan-job-trigger --location="$REGION" --project="$PROJECT" \
  --schedule="${SCAN_SCHEDULE:-*/30 * * * *}" --uri="$JOB_RUN_URI" --http-method=POST \
  --oauth-service-account-email="$SA" --attempt-deadline=180s \
  && echo "    + gws-scan-job-trigger (${SCAN_SCHEDULE:-*/30 * * * *} -> ${JOB}:run)" \
  || echo "    (scheduler trigger skipped — create manually if needed)"

echo "==> [3/3] Done."
cat <<EOF

  Run a scan now:   $GC run jobs execute $JOB --region=$REGION --project=$PROJECT
  Watch logs:       $GC run jobs executions list --job=$JOB --region=$REGION --project=$PROJECT
  Scan ONE tenant:  add --update-env-vars TENANT_ID=<id> to the execute command (wave-staggering for MSSP).

  Teardown (cost discipline):
    $GC run jobs delete $JOB --region=$REGION --project=$PROJECT --quiet
    $GC scheduler jobs delete gws-scan-job-trigger --location=$REGION --project=$PROJECT --quiet
EOF
