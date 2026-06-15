#!/usr/bin/env bash
#
# SOCRadar Google Workspace Connector — Deploy-to-GCP (customer self-host).
#
# Deploys the connector into the CUSTOMER'S OWN GCP project as a private Cloud Run SERVICE,
# running as a dedicated keyless service account (no JSON key). After it runs, it prints the
# one manual step the customer's Workspace super-admin must do (domain-wide delegation).
#
# Commands verified against GCP primary docs (Cloud Run / IAM Credentials / Secret Manager).
#
# Usage:
#   PROJECT=my-gcp-project \
#   REGION=europe-west1 \
#   ADMIN_SUBJECT=admin@customer.com \
#   DOMAIN=customer.com \
#   CUSTOMER_ID=my_customer \
#   FEED_KEY_FILE=/path/to/socradar-feed-key.txt \
#   FEED_COMPANY_ID=132 \
#   bash deploy/deploy-to-gcp.sh
#
set -euo pipefail

GC="${GCLOUD:-gcloud}"
PROJECT="${PROJECT:?set PROJECT (the customer GCP project id)}"
REGION="${REGION:-europe-west1}"
ADMIN_SUBJECT="${ADMIN_SUBJECT:?set ADMIN_SUBJECT (a real Workspace super-admin email to impersonate)}"
DOMAIN="${DOMAIN:?set DOMAIN (the customer Workspace primary domain)}"
CUSTOMER_ID="${CUSTOMER_ID:-my_customer}"
FEED_KEY_FILE="${FEED_KEY_FILE:?set FEED_KEY_FILE (path to a file containing ONLY the SOCRadar feed API key)}"
FEED_BASE="${FEED_BASE:-https://platform.socradar.com}"
FEED_COMPANY_ID="${FEED_COMPANY_ID:-}"

SA_NAME="gws-connector"
# SA_EMAIL override: reuse an EXISTING service account (e.g. one already authorized for DWD) instead of
# creating gws-connector@... — useful for a managed-deploy test against an already-DWD-authorized SA.
SA="${SA_EMAIL:-${SA_NAME}@${PROJECT}.iam.gserviceaccount.com}"
SERVICE="gws-connector"
APP_DIR="$(cd "$(dirname "$0")/../development/app" && pwd)"

[ -f "$FEED_KEY_FILE" ] || { echo "FEED_KEY_FILE not found: $FEED_KEY_FILE"; exit 1; }

echo "==> [1/6] Enabling required APIs (idempotent)"
$GC services enable \
  run.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com \
  iamcredentials.googleapis.com admin.googleapis.com cloudbuild.googleapis.com \
  --project="$PROJECT"

echo "==> [1b/6] Cloud Build permission for --source (new projects' default compute SA lacks it)"
# Since 2024 Google stopped auto-granting Editor to the default compute SA, so `gcloud run deploy
# --source` fails with a storage.objects.get 403 on the source bucket. Grant the build role.
PNUM="$($GC projects describe "$PROJECT" --format='value(projectNumber)')"
$GC projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:${PNUM}-compute@developer.gserviceaccount.com" \
  --role="roles/cloudbuild.builds.builder" --condition=None >/dev/null 2>&1 \
  || echo "    (could not grant — may need an org admin, or build with a prebuilt image)"

echo "==> [2/6] Runtime service account ($SA)"
if [ -z "${SA_EMAIL:-}" ]; then
  $GC iam service-accounts create "$SA_NAME" \
    --display-name="GWS Connector runtime SA" --project="$PROJECT" 2>/dev/null \
    || echo "    (already exists)"
else
  echo "    (reusing existing SA via SA_EMAIL — skip create; DWD likely already authorized)"
fi

echo "==> [3/6] Keyless DWD self-binding (tokenCreator ON ITSELF — load-bearing)"
# member == resource == same SA: lets the SA call signJwt to self-impersonate. No JSON key.
$GC iam service-accounts add-iam-policy-binding "$SA" \
  --member="serviceAccount:$SA" --role="roles/iam.serviceAccountTokenCreator" \
  --project="$PROJECT" >/dev/null

echo "==> [4/6] Feed API key -> Secret Manager (global; Cloud Run has no regional secrets)"
if $GC secrets describe socradar-feed-key --project="$PROJECT" >/dev/null 2>&1; then
  $GC secrets versions add socradar-feed-key --data-file="$FEED_KEY_FILE" --project="$PROJECT" >/dev/null
else
  $GC secrets create socradar-feed-key --replication-policy="automatic" \
    --data-file="$FEED_KEY_FILE" --project="$PROJECT" >/dev/null
fi
# runtime SA needs accessor on the secret (Cloud Run checks this AT DEPLOY TIME)
$GC secrets add-iam-policy-binding socradar-feed-key \
  --member="serviceAccount:$SA" --role="roles/secretmanager.secretAccessor" \
  --project="$PROJECT" >/dev/null

# Audit hash-chain HMAC key — OFF-BOX in Secret Manager (NOT in the same DB/container as the audit rows),
# so a row-writer cannot forge a valid chain. Auto-generated once; reused on redeploy.
if ! $GC secrets describe audit-hmac-key --project="$PROJECT" >/dev/null 2>&1; then
  python3 -c 'import secrets;print(secrets.token_urlsafe(48))' | \
    $GC secrets create audit-hmac-key --replication-policy="automatic" --data-file=- --project="$PROJECT" >/dev/null
fi
$GC secrets add-iam-policy-binding audit-hmac-key \
  --member="serviceAccount:$SA" --role="roles/secretmanager.secretAccessor" \
  --project="$PROJECT" >/dev/null

STORAGE_BACKEND="${STORAGE_BACKEND:-sqlite}"
if [ "$STORAGE_BACKEND" = "firestore" ]; then
  echo "==> [4b/6] Durable storage: enable Firestore + grant runtime SA datastore.user"
  $GC services enable firestore.googleapis.com --project="$PROJECT"
  $GC projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:$SA" --role="roles/datastore.user" --condition=None >/dev/null 2>&1 || true
  echo "    NOTE: a Firestore (Native mode) database must exist — one-time, if not yet created:"
  echo "      gcloud firestore databases create --location=$REGION --project=$PROJECT"
fi

ANALYTICS_BIGQUERY="${ANALYTICS_BIGQUERY:-false}"
if [ "$ANALYTICS_BIGQUERY" = "true" ]; then
  echo "==> [4c/6] Analytics: enable BigQuery + grant runtime SA dataEditor + jobUser"
  $GC services enable bigquery.googleapis.com --project="$PROJECT"
  for role in roles/bigquery.dataEditor roles/bigquery.jobUser; do
    $GC projects add-iam-policy-binding "$PROJECT" \
      --member="serviceAccount:$SA" --role="$role" --condition=None >/dev/null 2>&1 || true
  done
fi

echo "==> [5/6] Deploy private Cloud Run SERVICE from source (Cloud Build uses the Dockerfile)"
SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
SCAN_TOKEN="${SCAN_TRIGGER_TOKEN:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')}"

# SQLite is a per-instance file on ephemeral /tmp; the audit hash-chain, flagged state, approvals, and
# the hourly auto-action rate cap all assume a single writer. Pin sqlite deploys to one instance so a
# scale-out cannot fragment them. Firestore is multi-instance safe, so leave it unconstrained.
MAX_INSTANCES_FLAG=""
if [ "$STORAGE_BACKEND" = "sqlite" ]; then
  MAX_INSTANCES_FLAG="--max-instances=1"
  echo "    NOTE: STORAGE_BACKEND=sqlite -> pinning --max-instances=1 (single-writer). Set STORAGE_BACKEND=firestore to scale out durably."
fi

# Env vars use gcloud's custom-delimiter form `^##^k=v##k=v`: REMEDIATION_ADMINS / APPROVAL_ACTIONS /
# AUTO_ENABLED_ACTIONS are COMMA-separated values, and the default comma delimiter would split them into
# bogus extra keys (a multi-admin REMEDIATION_ADMINS hard-failed the deploy). `##` never appears in an
# email/domain/url/token, so it's a safe record separator. The remediation-policy + feed-window envs are
# forwarded when set in the environment (else safe defaults), so a customer can pre-set them before deploy.
# --quiet: on a first deploy (or after cleanup removed it) `run deploy --source` interactively prompts to
# create the cloud-run-source-deploy Artifact Registry repo. With no TTY (CI / background) that prompt hangs
# forever waiting on stdin. --quiet accepts the default (create the repo) so the deploy is non-interactive.
( cd "$APP_DIR" && $GC run deploy "$SERVICE" \
  --source=. \
  --quiet \
  --region="$REGION" \
  --service-account="$SA" \
  --no-allow-unauthenticated \
  $MAX_INSTANCES_FLAG \
  --set-secrets="FEED_API_KEY=socradar-feed-key:latest,AUDIT_HMAC_KEY=audit-hmac-key:latest" \
  --set-env-vars="^##^APP_ENV=prod##SERVICE_ACCOUNT=$SA##ADMIN_SUBJECT=$ADMIN_SUBJECT##REMEDIATION_ADMINS=${REMEDIATION_ADMINS:-$ADMIN_SUBJECT}##REQUIRE_APPROVAL=${REQUIRE_APPROVAL:-true}##APPROVAL_ACTIONS=${APPROVAL_ACTIONS:-suspend,reset_password,disable_2sv}##REMEDIATION_MODE=${REMEDIATION_MODE:-manual}##AUTO_ENABLED_ACTIONS=${AUTO_ENABLED_ACTIONS:-}##AUTO_DRY_RUN=${AUTO_DRY_RUN:-true}##AUTO_RATE_LIMIT_PER_HOUR=${AUTO_RATE_LIMIT_PER_HOUR:-20}##ALLOWED_DOMAIN=$DOMAIN##DEFAULT_DOMAIN=$DOMAIN##DEFAULT_CUSTOMER_ID=$CUSTOMER_ID##FEED_BASE=$FEED_BASE##FEED_COMPANY_ID=$FEED_COMPANY_ID##FEED_LOOKBACK_DAYS=${FEED_LOOKBACK_DAYS:-0}##FEED_START_DATE=${FEED_START_DATE:-2026-06-01}##GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID:-}##GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET:-}##SECRET_KEY=$SECRET_KEY##STORAGE_BACKEND=$STORAGE_BACKEND##PROJECT_ID=$PROJECT##ANALYTICS_BIGQUERY=$ANALYTICS_BIGQUERY##BIGQUERY_LOCATION=$REGION##CLOSE_SOCRADAR_ALARM=${CLOSE_SOCRADAR_ALARM:-false}##SCAN_TRIGGER_TOKEN=$SCAN_TOKEN##DB_PATH=/tmp/app.sqlite3" \
  --project="$PROJECT" )

# SIGN-IN (P0): the admin UI uses Google OAuth. Set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET (a Web OAuth
# client whose authorized redirect URI is the service URL + /auth/callback) — WITHOUT them the service
# fail-closes at startup (no sign-in method). Pass them as env to this script.
if [ -z "${GOOGLE_CLIENT_ID:-}" ]; then
  echo "    ⚠ GOOGLE_CLIENT_ID/SECRET not set — create a Web OAuth client + redeploy, or the UI cannot be entered."
fi

# AUTOMATED SCANNING (Entra parity): create a Cloud Scheduler job that hits /tasks/scan periodically.
echo "==> [5b/6] Cloud Scheduler: periodic scan (${SCAN_SCHEDULE:-0 */6 * * *}) + daily audit-verify"
$GC services enable cloudscheduler.googleapis.com --project="$PROJECT" 2>/dev/null || true
SVC_URL="$($GC run services describe "$SERVICE" --region="$REGION" --project="$PROJECT" --format='value(status.url)' 2>/dev/null)"
if [ -n "$SVC_URL" ]; then
  # The scheduler hits the PRIVATE service with the runtime SA's OIDC token, so that SA must be allowed
  # to invoke it. Without roles/run.invoker every scheduled /tasks/scan and /tasks/verify-audit returns 403.
  $GC run services add-iam-policy-binding "$SERVICE" --region="$REGION" --project="$PROJECT" \
    --member="serviceAccount:$SA" --role="roles/run.invoker" >/dev/null 2>&1 \
    && echo "    + run.invoker granted to $SA (scheduler can call the private service)" \
    || echo "    (could not grant run.invoker — scheduled scans will 403 until granted manually)"
  for job in "gws-scan:/tasks/scan:${SCAN_SCHEDULE:-0 */6 * * *}" "gws-verify-audit:/tasks/verify-audit:0 3 * * *"; do
    name="${job%%:*}"; rest="${job#*:}"; path="${rest%%:*}"; sched="${rest#*:}"
    $GC scheduler jobs delete "$name" --location="$REGION" --project="$PROJECT" --quiet 2>/dev/null || true
    $GC scheduler jobs create http "$name" --location="$REGION" --project="$PROJECT" \
      --schedule="$sched" --uri="${SVC_URL}${path}" --http-method=POST \
      --oidc-service-account-email="$SA" --oidc-token-audience="$SVC_URL" \
      --headers="X-Scan-Token=${SCAN_TOKEN}" --attempt-deadline=1800s 2>/dev/null \
      && echo "    + $name ($sched -> $path)" || echo "    (scheduler $name skipped — create manually if needed)"
  done
fi
# NOTE (P0 hardening): APP_ENV=prod makes the DEV_LOGIN auth-bypass structurally impossible (the app
# refuses to start if DEV_LOGIN=true on Cloud Run). REMEDIATION_ADMINS defaults to the operator only —
# set it to your security team's emails (comma-separated) to authorize more remediation admins.
# Optional further hardening (see docs/security-hardening.md): front with IAP + --ingress, two-person
# approval, tamper-evident off-box audit (Cloud Audit Logs Data Access for IAM Credentials + Cloud Run).

echo "==> [6/6] Outputs"
CLIENT_ID="$($GC iam service-accounts describe "$SA" --format='value(oauth2ClientId)' --project="$PROJECT")"
URL="$($GC run services describe "$SERVICE" --region="$REGION" --format='value(status.url)' --project="$PROJECT" 2>/dev/null || echo '(describe failed)')"

cat <<EOF

============================================================================
  DEPLOYED. One manual step remains — the customer Workspace SUPER ADMIN:
============================================================================
admin.google.com -> Security -> Access and data control -> API controls ->
  Domain-wide delegation -> Manage Domain Wide Delegation -> Add new

  Client ID:  $CLIENT_ID
              ^ the SA Client ID for DWD (for SAs oauth2ClientId == uniqueId; NOT the SA email)

  OAuth scopes (comma-delimited):
  https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.group.member

  -> Authorize. Propagation: usually minutes, up to 24h.

Service URL (PRIVATE — needs auth to open): $URL
  Open the admin UI locally:  gcloud run services proxy $SERVICE --region=$REGION --project=$PROJECT
  (or put Identity-Aware Proxy in front for browser access)

Teardown:  bash deploy/cleanup.sh   (cost discipline — deletes service, secrets, build images, scheduler jobs;
           the runtime SA + DWD authorization are left in place — both zero-cost IAM objects)
============================================================================
EOF
