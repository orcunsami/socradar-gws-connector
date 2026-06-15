#!/usr/bin/env bash
#
# Cloud Run Button — postcreate hook (app.json hooks.postcreate).
#
# The button itself only: docker-builds the Dockerfile, deploys a private Cloud Run service, and sets the
# app.json env vars. It CANNOT (a) run the service AS the DWD service account (app.json options has no
# service-account key), nor (b) self-bind tokenCreator for keyless DWD, nor (c) move secrets off plain env,
# nor (d) create the periodic scan. Without (a)+(b) the ambient token is the default compute SA and
# signJwt(SERVICE_ACCOUNT) fails -> DWD bootstrap fails -> scans never work. This hook does all of it,
# mirroring deploy/deploy-to-gcp.sh (which was proven live: /tasks/scan -> found=4 on real Cloud Run).
#
# Runs in Cloud Shell as the user (the customer super-admin), with these env vars provided by the button:
#   GOOGLE_CLOUD_PROJECT, GOOGLE_CLOUD_REGION, K_SERVICE  + every app.json env (SERVICE_ACCOUNT,
#   FEED_API_KEY, AUDIT_HMAC_KEY, SCAN_TRIGGER_TOKEN, ADMIN_SUBJECT, ...).
set -euo pipefail

P="${GOOGLE_CLOUD_PROJECT:?}"; R="${GOOGLE_CLOUD_REGION:?}"; SVC="${K_SERVICE:?}"
SA="${SERVICE_ACCOUNT:?SERVICE_ACCOUNT env is required — the keyless-DWD service account}"
SCOPES="https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.group.member"

echo "==> [1/6] Enabling the APIs the runtime needs (button only enabled run+build)"
gcloud services enable iamcredentials.googleapis.com secretmanager.googleapis.com \
  cloudscheduler.googleapis.com admin.googleapis.com --project="$P"

echo "==> [2/6] Ensure the runtime service account exists"
if ! gcloud iam service-accounts describe "$SA" --project="$P" >/dev/null 2>&1; then
  ACCT="${SA%%@*}"
  gcloud iam service-accounts create "$ACCT" --display-name="GWS Connector runtime SA" --project="$P"
fi

echo "==> [3/6] Keyless DWD self-binding (tokenCreator ON ITSELF — lets the SA signJwt to self-impersonate; no JSON key)"
gcloud iam service-accounts add-iam-policy-binding "$SA" \
  --member="serviceAccount:$SA" --role="roles/iam.serviceAccountTokenCreator" --project="$P" >/dev/null

echo "==> [4/6] Move feed key + audit-HMAC OFF plain env INTO Secret Manager (the button stored them as plaintext env)"
put_secret() { # name value
  if gcloud secrets describe "$1" --project="$P" >/dev/null 2>&1; then
    printf '%s' "$2" | gcloud secrets versions add "$1" --data-file=- --project="$P" >/dev/null
  else
    printf '%s' "$2" | gcloud secrets create "$1" --replication-policy="automatic" --data-file=- --project="$P" >/dev/null
  fi
  gcloud secrets add-iam-policy-binding "$1" \
    --member="serviceAccount:$SA" --role="roles/secretmanager.secretAccessor" --project="$P" >/dev/null
}
put_secret socradar-feed-key "${FEED_API_KEY:?FEED_API_KEY env missing}"
put_secret audit-hmac-key "${AUDIT_HMAC_KEY:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')}"

echo "==> [5/6] Re-point the service: run AS the DWD SA + read the secrets (and drop the plaintext env copies)"
gcloud run services update "$SVC" --region="$R" --project="$P" \
  --service-account="$SA" \
  --set-secrets="FEED_API_KEY=socradar-feed-key:latest,AUDIT_HMAC_KEY=audit-hmac-key:latest" \
  --remove-env-vars="FEED_API_KEY,AUDIT_HMAC_KEY"

echo "==> [6/6] Periodic scan + daily audit-verify (Cloud Scheduler -> private service via the SA's OIDC token)"
gcloud run services add-iam-policy-binding "$SVC" --region="$R" --project="$P" \
  --member="serviceAccount:$SA" --role="roles/run.invoker" >/dev/null 2>&1 || true
SVC_URL="$(gcloud run services describe "$SVC" --region="$R" --project="$P" --format='value(status.url)')"
for job in "gws-scan:/tasks/scan:${SCAN_SCHEDULE:-0 */6 * * *}" "gws-verify-audit:/tasks/verify-audit:0 3 * * *"; do
  name="${job%%:*}"; rest="${job#*:}"; path="${rest%%:*}"; sched="${rest#*:}"
  gcloud scheduler jobs delete "$name" --location="$R" --project="$P" --quiet 2>/dev/null || true
  gcloud scheduler jobs create http "$name" --location="$R" --project="$P" --schedule="$sched" \
    --uri="${SVC_URL}${path}" --http-method=POST --oidc-service-account-email="$SA" \
    --oidc-token-audience="$SVC_URL" --headers="X-Scan-Token=${SCAN_TRIGGER_TOKEN:-}" \
    --attempt-deadline=1800s >/dev/null 2>&1 \
    && echo "    + $name ($sched -> $path)" || echo "    (scheduler $name skipped — create later if needed)"
done

CLIENT_ID="$(gcloud iam service-accounts describe "$SA" --format='value(oauth2ClientId)' --project="$P")"
cat <<EOF

============================================================================
  DEPLOYED + WIRED. One manual step remains — the Workspace SUPER ADMIN:
============================================================================
admin.google.com -> Security -> Access and data control -> API controls ->
  Domain-wide delegation -> Manage Domain Wide Delegation -> Add new

  Client ID:  $CLIENT_ID
  OAuth scopes (one comma-separated line):
  $SCOPES

  -> Authorize. Propagation: usually minutes (up to 24h).

Service URL is PRIVATE. Open the admin UI either way:
  gcloud run services proxy $SVC --region=$R --project=$P      (quick: tunnels to localhost)
  or put Identity-Aware Proxy in front for a real https URL:   bash deploy/setup-iap.sh
============================================================================
EOF
