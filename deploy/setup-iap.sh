#!/usr/bin/env bash
# Put native Cloud Run IAP in front of the admin UI and let it REPLACE the app's own "Sign in with
# Google". IAP authenticates the user at the edge (the SAME https://SERVICE-...run.app URL — no load
# balancer, no DNS, no cost) and injects a signed assertion the app verifies (app/iap.py). This removes
# the app-side OAuth redirect entirely, so the Cloud Shell `redirect_uri_mismatch` disappears: you just
# open the run.app URL in a browser and IAP signs you in.
#
#   PROJECT=... REGION=europe-west1 SERVICE=gws-connector IAP_MEMBERS=user:you@yourdomain.com \
#       bash deploy/setup-iap.sh
#
# The connector's Workspace access is unaffected (keyless domain-wide delegation, not the user's OAuth).
set -euo pipefail

: "${PROJECT:?set PROJECT}"
SERVICE="${SERVICE:-gws-connector}"
REGION="${REGION:-europe-west1}"
: "${IAP_MEMBERS:?set IAP_MEMBERS (comma-separated, e.g. user:you@yourdomain.com or group:admins@yourdomain.com)}"
GC="${GCLOUD:-gcloud}"
PNUM="$($GC projects describe "$PROJECT" --format='value(projectNumber)')"
RUNTIME_SA="${SA_EMAIL:-gws-connector@${PROJECT}.iam.gserviceaccount.com}"
AUD="/projects/${PNUM}/locations/${REGION}/services/${SERVICE}"

echo "==> [1/6] Enable IAP API + create the IAP service agent (idempotent)"
$GC services enable iap.googleapis.com --project="$PROJECT"
$GC beta services identity create --service=iap.googleapis.com --project="$PROJECT" >/dev/null 2>&1 || true

echo "==> [2/6] Enable IAP on the Cloud Run service (same run.app URL, no load balancer)"
# The service is already private (deploy-to-gcp.sh deployed it with --no-allow-unauthenticated); --iap adds
# the IAP gate in front of it. (Note: --no-allow-unauthenticated is a `run deploy` flag, not a `run services
# update` flag — do not add it here.)
$GC run services update "$SERVICE" --region="$REGION" --project="$PROJECT" --iap

echo "==> [3/6] Let the IAP service agent invoke the service"
$GC run services add-iam-policy-binding "$SERVICE" --region="$REGION" --project="$PROJECT" \
  --member="serviceAccount:service-${PNUM}@gcp-sa-iap.iam.gserviceaccount.com" \
  --role="roles/run.invoker" >/dev/null

echo "==> [4/6] Switch the app to IAP identity (drops its own OAuth; GOOGLE_CLIENT_ID no longer needed)"
$GC run services update "$SERVICE" --region="$REGION" --project="$PROJECT" \
  --update-env-vars="IAP_MODE=true,IAP_AUDIENCE=${AUD}"

echo "==> [5/6] Grant access (roles/iap.httpsResourceAccessor) to your admins + the scheduler SA"
IFS=',' read -ra MEMBERS <<< "$IAP_MEMBERS"
for m in "${MEMBERS[@]}" "serviceAccount:${RUNTIME_SA}"; do
  $GC iap web add-iam-policy-binding --resource-type=cloud-run --service="$SERVICE" \
    --region="$REGION" --project="$PROJECT" --member="$m" --role="roles/iap.httpsResourceAccessor" >/dev/null \
    && echo "    + $m" || echo "    (could not grant $m — add it manually if needed)"
done

URL="$($GC run services describe "$SERVICE" --region="$REGION" --project="$PROJECT" --format='value(status.url)' 2>/dev/null || echo '(describe failed)')"
cat <<EOF

============================================================================
  IAP IS ON. Open the admin UI directly in your browser (IAP signs you in):
      $URL
  No proxy, no Web Preview, no redirect_uri — IAP authenticates at the edge and
  the app verifies the signed assertion + your domain ($SERVICE uses ALLOWED_DOMAIN).
============================================================================

  Security model: the admin UI is gated by IAP — the app cryptographically VERIFIES the IAP assertion
  (app/iap.py: ES256 + iss + this service's aud + your domain) and serves NOTHING without a valid one, so a
  direct (non-IAP) caller cannot enter the UI. The runtime SA still holds run.invoker (it is the scheduler's
  identity), so a parallel non-IAP ingress path exists for it; that path can only reach /tasks/scan, which is
  separately gated by SCAN_TRIGGER_TOKEN. For a single locked ingress, migrate the scheduler to call through
  IAP (OIDC aud = the IAP OAuth client) and then revoke run.invoker from the runtime SA.

  Scheduler note: the periodic-scan jobs call with an OIDC token whose audience is the run.app URL, which IAP
  rejects. Until reconfigured, trigger scans from the UI (Dashboard -> Run scan) or via /tasks/scan with the
  SCAN_TRIGGER_TOKEN. Disable IAP again:
      gcloud run services update $SERVICE --region=$REGION --no-iap --update-env-vars IAP_MODE=false
EOF
