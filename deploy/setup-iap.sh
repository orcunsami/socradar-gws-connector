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

echo "==> [1/6] Enable required APIs + create the IAP service agent (idempotent)"
# cloudresourcemanager is needed for the IAP/IAM operations below; enable it up front so the later
# 'gcloud ... --iap' step does not stop on an interactive 'enable and retry? (y/N)' prompt.
$GC services enable iap.googleapis.com cloudresourcemanager.googleapis.com --project="$PROJECT"
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
BAR="========================================================"

# ---- clean banner #1: IAP on, here is your link ----------------------------
echo
echo "$BAR"
echo
echo "     IAP IS ON.  Your admin panel (IAP signs you in at the edge):"
echo
echo "         $URL"
echo
echo "$BAR"
echo

# ---- recommended wait: IAP IAM grants take ~1 min to propagate -------------
# Opening before propagation finishes shows "You don't have access" (a 403). Wait it out with a
# visible countdown so the very first open just works. You CAN open now (Ctrl+C to skip the wait),
# but the first try may 403 until this counter reaches 0.
echo "  IAP access is propagating. Recommended wait so the first open works (no 403):"
echo
SKIP=""
trap 'SKIP=1' INT
i=60
while [ "$i" -gt 0 ] && [ -z "$SKIP" ]; do
  printf "\r        waiting %2ds   (Ctrl+C to open now)   " "$i"
  sleep 1 || SKIP=1
  i=$((i-1))
done
trap - INT
printf "\r                                                   \r"

# ---- clean banner #2: ready, open now --------------------------------------
echo
echo "$BAR"
echo
echo "     READY.  Open this in your browser now:"
echo
echo "         $URL"
echo
echo "$BAR"
echo
echo "  Next:  open the link  ->  Dashboard  ->  Run scan  ->  check Flagged Users."
echo "  Security model + scheduler notes:  docs/deploy-to-gcp-guide.md  (Security section)."
echo "  Turn IAP off later:  gcloud run services update $SERVICE --region=$REGION --no-iap --update-env-vars IAP_MODE=false"
echo
