#!/usr/bin/env bash
# Optional hardening: put Identity-Aware Proxy (IAP) in front of the private Cloud Run service as an
# INDEPENDENT second auth door (defense-in-depth) on top of the app's own Google OAuth + RBAC.
#
# Why: if the app's own OAuth has a bug or an over-broad "any org user" policy, IAP is a separate,
# Google-managed, IAM-revocable gate that authenticates EVERY request before it reaches the container.
#
# ⚠️ CAVEAT (verified): IAP replaces the caller identity → it can BREAK the Cloud Scheduler -> /tasks/scan
# path. Either (a) give the scheduler SA roles/iap.httpsResourceAccessor + have it mint an IAP OIDC token,
# or (b) keep /tasks/scan on a separate route/identity (it is already guarded by SCAN_TRIGGER_TOKEN).
# NOTE: the app does NOT yet validate the X-Goog-IAP-JWT-Assertion header — IAP gating here is enforced at
# the INFRA layer only (IAP + IAM). For full app-layer defense the app should also verify the assertion
# (ES256, iss=https://cloud.google.com/iap, correct aud) — see docs/security-hardening.md "IAP" (P2).
# Keep --no-allow-unauthenticated regardless.
set -euo pipefail

: "${PROJECT:?set PROJECT}"; : "${SERVICE:?set SERVICE (the Cloud Run service name)}"
: "${REGION:?set REGION}"; : "${IAP_MEMBERS:?set IAP_MEMBERS (comma user:EMAIL or group:EMAIL list)}"
GC="gcloud"
PROJECT_NUMBER="$($GC projects describe "$PROJECT" --format='value(projectNumber)')"

echo "==> Enable IAP API"
$GC services enable iap.googleapis.com --project="$PROJECT"

echo "==> Restrict ingress (internal + load balancing; Scheduler internal traffic still allowed)"
$GC run services update "$SERVICE" --region="$REGION" --project="$PROJECT" \
  --ingress=internal-and-cloud-load-balancing

echo "==> Enable IAP on the Cloud Run service"
$GC run services update "$SERVICE" --region="$REGION" --project="$PROJECT" --iap

echo "==> Grant the IAP service agent run.invoker"
$GC run services add-iam-policy-binding "$SERVICE" --region="$REGION" --project="$PROJECT" \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com" \
  --role="roles/run.invoker"

echo "==> Grant human operators IAP access (who may even reach the app)"
IFS=',' read -ra MEMBERS <<< "$IAP_MEMBERS"
for m in "${MEMBERS[@]}"; do
  $GC iap web add-iam-policy-binding --resource-type=cloud-run --service="$SERVICE" \
    --region="$REGION" --project="$PROJECT" --member="$m" --role="roles/iap.httpsResourceAccessor"
done

echo "==> Done. The service now requires: IAP (Google identity + IAM) -> app OAuth -> RBAC. Three gates."
echo "    Remember the Scheduler caveat above for /tasks/scan."
