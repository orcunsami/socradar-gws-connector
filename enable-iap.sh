#!/usr/bin/env bash
#
# Turn on native IAP for the admin UI — one command, no flags to type. It reads your project/region from
# deploy/customer.env and grants access to your signed-in account, then hands off to deploy/setup-iap.sh.
# After it finishes, open the printed https://...run.app URL directly in your browser: IAP signs you in
# (no proxy, no Web Preview, no redirect).
#
#   bash enable-iap.sh
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CFG="$HERE/deploy/customer.env"
GC="${GCLOUD:-gcloud}"

if [ ! -f "$CFG" ]; then
  echo "deploy/customer.env not found. Run  bash create-env.sh  then  bash setup.sh  first."; exit 1
fi
getv(){ grep -E "^$1=" "$CFG" | head -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*$//' | tr -d '[:space:]'; }
PROJECT="$(getv PROJECT)"
REGION="$(getv REGION)"; [ -n "$REGION" ] || REGION="europe-west1"
if [ -z "$PROJECT" ]; then
  echo "PROJECT is not set in deploy/customer.env. Run  bash create-env.sh  first."; exit 1
fi

ACCT="$($GC config get-value account 2>/dev/null || true)"
if [ -z "$ACCT" ] || [ "$ACCT" = "(unset)" ]; then
  echo "You are not signed in to gcloud. Run:  gcloud auth login"; exit 1
fi

echo "Enabling IAP for the admin UI  (project=$PROJECT, region=$REGION, access for: $ACCT)"
echo
PROJECT="$PROJECT" REGION="$REGION" SERVICE="${SERVICE:-gws-connector}" IAP_MEMBERS="user:$ACCT" \
  GCLOUD="$GC" bash "$HERE/deploy/setup-iap.sh"
