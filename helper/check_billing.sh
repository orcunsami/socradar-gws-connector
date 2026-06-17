#!/usr/bin/env bash
#
# Check whether billing is ON for a project (Cloud Run + Secret Manager + Scheduler need it).
# Usage:  bash helper/check_billing.sh [PROJECT_ID]
#         (no argument = your currently selected project)
#
set -uo pipefail
GC="${GCLOUD:-gcloud}"
gc_stderr(){ "$GC" "$@" 2>&1 1>/dev/null; }

PROJECT="${1:-$($GC config get-value project 2>/dev/null)}"
if [ -z "$PROJECT" ] || [ "$PROJECT" = "(unset)" ]; then
  echo "No project given and none selected."
  echo "Usage: bash helper/check_billing.sh YOUR_PROJECT_ID"
  echo "(see your projects with: bash helper/list_project_ids.sh)"
  exit 1
fi

err="$(gc_stderr billing projects describe "$PROJECT" || true)"
if printf '%s' "$err" | grep -qiE 'reauth|invalid_grant|auth tokens|unauthenticated|gcloud auth login'; then
  echo "Your gcloud session needs a refresh. Run:  gcloud auth login   then run this again."; exit 1
fi

raw="$($GC billing projects describe "$PROJECT" 2>/dev/null || true)"
EN="$(printf '%s' "$raw" | sed -n 's/^billingEnabled:[[:space:]]*//p')"
ACC="$(printf '%s' "$raw" | sed -n 's/^billingAccountName:[[:space:]]*//p')"
[ -n "$EN" ] || EN="unknown"

echo "Project:          $PROJECT"
echo "Billing enabled:  $EN"
[ -n "$ACC" ] && echo "Billing account:  $ACC"

case "$EN" in
  True)    echo "OK - this project is ready to deploy into." ;;
  False)   echo "Billing is OFF. Turn it on (deploy needs it):"
           echo "  https://console.cloud.google.com/billing/enable?project=$PROJECT" ;;
  *)       echo "Could not read billing status. Make sure the Cloud Billing API is on and you have access:"
           echo "  https://console.cloud.google.com/billing/enable?project=$PROJECT" ;;
esac
