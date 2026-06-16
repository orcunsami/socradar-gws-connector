#!/usr/bin/env bash
#
# Show every Google Cloud project you can access.
# Put one of the PROJECT_ID values into deploy/customer.env  ->  PROJECT=
#
set -uo pipefail

acct="$(gcloud config get-value account 2>/dev/null || true)"
if [ -z "$acct" ] || [ "$acct" = "(unset)" ]; then
  echo "You are not signed in to gcloud. Run:  gcloud auth login"
  exit 1
fi
echo "Signed in as: $acct"
echo

out="$(gcloud projects list --sort-by=projectId --format="table(projectId, name, projectNumber)" 2>&1)"
if printf '%s' "$out" | grep -qiE 'reauth|auth tokens|credentials|unauthenticated|gcloud auth login'; then
  echo "Your gcloud session needs a refresh. Run:"
  echo "  gcloud auth login"
  echo "then run this again."
  exit 1
fi
if printf '%s' "$out" | grep -qiE 'PERMISSION_DENIED|not been used|is disabled|SERVICE_DISABLED'; then
  echo "Could not list projects (API or permission). If you already know your project id you can use it"
  echo "directly. Otherwise see them here:  https://console.cloud.google.com/cloud-resource-manager"
  exit 1
fi
if ! printf '%s' "$out" | grep -q '[A-Za-z0-9]'; then
  echo "No projects found on this account. Create one first:"
  echo "  https://console.cloud.google.com/projectcreate"
  exit 1
fi

echo "Your Google Cloud projects (use a PROJECT_ID for customer.env -> PROJECT=):"
echo
printf '%s\n' "$out"
