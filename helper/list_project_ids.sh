#!/usr/bin/env bash
#
# Show every Google Cloud project you can access.
# Put one of the PROJECT_ID values into deploy/customer.env  ->  PROJECT=
#
set -uo pipefail
GC="${GCLOUD:-gcloud}"
# capture ONLY stderr (so a project NAMED "Credentials" cannot look like an auth error)
gc_stderr(){ "$GC" "$@" 2>&1 1>/dev/null; }

acct="$($GC config get-value account 2>/dev/null || true)"
if [ -z "$acct" ] || [ "$acct" = "(unset)" ]; then
  echo "You are not signed in to gcloud. Run:  gcloud auth login"; exit 1
fi
echo "Signed in as: $acct"
echo

err="$(gc_stderr projects list --limit=1 --format='value(projectId)' || true)"
if printf '%s' "$err" | grep -qiE 'reauth|invalid_grant|auth tokens|unauthenticated|gcloud auth login'; then
  echo "Your gcloud session needs a refresh. Run:  gcloud auth login   then run this again."; exit 1
fi
if printf '%s' "$err" | grep -qiE 'PERMISSION_DENIED|SERVICE_DISABLED|has not been used|is disabled'; then
  echo "Could not list projects (API or permission). If you already know your project id you can use it"
  echo "directly. Otherwise see them here:  https://console.cloud.google.com/cloud-resource-manager"; exit 1
fi

out="$($GC projects list --sort-by=projectId --format="table(projectId, name, projectNumber)" 2>/dev/null)"
if [ -z "$out" ]; then
  echo "No projects found on this account. Create one first:"
  echo "  https://console.cloud.google.com/projectcreate"; exit 1
fi

echo "Your Google Cloud projects (use a PROJECT_ID for customer.env -> PROJECT=):"
echo
printf '%s\n' "$out"
