#!/usr/bin/env bash
#
# ONE command that shows everything you need to fill deploy/customer.env:
# who you are, your projects, billing, and your Workspace domain.
# You do not need to know any gcloud commands - just run this and read.
#
#   bash helper/run_all_validations.sh
#
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
hr(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

hr "1) Who you are signed in as"
ACCT="$(gcloud config get-value account 2>/dev/null || true)"
if [ -z "$ACCT" ] || [ "$ACCT" = "(unset)" ]; then
  echo "Not signed in. Run:  gcloud auth login   then run this again."
  exit 1
fi
echo "$ACCT"
DOMAIN_HINT="${ACCT#*@}"

# auth freshness probe (Cloud Shell is usually fine; a stale session needs a refresh)
probe="$(gcloud projects list --limit=1 2>&1 || true)"
if printf '%s' "$probe" | grep -qiE 'reauth|auth tokens|credentials|unauthenticated|gcloud auth login'; then
  echo
  echo "Your gcloud session needs a refresh. Run:  gcloud auth login   then run this again."
  exit 1
fi

hr "2) Your projects  (pick one PROJECT_ID for customer.env -> PROJECT=)"
bash "$HERE/list_project_ids.sh" | tail -n +3   # skip the duplicate 'Signed in as' header

hr "3) Currently selected project + billing"
CUR="$(gcloud config get-value project 2>/dev/null || true)"
if [ -n "$CUR" ] && [ "$CUR" != "(unset)" ]; then
  bash "$HERE/check_billing.sh" "$CUR"
else
  echo "No project selected yet. After you pick one, set it:"
  echo "  gcloud config set project YOUR_PROJECT_ID"
fi

hr "4) Your Workspace organization (domain hint)"
gcloud organizations list --format="table(displayName, id)" 2>/dev/null \
  || echo "(no organization visible - that is fine)"

hr "What to put in deploy/customer.env"
cat <<EOF
  PROJECT=          one projectId from section 2
  REGION=           leave europe-west1 unless you prefer another Cloud Run region
  DOMAIN=           your verified Workspace domain  (looks like: ${DOMAIN_HINT})
  ADMIN_SUBJECT=    a least-privilege admin to impersonate, e.g. connector-bot@${DOMAIN_HINT}
  CUSTOMER_ID=      leave my_customer
  FEED_API_KEY=     your SOCRadar feed API key
  FEED_COMPANY_ID=  your SOCRadar company id

Next:  bash deploy/setup.sh        (creates deploy/customer.env and opens it)
       fill it in, save, then run  bash deploy/setup.sh  again to deploy.
EOF
