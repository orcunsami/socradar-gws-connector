#!/usr/bin/env bash
#
# ONE command that shows everything you need to fill deploy/customer.env:
# who you are, your projects, billing, and your Workspace domain.
# You do not need to know any gcloud commands - just run this and read.
#
#   bash helper/run_all_validations.sh
#
set -uo pipefail
GC="${GCLOUD:-gcloud}"
# capture ONLY stderr (so a project NAMED "Credentials" cannot look like an auth error)
gc_stderr(){ "$GC" "$@" 2>&1 1>/dev/null; }
hr(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

hr "1) Who you are signed in as"
ACCT="$($GC config get-value account 2>/dev/null || true)"
if [ -z "$ACCT" ] || [ "$ACCT" = "(unset)" ]; then
  echo "Not signed in. Run:  gcloud auth login   then run this again."; exit 1
fi
echo "$ACCT"
case "$ACCT" in *@*) DOMAIN_HINT="${ACCT#*@}";; *) DOMAIN_HINT="your-domain";; esac

auth_err="$(gc_stderr projects list --limit=1 --format='value(projectId)' || true)"
if printf '%s' "$auth_err" | grep -qiE 'reauth|invalid_grant|auth tokens|unauthenticated|gcloud auth login'; then
  echo
  echo "Your gcloud session needs a refresh. Run:  gcloud auth login   then run this again."
  exit 1
fi

hr "2) Your projects  (pick one PROJECT_ID for customer.env -> PROJECT=)"
$GC projects list --sort-by=projectId --format="table(projectId, name, projectNumber)" 2>/dev/null \
  || echo "No projects visible. Create one: https://console.cloud.google.com/projectcreate"

hr "3) Currently selected project + billing"
CUR="$($GC config get-value project 2>/dev/null || true)"
if [ -n "$CUR" ] && [ "$CUR" != "(unset)" ]; then
  EN="$($GC billing projects describe "$CUR" --format='value(billingEnabled)' 2>/dev/null || echo unknown)"
  [ -n "$EN" ] || EN="unknown"
  echo "Project: $CUR"
  echo "Billing enabled: $EN"
  [ "$EN" = "True" ] || echo "  -> enable: https://console.cloud.google.com/billing/enable?project=$CUR"
else
  echo "No project selected yet (that is fine - create-env.sh will ask you to pick one)."
fi

hr "4) Your Workspace organization (domain hint)"
$GC organizations list --format="table(displayName, id)" 2>/dev/null \
  || echo "(no organization visible - that is fine)"

hr "What to put in deploy/customer.env"
cat <<EOF
  PROJECT=          one projectId from section 2
  REGION=           leave europe-west1 unless you prefer another Cloud Run region
  DOMAIN=           your verified Workspace domain  (looks like: ${DOMAIN_HINT})
  ADMIN_SUBJECT=    an existing admin to impersonate (your own admin for a quick test,
                    or a dedicated connector-bot@${DOMAIN_HINT} for production)
  CUSTOMER_ID=      leave my_customer
  FEED_API_KEY=     your SOCRadar feed API key
  FEED_COMPANY_ID=  your SOCRadar company id

EASIEST: let the helper write deploy/customer.env for you, then add only the feed key:
  bash helper/create-env.sh     # fills PROJECT/REGION/DOMAIN/ADMIN_SUBJECT/CUSTOMER_ID, asks which project
  # then paste FEED_API_KEY + FEED_COMPANY_ID into deploy/customer.env, save, and:
  bash deploy/setup.sh
EOF
