#!/usr/bin/env bash
#
# SOCRadar Google Workspace Connector — one-command seamless deploy (Cloud Shell friendly).
#
# Usage (in YOUR Google Cloud Shell, after clicking "Open in Cloud Shell"):
#   bash deploy/setup.sh
#
# First run: creates deploy/customer.env from the template and opens it in the editor for you to fill.
# Second run (config filled): validates everything, then deploys the connector to YOUR Google Cloud project.
# Nothing is hosted by SOCRadar — it runs in your project, keyless (no service-account key file).
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CFG="$HERE/customer.env"
EXAMPLE="$HERE/customer.env.example"
GC="${GCLOUD:-gcloud}"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '   \033[0;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '   \033[0;33m! %s\033[0m\n' "$*"; }
die()  { printf '\n\033[0;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------- 1) first run: scaffold the config + open it for editing ----------
if [ ! -f "$CFG" ]; then
  cp "$EXAMPLE" "$CFG"
  say "Created your config file: deploy/customer.env"
  echo "   Fill in YOUR values (project, domain, admin, SOCRadar feed key), SAVE, then run this again:"
  echo "       bash deploy/setup.sh"
  # In Cloud Shell, 'cloudshell edit' opens the file in the built-in editor (IDE-like).
  if command -v cloudshell >/dev/null 2>&1; then
    cloudshell edit "$CFG" || true
    ok "Opened deploy/customer.env in the editor — fill it, save, then re-run 'bash deploy/setup.sh'."
  else
    echo "   (Open deploy/customer.env in your editor, fill it, then re-run.)"
  fi
  exit 0
fi

# ---------- 2) load + validate the config ----------
say "Loading your config (deploy/customer.env)"
set -a; # shellcheck disable=SC1090
source "$CFG"; set +a

problems=()
need() { eval "v=\${$1:-}"; case "$v" in ""|*CHANGE_ME*|*your-*|*customer.com*|*customer-gcp-project*|connector-bot@customer.com|my_customer) problems+=("$1 is not filled in (got: '${v:-empty}')");; esac; }
need PROJECT
need DOMAIN
need ADMIN_SUBJECT
need FEED_COMPANY_ID
# feed key: either inline FEED_API_KEY or a FEED_KEY_FILE path
if [ -z "${FEED_API_KEY:-}" ] && [ -z "${FEED_KEY_FILE:-}" ]; then
  problems+=("set FEED_API_KEY (paste the key) OR FEED_KEY_FILE (a path to a file with only the key)")
fi
if [ "${#problems[@]}" -gt 0 ]; then
  printf '\n\033[0;31mPlease fix deploy/customer.env:\033[0m\n'
  for p in "${problems[@]}"; do echo "   - $p"; done
  echo
  command -v cloudshell >/dev/null 2>&1 && cloudshell edit "$CFG" || true
  die "Config incomplete — edit deploy/customer.env, save, and run 'bash deploy/setup.sh' again."
fi
ok "Config looks complete."

# ---------- 3) gcloud preflight ----------
say "Checking gcloud (auth, project, billing)"
ACCT="$($GC config get-value account 2>/dev/null || true)"
[ -n "$ACCT" ] && [ "$ACCT" != "(unset)" ] || die "Not signed in. Run: gcloud auth login"
ok "Signed in as $ACCT"
$GC config set project "$PROJECT" >/dev/null 2>&1 || true
BILL="$($GC billing projects describe "$PROJECT" --format='value(billingEnabled)' 2>/dev/null || echo unknown)"
if [ "$BILL" = "False" ]; then
  die "Billing is NOT enabled on '$PROJECT'. Enable it (Cloud Run + Secret Manager need it): https://console.cloud.google.com/billing/enable?project=$PROJECT"
fi
ok "Project=$PROJECT billing=$BILL"

# ---------- 4) materialize the feed key into a file for the deployer ----------
TMPKEY=""
if [ -n "${FEED_API_KEY:-}" ]; then
  TMPKEY="$(mktemp)"; printf '%s' "$FEED_API_KEY" > "$TMPKEY"
  export FEED_KEY_FILE="$TMPKEY"
fi
cleanup() { [ -n "$TMPKEY" ] && rm -f "$TMPKEY"; }
trap cleanup EXIT

# ---------- 5) deploy (Service = admin UI + scheduler; Job = large-feed backfill host) ----------
export PROJECT REGION="${REGION:-europe-west1}" ADMIN_SUBJECT DOMAIN CUSTOMER_ID="${CUSTOMER_ID:-my_customer}" \
       FEED_BASE="${FEED_BASE:-https://platform.socradar.com}" FEED_COMPANY_ID \
       STORAGE_BACKEND="${STORAGE_BACKEND:-sqlite}" REMEDIATION_ADMINS="${REMEDIATION_ADMINS:-$ADMIN_SUBJECT}" \
       GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID:-}" GOOGLE_CLIENT_SECRET="${GOOGLE_CLIENT_SECRET:-}" \
       SA_EMAIL="${SA_EMAIL:-}"

case "${DEPLOY_MODE:-service}" in
  service) say "Deploying the Cloud Run SERVICE (admin UI + scheduled scans)"; bash "$HERE/deploy-to-gcp.sh" ;;
  job)     say "Deploying the Cloud Run JOB (large-feed backfill, no request timeout)"; bash "$HERE/deploy-job.sh" ;;
  both)    say "Deploying the SERVICE then the JOB"; bash "$HERE/deploy-to-gcp.sh"; STORAGE_BACKEND=firestore bash "$HERE/deploy-job.sh" ;;
  *) die "DEPLOY_MODE must be service | job | both (got '${DEPLOY_MODE:-}')" ;;
esac

say "Done. The connector is deployed in YOUR project ($PROJECT). The one manual step (domain-wide delegation) is printed above."
