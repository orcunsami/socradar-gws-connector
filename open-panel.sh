#!/usr/bin/env bash
#
# Open the deployed admin UI. Reads PROJECT + REGION from deploy/customer.env and starts the
# authenticated proxy to the private Cloud Run service - no flags to type.
#
#   bash open-panel.sh
#
# Then click Cloud Shell's "Web Preview" -> "Preview on port 8080" to open the panel in your browser.
#
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE"                       # this script lives at the repo root
CFG="$ROOT/deploy/customer.env"
GC="${GCLOUD:-gcloud}"
SERVICE="${SERVICE:-gws-connector}"
PORT="${PORT:-8080}"

if [ ! -f "$CFG" ]; then
  echo "deploy/customer.env not found. Run  bash create-env.sh  first."; exit 1
fi

# read a KEY=value from customer.env, stripping any inline comment and spaces
getv(){ grep -E "^$1=" "$CFG" | head -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*$//' | tr -d '[:space:]'; }
PROJECT="$(getv PROJECT)"
REGION="$(getv REGION)"; [ -n "$REGION" ] || REGION="europe-west1"

if [ -z "$PROJECT" ]; then
  echo "PROJECT is not set in deploy/customer.env. Run  bash create-env.sh  first."; exit 1
fi

echo "Opening the admin UI for service '$SERVICE'  (project=$PROJECT, region=$REGION, port=$PORT)"
echo "Once it says 'proxies to ...', click Cloud Shell's Web Preview -> 'Preview on port $PORT'."
echo "(Keep this command running; Ctrl-C stops it.)"
echo
exec "$GC" run services proxy "$SERVICE" --region="$REGION" --project="$PROJECT" --port="$PORT"
