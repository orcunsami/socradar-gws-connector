#!/usr/bin/env bash
#
# Local launcher for the SOCRadar Google Workspace Connector.
# Creates the virtualenv, installs deps, checks the .env, and starts the app on http://localhost:8080
#
# Usage:  bash deploy/run-local.sh
#
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/../development/app" && pwd)"
cd "$APP_DIR"

PY="${PYTHON:-python3}"

echo "==> [1/4] Virtualenv"
if [ ! -d .venv ]; then
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> [2/4] Dependencies"
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "==> [3/4] Config (.env)"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "    Created .env from .env.example."
  echo "    Set SECRET_KEY and FEED_API_KEY before a real scan."
  echo "    For a quick demo without OAuth, set DEV_LOGIN=true and APP_ENV=dev."
fi

# Warn (do not block) if the obvious local-demo values are still unset.
if grep -qE '^SECRET_KEY=change-me' .env 2>/dev/null; then
  echo "    WARNING: SECRET_KEY is still the placeholder. Set a real value for anything beyond a demo."
fi
if ! grep -qE '^FEED_API_KEY=.+' .env 2>/dev/null; then
  echo "    WARNING: FEED_API_KEY is empty. Scans will fail until it is set."
fi

echo "==> [4/4] Starting on http://localhost:8080  (Ctrl+C to stop)"
exec uvicorn app.main:app --reload --port 8080
