#!/usr/bin/env bash
# Local dev runner. Creates venv, installs deps, starts the app on :8080.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example — fill SECRET_KEY + FEED_API_KEY (+ OAuth or DEV_LOGIN=true)."
fi

exec uvicorn app.main:app --reload --port 8080
