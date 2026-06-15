# SOCRadar Google Workspace Connector — Internal Admin App

Turns the proven connector loop (SOCRadar feed → verified-domain filter → directory lookup →
gated remediation) into a real Workspace-facing admin app: a web UI where an admin runs scans,
sees exposed users, and revokes sessions — instead of a CLI.

Built as an **Internal user-type** app on the customer's own Workspace domain (verification-exempt).
Same code ports to the SOCRadar org later by flipping the OAuth consent screen Internal→External and
re-pointing the publisher/domain.

## Stack
FastAPI + Jinja2 admin UI + SQLite (or Firestore for durable state) + Google OAuth (admin sign-in) +
keyless domain-wide delegation (`signJwt` + `jwt-bearer`). Single service; runs locally ($0) and
deploys to Cloud Run unchanged.

## Run locally
```bash
cd development/app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # fill SECRET_KEY + FEED_API_KEY (+ OAuth or DEV_LOGIN=true)
uvicorn app.main:app --reload --port 8080
# open http://localhost:8080
```

### Auth options
- **Fast local demo:** set `DEV_LOGIN=true` in `.env` → "Sign in with Google" logs you in as
  `ADMIN_SUBJECT` without a real OAuth client. Never enable in production.
- **Real (Internal) OAuth:** in the Google Cloud console, set the OAuth consent screen to
  **Internal** user type, create an OAuth **Web application** client, add redirect URI
  `http://localhost:8080/auth/callback`, and put the client id/secret in `.env`. Only
  `ALLOWED_DOMAIN` (your Workspace domain) accounts can sign in.

> Scans/remediation need a live keyless-DWD bootstrap. Locally that means a working
> `gcloud auth login` (the app shells out to `gcloud auth print-access-token`). On Cloud Run the
> runtime SA's ambient token is used automatically.

### DWD scope grant
The DWD client must be authorized in `admin.google.com` for exactly the union of scopes the app uses —
defined as `connector.SCOPES_UNION` (all SENSITIVE, none restricted → no CASA):
`admin.directory.user.readonly` (lookup) · `admin.directory.user` (reset password, suspend) ·
`admin.directory.user.security` (signOut, 2SV off, revoke tokens/app-passwords) ·
`admin.directory.group.member` (quarantine group add/remove). Each action requests only its own scope at
call time; the grant is the union.

## What it does
- **Dashboard** — open vs remediated counts, last-scan totals (botnet/pii/vip), "Run scan now".
- **Flagged Users** — every leaked email in your verified domains, its sources, directory status
  (found / 403 denied / not-found), and per-action remediation buttons (gated, confirm dialog).
- **Settings** — verified domains, feed config, and which remediation actions are enabled
  (off by default; destructive).
- **Audit** — every scan, settings change, and remediation (including *blocked* ones) with actor.
- **Metrics** — dwell time (p50/p95), scan freshness, remediation success rate, audit-chain integrity.
- **Approvals** — the four-eyes queue: high-blast actions wait here for a second admin to approve or reject.
- **Tenants** — manage multiple Workspace customers (domains + feed config) from one deployment.

## Safety invariants (enforced in code)
- Verified-domain allowlist filters before any `users.get` (cross-domain = 403, not 404).
- 403 is `permission_denied`, never collapsed to not-found.
- The admin/operator subject is never remediated (signOut self-revoke trap).
- VIP records (name only, no email) surface as alarms but are never remediated.
- Feed records sanitized on ingest (`password_present` bool, never plaintext).
- Remediation requires: action enabled (toggle) + user found + in verified domain + not the operator.
- CSRF token on every state-changing POST.

## Deploy to Cloud Run (when billing is on)
Container is the same. Set env (no `BOOTSTRAP_TOKEN` — ambient metadata token is used), run as the
DWD service account (needs `iam.serviceAccountTokenCreator` on itself), put the feed key in Secret
Manager. See `../../docs/cloud-run-deploy.md`.

## Port to SOCRadar org
Flip OAuth consent Internal→External, re-point publisher + homepage + privacy/ToS to socradar.io,
move to a SOCRadar-org GCP project, submit OAuth verification. The app code does not change.
See `../../docs/marketplace-readiness.md` §7b.
