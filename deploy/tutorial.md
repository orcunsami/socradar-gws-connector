# Deploy the SOCRadar Google Workspace Connector

<walkthrough-tutorial-duration duration="10"></walkthrough-tutorial-duration>

This walkthrough deploys the connector into **your own** Google Cloud project as a private Cloud Run
service. It runs keyless (no service-account key file). SOCRadar hosts nothing.

You will:

1. Fill in one config file (`deploy/customer.env`).
2. Run one command.
3. Do one manual authorization in the Admin console.

Click **Start** to begin.

## Create your config (auto-filled)

Run this one helper. It reads your account, projects, domain and billing, asks which project to deploy into,
and writes **`deploy/customer.env`** for you (git-ignored, so your secrets never commit). You do not need to
know any gcloud commands:

```sh
bash helper/create-env.sh
```

It fills in PROJECT, REGION, DOMAIN, ADMIN_SUBJECT and CUSTOMER_ID from what it detected, then opens
<walkthrough-editor-open-file filePath="deploy/customer.env">deploy/customer.env</walkthrough-editor-open-file>
in the editor.

(Just want to look first, without writing anything? `bash helper/run_all_validations.sh` prints the same
information read-only.)

## Add your SOCRadar feed key

In <walkthrough-editor-open-file filePath="deploy/customer.env">deploy/customer.env</walkthrough-editor-open-file>,
fill the two values only you have, and save:

- **FEED_API_KEY** — paste your SOCRadar feed API key.
- **FEED_COMPANY_ID** — your SOCRadar company id.

Also double-check **ADMIN_SUBJECT** — a dedicated least-privilege admin the connector impersonates (e.g.
`connector-bot@yourdomain`, not a super-admin; the 7-privilege custom role is in `docs/deploy-to-gcp-guide.md`).
For a quick test you can set it to an admin you already have.

Optional: `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` add the admin UI "Sign in with Google" (you can add these
later). `DEPLOY_MODE` picks `service` (default), `job` (large-feed backfill), or `both`.

**Save the file** (Cmd/Ctrl+S) when done.

## Create the sign-in client (required for the admin UI)

The admin UI uses "Sign in with Google", so it needs one OAuth client. Without it the service will not
start. Create it once (about 1 minute):

1. **APIs & Services → OAuth consent screen** → User type **Internal** → app name `gws-connector` → Save.
2. **APIs & Services → Credentials → Create credentials → OAuth client ID** → type **Web application**.
3. Under **Authorized redirect URIs** add `http://localhost:8080/auth/callback` (used by the `proxy` access below).
4. Create, then copy the **Client ID** and **Client secret** into `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
   in <walkthrough-editor-open-file filePath="deploy/customer.env">deploy/customer.env</walkthrough-editor-open-file>,
   and save.

Just want a headless scan test (no UI)? Skip this step and set `DEPLOY_MODE=job` and `STORAGE_BACKEND=firestore`
in `deploy/customer.env` instead — the Job scans and reports without a UI.

## Deploy

Now deploy. This validates your config and builds everything:

```sh
bash deploy/setup.sh
```

It enables the APIs, creates a least-privilege service account, self-binds keyless domain-wide delegation,
stores your feed key and the audit key in Secret Manager, and deploys a private Cloud Run service (plus the
periodic-scan scheduler). When it finishes it prints the service account **Client ID** and the four OAuth
**scopes** — copy both for the next step.

## Authorize domain-wide delegation (one manual step)

Your Workspace **super admin** authorizes the connector once, in your own Admin console:

1. Go to **admin.google.com → Security → Access and data control → API controls → Domain-wide delegation →
   Manage Domain Wide Delegation → Add new**.
2. **Client ID**: paste the Client ID printed at the end of the deploy.
3. **OAuth scopes**: paste the four scopes printed by the deploy, as one comma-separated line.
4. Click **Authorize**. Propagation is usually minutes (up to 24h).

## Open the panel and run a scan

The service is private. Open it with one helper (it reads your project and region from `deploy/customer.env`,
so you do not type any flags). Keep it running:

```sh
bash helper/open-panel.sh
```

When it says `proxies to ...`, click Cloud Shell's **Web Preview → Preview on port 8080** (the monitor icon at
the top-right of Cloud Shell). Sign in with a `@your-domain` account, go to **Dashboard → Run scan**, then check
**Flagged Users**.

If sign-in shows `redirect_uri_mismatch`, the error lists the exact callback URL the app used — copy it and add
it under your OAuth client's **Authorized redirect URIs** (Console → Clients → your client), then sign in again.
This happens because Cloud Shell's preview URL differs from `localhost`.

For a real production URL (and to avoid the redirect step), put Identity-Aware Proxy in front instead — see
`deploy/setup-iap.sh`.

## Clean up (return to zero cost)

When you are done testing, remove every billable resource:

```sh
PROJECT="$(gcloud config get-value project)" bash deploy/cleanup.sh
```

<walkthrough-conclusion-trophy></walkthrough-conclusion-trophy>

**Done.** The connector is deployed in your own project — keyless, private, and audited. Nothing runs on
SOCRadar's side.
