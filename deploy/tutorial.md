# Deploy the SOCRadar Google Workspace Connector

<walkthrough-tutorial-duration duration="10"></walkthrough-tutorial-duration>

This walkthrough deploys the connector into **your own** Google Cloud project as a private Cloud Run
service. It runs keyless (no service-account key file). SOCRadar hosts nothing.

You will:

1. Fill in one config file (`deploy/customer.env`).
2. Run one command.
3. Do one manual authorization in the Admin console.

Click **Start** to begin.

## Pick your project

Choose the Google Cloud project to deploy into, then set it:

```sh
gcloud config set project YOUR_PROJECT_ID
```

Confirm billing is on (Cloud Run, Secret Manager, and Scheduler need it):

```sh
gcloud billing projects describe "$(gcloud config get-value project)" --format='value(billingEnabled)'
```

If that prints `False`, link a billing account in the console (**Billing → Link a billing account**) before
continuing.

## Create your config file

Run the setup helper once. It copies the template to your own **`deploy/customer.env`** (which is
git-ignored, so your secrets never get committed) and opens it in the editor:

```sh
bash deploy/setup.sh
```

The editor opens <walkthrough-editor-open-file filePath="deploy/customer.env">deploy/customer.env</walkthrough-editor-open-file>
on the right.

## Fill in your values

Edit <walkthrough-editor-open-file filePath="deploy/customer.env">deploy/customer.env</walkthrough-editor-open-file>
and replace the placeholders. The required fields are:

- **PROJECT** — your GCP project id (the one you set above).
- **DOMAIN** — your verified Workspace domain, e.g. `acme.com`.
- **ADMIN_SUBJECT** — a dedicated least-privilege admin the connector impersonates, e.g. `connector-bot@acme.com`
  (not a super-admin; the 7-privilege custom role is in `docs/deploy-to-gcp-guide.md`).
- **FEED_API_KEY** — paste your SOCRadar feed API key.
- **FEED_COMPANY_ID** — your SOCRadar company id.

Optional: `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` give the admin UI "Sign in with Google" (you can add
these later and reach the UI through a proxy meanwhile). `DEPLOY_MODE` picks `service` (admin UI + scheduled
scans, the default), `job` (large-feed backfill), or `both`.

**Save the file** (Cmd/Ctrl+S) when done.

## Deploy

Run the same command again. This time it validates your config and deploys:

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

The service is private. Tunnel to it from Cloud Shell (keep this running):

```sh
gcloud run services proxy gws-connector --region="$(grep -E '^REGION=' deploy/customer.env | cut -d= -f2 | tr -d ' ' || echo europe-west1)"
```

Use the Cloud Shell **Web Preview** (port 8080), sign in, go to **Dashboard → Run scan**, then check
**Flagged Users**.

For a real production URL, put Identity-Aware Proxy in front instead — see `deploy/setup-iap.sh`.

## Clean up (return to zero cost)

When you are done testing, remove every billable resource:

```sh
PROJECT="$(gcloud config get-value project)" bash deploy/cleanup.sh
```

<walkthrough-conclusion-trophy></walkthrough-conclusion-trophy>

**Done.** The connector is deployed in your own project — keyless, private, and audited. Nothing runs on
SOCRadar's side.
