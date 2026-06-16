# Deploy the SOCRadar Google Workspace Connector

This is the prose version of the deploy. The interactive, click-to-run version runs automatically in the
Cloud Shell **side panel** when you use the "Open in Cloud Shell" button (it is `deploy/tutorial.md`).

The connector deploys into **your own** Google Cloud project as a private Cloud Run service, running keyless
(no service-account key file). It takes about 10 minutes. SOCRadar hosts nothing.

The whole flow is **one config file and one command, run twice**.

## Before you begin

Pick the project to deploy into, set it, and confirm billing is on (Cloud Run, Secret Manager, and Cloud
Scheduler need it):

```bash
gcloud config set project YOUR_PROJECT_ID
gcloud billing projects describe "$(gcloud config get-value project)" --format='value(billingEnabled)'
```

If billing shows `False`, link a billing account in the console first (**Billing → Link a billing account**).

## Step 1 — Create your config file

Run the setup helper once. It copies the template to your own **`deploy/customer.env`** (git-ignored, so your
secrets never commit) and opens it in the editor:

```bash
bash deploy/setup.sh
```

## Step 2 — Fill in your values

Edit `deploy/customer.env` and replace the placeholders. Required:

| Field | What |
|-------|------|
| `PROJECT` | your GCP project id |
| `DOMAIN` | your verified Workspace domain, e.g. `acme.com` |
| `ADMIN_SUBJECT` | a dedicated least-privilege admin to impersonate, e.g. `connector-bot@acme.com` (not a super-admin) |
| `FEED_API_KEY` | your SOCRadar feed API key (paste it; the file is git-ignored) |
| `FEED_COMPANY_ID` | your SOCRadar company id |

Optional: `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` add "Sign in with Google" to the admin UI (you can add
them later). `DEPLOY_MODE` chooses `service` (default), `job`, or `both`. `STORAGE_BACKEND` chooses `sqlite`
(default) or `firestore` (durable; required for `job`/`both`).

Save the file.

## Step 3 — Deploy

Run the same command again. It validates the config and deploys:

```bash
bash deploy/setup.sh
```

When it finishes it prints the service account **Client ID** and the four OAuth **scopes** — you need both in
the next step.

## Step 4 — Authorize domain-wide delegation

Your Workspace **super admin** authorizes the connector once:

1. **admin.google.com → Security → Access and data control → API controls → Domain-wide delegation → Manage
   Domain Wide Delegation → Add new**.
2. **Client ID**: paste the Client ID from Step 3.
3. **OAuth scopes**: paste the four scopes from Step 3 as one comma-separated line.
4. Authorize. Propagation is usually minutes (up to 24h).

## Step 5 — Open the panel and run a scan

The service is private. Tunnel to it (keep this running):

```bash
gcloud run services proxy gws-connector --region=europe-west1
```

Open the Web Preview on port 8080, sign in, go to **Dashboard → Run scan**, then check **Flagged Users**.

For a real production URL, put Identity-Aware Proxy in front:

```bash
IAP_MEMBERS=user:admin@your-domain.com PROJECT="$(gcloud config get-value project)" REGION=europe-west1 SERVICE=gws-connector bash deploy/setup-iap.sh
```

## Step 6 — Clean up (return to zero cost)

When you are done testing, remove every billable resource:

```bash
PROJECT="$(gcloud config get-value project)" REGION=europe-west1 UNLINK_BILLING=1 bash deploy/cleanup.sh
```

Then verify: `gcloud run services list` is empty and `gcloud billing projects describe "$(gcloud config get-value project)"` shows `billingEnabled: False`.

You are done. The connector is deployed in your own project, keyless, private, and audited.
