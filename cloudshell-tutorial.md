# Deploy the SOCRadar Google Workspace Connector

This is the prose version of the deploy. The interactive, click-to-run version runs automatically in the
Cloud Shell **side panel** when you use the "Open in Cloud Shell" button (it is `deploy/tutorial.md`).

The connector deploys into **your own** Google Cloud project as a private Cloud Run service, running keyless
(no service-account key file). It takes about 10 minutes. SOCRadar hosts nothing.

The whole flow is **three commands**: `create-env.sh` (writes your config) → `setup.sh` (deploys) →
`enable-iap.sh` (turns on sign-in). Sign-in is native IAP — there is no OAuth client to create.

## Before you begin

Pick the project to deploy into, set it, and confirm billing is on (Cloud Run, Secret Manager, and Cloud
Scheduler need it):

```bash
gcloud config set project YOUR_PROJECT_ID
gcloud billing projects describe "$(gcloud config get-value project)" --format='value(billingEnabled)'
```

If billing shows `False`, link a billing account in the console first (**Billing → Link a billing account**).

## Step 1 — Create your config file

Run the config helper once. It auto-detects your project, domain and region, writes your own
**`deploy/customer.env`** (git-ignored, so your secrets never commit), and opens it in the editor:

```bash
bash create-env.sh
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

Sign-in is native IAP (run `bash enable-iap.sh` after deploy) — no OAuth client needed. `DEPLOY_MODE` chooses
`service` (default), `job`, or `both`. `STORAGE_BACKEND` is `firestore` (default, durable — audit/flagged/scan
history persist; setup.sh auto-creates the database); `sqlite` is in-memory `/tmp` for a throwaway demo only.

Save the file.

## Step 3 — Deploy

Run the same command again. It validates the config and deploys:

```bash
bash setup.sh
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

## Step 5 — Turn on sign-in and open the panel

Sign-in is **native IAP** — one command enables it and prints your admin URL (it reads your project/region
from `deploy/customer.env`):

```bash
bash enable-iap.sh
```

Open the printed `https://...run.app` URL in your browser — IAP signs you in with Google. Go to
**Dashboard → Run scan**, then check **Flagged Users**. To scan on a schedule, set **Settings → Feed → Auto-scan**.

(Alternative, `USE_IAP=false` only: tunnel with `gcloud run services proxy gws-connector --region=europe-west1`
and open the Web Preview on port 8080 — works only on your own machine, not in Cloud Shell.)

## Step 6 — Clean up (return to zero cost)

When you are done testing, remove every billable resource:

```bash
PROJECT="$(gcloud config get-value project)" REGION=europe-west1 UNLINK_BILLING=1 bash deploy/cleanup.sh
```

Then verify: `gcloud run services list` is empty and `gcloud billing projects describe "$(gcloud config get-value project)"` shows `billingEnabled: False`.

You are done. The connector is deployed in your own project, keyless, private, and audited.
