# Deploy the SOCRadar Google Workspace Connector

This walkthrough deploys the connector to **your own** Google Cloud project as a private Cloud Run
service, running keyless (no service-account key file). It takes about 10 minutes.

You run every command here in **your** Cloud Shell, signed in as yourself. SOCRadar hosts nothing.

## Before you begin

Pick the project to deploy into, then set it:

```bash
gcloud config set project YOUR_PROJECT_ID
```

Confirm you are signed in and billing is enabled on the project (the deploy needs Cloud Run, Secret
Manager, and Cloud Scheduler, which require billing):

```bash
gcloud config get-value account
gcloud billing projects describe "$(gcloud config get-value project)" --format='value(billingEnabled)'
```

If billing shows `False`, link a billing account in the console first (Billing → Link a billing account).

## Step 1 — Create the admin sign-in OAuth client

The admin UI uses "Sign in with Google", so create one OAuth client (one time):

1. In the console: **APIs & Services → OAuth consent screen** → User type **Internal** → app name `gws-connector` → Save.
2. **APIs & Services → Credentials → Create credentials → OAuth client ID** → type **Web application**, name `gws-connector`.
3. Under **Authorized redirect URIs** add `http://localhost:8080/auth/callback` (for the `proxy` access in Step 4).
4. Copy the **Client ID** and **Client secret** — you will paste them in the next step.

## Step 2 — Put your SOCRadar feed key in a file

Replace `YOUR_FEED_KEY` with your SOCRadar feed API key (the file holds only the key):

```bash
echo "YOUR_FEED_KEY" > "$HOME/feed-key.txt"
```

## Step 3 — Deploy

Fill in your values, then run the deploy script. It enables the APIs, creates a least-privilege
service account, self-binds keyless domain-wide delegation, stores the feed key and audit key in
Secret Manager, deploys a private Cloud Run service, and creates the periodic-scan scheduler job.

```bash
PROJECT="$(gcloud config get-value project)" \
REGION=europe-west1 \
ADMIN_SUBJECT=admin@your-domain.com \
DOMAIN=your-domain.com \
CUSTOMER_ID=my_customer \
FEED_COMPANY_ID=YOUR_COMPANY_ID \
FEED_KEY_FILE="$HOME/feed-key.txt" \
GOOGLE_CLIENT_ID=YOUR_CLIENT_ID \
GOOGLE_CLIENT_SECRET=YOUR_CLIENT_SECRET \
bash deploy/deploy-to-gcp.sh
```

When it finishes it prints the service account **Client ID** and the four OAuth **scopes** — you need
both in the next step.

## Step 4 — Authorize domain-wide delegation

Your Workspace **super admin** authorizes the connector once, the customer's own way:

1. Go to **admin.google.com → Security → Access and data control → API controls → Domain-wide delegation → Manage Domain Wide Delegation → Add new**.
2. **Client ID**: paste the Client ID printed at the end of Step 3.
3. **OAuth scopes**: paste the four scopes printed in Step 3 as one comma-separated line.
4. Authorize. Propagation is usually minutes (up to 24h).

## Step 5 — Open the panel and run a scan

The service is private. Open it one of two ways:

Quick (dev): tunnel to localhost (keep this running):

```bash
gcloud run services proxy gws-connector --region=europe-west1
```

Then open `http://localhost:8080`, sign in with Google, go to **Dashboard → Run scan**, and check
**Flagged Users**.

Real URL (recommended for production): put Identity-Aware Proxy in front:

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
