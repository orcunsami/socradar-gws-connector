# Deploy the SOCRadar Google Workspace Connector

<walkthrough-tutorial-duration duration="12"></walkthrough-tutorial-duration>

This walkthrough deploys the connector into **your own** Google Cloud project as a private Cloud Run
service. It runs keyless (no service-account key file). SOCRadar hosts nothing.

Everything you run lives at the top of this project — three scripts, in order:

1. **`bash create-env.sh`** — auto-writes your config (you add only the SOCRadar feed key).
2. **`bash setup.sh`** — validates and deploys.
3. **`bash open-panel.sh`** — opens the admin UI.

Between step 1 and step 2 you do two one-time Google setup tasks (a sign-in client, and after deploy a
domain-wide-delegation authorization). The steps below walk you through all of it.

Click **Start** to begin.

## 1) Create your config (auto-filled)

Run this one helper. It reads your account, projects, domain and billing, asks which project to deploy into,
and writes **`deploy/customer.env`** for you (git-ignored, so your secrets never commit). You do not need to
know any gcloud commands:

```sh
bash create-env.sh
```

It fills in PROJECT, REGION, DOMAIN, ADMIN_SUBJECT and CUSTOMER_ID from what it detected, then opens
<walkthrough-editor-open-file filePath="deploy/customer.env">deploy/customer.env</walkthrough-editor-open-file>
in the editor.

(Just want to look first, without writing anything? `bash helper/run_all_validations.sh` prints the same
information read-only.)

## 2) Add your SOCRadar feed key

In <walkthrough-editor-open-file filePath="deploy/customer.env">deploy/customer.env</walkthrough-editor-open-file>,
fill the two values only you have, and save:

- **FEED_API_KEY** — paste your SOCRadar feed API key.
- **FEED_COMPANY_ID** — your SOCRadar company id.

Also check **ADMIN_SUBJECT** — the admin the connector impersonates. It is pre-filled with your own account
(which works for a quick test). For production switch it to a dedicated least-privilege admin (e.g.
`connector-bot@yourdomain`, the 7-privilege custom role is in `docs/deploy-to-gcp-guide.md`). It must be a real,
existing admin either way.

**Save the file** (Cmd/Ctrl+S) when done.

## 3) Create the sign-in OAuth client (required for the admin UI)

The admin UI uses "Sign in with Google", so it needs one OAuth client in **your** project. Without it the
service container will not start. Create it once (about 1 minute):

1. **Console → APIs & Services → OAuth consent screen** (new console: **Google Auth platform**). If it is not
   set up yet, choose **User type: Internal** and save. Internal means only people in your own Workspace can use
   it, and Google does not require app verification. (If you already configured it, skip to step 2.)
2. **APIs & Services → Credentials → Create credentials → OAuth client ID** (new console: **Clients → Create
   client**) → Application type **Web application** → name it (e.g. `gws-connector`).
3. Under **Authorized redirect URIs** add: `http://localhost:8080/auth/callback`
   (this is where Google returns you after sign-in, via the proxy in step 6).
4. **Create**, then copy the **Client ID** and **Client secret** into `GOOGLE_CLIENT_ID` and
   `GOOGLE_CLIENT_SECRET` in
   <walkthrough-editor-open-file filePath="deploy/customer.env">deploy/customer.env</walkthrough-editor-open-file>,
   and **save**.

Just want a headless scan test instead (no UI, skip this step)? Set `DEPLOY_MODE=job` and
`STORAGE_BACKEND=firestore` in `deploy/customer.env` — the Job scans and reports without a UI or a sign-in client.

## 4) Deploy

Now deploy. It validates your config and builds everything:

```sh
bash setup.sh
```

It enables the APIs, creates a least-privilege service account, self-binds keyless domain-wide delegation,
stores your feed key and the audit key in Secret Manager, and deploys a private Cloud Run service (plus the
periodic-scan scheduler). When it finishes it prints the service account **Client ID** and the four OAuth
**scopes** — you need both in the next step.

## 5) Authorize domain-wide delegation (one manual step)

Only a Workspace **super admin** can register a delegation (that is a Google requirement for the *registration
action* — it does **not** mean the connector runs as a super admin). The connector itself is least-privilege: it
impersonates the dedicated `ADMIN_SUBJECT` you set, and it is limited to the **four narrow Directory scopes**
below (mostly read; the two write scopes are only for the specific remediation actions you enable). No Gmail,
no Drive, no broad admin access.

In your own Admin console:

1. **admin.google.com → Security → Access and data control → API controls → Domain-wide delegation → Manage
   Domain Wide Delegation → Add new**.
2. **Client ID**: the **`bash setup.sh`** run printed this near the end as `Client ID: ...`. Paste that number.
   (It is the service account's client id; the deploy also prints it again on its very last line so you do not
   have to scroll.)
3. **OAuth scopes**: paste exactly these four (already comma-separated, copy as one line):

```text
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.group.member
```

4. Click **Authorize**. Propagation is usually minutes (up to 24h), so wait 2–3 minutes before scanning.

## 6) Open the panel and run a scan

The service is private, so it needs a sign-in gate. The cleanest way that works from anywhere — including
Cloud Shell — is **native IAP**: Google signs you in at the edge on the same `run.app` URL, with no proxy and
no redirect step. Turn it on with one command (it reads your project and grants you access automatically):

```sh
bash enable-iap.sh
```

It prints your service URL. **Open that `https://...run.app` URL directly in your browser** — IAP signs you in
with Google, then go to **Dashboard → Run scan** and check **Flagged Users**. (With IAP on, the OAuth client
from step 3 is no longer used for the UI; the app trusts the IAP-verified identity.)

**Why not the proxy + Web Preview?** Behind `gcloud run services proxy` the app sees the `run.app` host, so its
OAuth callback can never match `localhost:8080`, and Cloud Shell's preview URL carries query params Google will
not register — you would hit `redirect_uri_mismatch`. The proxy path (`bash open-panel.sh`) works **only on your
OWN machine**, where `localhost:8080` really is your browser's localhost. In Cloud Shell, use IAP above.

## 7) Clean up (return to zero cost)

When you are done testing, remove every billable resource:

```sh
PROJECT="$(gcloud config get-value project)" bash deploy/cleanup.sh
```

<walkthrough-conclusion-trophy></walkthrough-conclusion-trophy>

**Done.** The connector is deployed in your own project — keyless, private, and audited. Nothing runs on
SOCRadar's side.
