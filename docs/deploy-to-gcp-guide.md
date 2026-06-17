# SOCRadar Google Workspace Connector — Deploy-to-GCP (Customer Self-Host) Guide

> The customer deploys the connector into **their own GCP project**. SOCRadar hosts nothing.
> This is the Google equivalent of an Azure Sentinel solution that deploys into the customer's
> own Azure. Distribution model chosen: **Deploy-to-GCP** (see `marketplace-readiness.md`).
> All commands verified against GCP primary docs (Cloud Run / IAM Credentials / Secret Manager),
> 2026-06-05.

---

## What gets created (in the customer's GCP project)
- A private **Cloud Run service** running the connector (admin UI + feed→lookup→remediation logic).
- A dedicated **runtime service account** `gws-connector@<project>` — **keyless** (no JSON key; it
  self-signs DWD JWTs via `iam.serviceAccountTokenCreator` on itself).
- A **Secret Manager** secret holding the SOCRadar feed API key.
No software is installed into Google Workspace itself — the connector calls the Workspace Admin SDK
APIs from the customer's Cloud Run, after the admin authorizes domain-wide delegation (one manual step).

## Prerequisites (customer side)
1. A **GCP project with billing enabled** (conscious cost decision — Cloud Run scales to zero, but
   billing must be on to deploy).
2. The person running the deploy needs **Owner/Editor** (or: `roles/run.admin`,
   `roles/iam.serviceAccountUser` on the runtime SA, `roles/serviceusage.serviceUsageAdmin`,
   `roles/secretmanager.admin`).
3. A **Workspace super administrator** (for the one-time domain-wide-delegation step).
4. `gcloud` ≥ 378, `python3`, and the SOCRadar feed **company ID + API key** (from SOCRadar).
5. Confirm the org doesn't block domain-wide delegation via an app-access policy.

## Step 0 — Create the admin-UI sign-in OAuth client (once)
The admin UI signs in with Google OAuth, so the service needs a **Web OAuth client**. Without
`GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` the service fail-closes at startup (no sign-in method) and
the deploy in Step 1 reports an unhealthy revision. In `console.cloud.google.com` → **APIs & Services →
Credentials → Create credentials → OAuth client ID → Web application**. Add an authorized redirect URI:
- `http://localhost:8080/auth/callback` if you'll reach the UI via `gcloud run services proxy` (Step 3), and/or
- `<service-url>/auth/callback` once you know the deployed URL (you can add it after Step 1).

Keep the generated **Client ID** and **Client secret** for Step 1.

## Step 1 — Deploy
```bash
# put ONLY the feed API key into a file (kept out of shell history)
printf '%s' 'YOUR_SOCRADAR_FEED_API_KEY' > /tmp/feed-key.txt

PROJECT=your-gcp-project \
REGION=europe-west1 \
ADMIN_SUBJECT=admin@yourdomain.com \
DOMAIN=yourdomain.com \
CUSTOMER_ID=my_customer \
FEED_COMPANY_ID=132 \
FEED_KEY_FILE=/tmp/feed-key.txt \
GOOGLE_CLIENT_ID=YOUR_CLIENT_ID.apps.googleusercontent.com \
GOOGLE_CLIENT_SECRET=YOUR_CLIENT_SECRET \
bash deploy/deploy-to-gcp.sh

rm -f /tmp/feed-key.txt   # shred the key file after
```
The script enables APIs, creates the keyless runtime SA, stores the feed key in Secret Manager,
deploys a private Cloud Run service, and prints the **Client ID + scopes** for Step 2.

## Step 2 — Authorize domain-wide delegation (Workspace super admin, one-time, manual)
The script prints the SA's **`oauth2ClientId`** and the scope list. In `admin.google.com`:
- **Security → Access and data control → API controls → Domain-wide delegation → Manage → Add new**
- **Client ID:** paste the printed numeric Client ID — ⚠️ NOT the SA *email* (using the email →
  `unauthorized_client`). For a service account `oauth2ClientId == uniqueId` (verified on our SA), so
  either field gives the correct value; the SA email does not.
- **OAuth scopes (comma-delimited):**
  ```
  https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.group.member
  ```
- **Authorize.** Propagation: usually minutes, up to 24h. (If Multi-Party Approval is on, a second
  super admin must approve.)

> All four scopes are **sensitive, not restricted** → no CASA / no annual security assessment.

### Least-privilege subject (recommended)
Authorizing DWD (above) is a one-time **super-admin** action. But the account the connector *impersonates*
on every call (`admin_subject`) does NOT have to be — and shouldn't be — a super admin. Create a dedicated
admin (e.g. `connector-bot@your-domain.com`) with a **custom admin role** holding **exactly** these privileges
(Admin console **display name** → Admin SDK **API constant** — give the admin both so they can match the checkboxes):

| Need | Admin console privilege | API constant |
|------|-------------------------|--------------|
| Read users (scan/lookup) — **REQUIRED, nothing works without it** | Users → Read | `USERS_RETRIEVE` |
| Read org units (companion to user/security actions) | Organizational Units → Read | `ORGANIZATION_UNITS_RETRIEVE` |
| signOut / turn off 2SV / revoke OAuth tokens / revoke app-passwords | User Security Management | `USER_SECURITY_ALL` |
| reset password | Users → Reset Password | `USERS_RESET_PASSWORD` |
| force change at next login | Users → Force Password Change | `USERS_FORCE_PASSWORD_CHANGE` |
| suspend + unsuspend | Users → Suspend Users | `USERS_SUSPEND` |
| add/remove from quarantine group | Groups (member management) | `GROUPS_ALL` |

Set that account as the subject. Two hard limits (both Google-enforced, primary-source verified):
- A custom-role subject **cannot act on another admin account** (the Admin SDK 403s, even read-only); the
  connector detects admin targets (`isAdmin`/`isDelegatedAdmin`) and refuses them. To remediate a *compromised
  admin* you need a **super-admin subject + manual review**.
- `turn off 2SV` (per-user) is delegable, but **org-wide 2SV enforcement** and the **disable-2SV action cannot
  be scoped to specific OUs** — only super-admins enforce 2SV org-wide.

> Source: Google "Administrator privilege definitions" (support.google.com/a/answer/1219251) + independent
> review (arastirma9 §B/§C). The earlier draft listed only display names and **omitted the read privileges** —
> a role without `USERS_RETRIEVE` would fail at runtime (the connector can't even read the directory).

## Step 3 — Use it
- The service is **private** (`--no-allow-unauthenticated`). Open the admin UI locally:
  ```bash
  gcloud run services proxy gws-connector --region=europe-west1 --project=your-gcp-project
  ```
  (or put **Identity-Aware Proxy** in front for browser access for your admins.)
- In the UI: set verified domains, enable the remediation actions you want, set a quarantine group,
  then **Run scan** → see flagged users → remediate (9 actions: signOut, reset password, suspend,
  restore/un-suspend, turn off 2SV, revoke tokens, revoke app-passwords, add/remove from quarantine group).

## Scale, quotas, cost & hardened-org notes

- **Quotas.** Remediation uses the Admin SDK Directory API: default **2,400 queries/minute per user per
  project** (adjustable in the Cloud console, review-gated), plus a separate per-Workspace-account limit that
  cannot be raised, and rapid-modify limits (~10 user-writes/sec/domain, 1 OU/sec/customer). Targeted
  incident-response volume stays well within these; the connector backs off with jitter on 429/5xx. It is not
  built for daily full-directory syncs.
- **Cost.** At IR volume (scans every few hours, scale-to-zero Cloud Run, 2-3 Secret Manager secrets, the
  scheduler jobs) the connector runs roughly **$0-5/month**, largely inside GCP's perpetual free tier; egress
  is usually the first marginal cost. Cloud Scheduler's 3 free jobs are **per billing account** (not per
  project); if you enable the durable Firestore backend, use the **(default)** database — non-default
  Firestore databases get no free quota.
- **VPC Service Controls.** Keep `iamcredentials.googleapis.com` inside the perimeter (it IS a VPC-SC-
  supported service — needed for `signJwt`). The Admin SDK (`admin.googleapis.com`) is **NOT** a VPC-SC-
  protected service: route it via `private.googleapis.com` (or a DNS/route exception) — a blanket
  `restricted.googleapis.com` route silently blocks directory calls. Run a scan after applying perimeter
  rules to confirm.
- **Org policies.** `iam.disableServiceAccountKeyCreation` does **not** affect the connector (it is keyless —
  a selling point). Under `run.allowedIngress=internal-and-cloud-load-balancing` the scheduled-pull path
  (Cloud Scheduler → `/tasks/scan`) still works; only an inbound public webhook would need an external load
  balancer / API Gateway.

## MSSP — serving multiple customer orgs from one deployment

One deployment can manage several customer Workspace organizations (an MSSP model). The single connector
service account is authorized independently by each org; the connector impersonates each org with its own
super-admin. No new service account, no redeploy per org.

**One-time per managed org (no redeploy):**
1. That org's Workspace super admin authorizes the **same** Client ID + the same 4 scopes (printed by the
   deploy in Step 2) in **their own** `admin.google.com` → API controls → Domain-wide delegation → Add new.
   Propagation can take up to 24h, usually minutes.
2. In the connector UI → **Tenants** → create a tenant for that org with:
   - **Customer ID** — that org's immutable Google `customerId` (each org must have a distinct real id; do
     not reuse `my_customer`).
   - **Verified domains** — that org's domains.
   - **Subject to impersonate** (`admin_subject`) — that org's own admin to act as (a least-privilege
     custom-role admin is recommended over a super admin — see "Least-privilege subject" above). Must be an
     email in one of its verified domains. Leave blank only for a single-org deploy; in MSSP each org sets its own.
   - **Feed company ID + API key** — that org's SOCRadar feed.
3. **Switch** to the new tenant and **Run scan**. The connector impersonates that org's own super admin.

**Why service_account stays global:** one connector SA, authorized by N orgs, is the documented and minimal
pattern for keyless self-hosted multi-org delegation. An optional per-tenant **Service account override**
field exists for the rare org that contractually requires a dedicated SA. If you use it, the Cloud Run
runtime identity must hold `roles/iam.serviceAccountTokenCreator` on that SA, and that SA must be
DWD-authorized in the org — otherwise signing fails with a clean error in that tenant's scan.

**MSSP safety notes:**
- Each org is impersonated by its OWN super admin; the connector refuses to remediate that org's super admin
  (so it never signs out the account it depends on for that org).
- A flagged user is only ever acted on within its own tenant — cross-org actions are rejected.
- **Auto remediation is disabled whenever more than one tenant is configured** (the auto policy — mode,
  kill-switch, exclusions, rate limit — is currently fleet-wide; one global policy must not auto-act across
  orgs with different risk appetites). Every exposure waits for a human in multi-org deployments. Per-tenant
  auto policy is planned; until then this is the safe default.
- Sign-in is restricted to your (the MSSP's) own domain; every signed-in operator can switch to and act on
  any managed org. This is by design for a single-operator MSSP console. If customer-org staff ever need
  direct login, a per-operator→tenant access list is required first.

## Step 4 — automated scanning (already wired by the deploy)
The deploy script does this for you. It grants the runtime SA `roles/run.invoker` on the private service
and creates two Cloud Scheduler jobs, both OIDC-authenticated and carrying the `X-Scan-Token` header:

- `gws-scan` calls `POST /tasks/scan` every 6 hours (override with `SCAN_SCHEDULE`).
- `gws-verify-audit` calls `POST /tasks/verify-audit` daily at 03:00 (re-checks the audit hash chain).

To change the scan cadence, set `SCAN_SCHEDULE` before deploying, for example:
```bash
SCAN_SCHEDULE="0 */3 * * *" PROJECT=your-gcp-project ... bash deploy/deploy-to-gcp.sh
```
To wire it yourself (only if you deployed without the script):
```bash
PROJECT=your-gcp-project ; REGION=europe-west1
URL=$(gcloud run services describe gws-connector --region=$REGION --format='value(status.url)' --project=$PROJECT)
SA=gws-connector@$PROJECT.iam.gserviceaccount.com
gcloud services enable cloudscheduler.googleapis.com --project=$PROJECT
gcloud run services add-iam-policy-binding gws-connector --region=$REGION \
  --member="serviceAccount:$SA" --role=roles/run.invoker --project=$PROJECT
gcloud scheduler jobs create http gws-scan --location=$REGION --schedule="0 */6 * * *" \
  --uri="$URL/tasks/scan" --http-method=POST \
  --oidc-service-account-email=$SA --oidc-token-audience="$URL" \
  --headers=X-Scan-Token=YOUR_TOKEN --project=$PROJECT
```
The `X-Scan-Token` header (matched against `SCAN_TRIGGER_TOKEN`) is defense-in-depth on top of the
private-ingress requirement.

## Remediation automation level — `REMEDIATION_MODE` (manual / semi_auto / auto)
The customer chooses how exposures become action. **Default = `manual` (safest).**
| Mode | Behaviour |
|------|-----------|
| **manual** | Scan only flags users; an admin clicks each action in the UI (current default). |
| **semi_auto** | Scan flags; the UI shows a one-click **"Remediate (all enabled)"** button per user — human reviews, one click applies all the tenant's enabled actions. |
| **auto** | Scan **automatically** applies the `AUTO_ENABLED_ACTIONS` allow-list to each found user, gated. |

**Auto mode is guarded (default-SAFE)** — enforced server-side in `app/guardrails.py` before any destructive call:
- `AUTO_DRY_RUN=true` (default) → logs intended actions, executes NOTHING until you turn it off.
- `AUTO_ENABLED_ACTIONS` allow-list — only listed actions auto-run; **`suspend` is never auto** (`AUTO_HIGH_BLAST_ACTIONS`).
- operator (`ADMIN_SUBJECT`) + `AUTO_EXCLUDE_USERS` (VIP/break-glass) excluded; verified-domain scoped; idempotent (no re-action).
- `AUTO_MAX_USERS_PER_SCAN` blast-radius cap; `AUTO_KILL_SWITCH=true` halts everything.
- Recommended rollout: manual → semi_auto → auto-with-dry-run → auto. (v1.1 hardening: confirm-window,
  never-auto-on-first-scan baseline, rate-limit/cooldown, circuit-breaker, post-state verify, isAdmin auto-detect.)

## Alternative: one-click deploy FORM (Cloud Run button) — the Azure-ARM-parameters equivalent
`development/app/app.json` defines a deploy-time **form** that prompts for every setting above (the Azure
custom-deployment-screen equivalent). Add to a PUBLIC deploy repo's README:
```
[![Run on Google Cloud](https://deploy.cloud.run/button.svg)](https://deploy.cloud.run/?git_repo=https://github.com/ORG/REPO.git&dir=development/app)
```
⚠️ **Caveats (so it's honest):** the Cloud Run button (a) needs a **PUBLIC** repo (scrub secrets first —
`Skill("pre-public-leak-scan")`), (b) **cannot set a specific runtime SA or Secret Manager secrets** — it
stores the feed key as a **plain env var** and runs as the default compute SA. So the button is for a
**quick/demo** deploy; for a **production-secure** deploy (keyless DWD SA + feed key in Secret Manager) use
`deploy/deploy-to-gcp.sh`. `options.allow-unauthenticated` is `false` so the service is never public.

## Teardown (cost discipline)
```bash
PROJECT=your-gcp-project REGION=europe-west1 bash deploy/cleanup.sh
# return the project to $0 / billing off in one go:
PROJECT=your-gcp-project REGION=europe-west1 UNLINK_BILLING=1 bash deploy/cleanup.sh
```
`cleanup.sh` deletes the Cloud Run service, both scheduler jobs (`gws-scan` + `gws-verify-audit`), both
Secret Manager secrets (`socradar-feed-key` + `audit-hmac-key`), the `cloud-run-source-deploy` Artifact
Registry repo, and the Cloud Build staging buckets. With `UNLINK_BILLING=1` it also unlinks billing
(`billingEnabled:false`). Left in place on purpose: the runtime SA and the DWD authorization (zero-cost
IAM objects) and, if you used them, the Firestore database / BigQuery dataset (they may hold your audit
trail — the script prints the manual delete commands). Verify $0 afterwards:
```bash
gcloud billing projects describe your-gcp-project   # billingEnabled: false
gcloud run services list --project=your-gcp-project  # empty
gcloud secrets list --project=your-gcp-project       # empty
```

---

## Known limitations (v1) — honest
- **Durable state via Firestore (recommended for prod).** By default the app uses SQLite at `/tmp` which
  is per-instance and resets on restart/scale-to-zero (fine for a demo, NOT for audit history). For durable,
  cross-instance state set `STORAGE_BACKEND=firestore` — the deploy script enables the Firestore API, grants
  the runtime SA `roles/datastore.user`, and passes `STORAGE_BACKEND`/`PROJECT_ID`. One-time prerequisite —
  create a Native-mode Firestore database in the project:
  ```bash
  gcloud firestore databases create --location=europe-west1 --project=your-gcp-project
  STORAGE_BACKEND=firestore PROJECT=your-gcp-project ... bash deploy/deploy-to-gcp.sh
  ```
  (Same code, same ambient SA auth as DWD; the Firestore emulator tests it billing-free. For an efficient
  `/audit` view at scale, create the composite index `audit_log: tenant_id ASC, ts DESC` — the app falls
  back to a bounded full read until it exists.)
- **At-rest feed-key encryption (optional).** Set a stable `FERNET_KEY` (generate once with
  `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"`, store in
  Secret Manager, inject pinned: `gcloud run services update gws-connector --region=REGION
  --update-secrets=FERNET_KEY=app-fernet-key:1`). Then per-tenant feed keys are stored encrypted; unset =
  plaintext (backward-compat). ⚠️ Generate the key ONCE and never lose it — a changed key makes stored
  ciphertext undecryptable.
- **Automated scanning is available** via the headless `POST /tasks/scan` endpoint + Cloud Scheduler
  (see below). Manual "Run scan" in the UI also works. (Durable history still needs the Cloud SQL/
  Firestore fix above; until then each scan's results live only until the next restart.)
- **Admin UI access** requires `gcloud run services proxy` or IAP (service is private by design).
  A public login page (`--allow-unauthenticated` + the app's Google OAuth) is possible but needs an
  OAuth client + Internal consent screen configured in the customer project.
- Per-customer **single-tenant**: each customer runs their own instance (the multi-tenant code works
  but here it serves one tenant = themselves).

## Security model — native IAP (recommended for the admin UI)
`bash enable-iap.sh` puts **native Cloud Run IAP** in front of the private service (same `run.app` URL, no
load balancer, no cost). IAP authenticates the admin with Google at the edge and injects a signed
`X-Goog-IAP-JWT-Assertion`; the app **cryptographically verifies** it (`app/iap.py`: ES256 + issuer +
this service's audience + your `ALLOWED_DOMAIN`) and serves nothing without a valid one — a direct,
non-IAP caller cannot enter the UI. With IAP on, the app drops its own Google-OAuth sign-in (no OAuth
client needed for the UI).

- **Propagation wait.** IAP IAM grants take ~1 minute to take effect; opening the URL too early returns
  `You don't have access` (a 403). `enable-iap.sh` ends with a ~60s countdown for exactly this — let it
  finish, then open the printed URL.
- **Residual ingress (honest note).** The runtime SA still holds `run.invoker` (it is the scheduler's
  identity), so a parallel non-IAP path exists for it; that path can only reach `/tasks/scan`, which is
  separately gated by `SCAN_TRIGGER_TOKEN`. For a single locked ingress, migrate the scheduler to call
  through IAP (OIDC `aud` = the IAP OAuth client) and then revoke `run.invoker` from the runtime SA.
- **Scheduler note.** Periodic-scan jobs call with an OIDC token whose audience is the `run.app` URL,
  which IAP rejects. Until reconfigured, trigger scans from the UI (Dashboard → Run scan) or via
  `/tasks/scan` with the `SCAN_TRIGGER_TOKEN`.
- **Turn IAP off:** `gcloud run services update gws-connector --region=REGION --no-iap --update-env-vars IAP_MODE=false`.

## Verified gotchas (baked into the script)
- `--service-account` = what the service RUNS AS; `--no-allow-unauthenticated` = who can CALL it —
  orthogonal. The connector uses a dedicated runtime SA + private ingress.
- The runtime SA needs `roles/iam.serviceAccountTokenCreator` **on itself** for keyless self-signJwt.
- The runtime SA needs `roles/secretmanager.secretAccessor` on the feed-key secret **before** deploy
  (Cloud Run checks at deploy time).
- DWD console field is **comma**-delimited; the JWT `scope` claim at runtime is **space**-delimited
  (the app handles this — don't carry commas into code).
- `iamcredentials.googleapis.com` (not legacy `iam.googleapis.com`) is the signJwt API.
- Env-var secrets resolve at instance start — re-run the deploy after rotating the feed key.
- **Cloud Build needs a grant in new projects:** `--source` builds run as the default compute SA, which
  (since 2024) no longer auto-gets Editor → a `storage.objects.get` 403. The script grants it
  `roles/cloudbuild.builds.builder` (step [1b]). Verified live on a real deploy (EXP-GOOGLE-0017).
- **Ambient token = metadata-direct.** On Cloud Run the connector reads the SA token straight from the
  metadata server (urllib only). It does NOT use `google.auth.transport.requests` (that needs the
  `requests` package, absent on the image — it silently broke the first real deploy; EXP-GOOGLE-0017).
- **`SECRET_KEY` is regenerated on every deploy run.** Re-running the script (e.g. to rotate the feed
  key) changes the session cookie-signing key, so all open admin-UI sessions are invalidated and
  admins must sign in again. Acceptable for v1; to keep sessions stable across redeploys, store
  `SECRET_KEY` in Secret Manager once and inject it via `--set-secrets` instead of regenerating.
- **Before publishing the deploy package to a PUBLIC repo:** the dev copy of `development/app/.env`
  holds a real preprod feed key (gitignored AND gcloudignored, so it never ships) — still, scrub/rotate
  it and ship only `.env.example`. Run `Skill("pre-public-leak-scan")` before any public push.

## Alternative distribution paths (documented, not the default)
- **Terraform module** (`GoogleCloudPlatform/cloud-run/google//modules/v2`) for IaC customers.
- **"Deploy to Cloud Run" button** (`deploy.cloud.run`) — lowest friction BUT needs a PUBLIC repo and
  can't set a specific runtime SA or wire Secret Manager → only for a quick demo, not this production
  flow. (Community-maintained, not an official Google product.)
- **Google Cloud Marketplace** — weeks of partner onboarding + reviews; only for a paid GTM motion,
  and its "SaaS" type is vendor-hosted (not customer-self-deploy). Not used here.
