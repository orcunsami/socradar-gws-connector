# SOCRadar Google Workspace Connector

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/orcunsami/socradar-gws-connector.git&cloudshell_workspace=.&cloudshell_tutorial=cloudshell-tutorial.md)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Automated remediation for **leaked employee credentials** detected by SOCRadar. It pulls Botnet, PII Exposure, and VIP Protection alerts, finds the matching accounts in your Google Workspace, and runs the response actions you choose (revoke sessions, suspend, reset password, and more). Every action is written to a tamper evident audit log. If you turn on alarm close-back, the originating SOCRadar alarm is resolved too (off by default).

You run it in your own Google Cloud project. SOCRadar hosts nothing. This is the same model as the Azure Sentinel deployment.

It works for a single organization and for an MSSP that manages several customer organizations from one deployment. See the MSSP section below.

## How it works

```
SOCRadar Platform (Botnet / PII / VIP)
        |
        v   on a schedule (configurable)
  Cloud Run service (Python, keyless DWD)
        |
   +----+----+
   |         |
 Google    Audit log
Workspace  (HMAC chain, off-box mirror)
   |
   +-- Actions: revoke session, reset password, suspend,
                turn off 2SV, revoke tokens / app passwords,
                add to / remove from quarantine group, restore
```

## Deploy

Two ways. Most customers use the button.

### Option 1: Open in Cloud Shell

Click the button at the top. Google Cloud Shell opens in your browser with this repository cloned and a step-by-step tutorial in the side panel. No local install. The tutorial walks you through setting your project, creating the sign-in OAuth client, and running the deploy.

The deploy (`deploy/deploy-to-gcp.sh`) enables the APIs, creates a least-privilege service account, self-binds keyless domain-wide delegation, stores the feed key and the audit key in Secret Manager, deploys a private Cloud Run service, and creates the periodic-scan scheduler job. At the end it prints the service account client id.

One manual step remains: your Workspace super admin authorizes that client id for the four directory scopes in `admin.google.com`, their own way.

### Option 2: One script (Secret Manager)

```bash
PROJECT=your-gcp-project \
REGION=europe-west1 \
ADMIN_SUBJECT=admin@your-domain.com \
DOMAIN=your-domain.com \
FEED_KEY_FILE=/path/to/feed-key.txt \
FEED_COMPANY_ID=your-company-id \
GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
bash deploy/deploy-to-gcp.sh
```

The script enables the APIs, creates a least privilege service account, stores the feed key and the audit key in Secret Manager, and deploys a private Cloud Run service. It also creates a scheduler job for periodic scanning and a daily audit check. At the end it prints the same `admin.google.com` authorization step.

When you are done, `deploy/cleanup.sh` removes every billable resource and returns the project to zero cost.

## Actions

Every action is off by default and enabled per tenant. High impact actions need a second admin to approve.

| Action | What it does |
|--------|--------------|
| Revoke sessions | Signs the user out of all sessions |
| Reset password | Forces a password change at next sign in |
| Suspend account | Disables the account |
| Restore account | Re-enables a suspended account |
| Turn off 2-Step Verification | De-enrolls the user's 2SV factors |
| Revoke OAuth tokens | Removes third party app grants |
| Revoke app passwords | Removes app specific passwords |
| Add to quarantine group | Moves the user into a restricted group |
| Remove from quarantine group | Reverses the quarantine |

## Security

Identity is keyless. The connector uses domain-wide delegation through `signJwt`, so there is no service account key file to store or leak. The Cloud Run service is private and requires authentication. Sign in is Google OAuth restricted to your domain. Destructive actions are limited to a remediation admin list, and the high impact ones need a second admin. Automatic remediation is off by default and ships with a dry run mode, a per scan blast cap, a kill switch, a rate limit, and a first scan baseline gate. The audit log is an HMAC hash chain held in Secret Manager, separate from the data store, re-checked daily.

Scopes are sensitive, not restricted. No Gmail or Drive access. Feed records are sanitized on ingest, so a leaked password is stored as a boolean, never as plaintext.

Full write up: `docs/security-hardening.md` and `docs/zero-trust-validation.md`.

## MSSP

One deployment can manage several customer Workspace organizations. One service account is authorized independently by each org, and the connector impersonates each org with its own super admin. A tenant created for org A acts only on org A. Cross org access is denied at the directory level. Each org sets its own super admin when its tenant is created. Leaving it blank uses the deployment default, which keeps a single org deploy unchanged. Onboarding steps for each org are in `docs/deploy-to-gcp-guide.md`.

## Configuration

The full deploy guide, including the from scratch setup, test, and teardown runbook and the MSSP onboarding steps, is in `docs/deploy-to-gcp-guide.md`.

## For developers

To run the connector on your own machine for development:

```bash
cd development/app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# set SECRET_KEY and FEED_API_KEY, then DEV_LOGIN=true for a quick demo
uvicorn app.main:app --reload --port 8080
```

Open http://localhost:8080 and sign in. A ready launcher is in `deploy/run-local.sh`. Scans need a working `gcloud auth login` locally; on Cloud Run the runtime service account provides the token.

## Status

Version 1.0.0. The connector loop, the remediation actions, the alarm close back, and the MSSP isolation are proven against live Google Workspace organizations. The managed Cloud Run deploy has been run end to end and torn down to zero cost.
