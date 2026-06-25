# Cloud Run Deploy Runbook — GWS Connector PoC

> ⚠️ **SUPERSEDED (2026-06-06).** This is the early JOB-shape PoC runbook. The real, proven path is the
> SERVICE-shape **Deploy-to-GCP** package: `deploy/deploy-to-gcp.sh` + `deploy/terraform/` +
> `docs/deploy-to-gcp-guide.md`. The managed deploy was run E2E and proven (`/tasks/scan` found=3), then
> torn down to $0 (EXP-GOOGLE-0017, TASK-0003). Use the guide, not this file. Kept for history.
>
> ~~Status: NOT deployed. Project `YOUR_PROJECT_ID` has billing OFF.~~ (no longer true — deploy proven + torn down)

## Shape
Periodic feed-poller → **Cloud Run JOB** (runs, exits) + **Cloud Scheduler** trigger.
NOT an always-on Service. Job runs the same `gws_connector_poc.py real-feed ...`.

## Auth model on Cloud Run
- Runtime identity = the DWD service account `SA_NAME@YOUR_PROJECT_ID.iam.gserviceaccount.com`.
- It self-signs the DWD JWT via IAM `signJwt`, so it needs `roles/iam.serviceAccountTokenCreator` **on itself**.
- No `BOOTSTRAP_TOKEN` env on Cloud Run — `google.auth.default()` picks up the metadata-server token. (Local docker passes `BOOTSTRAP_TOKEN`.)
- DWD (domain-wide delegation) client + 3 scopes already configured in admin.google.com.

## Steps (gated on billing + greenlight)
```bash
GC=~/google-cloud-sdk/bin/gcloud
PROJECT=your-gcp-project
SA=your-sa-name@$PROJECT.iam.gserviceaccount.com
REGION=europe-west1

# 1. Enable billing (CONSCIOUS DECISION — Azure 5587 TL lesson; this job is free-tier-cheap but billing acct must exist)
$GC billing projects link $PROJECT --billing-account=<BILLING_ACCOUNT_ID>

# 2. Enable APIs
$GC services enable run.googleapis.com artifactregistry.googleapis.com \
   cloudscheduler.googleapis.com secretmanager.googleapis.com

# 3. Runtime SA can self-signJwt (DWD)
$GC iam service-accounts add-iam-policy-binding $SA \
   --member="serviceAccount:$SA" --role="roles/iam.serviceAccountTokenCreator"

# 4. Feed key -> Secret Manager (NOT a plaintext arg)
printf '%s' '<SOCRADAR_API_KEY>' | $GC secrets create socradar-feed-key --data-file=- --project=$PROJECT
$GC secrets add-iam-policy-binding socradar-feed-key \
   --member="serviceAccount:$SA" --role="roles/secretmanager.secretAccessor"

# 5. Build + push image to Artifact Registry
$GC artifacts repositories create gws --repository-format=docker --location=$REGION
$GC auth configure-docker $REGION-docker.pkg.dev
IMG=$REGION-docker.pkg.dev/$PROJECT/gws/gws-connector:poc
docker tag gws-connector:poc $IMG && docker push $IMG

# 6. Deploy as a JOB (reads feed key from secret; refactor poc to read env SOCRADAR_KEY before this)
$GC run jobs deploy gws-connector --image=$IMG --region=$REGION \
   --service-account=$SA \
   --set-secrets=SOCRADAR_KEY=socradar-feed-key:latest \
   --args=real-feed,132,2026-06-01,https://platform.socradar.com

# 7. Schedule a 30-min tick (per-tenant Auto-scan interval gates which scans actually run)
$GC scheduler jobs create http gws-poller --location=$REGION --schedule="*/30 * * * *" \
   --uri="https://$REGION-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/$PROJECT/jobs/gws-connector:run" \
   --http-method=POST --oauth-service-account-email=$SA

# 8. Manual run / verify
$GC run jobs execute gws-connector --region=$REGION
```

## Before deploy: small code change needed
`real-feed` currently takes the key as argv. For Cloud Run, read it from env `SOCRADAR_KEY`
(injected by `--set-secrets`) so the key never appears in job args/logs.

## Cleanup (cost discipline)
```bash
$GC run jobs delete gws-connector --region=$REGION
$GC scheduler jobs delete gws-poller --location=$REGION
$GC secrets delete socradar-feed-key
$GC billing projects unlink $PROJECT     # back to $0
```
