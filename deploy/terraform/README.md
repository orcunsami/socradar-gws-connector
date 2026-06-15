# Deploy-to-GCP via Terraform (IaC path)

Same outcome as `../deploy-to-gcp.sh`, for customers who manage infra with Terraform. Deploys the
connector into the customer's own GCP project as a private Cloud Run service with a keyless runtime SA.

> Terraform requires a **prebuilt image** (it does not build from source). Either build+push the image
> first, or use `../deploy-to-gcp.sh` (which builds from source via Cloud Build). All other steps
> (APIs, keyless self-tokenCreator, secret + accessor, private service) are handled here.

## Use
```bash
cd deploy/terraform
export TF_VAR_feed_api_key='YOUR_SOCRADAR_FEED_API_KEY'
export TF_VAR_secret_key="$(openssl rand -base64 32)"

terraform init
terraform apply \
  -var project_id=your-gcp-project \
  -var region=europe-west1 \
  -var image=europe-west1-docker.pkg.dev/your-gcp-project/gws/gws-connector:TAG \
  -var admin_subject=admin@yourdomain.com \
  -var domain=yourdomain.com \
  -var customer_id=my_customer \
  -var feed_company_id=132
```

## After apply — the one manual step (Workspace super admin)
```bash
terraform output dwd_client_id   # the numeric Client ID to authorize
terraform output dwd_scopes      # the comma-delimited scopes
```
In `admin.google.com` → Security → Access and data control → API controls → Domain-wide delegation →
Add new: paste the Client ID + scopes → Authorize. (For service accounts `unique_id == oauth2ClientId`,
verified — this output is the correct DWD client id.)

## Access the admin UI (private service)
```bash
gcloud run services proxy gws-connector --region=europe-west1 --project=your-gcp-project
```
(or put Identity-Aware Proxy in front.)

## Teardown
```bash
terraform destroy   # removes the service, secret, SA, IAM bindings
```

## Notes
- `feed_api_key` and `secret_key` are `sensitive`; pass via `TF_VAR_*` env, never commit `terraform.tfvars` with real values.
- Pin the provider/module versions in production.
- Same v1 limitations as the script path: ephemeral SQLite on /tmp, single-tenant. See `../../docs/deploy-to-gcp-guide.md`.
- **State hygiene:** `terraform.tfstate` stores `feed_api_key` + `secret_key` in PLAINTEXT (a `.gitignore`
  guards them — never commit state). For automated scanning, wire Cloud Scheduler → `/tasks/scan` (set
  `scheduler_invoker_sa`).
- **v1.1:** `SECRET_KEY` is currently a plaintext env var (so it persists in state, unlike the bash path
  which regenerates it). Move it to Secret Manager + `value_source.secret_key_ref` like `FEED_API_KEY`.
