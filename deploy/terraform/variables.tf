variable "project_id" {
  type        = string
  description = "The customer's GCP project id (where the connector runs)."
}

variable "region" {
  type        = string
  default     = "europe-west1"
}

variable "image" {
  type        = string
  description = "Prebuilt container image URL, e.g. REGION-docker.pkg.dev/PROJECT/REPO/gws-connector:TAG. Terraform does not build from source — build+push first, or use deploy/deploy-to-gcp.sh (which uses --source)."
}

variable "admin_subject" {
  type        = string
  description = "A real Workspace super-admin email to impersonate via domain-wide delegation."
}

variable "domain" {
  type        = string
  description = "The customer Workspace primary domain (used as the verified domain + login restriction)."
}

variable "customer_id" {
  type    = string
  default = "my_customer"
}

variable "feed_api_key" {
  type        = string
  sensitive   = true
  description = "SOCRadar feed API key (stored in Secret Manager). Pass via TF_VAR_feed_api_key, never commit."
}

variable "feed_base" {
  type    = string
  default = "https://platform.socradar.com"
}

variable "feed_company_id" {
  type        = string
  description = "SOCRadar company id for the feed."
}

variable "secret_key" {
  type        = string
  sensitive   = true
  description = "Random session cookie-signing key. Generate one (e.g. openssl rand -base64 32)."
}

variable "scheduler_invoker_sa" {
  type        = string
  default     = ""
  description = "Optional: a Cloud Scheduler service account email to grant run.invoker (for automated /tasks/scan). Leave empty to skip."
}

variable "remediation_admins" {
  type        = string
  default     = ""
  description = "Comma-separated emails authorized to run destructive remediation (RBAC). Empty = ADMIN_SUBJECT only."
}

variable "google_client_id" {
  type        = string
  default     = ""
  description = "Web OAuth client id for admin sign-in. REQUIRED — without it the service fail-closes (no sign-in)."
}

variable "google_client_secret" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Web OAuth client secret for admin sign-in."
}

variable "scan_trigger_token" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Shared secret for the headless /tasks/scan + /tasks/verify-audit scheduler triggers."
}

variable "audit_hmac_key" {
  type        = string
  sensitive   = true
  description = "HMAC key for the tamper-evident audit chain (off-box in Secret Manager). Generate a random one."
}

variable "storage_backend" {
  type        = string
  default     = "sqlite"
  description = "sqlite (per-instance, pinned to 1 instance) or firestore (durable, multi-instance)."
}

variable "auto_rate_limit_per_hour" {
  type        = number
  default     = 20
  description = "Circuit breaker: max auto remediation actions per hour per tenant (0 = off)."
}

variable "analytics_bigquery" {
  type        = bool
  default     = false
  description = "Enable the optional best-effort BigQuery analytics export."
}

variable "close_socradar_alarm" {
  type        = bool
  default     = false
  description = "After a successful remediation, resolve the originating SOCRadar alarm (Incident V4)."
}

variable "max_instances" {
  type        = number
  default     = 4
  description = "Cloud Run max instances when STORAGE_BACKEND=firestore. sqlite is always pinned to 1."
}

# --- Phase 2 (ADR-0001): scan as a Cloud Run Job (scan-job.tf) ---
variable "enable_scan_job" {
  type        = bool
  default     = false
  description = "Deploy the scan as a Cloud Run JOB + Cloud Scheduler trigger (no request timeout, full backfill). Forces STORAGE_BACKEND=firestore for the job (durable across executions)."
}

variable "scan_job_timeout" {
  type        = string
  default     = "21600s" # 6h; Cloud Run Jobs allow up to 7 days (604800s)
  description = "Per-execution timeout for the scan Job. A SIGTERM/timeout resumes via the page cursor + lease."
}

variable "scan_job_max_retries" {
  type        = number
  default     = 3
  description = "Cloud Run Job max retries — a retried execution resumes the scan from its checkpoint."
}

variable "feed_overlap_days" {
  type        = number
  default     = 7
  description = "Incremental re-scan overlap: start each scan from (high_water - N days) so a backdated/late-ingested feed record is never missed (idempotent upsert dedups the overlap)."
}

variable "scan_schedule" {
  type        = string
  default     = "*/30 * * * *"
  description = "Cron tick for the scan Job trigger (Cloud Scheduler); the per-tenant Auto-scan interval gates which scans actually run."
}
