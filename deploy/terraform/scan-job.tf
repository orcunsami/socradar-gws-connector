# Phase 2 (ADR-0001): the scan as a Cloud Run JOB — no request timeout, so a full multi-month feed
# backfill is paged end-to-end with NO truncation (the streaming engine checkpoints a page cursor + a
# per-tenant lease, so a SIGTERM/timeout/crash resumes on the next execution). Same image as the Service;
# the container command is overridden to `python -m app.job`. A Job runs across separate executions, so its
# state MUST be durable across instances -> STORAGE_BACKEND=firestore (sqlite/tmp would lose the checkpoint).
# Opt-in via enable_scan_job=true (the base service deploy is unaffected by default).

resource "google_cloud_run_v2_job" "scan" {
  count    = var.enable_scan_job ? 1 : 0
  name     = "gws-scan-job"
  location = var.region

  template {
    template {
      service_account = google_service_account.runtime.email
      timeout         = var.scan_job_timeout    # Cloud Run Jobs allow up to 7 days; default 6h
      max_retries     = var.scan_job_max_retries

      containers {
        image   = var.image
        command = ["python"]
        args    = ["-m", "app.job"]

        # HCL: a single-line block may hold only ONE argument, so each env is multi-line (name + value).
        env {
          name  = "SERVICE_ACCOUNT"
          value = google_service_account.runtime.email
        }
        env {
          name  = "ADMIN_SUBJECT"
          value = var.admin_subject
        }
        env {
          name  = "ALLOWED_DOMAIN"
          value = var.domain
        }
        env {
          name  = "DEFAULT_DOMAIN"
          value = var.domain
        }
        env {
          name  = "DEFAULT_CUSTOMER_ID"
          value = var.customer_id
        }
        env {
          name  = "FEED_BASE"
          value = var.feed_base
        }
        env {
          name  = "FEED_COMPANY_ID"
          value = var.feed_company_id
        }
        env {
          name  = "FEED_FULL_SCAN"
          value = "true"
        }
        env {
          name  = "FEED_OVERLAP_DAYS"
          value = tostring(var.feed_overlap_days)
        }
        env {
          name  = "SCAN_PAGES_PER_RUN"
          value = "0" # unbounded — a Job has no request timeout
        }
        env {
          name  = "SECRET_KEY"
          value = var.secret_key
        }
        env {
          name  = "APP_ENV"
          value = "prod"
        }
        env {
          name  = "STORAGE_BACKEND"
          value = "firestore" # durable across executions (NOT sqlite/tmp)
        }
        env {
          name  = "PROJECT_ID"
          value = var.project_id
        }
        env {
          name = "FEED_API_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.feed_key.secret_id
              version = "latest"
            }
          }
        }
        env {
          name = "AUDIT_HMAC_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.audit_hmac.secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.accessor,
    google_secret_manager_secret_iam_member.accessor_hmac,
    google_service_account_iam_member.self_token_creator,
  ]
}

# The runtime SA needs run.invoker on the Job so Cloud Scheduler can trigger it (jobs:run).
resource "google_cloud_run_v2_job_iam_member" "job_invoker" {
  count    = var.enable_scan_job ? 1 : 0
  name     = google_cloud_run_v2_job.scan[0].name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.runtime.email}"
}

# Cloud Scheduler -> run the Job periodically (Cloud Run Admin jobs:run, with the SA's OAuth token).
resource "google_cloud_scheduler_job" "scan_trigger" {
  count            = var.enable_scan_job ? 1 : 0
  name             = "gws-scan-job-trigger"
  region           = var.region
  schedule         = var.scan_schedule
  attempt_deadline = "180s"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.scan[0].name}:run"
    oauth_token {
      service_account_email = google_service_account.runtime.email
    }
  }

  depends_on = [google_project_service.apis, google_cloud_run_v2_job_iam_member.job_invoker]
}
