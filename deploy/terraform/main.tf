# SOCRadar Google Workspace Connector — Deploy-to-GCP via Terraform (IaC path).
# Equivalent to deploy/deploy-to-gcp.sh, for customers who run Terraform.
# Requires a PREBUILT image (Terraform doesn't build from source — build+push first, or use the
# bash script which does --source). Steps verified against GCP primary docs (2026-06-05).

terraform {
  required_version = ">= 1.3"
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  apis = [
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "iamcredentials.googleapis.com", # signJwt (keyless DWD) — NOT legacy iam.googleapis.com
    "admin.googleapis.com",          # Admin SDK Directory (no standalone directory.googleapis.com)
    "cloudscheduler.googleapis.com", # scan-job.tf: Cloud Scheduler trigger for the scan Job
  ]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.apis)
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "runtime" {
  account_id   = "gws-connector"
  display_name = "GWS Connector runtime SA"
  depends_on   = [google_project_service.apis]
}

# Keyless DWD self-binding (load-bearing): the SA can signJwt as ITSELF (member == resource).
resource "google_service_account_iam_member" "self_token_creator" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_secret_manager_secret" "feed_key" {
  secret_id  = "socradar-feed-key"
  replication {
    auto {}
  } # Cloud Run has no regional secrets — global/auto required
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "feed_key_v1" {
  secret      = google_secret_manager_secret.feed_key.id
  secret_data = var.feed_api_key
}

# Runtime SA needs accessor BEFORE the service references the secret (Cloud Run checks at deploy).
resource "google_secret_manager_secret_iam_member" "accessor" {
  secret_id = google_secret_manager_secret.feed_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

# Tamper-evident audit HMAC key — off-box in Secret Manager (posture parity with the bash deploy).
resource "google_secret_manager_secret" "audit_hmac" {
  secret_id  = "audit-hmac-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "audit_hmac_v1" {
  secret      = google_secret_manager_secret.audit_hmac.id
  secret_data = var.audit_hmac_key
}

resource "google_secret_manager_secret_iam_member" "accessor_hmac" {
  secret_id = google_secret_manager_secret.audit_hmac.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

# Private Cloud Run SERVICE (interactive admin UI + connector). No allUsers invoker = private
# (auth required), the v2 equivalent of --no-allow-unauthenticated.
resource "google_cloud_run_v2_service" "connector" {
  name     = "gws-connector"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.runtime.email
    containers {
      image = var.image
      # HCL: a single-line block may hold only ONE argument; each env is multi-line (name + value).
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
        name  = "DB_PATH"
        value = "/tmp/app.sqlite3"
      }
      env {
        name  = "SECRET_KEY"
        value = var.secret_key
      }
      # env-var parity with deploy-to-gcp.sh (audit P2: both paths must produce the same revision config)
      env {
        name  = "STORAGE_BACKEND"
        value = var.storage_backend
      }
      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "AUTO_RATE_LIMIT_PER_HOUR"
        value = tostring(var.auto_rate_limit_per_hour)
      }
      env {
        name  = "ANALYTICS_BIGQUERY"
        value = tostring(var.analytics_bigquery)
      }
      env {
        name  = "BIGQUERY_LOCATION"
        value = var.region
      }
      env {
        name  = "CLOSE_SOCRADAR_ALARM"
        value = tostring(var.close_socradar_alarm)
      }
      # security posture parity with deploy-to-gcp.sh (audit P1: Terraform must NOT ship a weaker config)
      env {
        name  = "APP_ENV"
        value = "prod"
      }
      env {
        name  = "REQUIRE_APPROVAL"
        value = "true"
      }
      env {
        name  = "REMEDIATION_ADMINS"
        value = var.remediation_admins
      }
      env {
        name  = "GOOGLE_CLIENT_ID"
        value = var.google_client_id
      }
      env {
        name  = "GOOGLE_CLIENT_SECRET"
        value = var.google_client_secret
      }
      env {
        name  = "SCAN_TRIGGER_TOKEN"
        value = var.scan_trigger_token
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

    # SQLite is single-writer; pin to one instance so the audit chain / approvals / rate cap stay coherent
    # (parity with deploy-to-gcp.sh). Firestore is multi-instance safe.
    scaling {
      max_instance_count = var.storage_backend == "sqlite" ? 1 : var.max_instances
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.accessor,
    google_secret_manager_secret_iam_member.accessor_hmac,
    google_service_account_iam_member.self_token_creator,
  ]
}

# Optional: let a Cloud Scheduler SA invoke the private service (for automated /tasks/scan).
resource "google_cloud_run_v2_service_iam_member" "scheduler_invoker" {
  count    = var.scheduler_invoker_sa == "" ? 0 : 1
  name     = google_cloud_run_v2_service.connector.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.scheduler_invoker_sa}"
}
