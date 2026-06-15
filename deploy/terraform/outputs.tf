output "service_url" {
  value       = google_cloud_run_v2_service.connector.uri
  description = "Private service URL. Open the admin UI via `gcloud run services proxy gws-connector` or IAP."
}

output "runtime_sa_email" {
  value = google_service_account.runtime.email
}

output "dwd_client_id" {
  value       = google_service_account.runtime.unique_id
  description = "Authorize THIS numeric Client ID in admin.google.com -> Domain-wide delegation. For service accounts, unique_id == oauth2ClientId (verified), so this is the correct DWD client id."
}

output "dwd_scopes" {
  value       = "https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.group.member"
  description = "Comma-delimited scopes to paste into the DWD authorization (all sensitive, no CASA)."
}
