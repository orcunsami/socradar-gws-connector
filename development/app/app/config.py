"""Centralized settings — fully env-driven (defaults are neutral; the customer sets real values at deploy)."""
import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


def is_cloud_run() -> bool:
    """K_SERVICE / K_REVISION / K_CONFIGURATION are injected ONLY by the Cloud Run runtime —
    a reliable 'am I in production' signal that no app env var can forge."""
    return bool(os.environ.get("K_SERVICE") or os.environ.get("K_REVISION"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # web / session
    secret_key: str = "dev-insecure-change-me"
    dev_login: bool = False                      # local-only OAuth bypass; NEVER true in prod
    app_env: str = "dev"                          # "dev" | "prod" — dev_login only honored when dev + off-Cloud-Run
    session_max_age: int = 28800                  # session cookie lifetime in seconds (default 8h, was 14d)

    # RBAC: who may run DESTRUCTIVE remediation (vs. who may merely sign in / triage).
    # CSV of emails. Empty -> defaults to [admin_subject] (only the operator), the safe single-tenant default.
    remediation_admins: str = ""

    # Google OAuth (admin sign-in) — Internal user type. Set per customer (env / .env / deploy).
    google_client_id: str = ""
    google_client_secret: str = ""
    allowed_domain: str = ""                      # hd claim must match (the customer's Workspace domain)
    # Where Google returns the user after sign-in. We CANNOT derive this from the request: behind
    # `gcloud run services proxy` the request Host is the *.run.app URL (the proxy rewrites it), so
    # request.url_for would emit a run.app redirect that is not a registered/​reachable callback. Set this
    # to the URL the BROWSER actually uses — http://localhost:8080 for a local `gcloud run services proxy`,
    # or your IAP/real domain. It must match an Authorized redirect URI on the OAuth client. Empty -> fall
    # back to request.url_for (only correct when the app is reached directly, e.g. behind IAP on its real URL).
    oauth_redirect_base: str = "http://localhost:8080"

    # IAP mode: when the service is fronted by native Cloud Run IAP, IAP authenticates the user at the
    # edge and injects a signed X-Goog-IAP-JWT-Assertion. The app then trusts that VERIFIED identity and
    # does NOT run its own "Sign in with Google" OAuth (no app-side redirect -> no redirect_uri_mismatch).
    iap_mode: bool = False
    # Expected JWT audience for IAP verification: /projects/PROJECT_NUMBER/locations/REGION/services/SERVICE.
    # Set by deploy/setup-iap.sh. If empty, the signature + issuer are still verified but the audience is not.
    iap_audience: str = ""

    # connector identity (keyless DWD). On Cloud Run, auth is the ambient metadata token (gcloud_path unused).
    gcloud_path: str = "gcloud"                   # local-dev fallback only; resolved from PATH
    service_account: str = ""                     # the DWD-authorized runtime SA (set at deploy)
    admin_subject: str = ""                       # least-priv custom-role admin to impersonate (NOT super-admin) + remediation-excluded operator

    # default tenant bootstrap (set per customer at deploy)
    default_customer_id: str = "my_customer"      # Google's generic alias; or the immutable customerId
    default_domain: str = ""

    # SOCRadar feed seed (editable per-tenant in Settings)
    feed_base: str = "https://platform.socradar.com"
    feed_company_id: str = ""
    feed_api_key: str = ""
    feed_start_date: str = "2026-06-01"          # fixed fallback start date (used only if lookback_days=0)
    feed_lookback_days: int = 0                   # >0 = relative window: scan from (today - N days). 0 = fixed date.
    feed_page_limit: int = 100                    # records per feed page
    feed_max_pages: int = 50                      # legacy per-source page cap; only used when feed_full_scan=False
    # --- large-feed scan engine (ADR-0001) ---
    feed_full_scan: bool = True                   # True = page the WHOLE window (no 5,000 truncation), streaming + early-filter
    feed_overlap_days: int = 7                    # incremental: re-scan from (high_water - N days) so a boundary/backdated/late-ingested record is never missed (the feed's discovery-date can lag ingestion); idempotent upsert dedups the overlap, so a generous window is free correctness
    scan_pages_per_run: int = 0                   # self-continuation budget: max feed pages processed per scan invocation (0 = unbounded; for a Cloud Run Job. Set >0 on a request-bound Service)
    scan_lease_ttl: int = 1800                     # seconds; a 'running' scan whose heartbeat is older than this is a zombie (crash/SIGKILL) and is reclaimed+resumed. Generous so a slow page never false-reclaims a live scan (heartbeat is written every page)
    scan_max_stuck_resumes: int = 3                 # a mid-scan feed error keeps the checkpoint + resumes; after this many resumes that made ZERO progress (a permanent error e.g. bad key / feed down) the scan finalizes as error instead of looping forever
    feed_hard_page_cap: int = 100000                # absolute per-source page ceiling (~10M records) — a runaway-loop backstop if a feed never reports total_data_count and never returns an empty page

    # close-the-loop: after a Google remediation, resolve the originating SOCRadar alarm by alarm id
    # (Incident V4 /alarms/status/change — no operator email needed).
    close_socradar_alarm: bool = False           # opt-in: writes back into the customer's SOCRadar console

    # remediation automation level (default SAFE) — see app/guardrails.py for the enforced gates.
    remediation_mode: str = "manual"             # manual | semi_auto | auto
    auto_enabled_actions: str = ""               # CSV allow-list of actions auto/semi may apply (suspend excluded)
    auto_dry_run: bool = True                     # auto mode: log intended action, DO NOT execute (until turned off)
    auto_kill_switch: bool = False                # true halts ALL autonomous actions immediately
    auto_high_blast_actions: str = "suspend,disable_2sv"   # CSV actions that NEVER auto-fire (always need a human).
    # disable_2sv is here because on a LEAKED-PASSWORD account it can be a NET SECURITY DOWNGRADE (strips all 2nd
    # factors -> password-only unless 2SV is org-enforced). Only meaningful to remove an attacker-enrolled factor,
    # paired with reset_password + re-enforcement — never an autonomous routine action.
    auto_max_users_per_scan: int = 5             # blast-radius cap per scan per tenant
    auto_exclude_users: str = ""                 # CSV VIP/break-glass emails never auto-actioned
    auto_rate_limit_per_hour: int = 20           # circuit breaker: max auto actions/hour/tenant (0 = off)
    anomaly_baseline_scans: int = 5              # rolling window of prior scans for the found-count baseline
    anomaly_spike_factor: float = 3.0            # found_count > factor × median(baseline) → anomaly (0 = off)
    anomaly_min_count: int = 5                   # ignore spikes below this absolute count (noise floor)

    # two-person (four-eyes) approval for high-blast destructive actions
    require_approval: bool = False                # opt-in: high-blast actions need a second admin's approval
    approval_actions: str = "suspend,reset_password,disable_2sv"   # the destructive class requiring approval

    @property
    def approval_action_list(self) -> list[str]:
        return [a.strip() for a in self.approval_actions.split(",") if a.strip()]

    @property
    def auto_enabled_list(self) -> list[str]:
        return [a.strip() for a in self.auto_enabled_actions.split(",") if a.strip()]

    @property
    def auto_high_blast_list(self) -> list[str]:
        return [a.strip() for a in self.auto_high_blast_actions.split(",") if a.strip()]

    @property
    def auto_exclude_list(self) -> list[str]:
        return [e.strip().lower() for e in self.auto_exclude_users.split(",") if e.strip()]

    # optional shared-secret for the headless /tasks/scan trigger (defense-in-depth on top of
    # Cloud Run private ingress). If set, the scheduler must send header X-Scan-Token: <value>.
    scan_trigger_token: str = ""

    # storage backend: "sqlite" (local, ephemeral on Cloud Run /tmp) | "firestore" (durable, Cloud Run)
    storage_backend: str = "sqlite"
    db_path: str = "app_data.sqlite3"            # sqlite backend only
    project_id: str = ""                          # GCP project for firestore/bigquery; "" = ADC default

    # tamper-evident audit: HMAC key for the hash chain. MUST come from Secret Manager / KMS and live
    # OFF-BOX (not in the same DB/container as the audit rows) for real forgery resistance. Empty = the
    # chain is hash-only (tamper-EVIDENT vs an external verifier, but forgeable by a row-writer — weaker).
    audit_hmac_key: str = ""

    # at-rest encryption of the per-tenant feed key (Fernet). If set, feed keys are stored encrypted;
    # the KEK comes from Secret Manager on Cloud Run. If empty → plaintext (local dev / backward-compat).
    fernet_key: str = ""

    # analytics export to BigQuery (load jobs; sandbox-safe). Off by default.
    analytics_bigquery: bool = False
    bigquery_dataset: str = "socradar"
    bigquery_location: str = "US"                 # dataset location — set to the deploy REGION (data residency)

    @property
    def oauth_configured(self) -> bool:
        return bool(self.google_client_id and self.google_client_secret)

    @property
    def dev_login_active(self) -> bool:
        """DEV_LOGIN is HONORED only when explicitly dev AND not on Cloud Run — three independent
        conditions so no single env var enables the auth bypass."""
        return self.dev_login and self.app_env == "dev" and not is_cloud_run()

    @property
    def remediation_admin_list(self) -> list[str]:
        admins = [e.strip().lower() for e in self.remediation_admins.split(",") if e.strip()]
        return admins or [self.admin_subject.strip().lower()]   # safe default: only the operator


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


def assert_startup_safe() -> list[str]:
    """Fail-closed production guard — called once at startup. Raises on a catastrophic misconfig
    (auth bypass live in production); returns a list of non-fatal warnings to log."""
    warnings = []
    if settings.dev_login and is_cloud_run():
        # the single biggest risk: an env var turning the remediation tool into an unauthenticated console
        raise RuntimeError("FATAL: DEV_LOGIN=true on Cloud Run — auth bypass forbidden in production. "
                           "Unset DEV_LOGIN (and set APP_ENV=prod).")
    if is_cloud_run() and settings.secret_key == "dev-insecure-change-me":
        raise RuntimeError("FATAL: default SECRET_KEY on Cloud Run — set a real SECRET_KEY (session forgery risk).")
    # fail-CLOSED on a service nobody can sign into (DEV_LOGIN off in prod + no OAuth = a dead-end UI).
    # Better a loud startup failure the customer sees than a 'healthy' service no admin can enter.
    if is_cloud_run() and not settings.oauth_configured and not settings.dev_login and not settings.iap_mode:
        raise RuntimeError("FATAL: no sign-in method on Cloud Run — set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET "
                           "(create a Web OAuth client), OR front the service with native IAP and set IAP_MODE=true "
                           "(deploy/setup-iap.sh). Without a sign-in method the UI cannot be entered.")
    # IAP mode fail-closed: the audience binds an assertion to THIS service and ALLOWED_DOMAIN restricts who
    # may enter. Empty audience -> any validly-IAP-signed token (even one minted for a DIFFERENT resource)
    # would be accepted (confused-deputy). Empty domain -> any Google account IAP lets in could enter. Refuse
    # to start, mirroring the DEV_LOGIN / default-SECRET_KEY guards above. deploy/setup-iap.sh sets both.
    if settings.iap_mode:
        if not settings.iap_audience:
            raise RuntimeError("FATAL: IAP_MODE=true but IAP_AUDIENCE is empty — the audience binds the IAP "
                               "assertion to THIS Cloud Run service; without it a token minted for another IAP "
                               "resource would be accepted. Run deploy/setup-iap.sh (it sets IAP_AUDIENCE).")
        if not settings.allowed_domain:
            raise RuntimeError("FATAL: IAP_MODE=true but ALLOWED_DOMAIN is empty — no org restriction on who "
                               "may enter the admin UI. Set ALLOWED_DOMAIN (the deploy sets it from DOMAIN).")
    if settings.dev_login_active:
        warnings.append("DEV_LOGIN active (auth bypass) — local dev only; MUST be off in production.")
    if settings.oauth_configured and not settings.allowed_domain:
        # finish_login enforces the org domain on the signed-in user; with ALLOWED_DOMAIN empty there is
        # nothing to match, so EVERY OAuth sign-in 403s while the service still reports healthy. Surface it.
        warnings.append("OAuth is configured but ALLOWED_DOMAIN is empty — every sign-in will 403. "
                        "Set ALLOWED_DOMAIN to your Workspace domain.")
    return warnings
