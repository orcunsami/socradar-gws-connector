# Security Hardening — SOCRadar Google Workspace Connector

Defensive posture + the production-hardening roadmap. Researched against SOAR/auto-response guidance,
Google Cloud Run security best practice, OWASP, and the cloud-run-button schema (6-agent review, 2026-06-07).

## Threat model
The connector is a **powerful identity-remediation weapon**: anyone who can both *reach* it and *authenticate*
to it can suspend/lock/reset the company's Google Workspace accounts. The threat model therefore includes
**insiders** and a **compromised low-privilege identity** (privilege escalation / lateral movement), not just
the open internet. Hardening = abuse-resistance + integrity of authorization, on top of the already-strong
basic safety (keyless DWD, least-privilege scopes, default-off remediation guardrails).

## Already strong (baseline, do not remove)
- Private Cloud Run (`--no-allow-unauthenticated`) — platform rejects unauthenticated callers before the app.
- Google OAuth sign-in restricted to the org domain (`hd` claim).
- KEYLESS domain-wide delegation (signJwt + jwt-bearer) — **no SA JSON key to leak**.
- Only 4 **sensitive** Admin SDK scopes (no Gmail/Drive content) → no CASA.
- Remediation guardrails: per-tenant toggles default-off, `remediation_mode` default `manual`, auto dry-run
  default-on, **suspend HARD-never-auto**, per-user blast-radius cap, kill-switch, operator/VIP exclusion,
  idempotency, audit log.
- PII minimized to email + source + password_present + alarm ids. Feed key in Secret Manager (gcloud path).
- CSRF on state-changing routes; `SCAN_TRIGGER_TOKEN` on the headless `/tasks/scan`.

## ✅ DONE — P0 / quick-win batch (this round, tested: test_security_hardening 12/12)
| Control | What | Where |
|---------|------|-------|
| **DEV_LOGIN fail-closed** | App **refuses to start** if `DEV_LOGIN=true` on Cloud Run (K_SERVICE signal). `dev_login_active` honored only when `DEV_LOGIN=true AND APP_ENV=dev AND not Cloud Run` — three independent conditions. Deploy sets `APP_ENV=prod`. | `config.assert_startup_safe` / `dev_login_active`, `auth.start_login`, deploy env |
| **SECRET_KEY guard** | Refuse to start on Cloud Run if the default session key was left unchanged (session-forgery prevention). | `config.assert_startup_safe` |
| **RBAC** | "Can sign in / triage" ≠ "authorized to run destructive remediation". `REMEDIATION_ADMINS` allowlist (default = operator only) enforced server-side on `/flagged/{id}/remediate` + `/flagged/{id}/auto-remediate` (and `/settings`, `/tenants`); blocked attempts audited. | `auth.is_remediation_admin`, `main.py` routes |
| **Session cookie hardening** | `SameSite=strict`, `HttpOnly`, `https_only` on Cloud Run, bounded `max_age` (8h, was 14d default). | `main.py` SessionMiddleware |
| **No detail leak** | Generic 500 handler — no stack trace / internal detail (could carry secrets/PII) to the client. | `main.py` exception handler |
| **Startup transparency** | Logs env / cloud_run / oauth / dev_login_active / mode / feed-key-present at boot. | `main.py` `_startup` |
| **Dedicated least-priv runtime SA** | Deploy uses `--service-account` (never the Editor-carrying default compute SA); SA gets only tokenCreator(self) + secretAccessor(one secret) + storage role if selected. | `deploy/deploy-to-gcp.sh` |
| **Feed key via Secret Manager** | gcloud deploy uses `--set-secrets`; the one-click button is labeled DEV/EVAL-ONLY (plaintext-env limitation). | deploy script, app.json, deploy guide |

## ✅ DONE — heavier P0 (this round, tested)
| Control | What | Test |
|---------|------|------|
| **Two-person approval** | Four-eyes for high-blast actions (suspend/reset_password/disable_2sv): one admin's click QUEUES a pending approval; a DIFFERENT remediation-admin must approve before execution (requester != approver enforced; non-admin blocked; reject path). New `approvals` table (both backends), `/approvals` UI, opt-in `REQUIRE_APPROVAL` (prod deploy defaults ON). | test_two_person 11/11 |
| **Tamper-evident audit** | Per-tenant **hash-chain** (`entry_hash = sha256(prev_hash + canonical(entry))`) in the db facade (both backends) + every row **mirrored off-box to Cloud Logging**. `verify_audit_chain()` detects any edit/delete. (Remaining infra: enable Cloud Audit Logs Data Access for IAM Credentials + Cloud Run + a WORM export bucket — see below.) | test_baseline_audit (tamper detected) |
| **Never-auto-on-first-scan baseline** | First auto-eligible scan only ESTABLISHES the baseline (`tenant.auto_baseline_at`); only findings first-seen AT/AFTER baseline are auto-eligible — the historical backlog is never mass-auto-remediated. | test_baseline_audit |
| **Rate-limit / circuit-breaker** | `AUTO_RATE_LIMIT_PER_HOUR` — if the hourly auto-action count is hit, the breaker trips and HALTS the run (audited `circuit_breaker tripped`). | test (covered by guardrails/baseline harness) |
| **IAP + ingress** | Scripted: `deploy/setup-iap.sh` (enable IAP on the service + `--ingress=internal-and-cloud-load-balancing` + grant operators iap.httpsResourceAccessor). Caveat documented: IAP replaces caller identity → the Scheduler `/tasks/scan` path needs its own OIDC or stays on the token-guarded route. (Infra — run at deploy.) |

## P1 (recommended)
SECRET_KEY from Secret Manager + rotation · Fernet KEK → Cloud KMS (or drop Fernet once key in SM) ·
redacting log filter (structural, with a test) · VPC egress lockdown (allowlist Google APIs + SOCRadar host) ·
rate-limit + auto-tripping circuit breaker on remediation rate · confirm-window/staged execution ·
post-state verification (re-read directory after each action) · kill-switch fail-safe + asymmetric (OFF = high-blast) ·
pinned+hashed deps + SBOM · container vuln scan gate · no-secrets-in-image CI proof · **release signing (cosign/SLSA)** ·
distroless/non-root base · feed-key rotation runbook · audit-log treated as PII (retention, IAM-restricted read).

## P2 (nice-to-have)
Step-up re-auth for the most destructive actions · bind app session to IAP identity · Binary Authorization ·
VPC Service Controls · reproducible build (SLSA L3) · CMEK + region pinning + crypto-shred · allow-list serializer
on the SOCRadar write-back (alarm id + status only).

## Honest caveats
- IAP replaces caller identity → can break the Scheduler path (give it OIDC or a separate identity).
- VPC-SC protects Google API access but does NOT block exfil to a non-Google host (SOCRadar) — the egress
  firewall does that; they are complementary.
- VPC-SC service scope: `iamcredentials.googleapis.com` IS a VPC-SC-supported service (keep it in-perimeter
  for `signJwt`); `admin.googleapis.com` (Admin SDK) is **NOT** — route it via `private.googleapis.com`, not a
  blanket `restricted.googleapis.com` rule, which silently blocks directory calls.
- DWD / service-account actions have **no originating caller IP** in the Workspace admin audit log (the IP
  field is empty). SIEM correlation must key on actor + event + the connector's own app logs, not on caller IP.
- Starlette **signs** but does not **encrypt** the session → never put secrets in the session payload.
- App-layer Fernet with an env-sourced KEK adds near-zero protection (ciphertext + key share one trust boundary).
- The one-click Cloud Run button cannot set a runtime SA or Secret Manager secrets → it is DEV/EVAL-ONLY;
  production = `deploy/deploy-to-gcp.sh`.
- All reviews so far are AI-adversarial; an **independent human pentest / dev-cyber-sec-check** is still
  required before a production customer.
