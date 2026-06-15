# Zero Trust for AI Agents — validation of the SOCRadar GWS connector

Validated 2026-06-07 against Anthropic's **"Zero Trust for AI Agents"** (36-page framework: Foundation /
Enterprise / Advanced tiers). Honest scorecard — what we MEET, what's PARTIAL, what's a GAP.

## Framing
Our connector is a **deterministic FastAPI service**, not an LLM agent — so the LLM-specific tiers
(prompt-injection, memory/RAG poisoning, constitutional classifiers, spotlighting) are mostly **N/A to its
data path** (no model interprets untrusted NL to choose actions). But it IS an **autonomous system with high
blast radius** (auto-remediation can suspend/lock Workspace accounts), so the identity / access / blast-radius
/ audit / response tiers apply FULLY — and that's where we're measured.

## Scorecard

| Capability (framework) | Tier reached | Evidence in our system |
|------------------------|--------------|------------------------|
| **Agent identity** | Foundation ✓ (→Ent partial) | Keyless DWD: cryptographically-rooted SA identity (signJwt, no SA key). Single instance. No X.509 client-cert to SOCRadar (Ent gap). |
| **Service authentication** | Foundation ✓ | Short-lived DWD access tokens minted per call, auto-refresh, **no creds in code**; SECRET_KEY/SCAN_TOKEN generated; feed key in Secret Manager. GAP: SOCRadar feed = static API key ("API key = known gap" per doc) — external constraint, mitigated by Secret Manager + rotation runbook. |
| **Permission model** | Foundation ✓ (RBAC deny-by-default) | `enabled_actions` default `[]`, `REMEDIATION_ADMINS` RBAC, verified-domain + operator exclusion. Partial ABAC (domain = a context attribute); no continuous authz (Adv). |
| **Privilege scoping** | Foundation ✓ (→Adv-ish) | **Per-action scope minting** — each remediate() mints a token for ONLY that action's scope, expires (JIT-like least-agency). 4 sensitive scopes, no Gmail/Drive. |
| **Resource boundaries** | Foundation ✓ (→Ent) | Cloud Run = gVisor-sandboxed container; private ingress (`--no-allow-unauthenticated`), dedicated least-priv runtime SA, IAP script. |
| **Action logging** | **Enterprise ✓** | audit_log (ts/actor/target/result/detail) + **HMAC tamper-evident hash-chain + seq + verify_audit_chain** + off-box mirror to Cloud Logging (stdout). Adv gap: real-time SIEM correlation. |
| **Traceability** | Foundation partial | scan_id links scan→flagged; audit ties actor→action→target + close-the-loop. No formal request-id propagated everywhere (Ent distributed tracing gap). |
| **Behavioral baseline** | Foundation ✓ (2026-06-07) | Rolling found-count baseline (median of last N scans); a spike (×factor, ≥min) is flagged. |
| **Anomaly detection** | Foundation ✓ (2026-06-07) | `service._scan_is_anomalous` → audits `anomaly_detected` AND **suppresses auto-remediation that scan** (a flood needs a human, not mass-action) + circuit-breaker rate halt. |
| **Automated response** | **Enterprise ✓** (our strength) | Auto-remediation IS automated containment (signout/suspend/...) WITH guardrails: dry-run, blast-cap, kill-switch, **two-person approval for high-blast** ("automate bookkeeping, not decisions" — humans on the destructive decisions). |
| **Input validation** | Foundation ✓ (for our surface) | Feed treated as untrusted: narrow extraction (email/alarmId only), `@`-check, verified-domain filter; form input CSRF + typed + action allow-list. Prompt-injection tier ~N/A (no LLM in path). |
| **Output filtering** | Foundation ✓ | No PII/secret echo: redaction, generic 500, feed key never logged. |
| **Config integrity** | Foundation partial | app.json/deploy in repo; Settings changes RBAC-gated + audited; container image immutable-ish. GAP: signed config/image is documented (supply-chain.md), not implemented. |
| **Recovery** | Foundation ✓ | Cloud Run revision rollback; cleanup.sh teardown; per-action idempotency; `partial` status. No auto-rollback-on-health-fail (Ent). |
| **AI governance** | Foundation partial | docs/security-hardening.md + EXP records + opt-in flags. Formal governance committee = customer org's job. |

## Implementation workflow (8 phases)
| Phase | Status |
|-------|--------|
| 1 Identify requirements | ✓ (discovery + recommendation.md) |
| 2 Supply chain | **PARTIAL** — supply-chain.md runbook (dep-pin/SBOM/trivy/cosign) DOCUMENTED, not yet executed; deps not hash-pinned |
| 3 Agent boundaries | ✓ STRONG — action allow-list, two-person escalation, verified-domain scope, blast-radius cap |
| 4 Defend prompt injection | ~N/A (no LLM in data path) + feed narrowly extracted |
| 5 Secure tool access | ✓ — the 8 Admin SDK actions: allow-listed, param-validated, sandboxed (Cloud Run), approval-escalated |
| 6 Protect credentials | ✓ Foundation — keyless short-lived DWD; static feed key = external gap; hardware-bound = Adv (not done) |
| 7 Safeguard memory | ~N/A (no LLM memory) + at-rest Fernet + tenant isolation; retention not formalized |
| 8 Measure what matters | ✓ (2026-06-07) — `app/metrics.py` + `/metrics` + `/metrics.json`: dwell p50/p95 (detection→remediation), coverage, success rate, scan freshness, audit-integrity, anomaly count |

## Defensive-ops (Part V) — "trust through verification for defensive agents"
We ARE defensive automation; the doc says apply ZT to the defensive agent itself. We do: limited blast radius
(cap), kill-switch, two-person on high-impact, tamper-evident audit, RBAC, fail-closed. "Automate bookkeeping
not decisions" ✓. GAP: MITRE ATT&CK coverage map + multi-incident tabletop (ops practice, not built).

## The doc's "impossible, not tedious" test applied to our controls
- **Capability-REMOVING (impossible) — strong:** DEV_LOGIN fail-closed, RBAC allowlist, two-person, suspend-HARD-never-auto, deny-by-default actions, keyless (no key to steal).
- **Throttling (tedious) — friction only:** blast-cap, circuit-breaker, rate-limit. The doc is explicit these
  "buy time but don't stop a determined agentic attacker" — so we treat them as defense-in-depth, NOT primary
  barriers. The primary barriers are the capability-removing controls above. ✓ aligned.

## Honest GAPS to close (prioritized)
1. ~~Measure-what-matters metrics~~ ✓ DONE 2026-06-07 (app/metrics.py + /metrics).
2. ~~Behavioral baseline + anomaly detection~~ ✓ DONE 2026-06-07 (anomaly spike → suppress auto + alert).
3. **Supply chain execution** — PARTIAL ✓ 2026-06-07: Dockerfile hardened (multi-stage, **non-root** uid 10001) + `.dockerignore` (no .env/keys/sqlite in image) + deps **exact-version pinned**. Remaining (CI): full hash-pinning (--require-hashes), SBOM, trivy gate, cosign signing — in deploy/supply-chain.md.
4. **Audit hardening** — MOSTLY ✓ 2026-06-07: HMAC key now from **Secret Manager** (off-box, deploy `--set-secrets AUDIT_HMAC_KEY=audit-hmac-key`) + **scheduled `/tasks/verify-audit`** endpoint (Cloud Scheduler, token-guarded, 502+alert on tamper). Remaining (Adv): KMS-bound key + WORM head-anchor + real-time SIEM.
5. **Post-state verification** ✓ 2026-06-07: `connector.verify_action_effect` re-reads directory after suspend/group actions → confirmed/failed/unverifiable; a 'failed' (action returned ok but state didn't change) downgrades the user to `partial`.
6. **Signed/attested config + image** — runbook (deploy/supply-chain.md), not yet executed.
7. **Independent human pentest** (still mandatory before production — AI review ≠ pentest).

## Verdict
Solidly **Foundation**, and **Enterprise on the high-leverage axes** (automated response + guardrails,
tamper-evident audit, RBAC, identity-based isolation, two-person, least-agency per-action scope, keyless
short-lived creds). The framework independently validates the architecture we converged on — and names the
exact gaps we'd already flagged (metrics, anomaly detection, supply-chain, pentest). No control we built
contradicts the framework; the remaining work is additive, not corrective.
