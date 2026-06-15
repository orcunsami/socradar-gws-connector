"""Auto-remediation guardrails — the safety gate before any AUTONOMOUS destructive action.

Default posture is SAFE: mode=manual, dry-run ON, suspend NEVER auto, tight blast cap, opt-in allow-list.
Verified against SOAR / auto-response guardrail guidance (blast-radius x confidence, kill switch, default-off,
per-action opt-in, dry-run, exclusions, caps, idempotency). The gate runs server-side, top-to-bottom, BEFORE
service.remediate executes — and remediate adds its OWN gates (verified-domain, operator-excluded, action
enabled per-tenant, lookup==found), so this is defense-in-depth, never the only check.

v1 implements the critical subset; confirm-window/baseline/circuit-breaker/post-state-verify are documented
v1.1 hardening (EXP-GOOGLE-0022). Code defaults are safe even if env is missing/garbage.
"""
from __future__ import annotations

from .config import settings

EXECUTE = "execute"   # all gates passed -> apply
DRYRUN = "dryrun"     # would execute, but dry-run on -> log only

# Hard floor: these NEVER auto-fire regardless of env config (defense-in-depth; an operator can't
# remove suspend from the high-blast set and silently auto-suspend). Account disablement = outage risk.
_HARD_HIGH_BLAST = {"suspend"}


def _skip(reason: str) -> str:
    return f"skip:{reason}"


def effective_mode() -> str:
    m = (settings.remediation_mode or "manual").strip().lower()
    return m if m in ("manual", "semi_auto", "auto") else "manual"


def decide(tenant, fu, action, run_ctx) -> str:
    """Decide whether to AUTO-apply `action` to flagged user `fu`. Returns EXECUTE | DRYRUN | 'skip:<reason>'.
    run_ctx = {"actioned": int} — a per-scan counter the caller increments on EXECUTE/DRYRUN (blast cap)."""
    if settings.auto_kill_switch:                                    # G0 kill switch (out-of-band-ish)
        return _skip("kill_switch")
    if action not in settings.auto_enabled_list:                    # G2 per-action opt-in allow-list
        return _skip("not_in_allowlist")
    if action in _HARD_HIGH_BLAST or action in settings.auto_high_blast_list:  # G3 high-blast never auto
        return _skip("high_blast_needs_human")
    # G3b: anything requiring two-person approval must NEVER auto-fire on zero humans (superset floor).
    if settings.require_approval and action in settings.approval_action_list:
        return _skip("approval_required")
    email = (fu.get("email") or "").strip().lower()
    # G6 operator excluded — MSSP: this tenant's OWN super-admin ('' -> global), not the global one,
    # so auto mode never signs out the admin we impersonate for THIS org (EXP-GOOGLE-0005).
    t_subject = (tenant["admin_subject"] if "admin_subject" in tenant.keys() else "") or settings.admin_subject
    if email == (t_subject or "").strip().lower():
        return _skip("operator_excluded")
    if email in settings.auto_exclude_list:                         # G6 VIP/break-glass excluded
        return _skip("user_excluded")
    if fu.get("status") == "remediated":                            # G11 idempotency
        return _skip("already_remediated")
    if run_ctx.get("actioned", 0) >= settings.auto_max_users_per_scan:  # G9 blast-radius cap
        return _skip("blast_cap")
    if settings.auto_dry_run:                                       # G4 dry-run
        return DRYRUN
    return EXECUTE
