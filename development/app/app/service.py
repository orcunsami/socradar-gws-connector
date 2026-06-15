"""
Service layer — orchestrates the connector against a tenant and persists results.

Enforces the safety invariants at the application boundary:
  - verified-domain filter before any directory call (EXP-GOOGLE-0003)
  - admin/operator subject excluded from remediation (EXP-GOOGLE-0005)
  - remediation action must be enabled (per-tenant toggle) AND user must be found
"""
from __future__ import annotations

import datetime
import json
import time

from . import analytics, connector, db, guardrails
from .config import settings


def _tenant_domains(tenant) -> list[str]:
    return json.loads(tenant["verified_domains"])


def _tenant_subject(tenant) -> str:
    """MSSP: the org's own super-admin to impersonate. '' / missing -> the global config admin_subject
    (single-org default). Cross-backend safe: tenant may be a sqlite Row or a firestore dict."""
    v = tenant["admin_subject"] if "admin_subject" in tenant.keys() else ""
    return v or settings.admin_subject


def _tenant_sa(tenant) -> str:
    """MSSP: the per-org DWD service account override. '' / missing -> the shared global SA."""
    v = tenant["service_account"] if "service_account" in tenant.keys() else ""
    return v or settings.service_account


def _enabled_actions(tenant) -> list[str]:
    return json.loads(tenant["enabled_actions"])


def _effective_start_date(tenant) -> str:
    """Feed window. feed_lookback_days > 0 → relative 'look back N days' (today - N), the customer-set
    1-week / 1-month window. 0 → the tenant's fixed feed_start_date. Keep N bounded (EXP-GOOGLE-0009:
    a wide window pulls a lot of real PII)."""
    days = settings.feed_lookback_days
    if days and days > 0:
        return (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
    return tenant["feed_start_date"]


def _scan_is_anomalous(tenant, found_count) -> bool:
    """Behavioral baseline: compare this scan's found_count to the rolling median of prior scans.
    A sudden spike (e.g. feed poisoning, a too-wide window, a mass-exposure event) is flagged and
    SUPPRESSES auto-remediation for this scan — a flood of 'new' findings must get a human, not mass-action."""
    factor = settings.anomaly_spike_factor
    if not factor or found_count < settings.anomaly_min_count:
        return False
    prior = [s.get("found_count", 0) for s in db.recent_scans(tenant["id"], settings.anomaly_baseline_scans + 1)]
    prior = prior[1:] if prior else []   # drop the just-finished scan (newest)
    if len(prior) < 2:                   # not enough history to judge a baseline yet
        return False
    s = sorted(prior)
    median = s[len(s) // 2] or 0
    return median > 0 and found_count > factor * median


def _close_socradar_alarm(tenant, fu, actor):
    """Resolve the originating SOCRadar alarm(s) by alarm id after a successful Google remediation —
    close the loop (Incident V4, no operator email). Fully best-effort + DECOUPLED: a SOCRadar write-back
    failure here NEVER affects the already-successful Google remediation. Opt-in (close_socradar_alarm)."""
    if not settings.close_socradar_alarm:
        return
    try:
        alarm_ids = json.loads(fu.get("socradar_refs") or "[]")
        if not alarm_ids:
            return
        res = connector.socradar_close_alarms(
            tenant["feed_base"], tenant["feed_company_id"], tenant["feed_api_key"], alarm_ids)
        db.set_close_status(fu["id"], json.dumps(res))
        db.audit(tenant["id"], actor, "socradar_close", "ok" if res.get("ok") else "fail",
                 fu["email"], (res.get("message") or "")[:200])
    except Exception:   # best-effort: never break the remediation on a write-back issue
        pass


def run_scan(tenant, actor: str) -> dict:
    """Fetch feed -> filter by verified domains -> lookup each -> persist. No remediation here."""
    now = time.time()
    scan_id = db.start_scan(tenant["id"], now)
    events = []
    found_ids = []
    try:
        by_email, totals, alarms_by_email, coverage = connector.fetch_all_sources(
            tenant["feed_base"], tenant["feed_company_id"], tenant["feed_api_key"], _effective_start_date(tenant))
        domains = _tenant_domains(tenant)
        in_scope = {e: s for e, s in by_email.items() if connector.in_verified_domains(e, domains)}

        token = connector.get_dwd_token([connector.SCOPE_READONLY],
                                        subject=_tenant_subject(tenant), service_account=_tenant_sa(tenant)) if in_scope else None
        found, denied = 0, 0
        for email, sources in sorted(in_scope.items()):
            status = connector.lookup_user(email, token)
            fid = db.upsert_flagged(tenant["id"], email, sources, status, now, alarms_by_email.get(email))
            if analytics.enabled():
                events.append(analytics.event("flagged", status, email=email,
                              source=",".join(sorted(sources)), tenant_id=tenant["id"], actor=actor))
            if status == "found":
                found += 1
                found_ids.append(fid)
            elif status == "permission_denied":
                denied += 1

        truncated = {s: c for s, c in coverage.items() if c.get("truncated")}
        db.finish_scan(scan_id, time.time(), totals=totals, found=found, unique=len(by_email))
        db.audit(tenant["id"], actor, "scan", "ok",
                 detail=f"totals={totals} processed={ {s: c['processed'] for s, c in coverage.items()} } "
                        f"in_scope={len(in_scope)} found={found}" + (f" TRUNCATED={list(truncated)}" if truncated else ""))
        if truncated:   # NEVER claim coverage we didn't achieve
            db.audit(tenant["id"], actor, "feed_truncated", "alert",
                     detail=f"hit feed_max_pages — only processed part of: {truncated}; raise FEED_MAX_PAGES / narrow the window")
        # all in-scope lookups 403 → DWD almost certainly not authorized yet (day-1 state) — make it actionable
        if in_scope and denied == len(in_scope):
            db.audit(tenant["id"], actor, "scan", "warning",
                     detail="ALL lookups returned 403 — domain-wide delegation likely not authorized yet "
                            "(authorize the Client ID + 4 scopes in admin.google.com; propagation up to 24h)")
        result = {"ok": True, "totals": totals, "coverage": coverage, "truncated": bool(truncated),
                  "unique": len(by_email), "in_scope": len(in_scope), "found": found,
                  "denied": denied, "skipped_foreign": len(by_email) - len(in_scope)}
    except connector.ConnectorError as e:
        db.finish_scan(scan_id, time.time(), error=str(e))
        db.audit(tenant["id"], actor, "scan", "error", detail=str(e))
        result = {"ok": False, "error": str(e)}
    except Exception as e:   # ANY other error -> finish the scan row (never a permanent zombie) + 500-safe
        db.finish_scan(scan_id, time.time(), error=f"unexpected: {type(e).__name__}: {e}")
        try:
            db.audit(tenant["id"], actor, "scan", "error", detail=f"unexpected {type(e).__name__}")
        except Exception:
            pass
        result = {"ok": False, "error": "scan failed unexpectedly"}
    analytics.write_events(events)   # strictly OUTSIDE the core try — best-effort, can never break the scan
    # behavioral anomaly check: a spike vs the rolling baseline suppresses auto-remediation this scan
    anomalous = False
    if result.get("ok"):
        try:
            anomalous = _scan_is_anomalous(tenant, result.get("found", 0))
            if anomalous:
                db.audit(tenant["id"], actor, "anomaly_detected", "alert", detail=(
                    f"found={result.get('found')} spikes vs baseline (×{settings.anomaly_spike_factor}) — "
                    "auto-remediation SUPPRESSED this scan; needs human review"))
                result["anomaly"] = True
        except Exception:
            pass
    # AUTO mode: gated, best-effort autonomous remediation of this scan's found users.
    # manual/semi_auto do NOTHING here (semi_auto is a human one-click in the UI).
    # MSSP safety (R2): the auto-mode policy (mode/kill-switch/exclusions/rate-limit) is GLOBAL/fleet-wide.
    # One global policy must NOT auto-act across multiple customer orgs (their risk appetites differ). Until
    # per-tenant policy exists, auto is force-disabled whenever more than one tenant is configured — every
    # exposure then waits for a human. Single-org deploys are unaffected.
    auto_ok = guardrails.effective_mode() == "auto" and len(db.list_tenants()) <= 1
    if result.get("ok") and not anomalous and auto_ok and found_ids:
        try:
            baseline = tenant.get("auto_baseline_at", 0) or 0
            if not baseline:
                # never-auto-on-first-scan: the first auto-eligible scan only ESTABLISHES the baseline
                # (the whole historical backlog is "new" — auto-remediating it en masse is catastrophic).
                db.update_tenant(tenant["id"], auto_baseline_at=now)
                db.audit(tenant["id"], "auto", "baseline_established", "ok",
                         detail="first auto scan — baseline set; auto-remediation begins on the NEXT scan")
            else:
                _auto_remediate(tenant, found_ids, "auto", baseline)
        except Exception as e:   # best-effort: auto-remediation must never break the scan result
            try:
                db.audit(tenant["id"], "auto", "auto_aborted", "error", detail=str(e)[:200])
            except Exception:
                pass
    return result


def remediate(tenant, flagged_id, action: str, actor: str, approved: bool = False) -> dict:
    """Gated remediation on one flagged user (id is opaque: sqlite int / firestore str). Returns {ok, error?}.
    `approved=True` means a second-admin four-eyes approval already happened — ONLY the approval path sets it.
    The two-person gate lives HERE (single chokepoint) so EVERY caller (manual route, semi-auto one-click,
    auto mode) inherits it — no path can run a high-blast action without approval."""
    # MSSP ownership chokepoint — str()-coerced to match get_flagged_for_tenant (uniform across backends:
    # sqlite int id vs firestore str customer_id). Distinct ids never compare equal; mismatch fails safe.
    fu = db.get_flagged(flagged_id)
    if not fu or str(fu["tenant_id"]) != str(tenant["id"]):
        return {"ok": False, "error": "flagged user not found"}
    email = fu["email"]

    # --- gates ---
    if action not in connector.ACTIONS:
        return {"ok": False, "error": f"unknown action {action}"}
    if action not in _enabled_actions(tenant):
        db.audit(tenant["id"], actor, f"remediate:{action}", "blocked", email, "action not enabled")
        return {"ok": False, "error": "action not enabled for this tenant (enable it in Settings)"}
    # two-person rule (single chokepoint): high-blast actions require a prior four-eyes approval.
    if settings.require_approval and action in settings.approval_action_list and not approved:
        db.audit(tenant["id"], actor, f"remediate:{action}", "blocked", email, "requires two-person approval")
        return {"ok": False, "error": "requires two-person approval", "needs_approval": True}
    if email.strip().lower() == _tenant_subject(tenant).strip().lower():
        # MSSP: exclude THIS tenant's own super-admin (not the global one) — signing out the admin we
        # impersonate for this org would self-revoke the connector's access to that org (EXP-GOOGLE-0005).
        db.audit(tenant["id"], actor, f"remediate:{action}", "blocked", email, "operator excluded")
        return {"ok": False, "error": "refusing to remediate the operator/admin subject"}
    if not connector.in_verified_domains(email, _tenant_domains(tenant)):
        db.audit(tenant["id"], actor, f"remediate:{action}", "blocked", email, "out of verified domains")
        return {"ok": False, "error": "email not in tenant verified domains"}
    if fu["lookup_status"] != "found":
        return {"ok": False, "error": f"user lookup status is {fu['lookup_status']}, not found"}

    group = None
    if connector.ACTIONS[action]["needs_group"]:
        group = (tenant["quarantine_group"] if "quarantine_group" in tenant.keys() else "") or ""
        if not group:
            db.audit(tenant["id"], actor, f"remediate:{action}", "blocked", email, "no quarantine group set")
            return {"ok": False, "error": "set a quarantine group in Settings first"}
        if not connector.in_verified_domains(group, _tenant_domains(tenant)):
            db.audit(tenant["id"], actor, f"remediate:{action}", "blocked", email, "quarantine group out of verified domains")
            return {"ok": False, "error": "quarantine group is not in the tenant's verified domains"}

    # Admin-target safeguard (EXP-GOOGLE-0041): a custom-role (non-super) subject CANNOT act on an admin
    # target (Admin SDK 403s), and locking out the IT dept is dangerous. Refuse here with a clear status
    # instead of a raw 403. Best-effort readonly pre-check; ANY failure falls through (the action's own 403
    # is the backstop) so a transient blip never blocks a legitimate remediation.
    try:
        ro_token = connector.get_dwd_token([connector.SCOPE_READONLY],
                                           subject=_tenant_subject(tenant), service_account=_tenant_sa(tenant))
        if connector.is_admin(email, ro_token):
            db.audit(tenant["id"], actor, f"remediate:{action}", "blocked", email, "admin target excluded")
            return {"ok": False, "error": "refusing to remediate an admin account (needs a super-admin subject + manual review)"}
    except Exception:
        pass

    # --- act ---
    try:
        token = connector.get_dwd_token([connector.ACTIONS[action]["scope"]],
                                        subject=_tenant_subject(tenant), service_account=_tenant_sa(tenant))
        ok = connector.apply_action(action, email, token, group=group)
    except connector.ConnectorError as e:
        db.audit(tenant["id"], actor, f"remediate:{action}", "error", email, str(e))
        return {"ok": False, "error": str(e)}

    if ok:
        db.mark_remediated(flagged_id, time.time())
        db.audit(tenant["id"], actor, f"remediate:{action}", "ok", email)
        # post-state verification (execution != effect): re-read directory; best-effort, never blocks
        try:
            effect = connector.verify_action_effect(action, email, token, group=group)
            if effect != "unverifiable":
                db.audit(tenant["id"], actor, f"verify:{action}", effect, email)
                if effect == "failed":   # action returned ok but state didn't change -> not really done
                    db.set_flagged_status(flagged_id, "partial")
        except Exception:
            pass
        _close_socradar_alarm(tenant, fu, actor)   # close the loop — best-effort, decoupled (below)
        result = {"ok": True}
    else:
        db.audit(tenant["id"], actor, f"remediate:{action}", "fail", email, "API returned failure")
        result = {"ok": False, "error": "remediation API call failed"}
    # strictly last + best-effort: the destructive action + its DB bookkeeping are already done above
    analytics.write_events([analytics.event(f"remediate:{action}", "success" if ok else "failed",
                            email=email, tenant_id=tenant["id"], actor=actor,
                            details=None if ok else "API returned failure")])
    return result


def _auto_remediate(tenant, found_ids, actor, baseline_at=0):
    """AUTO mode: apply the auto-enabled actions to this scan's found users, each through the guardrail
    gate, then service.remediate. fu is snapshotted ONCE per user so applying action #2 isn't blocked by
    action #1 marking the user remediated. run_ctx counts USERS (blast cap is per-user, not per-action).
    Honesty: a user is only left 'remediated' if EVERY executed action succeeded — else 'partial'.
    Only findings first seen AT/AFTER the baseline are auto-eligible (never-auto-on-first-scan).
    A circuit breaker trips the whole run if the hourly auto-action rate limit is reached."""
    run_ctx = {"actioned": 0}
    limit = settings.auto_rate_limit_per_hour
    recent = db.count_auto_actions_since(tenant["id"], time.time() - 3600) if limit else 0
    executed = 0
    # The auto allow-list (AUTO_ENABLED_ACTIONS) is a GLOBAL/fleet setting; intersect it with what THIS
    # tenant actually enabled. Otherwise auto would call service.remediate for an action the tenant disabled,
    # which blocks inside remediate() but still burns a blast-cap slot and flips the user to 'partial'.
    tenant_enabled = _enabled_actions(tenant)
    auto_actions = [a for a in settings.auto_enabled_list if a in tenant_enabled]
    for fid in found_ids:
        if run_ctx["actioned"] >= settings.auto_max_users_per_scan:   # per-user blast-radius cap
            break
        fu = db.get_flagged_for_tenant(fid, tenant["id"])   # MSSP: scope by tenant (cross-org handle guard)
        if not fu:
            continue
        if baseline_at and (fu.get("first_seen") or 0) < baseline_at:   # pre-baseline backlog: never auto
            db.audit(tenant["id"], actor, "auto", "skipped", fu["email"], "pre-baseline finding")
            continue
        acted, all_ok = False, True
        for action in auto_actions:
            verdict = guardrails.decide(tenant, fu, action, run_ctx)
            if verdict == guardrails.EXECUTE:
                if limit and (recent + executed) >= limit:   # circuit breaker: hourly rate cap reached
                    db.audit(tenant["id"], actor, "circuit_breaker", "tripped", fu["email"],
                             f"auto rate limit {limit}/h reached — halting run, manual re-arm")
                    return
                acted = True
                ok = bool(remediate(tenant, fid, action, actor).get("ok"))
                all_ok = all_ok and ok
                if ok:
                    executed += 1   # rate counter tracks SUCCESSFUL actions (matches count_auto_actions_since)
                db.audit(tenant["id"], actor, f"auto:{action}", "ok" if ok else "fail", fu["email"])
            elif verdict == guardrails.DRYRUN:
                acted = True
                db.audit(tenant["id"], actor, f"auto:{action}", "dryrun", fu["email"], "would execute (dry-run)")
            else:
                db.audit(tenant["id"], actor, f"auto:{action}", "skipped", fu["email"], verdict)
        if acted:
            run_ctx["actioned"] += 1
            if not settings.auto_dry_run and not all_ok:
                db.set_flagged_status(fid, "partial")   # a real action failed -> don't claim 'remediated'


def apply_enabled_actions(tenant, flagged_id, actor):
    """SEMI-AUTO one-click (human-triggered): apply the tenant's enabled actions to one user. Actions that
    require two-person approval are QUEUED (not executed) so the one-click path can't bypass four-eyes;
    the rest go through the gated service.remediate. Leaves the user 'partial' if any executed action failed."""
    out, all_ok = [], True
    fu = db.get_flagged_for_tenant(flagged_id, tenant["id"])   # MSSP: cross-org handle guard
    if not fu:
        # the flagged-id is not this tenant's (cross-org or gone) -> do nothing, never mutate another org's row
        return [("_", "not in this tenant")]
    for action in _enabled_actions(tenant):
        if settings.require_approval and action in settings.approval_action_list:
            db.create_approval(tenant["id"], flagged_id, fu["email"] if fu else "", action, actor)
            db.audit(tenant["id"], actor, f"approval_requested:{action}", "pending", fu["email"] if fu else None)
            out.append((action, "queued (needs approval)"))
            continue
        ok = bool(remediate(tenant, flagged_id, action, actor).get("ok"))
        all_ok = all_ok and ok
        out.append((action, "ok" if ok else "fail"))
    if any(s == "fail" for _, s in out):
        db.set_flagged_status(flagged_id, "partial")
    return out
