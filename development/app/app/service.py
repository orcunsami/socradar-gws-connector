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
    """Feed window (startDate = a discovery-date filter, EXP-GOOGLE-0009). Resolution order:
    (1) INCREMENTAL high-water mark — once a tenant has a feed_high_water (the last fully-scanned discovery
        date), the next scan starts from (high_water - feed_overlap_days) so a boundary/backdated record is
        never missed; the idempotent (tenant,email) upsert dedups the overlap. This makes daily scans small DELTAS.
    (2) Before the first complete scan (high_water=''): the configured backfill window — per-tenant rolling
        preset feed_lookback_days > 0 → today-N, else the global env lookback, else the fixed feed_start_date.
    Keep the backfill bounded (a wide window pulls a lot of real PII)."""
    hw = (tenant["feed_high_water"] if "feed_high_water" in tenant.keys() else "") or ""
    if hw:
        try:
            return (datetime.date.fromisoformat(hw)
                    - datetime.timedelta(days=max(0, settings.feed_overlap_days))).isoformat()
        except ValueError:
            pass   # malformed high-water -> fall through to the backfill window
    # Per-tenant window is authoritative: 0 means "Custom date" (the UI label) -> fall through to
    # feed_start_date. The deploy-wide FEED_LOOKBACK_DAYS default is SEEDED onto the tenant at creation
    # (db.ensure_default_tenant), NOT applied here as a runtime override — otherwise an explicit "Custom date"
    # (0) would be silently overridden by the global preset, and the Settings dropdown (which reads the
    # per-tenant value) would show "Custom date" while the scan used the global rolling window.
    days = (tenant["feed_lookback_days"] if "feed_lookback_days" in tenant.keys() else 0) or 0
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
    """Scan dispatcher (ADR-0001). feed_full_scan (default True) = the streaming, full-coverage, incremental,
    resumable engine. feed_full_scan=False = the legacy single-shot path (bounded by feed_max_pages, kept as a
    fallback + for the orchestration tests that mock connector.fetch_all_sources)."""
    if settings.feed_full_scan:
        return _run_scan_streaming(tenant, actor)
    return _run_scan_legacy(tenant, actor)


def _post_scan(tenant, actor, result, found_ids, events, now):
    """Shared finalize tail for BOTH engines: best-effort analytics + behavioral anomaly check (a spike vs the
    rolling baseline suppresses auto this scan) + gated AUTO-mode remediation of THIS scan's found users.
    Runs ONCE against the COMPLETE found set (ADR-0001 #2: the blast-cap/anomaly/baseline gates assume one
    atomic scan — they must never see a per-chunk partial count)."""
    analytics.write_events(events)
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
    # MSSP safety: the auto-mode policy is GLOBAL/fleet-wide — force-disable auto when >1 tenant is configured.
    auto_ok = guardrails.effective_mode() == "auto" and len(db.list_tenants()) <= 1
    if result.get("ok") and not anomalous and auto_ok and found_ids:
        try:
            baseline = tenant.get("auto_baseline_at", 0) or 0
            if not baseline:
                # never-auto-on-first-scan: the first auto-eligible scan only ESTABLISHES the baseline.
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


def _run_scan_streaming(tenant, actor: str) -> dict:
    """Streaming, full-coverage, incremental, resumable scan (ADR-0001). Pages the whole window source by
    source; applies the verified-domain filter INSIDE the page loop so only the tiny in-scope subset (~0.08%)
    is retained (no OOM + PII minimization, EXP-GOOGLE-0009); Directory-looks-up only that subset; idempotently
    upserts (UNION sources). Single-flight per tenant via a lease that reclaims a crashed zombie and resumes
    from the page cursor. A per-invocation page budget (scan_pages_per_run) self-continues under a request
    timeout; unset (Cloud Run Job) it runs to completion. On full completion it advances the tenant
    high-water mark (the next scan is an incremental delta) and emits ONE honest coverage summary."""
    now = time.time()
    window_start = _effective_start_date(tenant)
    scan_id, cursor_json, mode = db.claim_or_resume_scan(tenant["id"], now, settings.scan_lease_ttl, window_start)
    if scan_id is None:
        return {"ok": False, "busy": True, "error": "a scan is already running for this tenant"}
    if mode == "resume":
        active = db.get_active_scan(tenant["id"])
        window_start = (active.get("window_start") if active else None) or window_start
    cur = json.loads(cursor_json) if cursor_json else {}
    done = list(cur.get("done", []))
    cur_src, cur_page = cur.get("src"), cur.get("page", 1)
    totals, processed = dict(cur.get("totals", {})), dict(cur.get("processed", {}))
    inscope_seen, found_emails = set(cur.get("inscope", [])), set(cur.get("found", []))
    found_ids, denied = list(cur.get("found_ids", [])), int(cur.get("denied", 0))
    last_state = dict(cur)   # the most recent durable checkpoint — used to pause+resume on a mid-scan feed error
    domains = _tenant_domains(tenant)
    events, token, pages_this_run = [], [None], 0
    budget = settings.scan_pages_per_run

    def _tok():
        if token[0] is None:
            token[0] = connector.get_dwd_token([connector.SCOPE_READONLY],
                                               subject=_tenant_subject(tenant), service_account=_tenant_sa(tenant))
        return token[0]

    try:
        for src in connector.SOC_SOURCES:
            if src in done:
                continue
            totals.setdefault(src, 0)        # ensure every source appears in the honest summary (even empty ones)
            processed.setdefault(src, 0)
            start_page = cur_page if src == cur_src else 1
            for page_no, recs, total in connector.stream_source(
                    tenant["feed_base"], tenant["feed_company_id"], tenant["feed_api_key"],
                    src, window_start, start_page=start_page):
                totals[src] = total
                # `recs` can be a SANITIZED-empty page (a page whose raw records carried no @-email, e.g. VIP
                # brand monitors). Process it as a no-op but STILL advance the cursor/budget so later pages with
                # real emails are reached — never break here. stream_source only YIELDS raw-non-empty pages and
                # ENDS on a raw-empty page, so this for-loop finishes exactly when the source is truly exhausted.
                processed[src] = processed.get(src, 0) + len(recs)
                # early in-scope filter: keep only the tiny verified-domain batch for THIS page, discard the rest
                batch = {}
                for r in recs:
                    if connector.in_verified_domains(r["email"], domains):
                        b = batch.setdefault(r["email"], {"sources": set(), "alarms": []})
                        b["sources"].add(src)
                        if r["alarm_id"] is not None and r["alarm_id"] not in b["alarms"]:
                            b["alarms"].append(r["alarm_id"])
                for email, info in sorted(batch.items()):
                    status = connector.lookup_user(email, _tok())
                    fid = db.upsert_flagged(tenant["id"], email, info["sources"], status, now, info["alarms"])
                    inscope_seen.add(email)
                    if analytics.enabled():
                        events.append(analytics.event("flagged", status, email=email,
                                      source=",".join(sorted(info["sources"])), tenant_id=tenant["id"], actor=actor))
                    if status == "found":
                        found_emails.add(email)
                        if fid not in found_ids:
                            found_ids.append(fid)
                    elif status == "permission_denied":
                        denied += 1
                pages_this_run += 1
                # checkpoint per page: cursor (resume), heartbeat (lease) + running tallies (accurate progress)
                state = {"done": done, "src": src, "page": page_no + 1, "totals": totals, "processed": processed,
                         "inscope": sorted(inscope_seen), "found": sorted(found_emails),
                         "found_ids": found_ids, "denied": denied}
                last_state = state
                db.scan_heartbeat(scan_id, time.time(), cursor=json.dumps(state),
                                  totals=totals, found=len(found_emails), unique=len(inscope_seen))
                if budget and pages_this_run >= budget:
                    db.pause_scan(scan_id, time.time(), json.dumps(state))   # hand off to the next invocation
                    db.audit(tenant["id"], actor, "scan", "progress",
                             detail=f"checkpoint: {len(done)} sources done, {src}@page {page_no}; "
                                    f"in_scope={len(inscope_seen)} found={len(found_emails)} (resuming next run)")
                    return {"ok": True, "more": True, "in_scope": len(inscope_seen),
                            "found": len(found_emails), "processed": dict(processed)}
            done.append(src)
            cur_src, cur_page = None, 1
            last_state = {"done": done, "src": None, "page": 1, "totals": totals, "processed": processed,
                          "inscope": sorted(inscope_seen), "found": sorted(found_emails),
                          "found_ids": found_ids, "denied": denied}
        # --- every source fully paged: finalize (no truncation) ---
        db.finish_scan(scan_id, time.time(), totals=totals, found=len(found_emails),
                       unique=len(inscope_seen), status="done")
        db.audit(tenant["id"], actor, "scan", "ok",
                 detail=f"totals={totals} processed={processed} in_scope={len(inscope_seen)} "
                        f"found={len(found_emails)} window>={window_start} (full coverage)")
        if inscope_seen and denied >= len(inscope_seen):
            db.audit(tenant["id"], actor, "scan", "warning",
                     detail="ALL lookups returned 403 — domain-wide delegation likely not authorized yet "
                            "(authorize the Client ID + 4 scopes in admin.google.com; propagation up to 24h)")
        # incremental: the window is fully covered up to today -> advance the high-water mark (next scan = delta)
        db.update_tenant(tenant["id"], feed_high_water=datetime.date.today().isoformat())
        result = {"ok": True, "totals": totals, "processed": processed, "truncated": False,
                  "in_scope": len(inscope_seen), "found": len(found_emails), "denied": denied}
    except connector.ConnectorError as e:
        # A feed/network error mid-backfill is usually TRANSIENT. KEEP the per-page checkpoint and flip the row
        # to 'paused' so the NEXT execution RESUMES from where we stopped (NOT a fresh restart from window_start
        # that would orphan hours of paging). Guard a PERMANENT error (bad key / feed down): count resumes that
        # made ZERO progress and finalize 'error' after scan_max_stuck_resumes so it can't loop forever.
        stuck = 0 if pages_this_run > 0 else int(cur.get("stuck", 0)) + 1
        if stuck >= settings.scan_max_stuck_resumes:
            db.finish_scan(scan_id, time.time(), error=str(e), status="error")
            db.audit(tenant["id"], actor, "scan", "error",
                     detail=f"giving up after {stuck} no-progress resumes: {str(e)[:160]}")
            result = {"ok": False, "error": str(e)}
        else:
            resume_cursor = dict(last_state)
            resume_cursor["stuck"] = stuck
            db.pause_scan(scan_id, time.time(), json.dumps(resume_cursor))   # keep checkpoint -> next run resumes
            db.audit(tenant["id"], actor, "scan", "error",
                     detail=f"feed error mid-scan — checkpoint kept, will resume "
                            f"(attempt {stuck}/{settings.scan_max_stuck_resumes}): {str(e)[:140]}")
            result = {"ok": False, "error": str(e), "resumable": True}
    except Exception as e:   # never leave a permanent zombie 'running' row
        db.finish_scan(scan_id, time.time(), error=f"unexpected: {type(e).__name__}: {e}", status="error")
        try:
            db.audit(tenant["id"], actor, "scan", "error", detail=f"unexpected {type(e).__name__}")
        except Exception:
            pass
        result = {"ok": False, "error": "scan failed unexpectedly"}
    return _post_scan(tenant, actor, result, found_ids, events, now)


def _run_scan_legacy(tenant, actor: str) -> dict:
    """Legacy single-shot scan (feed_full_scan=False): fetch all -> filter -> lookup -> persist, bounded by
    feed_max_pages (so a huge feed truncates — the problem ADR-0001 fixes). Kept as a fallback."""
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
    except Exception as e:
        db.finish_scan(scan_id, time.time(), error=f"unexpected: {type(e).__name__}: {e}")
        try:
            db.audit(tenant["id"], actor, "scan", "error", detail=f"unexpected {type(e).__name__}")
        except Exception:
            pass
        result = {"ok": False, "error": "scan failed unexpectedly"}
    return _post_scan(tenant, actor, result, found_ids, events, now)


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

    # Admin-target safeguard (EXP-GOOGLE-0041 + arastirma9 §F1): a custom-role (non-super) subject CANNOT act
    # on an admin target (the Admin SDK 403s even read-only), and locking out the IT dept is dangerous.
    # FAIL CLOSED + LOUD: refuse if the target IS an admin OR if we cannot PROVE it is not (is_admin -> None).
    # A transient blip must NOT let an admin-account remediation slip through (the old code returned on
    # exception = fail-open). The refusal is an "alert"-severity audit (not a silent "blocked") so it surfaces.
    admin_state = None
    try:
        ro_token = connector.get_dwd_token([connector.SCOPE_READONLY],
                                           subject=_tenant_subject(tenant), service_account=_tenant_sa(tenant))
        admin_state = connector.is_admin(email, ro_token)
    except Exception:
        admin_state = None   # could not pre-check -> indeterminate -> fail closed (below)
    if admin_state is not False:   # True (admin) OR None (indeterminate) -> refuse, loudly
        reason = "target is an admin" if admin_state is True else "admin status could not be verified"
        db.audit(tenant["id"], actor, f"remediate:{action}", "alert", email,
                 f"BLOCKED ({reason}) — needs a super-admin subject + manual review")
        return {"ok": False, "admin_blocked": True,
                "error": f"refusing to remediate: {reason} (needs a super-admin subject + manual review)"}

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
        if action == "disable_2sv":
            # SECURITY SEMANTICS (Claude-web review): disable_2sv strips ALL second factors -> the account becomes
            # password-only UNLESS 2SV is org-ENFORCED (then the user must re-enroll). On our use-case (a LEAKED-
            # password feed = the attacker already knows the password) this is a NET DOWNGRADE if used alone. Loud
            # 'alert' audit so an operator never treats it as routine: it's only for stripping an attacker-enrolled
            # factor, and must be paired with reset_password + 2SV re-enforcement.
            db.audit(tenant["id"], actor, "remediate:disable_2sv", "alert", email,
                     "2SV DISABLED — all 2nd factors removed; account is password-only unless 2SV is org-enforced. "
                     "On a leaked-password account this is a DOWNGRADE alone — pair with reset_password + re-enforce 2SV.")
        # SECURITY PAIRING (arastirma9 §F2): a Directory-API password reset does NOT reliably revoke OAuth
        # tokens (the re-hash trap) and never revokes ASPs — so a bare reset_password leaves the ATO open.
        # Auto-pair it with token + ASP revocation. Security-mandated, so it runs independent of the per-tenant
        # enabled-toggle AND of two-person approval (the toggle is whether YOU chose reset; revoking the tokens a
        # reset can't kill is non-optional). It calls connector.apply_action DIRECTLY on the SAME already-gated
        # email (operator/domain/admin-target all cleared above) — never re-enters remediate(), so no recursion.
        # The DWD client must authorize SCOPE_SECURITY (it's in SCOPES_UNION) or the pair token exchange 403s.
        pairing_failed = False
        for pair in connector.ACTIONS[action].get("pairs", []):
            try:
                ptok = connector.get_dwd_token([connector.ACTIONS[pair]["scope"]],
                                               subject=_tenant_subject(tenant), service_account=_tenant_sa(tenant))
                pok = connector.apply_action(pair, email, ptok)
                db.audit(tenant["id"], actor, f"paired:{pair}", "ok" if pok else "fail", email,
                         "security pairing after reset_password (a bare reset doesn't revoke tokens/ASPs)")
                pairing_failed = pairing_failed or not pok
            except Exception as ex:
                db.audit(tenant["id"], actor, f"paired:{pair}", "error", email, str(ex)[:160])
                pairing_failed = True
        if pairing_failed:
            # TRUTHFULNESS (adversary review): a failed token/ASP revoke reproduces EXACTLY the open-ATO state the
            # pairing exists to close. Do NOT report a green 'remediated' — flag partial + alert, and DON'T close
            # the SOCRadar alarm below (the exposure is not fully contained: tokens may still be live).
            db.set_flagged_status(flagged_id, "partial")
            db.audit(tenant["id"], actor, f"remediate:{action}", "alert", email,
                     "PAIRING INCOMPLETE — reset done but token/ASP revoke failed; tokens may still be live (manual follow-up)")
        # post-state verification (execution != effect): re-read directory; best-effort, never blocks
        try:
            effect = connector.verify_action_effect(action, email, token, group=group)
            if effect != "unverifiable":
                db.audit(tenant["id"], actor, f"verify:{action}", effect, email)
                if effect == "failed":   # action returned ok but state didn't change -> not really done
                    db.set_flagged_status(flagged_id, "partial")
        except Exception:
            pass
        if not pairing_failed:
            _close_socradar_alarm(tenant, fu, actor)   # close the loop ONLY if full containment landed
        result = {"ok": True} if not pairing_failed else {
            "ok": True, "partial": True, "warning": "reset done; token/ASP revoke failed — tokens may still be live"}
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
