"""
SOCRadar Google Workspace Connector — Internal admin app.

Single FastAPI service: admin web UI (the Workspace surface) + the proven connector behind it.
Runs locally ($0, DEV_LOGIN or localhost OAuth) and deploys to Cloud Run unchanged.
"""
from __future__ import annotations

import json
import logging
import secrets
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import auth, connector, db, guardrails, metrics, service
from .config import assert_startup_safe, is_cloud_run, settings

log = logging.getLogger("socradar.gws")

BASE = Path(__file__).parent
app = FastAPI(title="SOCRadar Google Workspace Connector")
# Hardened session cookie: encrypted transport in prod, bounded lifetime (was 14d default).
# same_site="lax" (NOT strict): the Google OAuth callback is a cross-site top-level GET redirect from
# accounts.google.com; SameSite=strict withholds the session cookie on it, so Authlib can't read the
# OAuth state it stored and EVERY production sign-in fails. Lax sends the cookie on top-level GET
# navigations (callback works) while still withholding it on cross-site POSTs. State-changing POSTs are
# separately protected by the per-form _csrf token, so lax is not a CSRF regression.
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key,
                   same_site="lax", https_only=is_cloud_run(), max_age=settings.session_max_age)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    """Defensive response headers (DAST finding): clickjacking, MIME-sniff, referrer leak, and a strict
    CSP. HSTS only over HTTPS (Cloud Run) — meaningless/harmful on local http."""
    resp = await call_next(request)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if is_cloud_run():
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


@app.exception_handler(Exception)
async def _generic_error(request: Request, exc: Exception):
    """Never leak a stack trace / internal detail to the client (could carry secrets/PII).
    The trace goes to the server log only (Cloud Run logs) — exc_info so we can actually diagnose."""
    log.error("unhandled error on %s %s: %s", request.method, request.url.path,
              type(exc).__name__, exc_info=True)
    return JSONResponse({"error": "internal error"}, status_code=500)


def _fmt_ts(epoch):
    if not epoch:
        return "—"
    import datetime
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_dur(seconds):
    """Human-readable duration for the dashboard KPIs. None -> em dash."""
    if seconds is None:
        return "—"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{s // 86400}d {(s % 86400) // 3600}h"


templates.env.filters["dt"] = _fmt_ts
templates.env.filters["dur"] = _fmt_dur


@app.on_event("startup")
def _startup():
    # emit INFO to stdout so the off-box audit mirror (socradar.audit) is actually captured by Cloud Logging
    logging.basicConfig(level=logging.INFO)
    for w in assert_startup_safe():        # fail-closed guard (raises on catastrophic misconfig)
        log.warning("STARTUP WARNING: %s", w)
    log.info("startup: env=%s cloud_run=%s oauth=%s dev_login_active=%s remediation_mode=%s feed_key=%s",
             settings.app_env, is_cloud_run(), settings.oauth_configured, settings.dev_login_active,
             guardrails.effective_mode(), "set" if settings.feed_api_key else "MISSING")
    db.init_db()


# ---------- helpers ----------
def _csrf(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["csrf"] = tok
    return tok


def _check_csrf(request: Request, sent: str) -> bool:
    return bool(sent) and secrets.compare_digest(sent, request.session.get("csrf", ""))


def _active_tenant(request: Request):
    """The tenant the admin is currently operating on (session-selected; defaults to first).
    Never returns None: every page does t["id"], so if the tenants table was emptied (manual
    delete / corruption) we re-assert the startup invariant (idempotent re-bootstrap) rather than
    let 14 routes 500 on a None tenant."""
    tid = request.session.get("tenant_id")
    if tid:
        t = db.get_tenant(tid)
        if t:
            return t
    t = db.first_tenant()
    if t is None:
        db.ensure_default_tenant()
        t = db.first_tenant()
    return t


def _ctx(request: Request, user: dict, **extra) -> dict:
    base = {"user": user, "csrf": _csrf(request),
            "version": __import__("app").__version__, "actions": connector.ACTIONS,
            "active_tenant": _active_tenant(request), "all_tenants": db.list_tenants(),
            "require_approval": settings.require_approval}   # nav shows Approvals only when this is on
    base.update(extra)
    return base


def _render(name, request, user, **extra) -> HTMLResponse:
    return templates.TemplateResponse(request, name, _ctx(request, user, **extra))


# ---------- auth routes ----------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if auth.current_user(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {
        "oauth": settings.oauth_configured, "dev": settings.dev_login_active,
        "domain": settings.allowed_domain})


@app.get("/auth/login")
async def auth_login(request: Request):
    return await auth.start_login(request)


@app.get("/auth/callback", name="auth_callback")
async def auth_callback(request: Request):
    return await auth.finish_login(request)


@app.get("/auth/logout")
def auth_logout(request: Request):
    return auth.logout(request)


# ---------- pages ----------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    t = _active_tenant(request)
    counts = db.flagged_counts(t["id"])
    last = db.last_scan(t["id"])
    return _render("dashboard.html", request, user, tenant=t, counts=counts, last=last,
                   totals=json.loads(last["totals"]) if last and last["totals"] else {},
                   # verify_chain=False: keep the unbounded audit-chain recompute OFF the landing hot path
                   # (it's a scheduled tamper-check, not a per-load KPI). Cheap KPIs only here.
                   m=metrics.compute(t["id"], verify_chain=False))


@app.post("/scan")
def scan(request: Request, csrf: str = Form("")):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not _check_csrf(request, csrf):
        return RedirectResponse("/?err=csrf", status_code=303)
    t = _active_tenant(request)
    result = service.run_scan(t, user["email"])
    # a budget-bounded scan can return part-way (more=True) or refuse if one is already running (busy=True);
    # don't flash a FALSE "completed" on a partial, and don't flash "failed" on a busy.
    if result.get("more"):
        flag = "scan_more"
    elif result.get("busy"):
        flag = "scan_busy"
    elif result.get("ok"):
        flag = "scan_ok"
    else:
        flag = "scan_err"
    # Land on Flagged Users. If the scan is still going (budget-chunked on the Service), pass its id so the page
    # shows a live progress banner that drives the remaining chunks (POST /scans/{id}/tick) until done.
    s = db.last_scan(t["id"]) or {}
    qs = f"{flag}=1" + (f"&scan={s['id']}" if s.get("id") else "")
    return RedirectResponse(f"/flagged?{qs}", status_code=303)


def _scan_progress(s: dict) -> dict:
    """JSON-safe live progress for the scanning banner, read from a scan_runs row."""
    try:
        cur = json.loads(s.get("cursor") or "{}")
    except Exception:
        cur = {}
    try:
        totals = json.loads(s["totals"]) if s.get("totals") else {}
    except Exception:
        totals = {}
    status = s.get("status") or "running"
    return {"id": s.get("id"), "status": status,
            "done": status in ("done", "error"), "more": status == "paused",
            "found": s.get("found_count") or 0, "unique": s.get("unique_emails") or 0,
            "totals": totals if isinstance(totals, dict) else {},
            "source": cur.get("src"), "page": cur.get("page"),
            "sources_done": len(cur.get("done", []) or []), "error": s.get("error")}


@app.post("/scans/{scan_id}/tick")
def scan_tick(request: Request, scan_id: str, csrf: str = Form("")):
    """Advance ONE budget-chunk of the tenant's in-flight scan and return live progress (JSON). The Flagged
    Users page polls this in a sequential loop so a long scan runs in small request-bound steps with a live
    progress bar — Cloud-Run-safe (no background thread). No-ops once the scan is done (never starts a new one)."""
    user = auth.current_user(request)
    if not user:
        return JSONResponse({"error": "auth"}, status_code=401)
    if not _check_csrf(request, csrf):
        return JSONResponse({"error": "csrf"}, status_code=400)
    t = _active_tenant(request)
    s = db.last_scan(t["id"])
    if not s or str(s.get("id")) != str(scan_id):
        return JSONResponse({"stale": True})            # a newer scan exists -> client should reload
    if (s.get("status") or "") in ("done", "error"):
        return JSONResponse(_scan_progress(s))          # finished -> report only, do NOT start a new scan
    service.run_scan(t, user["email"])                  # resumes the paused scan, runs exactly one budget chunk
    return JSONResponse(_scan_progress(db.last_scan(t["id"]) or s))


@app.get("/flagged", response_class=HTMLResponse)
def flagged(request: Request):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    t = _active_tenant(request)
    rows = []
    for r in db.list_flagged(t["id"]):
        rows.append({**dict(r), "sources_list": json.loads(r["sources"])})
    # per-user activity timeline (so a flagged row can show exactly what was done to it, when, and in WHICH
    # scan's window). The audit trail records every remediate:/paired:/verify:/auto:/approval row with a
    # target_email; group it by email (no schema change) and tag each with the scan it falls under.
    scans = db.recent_scans(t["id"], 200)   # newest first

    def _scan_of(ts):
        for s in scans:                      # the most recent scan started at/before this event
            if s["started_at"] <= ts:
                return s
        return None
    history = {}
    for a in db.list_audit(t["id"], 500):
        em = a.get("target_email")
        if not em:
            continue
        sc = _scan_of(a["ts"])
        row = dict(a)
        row["scan_id"] = sc["id"] if sc else None
        row["scan_started"] = sc["started_at"] if sc else None
        history.setdefault(em, []).append(row)
    # live progress: if a scan is still in flight (budget-chunked), surface a banner that the page polls
    # (POST /scans/{id}/tick) to drive the remaining chunks + show found/pages live.
    live = db.last_scan(t["id"])
    live_scan = _scan_progress(live) if live and (live.get("status") or "") in ("running", "paused") else None
    return _render("flagged.html", request, user, tenant=t, rows=rows, history=history,
                   live_scan=live_scan,
                   enabled=json.loads(t["enabled_actions"]),
                   admin_subject=service._tenant_subject(t),   # MSSP: hide remediation for THIS org's admin
                   mode=guardrails.effective_mode(), dry_run=settings.auto_dry_run,
                   kill_switch=settings.auto_kill_switch, close_alarm=settings.close_socradar_alarm)


def _tenant_match(request: Request, t, exp_tenant: str) -> bool:
    """MSSP stale-tab guard (R3): the form was rendered for exp_tenant; if the session's active tenant has
    since changed (another tab switched orgs), the POST would hit the WRONG org. Reject the mismatch."""
    return not exp_tenant or str(exp_tenant) == str(t["id"])


@app.post("/flagged/{flagged_id}/remediate")
def remediate(request: Request, flagged_id: str, action: str = Form(...), exp_tenant: str = Form(""),
              csrf: str = Form("")):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not _check_csrf(request, csrf):
        return RedirectResponse("/flagged?err=csrf", status_code=303)
    if not auth.is_remediation_admin(user["email"]):   # RBAC: triage != authorized to act
        db.audit(_active_tenant(request)["id"], user["email"], f"remediate:{action}", "blocked",
                 detail="not a remediation admin")
        return RedirectResponse("/flagged?err=forbidden", status_code=303)
    t = _active_tenant(request)
    if not _tenant_match(request, t, exp_tenant):   # stale-tab: active org changed since the page rendered
        return RedirectResponse("/flagged?err=tenant", status_code=303)
    # two-person rule: high-blast actions don't execute on one admin's click — queue for a second admin
    if settings.require_approval and action in settings.approval_action_list:
        fu = db.get_flagged_for_tenant(flagged_id, t["id"])   # MSSP: never queue another org's email/id
        if fu:
            db.create_approval(t["id"], flagged_id, fu["email"], action, user["email"])
            db.audit(t["id"], user["email"], f"approval_requested:{action}", "pending", fu["email"])
            return RedirectResponse("/approvals?requested=1", status_code=303)
    result = service.remediate(t, flagged_id, action, user["email"])
    flag = "rem_ok" if result.get("ok") else "rem_err"
    return RedirectResponse(f"/flagged?{flag}=1", status_code=303)


@app.get("/metrics", response_class=HTMLResponse)
def metrics_page(request: Request):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    t = _active_tenant(request)
    return _render("metrics.html", request, user, tenant=t, m=metrics.compute(t["id"]))


@app.get("/metrics.json")
def metrics_json(request: Request):
    user = auth.current_user(request)
    if not user:
        return JSONResponse({"error": "login required"}, status_code=401)
    t = _active_tenant(request)
    return JSONResponse(metrics.compute(t["id"]))


@app.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    t = _active_tenant(request)
    return _render("approvals.html", request, user, tenant=t,
                   pending=db.list_approvals(t["id"], "pending"),
                   recent=db.list_approvals(t["id"])[:20],
                   is_admin=auth.is_remediation_admin(user["email"]),
                   me=user["email"])


@app.post("/approvals/{approval_id}/approve")
def approval_approve(request: Request, approval_id: str, csrf: str = Form("")):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not _check_csrf(request, csrf):
        return RedirectResponse("/approvals?err=csrf", status_code=303)
    t = _active_tenant(request)
    ap = db.get_approval(approval_id)
    if not ap or str(ap["tenant_id"]) != str(t["id"]) or ap["state"] != "pending":
        return RedirectResponse("/approvals?err=state", status_code=303)
    if not auth.is_remediation_admin(user["email"]):
        return RedirectResponse("/approvals?err=forbidden", status_code=303)
    if user["email"].strip().lower() == (ap["requester"] or "").strip().lower():
        # four-eyes: the requester cannot approve their own request
        db.audit(t["id"], user["email"], f"approval_approve:{ap['action']}", "blocked",
                 ap["email"], "requester==approver (four-eyes)")
        return RedirectResponse("/approvals?err=foureyes", status_code=303)
    # atomic claim (CAS): only the request that flips pending->executed proceeds (anti double-execution)
    if not db.set_approval_state(approval_id, "executed", user["email"], expect="pending"):
        return RedirectResponse("/approvals?err=state", status_code=303)
    result = service.remediate(t, ap["flagged_id"], ap["action"], user["email"], approved=True)
    if not result.get("ok"):
        # The action was claimed executed (CAS, line above) BEFORE remediate ran. If remediate then failed a
        # gate (action since disabled, email's domain removed, lookup status changed), the approval would be
        # left falsely 'executed' while nothing happened. Revert it to 'pending' so its state reflects reality
        # and an admin can retry or reject. (The CAS already prevents a concurrent double-execution.)
        db.set_approval_state(approval_id, "pending", user["email"], expect="executed")
    db.audit(t["id"], user["email"], f"approval_approve:{ap['action']}",
             "ok" if result.get("ok") else "fail", ap["email"], f"requested by {ap['requester']}")
    return RedirectResponse("/approvals?approved=1" if result.get("ok") else "/approvals?err=remediate_failed",
                            status_code=303)


@app.post("/approvals/{approval_id}/reject")
def approval_reject(request: Request, approval_id: str, csrf: str = Form("")):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not _check_csrf(request, csrf):
        return RedirectResponse("/approvals?err=csrf", status_code=303)
    t = _active_tenant(request)
    ap = db.get_approval(approval_id)
    if not ap or str(ap["tenant_id"]) != str(t["id"]) or ap["state"] != "pending":
        return RedirectResponse("/approvals?err=state", status_code=303)
    if not auth.is_remediation_admin(user["email"]):
        return RedirectResponse("/approvals?err=forbidden", status_code=303)
    # CAS (same as approve): only flip a still-pending approval. Without expect=, a concurrent approve that
    # just executed (pending->executed) could be overwritten as 'rejected', mis-recording an executed action.
    if not db.set_approval_state(approval_id, "rejected", user["email"], expect="pending"):
        return RedirectResponse("/approvals?err=state", status_code=303)
    db.audit(t["id"], user["email"], f"approval_reject:{ap['action']}", "rejected", ap["email"])
    return RedirectResponse("/approvals?rejected=1", status_code=303)


@app.post("/flagged/{flagged_id}/auto-remediate")
def auto_remediate_one(request: Request, flagged_id: str, exp_tenant: str = Form(""), csrf: str = Form("")):
    """Semi-auto one-click: apply ALL enabled actions to one user (human-triggered)."""
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not _check_csrf(request, csrf):
        return RedirectResponse("/flagged?err=csrf", status_code=303)
    if not auth.is_remediation_admin(user["email"]):   # RBAC: triage != authorized to act
        db.audit(_active_tenant(request)["id"], user["email"], "auto-remediate", "blocked",
                 detail="not a remediation admin")
        return RedirectResponse("/flagged?err=forbidden", status_code=303)
    t = _active_tenant(request)
    if not _tenant_match(request, t, exp_tenant):   # stale-tab guard (R3)
        return RedirectResponse("/flagged?err=tenant", status_code=303)
    results = service.apply_enabled_actions(t, flagged_id, user["email"])
    # honest UI: don't flash success when nothing ran, an action failed, or the id wasn't this tenant's.
    statuses = [s for _, s in results]
    ok = bool(results) and statuses != ["not in this tenant"] and not any(s == "fail" for s in statuses)
    return RedirectResponse(f"/flagged?{'rem_ok' if ok else 'rem_err'}=1", status_code=303)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    t = _active_tenant(request)
    return _render("settings.html", request, user, tenant=t,
                   verified_domains=", ".join(json.loads(t["verified_domains"])),
                   enabled=json.loads(t["enabled_actions"]),
                   approval_actions=settings.approval_action_list,   # which actions need a 2nd-admin approval
                   high_blast=settings.auto_high_blast_list,         # which never fire automatically
                   require_approval=settings.require_approval)


@app.post("/settings")
def settings_save(request: Request, verified_domains: str = Form(""), feed_base: str = Form(""),
                  feed_company_id: str = Form(""), feed_api_key: str = Form(""),
                  feed_start_date: str = Form(""), feed_lookback_days: int = Form(0),
                  reset_backfill: str = Form(""), quarantine_group: str = Form(""),
                  admin_subject: str = Form(""), service_account: str = Form(""),
                  enabled_actions: list[str] = Form(default=[]), csrf: str = Form("")):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not _check_csrf(request, csrf):
        return RedirectResponse("/settings?err=csrf", status_code=303)
    if not auth.is_remediation_admin(user["email"]):   # changing enabled_actions/feed-key/domains is privileged
        db.audit(_active_tenant(request)["id"], user["email"], "settings_save", "blocked",
                 detail="not a remediation admin")
        return RedirectResponse("/settings?err=forbidden", status_code=303)
    t = _active_tenant(request)
    domains = [d.strip().lower() for d in verified_domains.split(",") if d.strip()]
    # MSSP isolation (cross-tenant contamination guard): an empty domains field must NEVER backfill the
    # GLOBAL settings.default_domain — that is org A's domain, not this tenant's. Doing so would silently
    # widen tenant B's scope to org A and (with a blank admin_subject inheriting the global super-admin)
    # turn the documented "fails safe / cross-org 403" fallback into a live cross-org remediation path.
    # Keep THIS tenant's existing domains instead; the form just didn't change them.
    if not domains:
        domains = json.loads(t["verified_domains"])
    valid_actions = [a for a in enabled_actions if a in connector.ACTIONS]
    qg = quarantine_group.strip()
    if qg and not connector.in_verified_domains(qg, domains):
        return RedirectResponse("/settings?err=qgroup", status_code=303)
    # MSSP (edit-tenant): the per-org super-admin must live in this tenant's verified domains (same rule as create)
    asub = admin_subject.strip().lower()
    if asub and ("@" not in asub or not connector.in_verified_domains(asub, domains)):
        return RedirectResponse("/settings?err=adminsub", status_code=303)
    # largest preset is 30 days (1 month); a longer window must be set via a Custom start date (lookback=0).
    # A wide rolling window times out the request and reads a lot of PII, so it is intentionally not a 1-click preset.
    new_lookback = feed_lookback_days if feed_lookback_days in (0, 1, 7, 30) else 0
    new_start = feed_start_date.strip() or t["feed_start_date"]
    fields = {
        "verified_domains": json.dumps(domains),
        "feed_base": feed_base.strip() or t["feed_base"],
        "feed_company_id": feed_company_id.strip() or t["feed_company_id"],
        "feed_start_date": new_start,
        # rolling-window preset (today - N). 0 = use the fixed feed_start_date. Validated against the offered set.
        "feed_lookback_days": new_lookback,
        "enabled_actions": json.dumps(valid_actions),
        "quarantine_group": qg,
        "admin_subject": asub,
        "service_account": service_account.strip(),
    }
    if feed_api_key.strip():                 # only overwrite key if a new one was typed
        fields["feed_api_key"] = feed_api_key.strip()
    # Drop the incremental high-water mark (force a full re-read of the window on the next scan) when the feed
    # WINDOW changed, the feed CREDENTIALS changed (a different SOCRadar account/company has its own timeline),
    # or the operator ticked "re-scan the full window". Otherwise once a tenant has scanned once,
    # _effective_start_date() returns at the high-water branch and the new setting silently does nothing.
    cur_lookback = (t["feed_lookback_days"] if "feed_lookback_days" in t.keys() else 0) or 0
    feed_creds_changed = ((feed_base.strip() and feed_base.strip() != t["feed_base"])
                          or (feed_company_id.strip() and feed_company_id.strip() != t["feed_company_id"])
                          or bool(feed_api_key.strip()))
    if reset_backfill or new_lookback != cur_lookback or new_start != t["feed_start_date"] or feed_creds_changed:
        fields["feed_high_water"] = ""
        db.cancel_active_scan(t["id"])   # a paused scan would otherwise RESUME with its OLD stored window_start
    db.update_tenant(t["id"], **fields)
    db.audit(t["id"], user["email"], "settings", "ok",
             detail=f"domains={domains} actions={valid_actions}")
    return RedirectResponse("/settings?saved=1", status_code=303)


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    t = _active_tenant(request)
    return _render("audit.html", request, user, tenant=t, rows=db.list_audit(t["id"]))


@app.get("/scans", response_class=HTMLResponse)
def scans_page(request: Request):
    """History of every scan run (a 'Scans' tab alongside 'Flagged Users'). Answers 'show me each scan and
    whether anything was DONE about it' — for each scan we also count the successful remediations that landed
    in that scan's window, read from the same audit trail (no extra schema)."""
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    t = _active_tenant(request)
    scans = db.recent_scans(t["id"], 50)   # finished scans, newest first
    # remediation timestamps (guarded: an audit row with a null/odd action or ts must not 500 the page)
    rem_ts = [a["ts"] for a in db.list_audit(t["id"], 1000)
              if a.get("ts") is not None and (a.get("action") or "").startswith("remediate:")
              and a.get("result") == "ok"]
    enriched = []
    for i, s in enumerate(scans):
        # never let one malformed scan row (bad totals JSON, null started_at, ...) take down the whole page.
        try:
            lo = s.get("started_at") or 0
            hi = scans[i - 1].get("started_at") if i > 0 else None   # window up to the next-newer scan
            hi = hi if hi is not None else float("inf")
            tm = json.loads(s["totals"]) if s.get("totals") else {}
            if not isinstance(tm, dict):
                tm = {}
            rem = sum(1 for ts in rem_ts if lo <= ts < hi)
        except Exception:
            log.warning("scans: skipping enrichment for scan %s", s.get("id"), exc_info=True)
            tm, rem = {}, 0
        enriched.append({**s, "totals_map": tm, "remediations": rem})
    return _render("scans.html", request, user, tenant=t, scans=enriched)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail_page(request: Request, scan_id: str):
    """Drill into one scan: its own counts + the EXACT actions taken in its window (between this scan and
    the next one). Lets the operator see a scan's result and what was done about it, in one place."""
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    t = _active_tenant(request)
    scans = db.recent_scans(t["id"], 200)
    idx = next((i for i, s in enumerate(scans) if str(s["id"]) == str(scan_id)), None)
    if idx is None:
        return RedirectResponse("/scans?err=notfound", status_code=303)
    s = scans[idx]
    lo = s.get("started_at") or 0
    hi = scans[idx - 1].get("started_at") if idx > 0 else None   # window up to the next-newer scan
    hi = hi if hi is not None else float("inf")
    in_window = [a for a in db.list_audit(t["id"], 1000)
                 if a.get("ts") is not None and lo <= a["ts"] < hi]
    meta_rows = [a for a in in_window if (a.get("action") or "") in ("scan", "feed_truncated", "anomaly_detected")]
    action_rows = [a for a in in_window
                   if (a.get("action") or "").startswith(("remediate:", "paired:", "verify:", "auto:", "approval"))]
    try:
        tm = json.loads(s["totals"]) if s.get("totals") else {}
        if not isinstance(tm, dict):
            tm = {}
    except Exception:
        tm = {}
    dur = None
    if s.get("finished_at") is not None and s.get("started_at") is not None:
        dur = s["finished_at"] - s["started_at"]
    scan = {**s, "totals_map": tm, "duration": dur}
    return _render("scan_detail.html", request, user, tenant=t, scan=scan,
                   meta_rows=meta_rows, action_rows=action_rows)


@app.get("/tenants", response_class=HTMLResponse)
def tenants_page(request: Request):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    rows = [{**dict(t), "domains": ", ".join(json.loads(t["verified_domains"]))} for t in db.list_tenants()]
    return _render("tenants.html", request, user, tenant=_active_tenant(request), tenants=rows)


@app.post("/tenants")
def tenant_create(request: Request, customer_id: str = Form(...), name: str = Form(...),
                  verified_domains: str = Form(...), feed_base: str = Form(...),
                  feed_company_id: str = Form(...), feed_start_date: str = Form(...),
                  feed_api_key: str = Form(""), admin_subject: str = Form(""),
                  service_account: str = Form(""), csrf: str = Form("")):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not _check_csrf(request, csrf):
        return RedirectResponse("/tenants?err=csrf", status_code=303)
    if not auth.is_remediation_admin(user["email"]):   # creating a tenant (domains+feed key) is privileged
        db.audit(_active_tenant(request)["id"], user["email"], "tenant_create", "blocked", detail="not a remediation admin")
        return RedirectResponse("/tenants?err=forbidden", status_code=303)
    domains = [d.strip().lower() for d in verified_domains.split(",") if d.strip()]
    cid = customer_id.strip()
    # customerId is an immutable Google id (alphanumeric/underscore); require it + at least one domain
    if not cid or not cid.replace("_", "").isalnum() or not name.strip() or not domains:
        return RedirectResponse("/tenants?err=invalid", status_code=303)
    # MSSP: the per-org super-admin to impersonate MUST live in one of THIS tenant's verified domains
    # (an org can only be impersonated via its own admin; this also blocks pointing tenant A at B's domain).
    asub = admin_subject.strip().lower()
    if asub and ("@" not in asub or not connector.in_verified_domains(asub, domains)):
        return RedirectResponse("/tenants?err=adminsub", status_code=303)
    try:
        tid = db.create_tenant(cid, name.strip(), domains, feed_base.strip(),
                               feed_company_id.strip(), feed_api_key.strip(), feed_start_date.strip(),
                               admin_subject=asub, service_account=service_account.strip())
    except db.DuplicateTenantError:
        return RedirectResponse("/tenants?err=dup", status_code=303)
    # MSSP hygiene: a multi-tenant deploy where this org has no admin_subject silently inherits the global
    # one — fails safe (cross-org 403, no leak) but is a misconfiguration. Audit it once so it's visible.
    if not asub and len(db.list_tenants()) > 1:
        db.audit(tid, user["email"], "tenant_create", "warning",
                 detail="no per-tenant admin_subject in a multi-tenant deploy — falling back to the global; "
                        "set this org's own super-admin so it isn't impersonated as another org's admin")
    db.audit(tid, user["email"], "tenant_create", "ok", detail=f"{name} ({customer_id}) domains={domains}")
    return RedirectResponse("/tenants?created=1", status_code=303)


@app.post("/tenants/switch")
def tenant_switch(request: Request, tenant_id: str = Form(...), csrf: str = Form("")):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not _check_csrf(request, csrf):
        return RedirectResponse("/tenants?err=csrf", status_code=303)
    if not auth.is_remediation_admin(user["email"]):   # switching the operating tenant is privileged
        return RedirectResponse("/tenants?err=forbidden", status_code=303)
    if db.get_tenant(tenant_id):
        request.session["tenant_id"] = tenant_id
    return RedirectResponse("/", status_code=303)


@app.post("/tasks/scan")
def tasks_scan(request: Request):
    """Headless scan trigger for Cloud Scheduler (automated periodic scanning).

    NOT app-login/CSRF gated — protected at the INFRASTRUCTURE layer: deploy the service with
    --no-allow-unauthenticated and grant the scheduler's service account roles/run.invoker, so only
    its OIDC-authenticated call reaches this route. Scans EVERY tenant (headless has no session, so it
    must not depend on the session-selected tenant — it would otherwise only ever scan the first one).
    """
    if settings.scan_trigger_token and not secrets.compare_digest(
            request.headers.get("x-scan-token", ""), settings.scan_trigger_token):
        return JSONResponse({"ok": False, "error": "forbidden"}, status_code=403)
    tenants = db.list_tenants()
    if not tenants:
        return JSONResponse({"ok": False, "error": "no tenant configured"}, status_code=400)
    results = {}
    all_ok = True
    for t in tenants:
        r = service.run_scan(t, "scheduler")
        results[str(t["id"])] = r
        all_ok = all_ok and r.get("ok", False)
    return JSONResponse({"ok": all_ok, "tenants": results}, status_code=200 if all_ok else 502)


@app.post("/tasks/verify-audit")
def tasks_verify_audit(request: Request):
    """Scheduled tamper-check of the audit hash-chain for every tenant (Cloud Scheduler). Same infra +
    token guard as /tasks/scan. A broken chain (edit/deletion/reorder) is itself audited + 502'd so it
    surfaces in monitoring — turning the off-line integrity check into an active, scheduled control."""
    if settings.scan_trigger_token and not secrets.compare_digest(
            request.headers.get("x-scan-token", ""), settings.scan_trigger_token):
        return JSONResponse({"ok": False, "error": "forbidden"}, status_code=403)
    results = {}
    all_ok = True
    for t in db.list_tenants():
        v = db.verify_audit_chain(t["id"])
        results[str(t["id"])] = v
        if not v.get("ok"):
            all_ok = False
            db.audit(t["id"], "scheduler", "audit_integrity", "alert",
                     detail=f"chain verify FAILED: {v.get('reason')} @ {v.get('broken_at')}")
    return JSONResponse({"ok": all_ok, "tenants": results}, status_code=200 if all_ok else 502)


@app.get("/healthz")
def healthz():
    try:
        db.first_tenant()
        return JSONResponse({"status": "ok", "oauth": settings.oauth_configured})
    except Exception as e:
        return JSONResponse({"status": "error", "detail": str(e)}, status_code=500)
