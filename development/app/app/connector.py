"""
Connector core — the proven SOCRadar Google Workspace loop, refactored from the CLI PoC.

Loop: SOCRadar feed (botnet/pii/vip) -> verified-domain filter -> Admin SDK users.get lookup
      -> action-gated remediation (users.signOut, + future actions).

Auth: KEYLESS domain-wide delegation (signJwt + jwt-bearer). One codebase, both environments:
  - Cloud Run / GCE: ambient metadata token (google.auth.default)
  - local: BOOTSTRAP_TOKEN env, else gcloud user token

Safety invariants enforced here (see EXP-GOOGLE-0003/0005/0009):
  - verified-domain allowlist filters BEFORE users.get (cross-domain = 403, not 404)
  - 403 is permission_denied, never collapsed to not_found
  - the impersonation/admin subject is NEVER remediated (signOut self-revoke trap)
  - feed records are sanitized on ingest: password_present bool only, never plaintext
"""
from __future__ import annotations

import json
import logging
import os
import random
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from .config import settings

log = logging.getLogger("socradar.gws.connector")

DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
# Scopes (all SENSITIVE, none restricted → no CASA). Each action requests only the one it needs;
# the union below is what the DWD client must be authorized for in admin.google.com.
SCOPE_READONLY = "https://www.googleapis.com/auth/admin.directory.user.readonly"          # lookup
SCOPE_USER     = "https://www.googleapis.com/auth/admin.directory.user"                   # reset password, suspend
SCOPE_SECURITY = "https://www.googleapis.com/auth/admin.directory.user.security"          # signOut, 2SV, tokens, asps
SCOPE_GROUP    = "https://www.googleapis.com/auth/admin.directory.group.member"           # group add/remove (narrowest)

SOC_SOURCES = {
    "botnet": "dark-web-monitoring/botnet-data/v2",
    "pii": "dark-web-monitoring/pii-exposure/v2",
    "vip": "vip-protection/v2",
}

# Remediation action catalog (Entra parity). All gated by per-tenant toggles (default OFF).
# needs_group=True actions require the tenant's quarantine_group to be set.
# Each action carries `help` (what it does / when to reach for it / its blast radius). The Settings UI
# surfaces this so an operator can tell the actions apart. Gating (which need a 2nd-admin approval, which
# never auto-fire, which auto-pair) is derived from config at render time, not hard-coded here.
ACTIONS = {
    "signout": {"label": "Revoke sessions (signOut)", "scope": SCOPE_SECURITY, "destructive": True, "needs_group": False,
        "short": "Ends all active sessions. No password change.",
        "help": "Ends every active web/mobile session and forces a fresh sign-in. Does NOT change the password or "
                "disable the account. The fastest first move on any leaked account: cuts a live attacker session "
                "in seconds. Often paired with reset_password."},
    "reset_password": {"label": "Reset password (force change)", "scope": SCOPE_USER, "destructive": True, "needs_group": False, "pairs": ["revoke_tokens", "revoke_asps"],
        "short": "New password + revokes tokens & app-passwords.",
        "help": "Sets a random password and forces a change at next login: the core fix when THE PASSWORD leaked. "
                "Auto-pairs with revoke OAuth tokens + app-passwords (a bare reset doesn't kill those, so an attacker "
                "could stay in). High-blast: needs a second-admin approval when approvals are on."},
    "suspend": {"label": "Suspend account", "scope": SCOPE_USER, "destructive": True, "needs_group": False,
        "short": "Fully disables the account (can't sign in).",
        "help": "Fully disables the account: the user cannot sign in at all (strongest containment). For a confirmed "
                "compromise where you want it frozen, not just logged out. Locks the real user out too. High-blast: "
                "needs approval and NEVER fires automatically."},
    "unsuspend": {"label": "Restore account (un-suspend)", "scope": SCOPE_USER, "destructive": False, "needs_group": False,
        "short": "Re-enables a suspended account.",
        "help": "Recovery action: re-enables a previously suspended account. Safe (non-destructive). Use after a "
                "false positive or once the incident is cleared."},
    "disable_2sv": {"label": "Turn off 2-Step Verification", "scope": SCOPE_SECURITY, "destructive": True, "needs_group": False,
        "short": "Turns off 2FA. A downgrade if used alone.",
        "help": "Removes ALL second factors. WARNING: on a leaked-PASSWORD account this is a SECURITY DOWNGRADE if "
                "used alone (the account becomes password-only, and the attacker knows the password). Only to strip an "
                "attacker-enrolled factor, and always pair with reset_password + re-enforce 2SV. Needs approval, never auto."},
    "revoke_tokens": {"label": "Revoke 3rd-party OAuth tokens", "scope": SCOPE_SECURITY, "destructive": True, "needs_group": False,
        "short": "Revokes 3rd-party OAuth app access.",
        "help": "Revokes every 3rd-party app's OAuth access (Gmail/Drive grants etc.): closes the door a password reset "
                "alone leaves open. Runs automatically as part of reset_password; enable standalone to revoke app access "
                "without resetting the password."},
    "revoke_asps": {"label": "Revoke app-specific passwords", "scope": SCOPE_SECURITY, "destructive": True, "needs_group": False,
        "short": "Revokes app-specific passwords (legacy clients).",
        "help": "Revokes all app-specific passwords (legacy IMAP/SMTP clients that bypass 2SV). Also runs automatically "
                "with reset_password: those credentials survive a normal reset otherwise."},
    "add_to_group": {"label": "Add to quarantine group", "scope": SCOPE_GROUP, "destructive": True, "needs_group": True,
        "short": "Adds to your quarantine group (tighter policy).",
        "help": "Adds the user to your quarantine Google Group so group-scoped policies (tighter DLP, blocked external "
                "sharing) apply. Requires a quarantine group set in Settings. Containment without locking the account out."},
    "remove_from_group": {"label": "Remove from quarantine group", "scope": SCOPE_GROUP, "destructive": False, "needs_group": True,
        "short": "Removes from the quarantine group.",
        "help": "Recovery action: removes the user from the quarantine group once the incident is cleared. Safe "
                "(non-destructive). Requires a quarantine group set in Settings."},
}

# The full minimal scope set the DWD client must be authorized for (union of all actions + lookup).
SCOPES_UNION = [SCOPE_READONLY, SCOPE_USER, SCOPE_SECURITY, SCOPE_GROUP]


class ConnectorError(Exception):
    pass


# ---------- HTTP with bounded retry/backoff ----------
def _urlopen(req, timeout=40, retries=3):
    """urlopen with bounded retry: honor Retry-After on 429, retry 5xx + transient network errors with
    backoff. 4xx (401/403/404) raise immediately so callers keep their status semantics. Transient
    failures after the budget raise ConnectorError (never an uncaught URLError that 500s / zombies a scan)."""
    last = None
    for attempt in range(retries):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code == 429 or 500 <= e.code < 600:
                ra = e.headers.get("Retry-After") if e.headers else None
                # honor Retry-After but CAP it: a hostile/misconfigured 'Retry-After: 3600' must not stall
                # the synchronous request worker for an hour. Bounded to 30s (< the 40s socket timeout).
                # jitter (<=1s) on the computed backoff so concurrent retries don't thunder together
                delay = min(float(ra), 30) if ra and str(ra).isdigit() else min(2 ** attempt, 8) + random.uniform(0, 1)
                if attempt < retries - 1:
                    last = e
                    time.sleep(delay)
                    continue
            raise                                   # 4xx -> caller inspects (403=denied, 404=not_found)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            if attempt < retries - 1:
                time.sleep(min(2 ** attempt, 8) + random.uniform(0, 1))
                continue
            raise ConnectorError(f"network error after {retries} attempts: {e}") from e
    raise ConnectorError(f"request failed: {last}")


def _req(url, data, headers, method="POST"):
    try:
        return json.load(_urlopen(urllib.request.Request(url, data=data, headers=headers, method=method)))
    except ValueError as e:                          # malformed/non-JSON body -> clean error, never a 500
        raise ConnectorError(f"invalid JSON from {url}: {e}") from e


def _get(url, headers):
    try:
        return json.load(_urlopen(urllib.request.Request(url, headers=headers)))
    except ValueError as e:
        raise ConnectorError(f"invalid JSON from {url}: {e}") from e


_METADATA_TOKEN_URL = ("http://metadata.google.internal/computeMetadata/v1/"
                       "instance/service-accounts/default/token")


def _bootstrap_token() -> str:
    """cloud-platform token that AUTHORIZES the signJwt call (not the DWD token itself).

    Cloud Run / GCE: ambient token straight from the metadata server. We deliberately do NOT use
    google.auth.transport.requests (its Request transport needs the `requests` package, which is not
    a Cloud Run runtime dep — that mismatch silently fell through to the gcloud path and broke the
    real Cloud Run deploy). Metadata-direct needs only urllib. Local: gcloud user token.
    """
    tok = os.environ.get("BOOTSTRAP_TOKEN")
    if tok:
        return tok.strip()
    try:  # Cloud Run / GCE ambient identity
        req = urllib.request.Request(_METADATA_TOKEN_URL, headers={"Metadata-Flavor": "Google"})
        return json.load(urllib.request.urlopen(req, timeout=5))["access_token"]
    except (urllib.error.URLError, OSError, KeyError, ValueError):
        pass
    return subprocess.check_output([settings.gcloud_path, "auth", "print-access-token"]).decode().strip()


def get_dwd_token(scopes: list[str], subject: str = None, service_account: str = None) -> str:
    """Keyless DWD: bootstrap token -> signJwt(SA, subject) -> jwt-bearer exchange -> access token.

    MSSP: subject (the impersonated super-admin) and service_account (the signer SA) are per-tenant.
    Both default to the global config when None/empty, so a single-org caller that passes nothing behaves
    exactly as before. The SA must be substituted in BOTH the iss claim AND the signJwt URL path."""
    sa = service_account or settings.service_account
    sub = subject or settings.admin_subject
    try:
        user_tok = _bootstrap_token()
        now = int(time.time())
        claims = {"iss": sa, "sub": sub,
                  "scope": " ".join(scopes), "aud": "https://oauth2.googleapis.com/token",
                  "iat": now, "exp": now + 3600}
        signed = _req(
            f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:signJwt",
            json.dumps({"payload": json.dumps(claims)}).encode(),
            {"Authorization": f"Bearer {user_tok}", "Content-Type": "application/json"})["signedJwt"]
        return _req("https://oauth2.googleapis.com/token",
                    urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                            "assertion": signed}).encode(),
                    {"Content-Type": "application/x-www-form-urlencoded"})["access_token"]
    except urllib.error.HTTPError as e:
        raise ConnectorError(f"DWD token failed (HTTP {e.code}): {e.read().decode()[:200]}") from e
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
        raise ConnectorError("DWD bootstrap failed — gcloud token dead/missing? run `gcloud auth login`") from e


# ---------- feed ----------
def _as_int(v, default):
    """Coerce a feed-supplied count to int. The pagination stop uses `page*limit >= total`, so a string
    total_data_count (API drift / proxy) would raise TypeError mid-scan — fall back to the running default."""
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _raise_feed_http_error(source, e):
    """Always raises a ConnectorError. Distinguishes a feed-SERVER outage (5xx, transient — wait) from a config
    error (401/403 — fix the key/company id), so the operator never thinks the connector or their setup is broken
    during a SOCRadar feed outage. A 502/503/504 means the connector REACHED the feed and got an error RESPONSE
    (not a network/DNS failure). Used by BOTH feed paths (socradar_fetch + stream_source) so they never diverge."""
    if e.code >= 500:
        raise ConnectorError(
            f"the SOCRadar feed is temporarily unavailable (HTTP {e.code} from its gateway for {source}) — "
            f"this is a feed-server outage, not the connector or your config; retry when the feed is back"
        ) from e
    hint = " — check the feed API key / company id" if e.code in (401, 403) else ""
    raise ConnectorError(f"feed {source} HTTP {e.code}{hint}: {e.read().decode()[:140]}") from e


def socradar_fetch(base, company_id, api_key, source, start_date, limit=None, max_pages=None):
    """Fetch one SOCRadar source. Sanitizes: only password_present kept, never plaintext. Returns
    (records, total, processed, truncated): `processed` = how many records we actually paged through,
    `truncated` = True if we hit max_pages while total>processed (so the caller NEVER reports a coverage
    it didn't achieve). Transient errors come back as ConnectorError (not an uncaught URLError)."""
    limit = limit or settings.feed_page_limit
    max_pages = max_pages or settings.feed_max_pages
    path = SOC_SOURCES[source]
    url = f"{base}/api/company/{company_id}/{path}"
    headers = {"API-Key": api_key, "Content-Type": "application/json", "User-Agent": "SOCRadar-GWS/1.0"}
    out, page, total, processed = [], 1, 0, 0
    while page <= max_pages:
        q = urllib.parse.urlencode({"page": page, "limit": limit, "startDate": start_date})
        try:
            r = _get(url + "?" + q, headers)          # _get retries 429/5xx/transient, raises ConnectorError
        except urllib.error.HTTPError as e:
            _raise_feed_http_error(source, e)
        if not isinstance(r, dict) or not r.get("is_success"):
            raise ConnectorError(f"feed {source} bad response: {str(r)[:120]}")
        payload = r.get("data") or {}
        recs = payload.get("data") or []
        if not isinstance(recs, list):                # malformed body -> clean error, never a crash
            raise ConnectorError(f"feed {source} data not a list: {type(recs).__name__}")
        total = _as_int(payload.get("total_data_count"), total)
        processed += len(recs)
        for rec in recs:
            # VIP records put the monitored value in `keyword` (can be an email) — read it too.
            email = (rec.get("email") or rec.get("user") or rec.get("keyword") or "").strip().lower()
            if "@" not in email:          # keyword may be a name/domain (no @) -> only email values are actionable
                continue
            # alarmId closes the parent SOCRadar alarm later (Incident V4 — close by alarm id, no email)
            out.append({"email": email, "source": source,
                        "password_present": bool(rec.get("password")), "alarm_id": rec.get("alarmId")})
        # stop when a page comes back empty (always), or once we've paged past the reported total.
        # Guard `total`: if the API omits total_data_count it stays 0 — DON'T treat 0 as "done after page 1"
        # (that would silently drop pages 2+ and still report truncated=False). Page until recs run out.
        if not recs or (total and page * limit >= total):
            break
        page += 1
        time.sleep(0.5)
    truncated = (page > max_pages) and (total > processed)
    return out, total, processed, truncated


def stream_source(base, company_id, api_key, source, start_date, start_page=1, page_limit=None):
    """Streaming generator over ONE feed source (ADR-0001): yields (page_no, records, total) page by page
    from start_page, NEVER buffering the whole feed. `records` are sanitized ({email, source,
    password_present, alarm_id}); only @-emails are kept. Pages until a page is empty or we've passed
    total_data_count (NO 5,000-record truncation — the caller bounds the per-invocation budget). The
    page-number cursor is safe for resume because the verified-domain filter + idempotent (tenant,email)
    upsert make re-paging an overlap harmless (EXP-GOOGLE-0009: startDate is a discovery-date high-water mark)."""
    limit = page_limit or settings.feed_page_limit
    path = SOC_SOURCES[source]
    url = f"{base}/api/company/{company_id}/{path}"
    headers = {"API-Key": api_key, "Content-Type": "application/json", "User-Agent": "SOCRadar-GWS/1.0"}
    page, total = start_page, 0
    hard_cap = settings.feed_hard_page_cap or 10**9
    while True:
        if page > hard_cap:        # runaway backstop: a feed that never reports total + never returns empty
            log.warning("feed %s: hit hard page cap (%s) — stopping (coverage may be partial)", source, hard_cap)
            break
        q = urllib.parse.urlencode({"page": page, "limit": limit, "startDate": start_date})
        try:
            r = _get(url + "?" + q, headers)          # _get retries 429/5xx/transient + honors Retry-After
        except urllib.error.HTTPError as e:
            _raise_feed_http_error(source, e)
        if not isinstance(r, dict) or not r.get("is_success"):
            raise ConnectorError(f"feed {source} bad response: {str(r)[:120]}")
        payload = r.get("data") or {}
        recs = payload.get("data") or []
        if not isinstance(recs, list):
            raise ConnectorError(f"feed {source} data not a list: {type(recs).__name__}")
        total = _as_int(payload.get("total_data_count"), total)
        if not recs:
            break                                    # RAW-empty page = source exhausted -> stop BEFORE yielding
        # `out` may be empty even though `recs` is not (a page of keyword-only / non-@ records, e.g. VIP brand
        # monitors). We STILL yield it so the consumer advances the cursor past it and reaches later pages that
        # DO carry @-emails — never treat a sanitized-empty page as end-of-source (that silently drops data).
        out = []
        for rec in recs:
            email = (rec.get("email") or rec.get("user") or rec.get("keyword") or "").strip().lower()
            if "@" not in email:
                continue
            out.append({"email": email, "source": source,
                        "password_present": bool(rec.get("password")), "alarm_id": rec.get("alarmId")})
        yield page, out, total
        if total and page * limit >= total:
            break                                    # paged past the reported total -> done (no extra fetch)
        page += 1
        time.sleep(0.5)                              # politeness between pages (feed 429 protection)


def fetch_all_sources(base, company_id, api_key, start_date):
    """Returns (by_email: {email: set(sources)}, totals: {source: total}, alarms_by_email: {email:[alarmId]},
               coverage: {source: {processed, total, truncated}}). `coverage` lets the caller report
               HONEST coverage — if a source was truncated, the UI must not claim it processed the full total."""
    by_email: dict[str, set] = {}
    totals: dict[str, int] = {}
    alarms_by_email: dict[str, list] = {}
    coverage: dict[str, dict] = {}
    for src in SOC_SOURCES:
        recs, total, processed, truncated = socradar_fetch(base, company_id, api_key, src, start_date)
        totals[src] = total
        coverage[src] = {"processed": processed, "total": total, "truncated": truncated}
        for r in recs:
            by_email.setdefault(r["email"], set()).add(src)
            aid = r.get("alarm_id")
            lst = alarms_by_email.setdefault(r["email"], [])
            if aid is not None and aid not in lst:
                lst.append(aid)
    return by_email, totals, alarms_by_email, coverage


# ---------- SOCRadar write-back: close the alarm after remediation (close the loop) ----------
# Incident API V4 — VERIFIED LIVE on preprod (close + restore):
#   POST {base}/api/company/{cid}/alarms/status/change   body {alarm_ids:[int], status:int, comments?}
# status: 0=OPEN, 1=INVESTIGATING, 2=RESOLVED (close), 9=FALSE_POSITIVE, 12=MITIGATED.
# Closes by ALARM ID (every botnet/pii feed record carries alarmId) — NO operator email, ONE endpoint.
def socradar_close_alarms(base, company_id, api_key, alarm_ids, status=2,
                          comment="Remediated via SOCRadar GWS connector"):
    """Best-effort resolve of the parent SOCRadar alarm(s) by id. status=2=RESOLVED. Returns
    {ok: bool, message: str}; NEVER raises (a SOCRadar failure must not undo the Google remediation)."""
    ids = [a for a in (alarm_ids or []) if a is not None]
    if not ids:
        return {}
    headers = {"API-Key": api_key, "Content-Type": "application/json", "User-Agent": "SOCRadar-GWS/1.0"}
    body = {"alarm_ids": ids, "status": status, "comments": comment}
    try:
        r = _req(f"{base}/api/company/{company_id}/alarms/status/change", json.dumps(body).encode(), headers)
        return {"ok": bool(r.get("is_success")), "message": r.get("message")}
    except urllib.error.HTTPError as e:
        return {"ok": False, "message": f"HTTP {e.code}: {e.read().decode()[:120]}"}
    # include ConnectorError: _req raises it on transient-after-retries / bad JSON. Catch it here so this
    # function honors its "NEVER raises" contract (a SOCRadar write-back failure must not bubble up and
    # undo / mask the already-successful Google remediation).
    except (ConnectorError, urllib.error.URLError, OSError, ValueError) as e:
        return {"ok": False, "message": str(e)}


# ---------- directory ----------
def in_verified_domains(email: str, domains: list[str]) -> bool:
    return email.split("@")[-1].lower() in {d.lower() for d in domains}


def lookup_user(email: str, token: str) -> str:
    """Returns found / not_found / permission_denied / error_NNN / error_transient. Never collapse 403 ->
    not_found (cross-domain = 403). A transient network error is NOT a real not_found — it's flagged
    error_transient so the UI doesn't mark an exposed user 'not in directory' on a blip."""
    try:
        _get(f"{DIRECTORY}/users/{urllib.parse.quote(email)}", {"Authorization": f"Bearer {token}"})
        return "found"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "not_found"
        if e.code == 403:
            return "permission_denied"
        return f"error_{e.code}"
    except ConnectorError:                            # transient network/JSON after retries (from _get)
        return "error_transient"


def is_admin(email: str, token: str):
    """Is the target a Workspace admin (super or delegated)? Three-state (arastirma9 §F1 — must FAIL CLOSED):
      True  -> definitely an admin (refuse remediation)
      False -> definitely NOT an admin (safe to proceed)
      None  -> could NOT determine (caller must FAIL CLOSED, not silently proceed).
    Refusing on admins matters because a custom-role (non-super) subject 403s on admins anyway, and locking
    out IT is dangerous. A 403 on this readonly pre-check often MEANS the target is an admin a custom-role
    can't read — so we return None (indeterminate -> refuse), never a false 'not an admin'."""
    try:
        u = _api("GET", f"{DIRECTORY}/users/{urllib.parse.quote(email)}?fields=isAdmin,isDelegatedAdmin", token)
        return bool(u.get("isAdmin") or u.get("isDelegatedAdmin"))
    except Exception:
        return None   # indeterminate — never collapse to False (that re-introduces the fail-open hole)


def revoke_sessions(email: str, token: str) -> bool:
    try:
        _api("POST", f"{DIRECTORY}/users/{urllib.parse.quote(email)}/signOut", token)
        return True
    except urllib.error.HTTPError:
        return False


def _api(method: str, url: str, token: str, body=None):
    """Generic Admin SDK call. body=None -> empty request body. Returns parsed JSON or {} (empty resp).
    Goes through _urlopen (bounded retry/backoff) so a single transient 429/503 doesn't fail a remediation;
    4xx still raise immediately, so callers keep idempotency semantics (409 already-member, 404 not-member)."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    resp = _urlopen(urllib.request.Request(url, data=data, headers=headers, method=method))
    raw = resp.read()
    return json.loads(raw) if raw else {}


def reset_password(email: str, token: str) -> bool:
    # PATCH (partial) so other User fields aren't clobbered. Random throwaway; user must change at login.
    body = {"password": secrets.token_urlsafe(18), "changePasswordAtNextLogin": True}
    _api("PATCH", f"{DIRECTORY}/users/{urllib.parse.quote(email)}", token, body)
    return True  # NOTE: does not kill live sessions — pair with signout for hard lockout


def suspend_user(email: str, token: str) -> bool:
    _api("PATCH", f"{DIRECTORY}/users/{urllib.parse.quote(email)}", token, {"suspended": True})
    return True  # NOTE: session cutoff is not instant (~1h Gmail web) — pair with signout if hard revoke needed


def unsuspend_user(email: str, token: str) -> bool:
    # reverse of suspend — re-enable a suspended account to recover a false positive. PATCH (partial),
    # same endpoint and scope as suspend; non-destructive recovery action (Entra enable_account parity).
    _api("PATCH", f"{DIRECTORY}/users/{urllib.parse.quote(email)}", token, {"suspended": False})
    return True


def disable_2sv(email: str, token: str) -> bool:
    # POST, empty body. De-enrolls the user's 2SV factors. (If 2SV is policy-ENFORCED, change the policy.)
    _api("POST", f"{DIRECTORY}/users/{urllib.parse.quote(email)}/twoStepVerification/turnOff", token)
    return True


def revoke_oauth_tokens(email: str, token: str) -> bool:
    # list-then-delete; DELETE key is the OAuth clientId; one DELETE wipes all tokens for that app.
    u = urllib.parse.quote(email)
    listing = _api("GET", f"{DIRECTORY}/users/{u}/tokens", token)
    for t in listing.get("items", []):
        cid = t.get("clientId")
        if cid:
            _api("DELETE", f"{DIRECTORY}/users/{u}/tokens/{urllib.parse.quote(cid)}", token)
    return True


def revoke_asps(email: str, token: str) -> bool:
    # list-then-delete; DELETE key is the integer codeId. items[] may be absent when none exist.
    u = urllib.parse.quote(email)
    listing = _api("GET", f"{DIRECTORY}/users/{u}/asps", token)
    for a in listing.get("items", []):
        cid = a.get("codeId")
        if cid is not None:
            _api("DELETE", f"{DIRECTORY}/users/{u}/asps/{cid}", token)
    return True


def add_to_group(email: str, group: str, token: str) -> bool:
    if not group:
        raise ConnectorError("no quarantine group configured for this tenant")
    # member goes in the BODY (no memberKey in path). 409 = already a member -> idempotent success.
    try:
        _api("POST", f"{DIRECTORY}/groups/{urllib.parse.quote(group)}/members", token,
             {"email": email, "role": "MEMBER"})
        return True
    except urllib.error.HTTPError as e:
        if e.code == 409:
            return True
        raise


def remove_from_group(email: str, group: str, token: str) -> bool:
    if not group:
        raise ConnectorError("no quarantine group configured for this tenant")
    # member goes in the PATH, empty body. 404 = not a member -> idempotent success.
    try:
        _api("DELETE", f"{DIRECTORY}/groups/{urllib.parse.quote(group)}/members/{urllib.parse.quote(email)}", token)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True
        raise


_ACTION_FNS = {
    "signout":           lambda email, token, group: revoke_sessions(email, token),
    "reset_password":    lambda email, token, group: reset_password(email, token),
    "suspend":           lambda email, token, group: suspend_user(email, token),
    "unsuspend":         lambda email, token, group: unsuspend_user(email, token),
    "disable_2sv":       lambda email, token, group: disable_2sv(email, token),
    "revoke_tokens":     lambda email, token, group: revoke_oauth_tokens(email, token),
    "revoke_asps":       lambda email, token, group: revoke_asps(email, token),
    "add_to_group":      lambda email, token, group: add_to_group(email, group, token),
    "remove_from_group": lambda email, token, group: remove_from_group(email, group, token),
}


def apply_action(action: str, email: str, token: str, group: str = None) -> bool:
    fn = _ACTION_FNS.get(action)
    if not fn:
        raise ConnectorError(f"unknown action: {action}")
    try:
        return fn(email, token, group)
    except ConnectorError:
        raise  # e.g. missing quarantine group -> let the service surface a clean message
    except (urllib.error.URLError, OSError, ValueError):
        return False  # HTTPError/timeout/DNS/JSON decode -> clean failure, never a 500


def verify_action_effect(action: str, email: str, token: str, group: str = None) -> str:
    """Post-state verification: re-read directory state after a successful action to CONFIRM the effect
    actually landed (execution != effect). Returns 'confirmed' | 'failed' | 'unverifiable'. Best-effort —
    only actions with a queryable persistent state are checked; events (signout/reset/token-revoke) have
    no post-state to read, so they're 'unverifiable'. Never raises."""
    u = urllib.parse.quote(email)
    try:
        if action == "suspend":
            r = _api("GET", f"{DIRECTORY}/users/{u}?fields=suspended", token)
            return "confirmed" if r.get("suspended") is True else "failed"
        if action == "unsuspend":
            r = _api("GET", f"{DIRECTORY}/users/{u}?fields=suspended", token)
            return "confirmed" if r.get("suspended") is False else "failed"
        if action in ("add_to_group", "remove_from_group") and group:
            g = urllib.parse.quote(group)
            try:
                _api("GET", f"{DIRECTORY}/groups/{g}/members/{u}", token)
                present = True
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    present = False
                else:
                    return "unverifiable"
            want_present = action == "add_to_group"
            return "confirmed" if present == want_present else "failed"
    except (urllib.error.URLError, OSError, ValueError):
        return "unverifiable"
    return "unverifiable"
