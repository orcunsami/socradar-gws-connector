"""
Admin sign-in via Google OAuth (Authlib). Internal restriction: the signed-in user's `hd`
(hosted-domain) claim must equal ALLOWED_DOMAIN — this is what makes the app effectively
Internal-user-type (only the org's own admins get in).

DEV_LOGIN=true is a local-only escape hatch to work without an OAuth client; it logs you in as
ADMIN_SUBJECT. It refuses to run unless DEV_LOGIN is explicitly true (never enable in prod).
"""
from __future__ import annotations

from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request
from starlette.responses import RedirectResponse

from .config import settings

oauth = OAuth()
if settings.oauth_configured:
    oauth.register(
        name="google",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile", "hd": settings.allowed_domain},
    )


def current_user(request: Request) -> dict | None:
    return request.session.get("user")


def is_remediation_admin(email: str) -> bool:
    """RBAC: only these principals may run DESTRUCTIVE remediation (signing in / triage is broader).
    Separates 'can reach + authenticate' from 'authorized to lock/suspend accounts'."""
    return (email or "").strip().lower() in settings.remediation_admin_list


def require_login(request: Request) -> dict:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=307, detail="login required",
                            headers={"Location": "/login"})
    return user


async def start_login(request: Request):
    if settings.dev_login_active:   # honored only off-Cloud-Run + APP_ENV=dev (config.dev_login_active)
        request.session["user"] = {"email": settings.admin_subject, "name": "Dev Admin", "dev": True}
        return RedirectResponse("/", status_code=303)
    if not settings.oauth_configured:
        raise HTTPException(503, "Sign-in is not configured. Set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET "
                                 "(a Web OAuth client with this service's /auth/callback URL), then redeploy.")
    # Behind `gcloud run services proxy` the request Host is the *.run.app URL, so request.url_for would
    # emit a redirect that is neither registered nor browser-reachable. Use the configured base (the URL the
    # browser actually uses, e.g. http://localhost:8080 for a local proxy). Empty -> derive from the request
    # (correct only when reached directly, e.g. behind IAP on its real URL).
    base = (settings.oauth_redirect_base or "").rstrip("/")
    redirect_uri = f"{base}/auth/callback" if base else str(request.url_for("auth_callback"))
    return await oauth.google.authorize_redirect(request, redirect_uri)


async def finish_login(request: Request):
    token = await oauth.google.authorize_access_token(request)
    info = token.get("userinfo") or {}
    email = (info.get("email") or "").lower()
    hd = info.get("hd")
    # Internal restriction: enforce the org domain on both hd claim and email domain.
    if hd != settings.allowed_domain and not email.endswith("@" + settings.allowed_domain):
        raise HTTPException(403, f"only {settings.allowed_domain} accounts may sign in")
    if not info.get("email_verified", False):
        raise HTTPException(403, "email not verified")
    request.session["user"] = {"email": email, "name": info.get("name", email)}
    return RedirectResponse("/", status_code=303)


def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse("/login", status_code=303)
