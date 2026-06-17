"""
IAP identity — when the service is fronted by native Cloud Run IAP (deploy/setup-iap.sh), IAP
authenticates the user at the edge and injects a signed `X-Goog-IAP-JWT-Assertion`. We VERIFY that
assertion (ES256 signature against Google's IAP public keys, issuer = https://cloud.google.com/iap,
and the configured audience) and read the user's email. In IAP mode the app runs NO "Sign in with
Google" OAuth of its own, so there is no app-side redirect_uri to mismatch. The org-domain restriction
(ALLOWED_DOMAIN) still applies on top of IAP.

No new dependency: uses authlib (already required for app OAuth) for ES256 verification and urllib for
the public-key fetch. The Workspace Admin SDK access is unaffected — that uses keyless DWD, not the
signed-in user's identity.
"""
from __future__ import annotations

import json
import time
import urllib.request

from authlib.jose import JsonWebToken

from .config import settings

# Restrict to ES256 (the algorithm IAP signs with). This is SECURITY-CRITICAL: a default JsonWebToken also
# accepts HS256/RS256, which would enable an algorithm-confusion attack (an attacker signing a forged token
# with the EC *public* key used as an HMAC secret, or downgrading to alg=none). Pinning ES256 blocks that.
_jwt = JsonWebToken(["ES256"])

_IAP_KEYS_URL = "https://www.gstatic.com/iap/verify/public_key"
_IAP_ISSUER = "https://cloud.google.com/iap"
_keys_cache: dict = {"keys": None, "exp": 0.0}


def _iap_public_keys() -> dict:
    """Fetch Google's IAP public keys ({kid: PEM}), cached for an hour."""
    now = time.time()
    if _keys_cache["keys"] and _keys_cache["exp"] > now:
        return _keys_cache["keys"]
    with urllib.request.urlopen(_IAP_KEYS_URL, timeout=5) as resp:  # noqa: S310 (fixed Google URL)
        keys = json.loads(resp.read().decode("utf-8"))
    _keys_cache["keys"] = keys
    _keys_cache["exp"] = now + 3600
    return keys


def iap_identity(request) -> dict | None:
    """Return {'email','name','via'} from a VERIFIED IAP assertion, or None if absent/invalid.

    Returns None (never raises) so callers can treat 'no valid IAP identity' uniformly.
    """
    assertion = request.headers.get("x-goog-iap-jwt-assertion")
    if not assertion:
        return None
    # `aud` is the ONLY claim binding an assertion to THIS Cloud Run service (every IAP token is signed by
    # Google's single global key and carries the same iss). Without a configured audience we CANNOT safely
    # verify, so refuse — never accept an unbound token. (validate_settings also fails startup in this case.)
    if not settings.iap_audience:
        return None
    if not settings.allowed_domain:
        return None
    try:
        keys = _iap_public_keys()

        def _load_key(header, payload):
            # pick the signing key by the JWT 'kid'; unknown kid -> verification fails
            return keys.get(header.get("kid"))

        # claims_options enforces PRESENCE + VALUE inside the cryptographically-verified path: exp must
        # exist (no never-expiring tokens) and iss/aud must equal the expected values.
        claims_options = {
            "iss": {"essential": True, "value": _IAP_ISSUER},
            "aud": {"essential": True, "value": settings.iap_audience},
            "exp": {"essential": True},
        }
        claims = _jwt.decode(assertion, _load_key, claims_options=claims_options)
        claims.validate()  # essential presence + value + exp/nbf/iat
        email = claims.get("email")
        if not isinstance(email, str):
            return None
        email = email.strip().lower()
        if not email or not email.endswith("@" + settings.allowed_domain):
            return None
        return {"email": email, "name": email, "via": "iap"}
    except Exception:
        return None
