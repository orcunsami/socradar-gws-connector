"""Verify app/iap.py: ES256 IAP-assertion verification accepts a valid token and rejects every
tampered/forged/mismatched case. Uses a locally-generated EC key as a stand-in for Google's IAP keys."""
import json
import os
import time

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["IAP_AUDIENCE"] = "/projects/123/locations/europe-west1/services/gws-connector"
os.environ["ALLOWED_DOMAIN"] = "acme.com"

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from authlib.jose import jwt as jose_jwt

from app import iap as iapmod
from app.config import settings

# local EC P-256 keypair standing in for Google's IAP signing key
_priv = ec.generate_private_key(ec.SECP256R1())
_priv_pem = _priv.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
_pub_pem = _priv.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
KID = "testkid1"

# force the verifier to use our public key (no network)
iapmod._keys_cache["keys"] = {KID: _pub_pem.decode()}
iapmod._keys_cache["exp"] = time.time() + 9999

# keep config in sync (env may have been read before our os.environ writes)
settings.iap_audience = "/projects/123/locations/europe-west1/services/gws-connector"
settings.allowed_domain = "acme.com"
settings.iap_mode = True


def make_token(**over):
    now = int(time.time())
    claims = {
        "iss": "https://cloud.google.com/iap",
        "aud": settings.iap_audience,
        "email": "admin@acme.com",
        "iat": now, "exp": now + 600, "sub": "123",
    }
    claims.update(over)
    return jose_jwt.encode({"alg": "ES256", "kid": KID}, claims, _priv_pem).decode()


class Req:
    def __init__(self, token=None):
        self.headers = {"x-goog-iap-jwt-assertion": token} if token else {}


def run():
    P = F = 0
    def chk(name, cond):
        nonlocal P, F
        if cond: print(f"  PASS: {name}"); P += 1
        else: print(f"  FAIL: {name}"); F += 1

    # valid
    u = iapmod.iap_identity(Req(make_token()))
    chk("valid token -> email", u is not None and u["email"] == "admin@acme.com")
    chk("valid token via=iap", u is not None and u.get("via") == "iap")

    # no header
    chk("no header -> None", iapmod.iap_identity(Req()) is None)

    # wrong issuer
    chk("wrong iss -> None", iapmod.iap_identity(Req(make_token(iss="https://evil.example"))) is None)

    # wrong audience
    chk("wrong aud -> None", iapmod.iap_identity(Req(make_token(aud="/projects/999/x"))) is None)

    # expired
    chk("expired -> None", iapmod.iap_identity(Req(make_token(exp=int(time.time()) - 10))) is None)

    # wrong domain
    chk("foreign domain -> None", iapmod.iap_identity(Req(make_token(email="x@evil.com"))) is None)

    # tampered signature (flip a char in the signature segment)
    t = make_token(); parts = t.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    chk("tampered signature -> None", iapmod.iap_identity(Req(".".join(parts))) is None)

    # forged with a DIFFERENT key (attacker self-signs)
    other = ec.generate_private_key(ec.SECP256R1())
    other_pem = other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    forged = jose_jwt.encode({"alg": "ES256", "kid": KID},
                             {"iss": "https://cloud.google.com/iap", "aud": settings.iap_audience,
                              "email": "admin@acme.com", "iat": int(time.time()),
                              "exp": int(time.time()) + 600}, other_pem).decode()
    chk("forged with wrong key -> None", iapmod.iap_identity(Req(forged)) is None)

    # algorithm-confusion: forge an HS256 token using the EC PUBLIC pem as the HMAC secret
    try:
        hs = jose_jwt.encode({"alg": "HS256", "kid": KID},
                             {"iss": "https://cloud.google.com/iap", "aud": settings.iap_audience,
                              "email": "admin@acme.com", "iat": int(time.time()),
                              "exp": int(time.time()) + 600}, _pub_pem).decode()
        chk("HS256 alg-confusion -> None", iapmod.iap_identity(Req(hs)) is None)
    except Exception:
        chk("HS256 alg-confusion -> None (encode refused)", True)

    # alg=none (unsigned)
    import base64
    def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    none_tok = b64({"alg": "none", "kid": KID}) + "." + b64(
        {"iss": "https://cloud.google.com/iap", "aud": settings.iap_audience, "email": "admin@acme.com",
         "exp": int(time.time()) + 600}) + "."
    chk("alg=none -> None", iapmod.iap_identity(Req(none_tok)) is None)

    # unknown kid
    chk("unknown kid -> None",
        iapmod.iap_identity(Req(jose_jwt.encode({"alg": "ES256", "kid": "nope"},
                                                {"iss": "https://cloud.google.com/iap",
                                                 "aud": settings.iap_audience, "email": "admin@acme.com",
                                                 "iat": int(time.time()), "exp": int(time.time()) + 600},
                                                _priv_pem).decode())) is None)

    # empty audience -> verifier refuses (cannot bind token to this service)
    saved = settings.iap_audience
    settings.iap_audience = ""
    chk("empty IAP_AUDIENCE -> None (no unbound tokens)", iapmod.iap_identity(Req(make_token())) is None)
    settings.iap_audience = saved

    # missing exp -> rejected (essential)
    noexp = jose_jwt.encode({"alg": "ES256", "kid": KID},
                            {"iss": "https://cloud.google.com/iap", "aud": settings.iap_audience,
                             "email": "admin@acme.com", "iat": int(time.time())}, _priv_pem).decode()
    chk("missing exp -> None", iapmod.iap_identity(Req(noexp)) is None)

    # non-string email -> None, must NOT raise (contract)
    try:
        bad = iapmod.iap_identity(Req(make_token(email=["admin@acme.com"])))
        chk("non-string email -> None (no raise)", bad is None)
    except Exception as e:
        chk(f"non-string email raised {type(e).__name__} (BAD)", False)

    print(f"\nRESULT: {P} passed, {F} failed")
    return F == 0


if __name__ == "__main__":
    import sys
    sys.exit(0 if run() else 1)
