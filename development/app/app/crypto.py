"""At-rest encryption for the per-tenant feed key (Fernet).

Opt-in: if settings.fernet_key is set, feed keys are stored encrypted (the KEK is injected from Secret
Manager on Cloud Run, pinned to a version). If unset → identity passthrough (plaintext) for local dev and
backward-compat with existing SQLite DBs.

Threat model (honest): a Fernet column defends DB-file / backup / snapshot / accidental-commit exfiltration
that does NOT also leak the runtime env. An attacker with process/env access (RCE) holds both the KEK and
the ciphertext, so this is storage-layer defense-in-depth, not a silver bullet. The KEK must be generated
ONCE (Fernet.generate_key()) and persisted — regenerating it makes every stored ciphertext undecryptable.
"""
from __future__ import annotations

from functools import lru_cache

from .config import settings


@lru_cache(maxsize=1)
def _fernet():
    key = (settings.fernet_key or "").strip()
    if not key:
        return None
    from cryptography.fernet import Fernet
    return Fernet(key.encode())  # raises if the key is not a valid 32-byte url-safe b64 key — fail fast


def enc(plaintext):
    """Encrypt a secret for storage. No-op if encryption is disabled or value is empty/None."""
    f = _fernet()
    if f is None or not plaintext:
        return plaintext
    return f.encrypt(plaintext.encode()).decode()


def dec(token):
    """Decrypt a stored secret. No-op if encryption is disabled or value is empty/None.
    Tolerates legacy plaintext (pre-encryption rows): an undecryptable value is returned as-is."""
    f = _fernet()
    if f is None or not token:
        return token
    from cryptography.fernet import InvalidToken
    try:
        return f.decrypt(token.encode()).decode()
    except InvalidToken:
        return token  # legacy plaintext written before encryption was enabled
