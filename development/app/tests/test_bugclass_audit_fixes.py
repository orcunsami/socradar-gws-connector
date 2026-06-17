#!/usr/bin/env python3
"""Regression tests for the system-wide bug-class audit fixes (EXP-GOOGLE-0057):
  D: empty DEFAULT_DOMAIN -> verified_domains=[] (never [''], which matches nothing -> silent found=0).
  E: Firestore _tenant_doc backfills enabled_actions/verified_domains/feed_lookback_days/feed_high_water.
  F: connector._as_int coerces a string total_data_count instead of crashing pagination.
  G: crypto.dec RAISES on a Fernet-looking-but-undecryptable value (rotated key); passes legacy plaintext.
  B: db.cancel_active_scan aborts an in-flight scan so a config change is honored on the next scan.
  H: an approval can be reverted executed->pending via CAS (used when remediate fails after the claim).
Run from app dir: python3 tests/test_bugclass_audit_fixes.py"""
import json
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/bugclass.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0bc"
os.environ["DEFAULT_DOMAIN"] = "example.com"

from app import connector, db  # noqa: E402
from app.config import settings  # noqa: E402
import app.crypto as crypto  # noqa: E402
import app.storage_firestore as fs  # noqa: E402

P = F = 0
def chk(name, cond):
    global P, F
    print(("  PASS: " if cond else "  FAIL: ") + name)
    if cond:
        P += 1
    else:
        F += 1


db.init_db()

# F — _as_int coercion
chk("F: _as_int('5000') -> 5000", connector._as_int("5000", 0) == 5000)
chk("F: _as_int(None, 9) keeps default", connector._as_int(None, 9) == 9)
chk("F: _as_int('xyz', 7) keeps default", connector._as_int("xyz", 7) == 7)
chk("F: _as_int(42, 0) -> 42", connector._as_int(42, 0) == 42)

# E — firestore _tenant_doc backfill (no emulator; fake snapshot missing the new fields)
class _Snap:
    exists = True
    id = "C0x"
    def to_dict(self):
        return {"feed_base": "x", "feed_company_id": "1", "feed_api_key": "k", "feed_start_date": "2026-06-01"}

d = fs._tenant_doc(_Snap())
chk("E: firestore backfills enabled_actions", d.get("enabled_actions") == "[]")
chk("E: firestore backfills verified_domains", d.get("verified_domains") == "[]")
chk("E: firestore backfills feed_lookback_days", d.get("feed_lookback_days") == 0)
chk("E: firestore backfills feed_high_water", d.get("feed_high_water") == "")

# G — crypto.dec
from cryptography.fernet import Fernet  # noqa: E402
settings.fernet_key = Fernet.generate_key().decode()
crypto._fernet.cache_clear()
tok = crypto.enc("supersecret")
chk("G: enc/dec round-trip", crypto.dec(tok) == "supersecret")
chk("G: legacy plaintext (no gAAAAA) passes through", crypto.dec("plain-old-key") == "plain-old-key")
settings.fernet_key = Fernet.generate_key().decode()   # rotate
crypto._fernet.cache_clear()
raised = False
try:
    crypto.dec(tok)            # old ciphertext, new key, looks like a token -> must raise, not return garbage
except RuntimeError:
    raised = True
chk("G: rotated key on real ciphertext RAISES (no silent garbage)", raised)
settings.fernet_key = ""
crypto._fernet.cache_clear()

# D — empty DEFAULT_DOMAIN -> [] not [""]
con = sqlite3.connect(os.environ["DB_PATH"]); con.execute("DELETE FROM tenants"); con.commit(); con.close()
_old_dom = settings.default_domain
settings.default_domain = ""
db.ensure_default_tenant()
td = db.first_tenant()
chk("D: empty DEFAULT_DOMAIN -> verified_domains == [] (not [''])", json.loads(td["verified_domains"]) == [])
settings.default_domain = _old_dom
con = sqlite3.connect(os.environ["DB_PATH"]); con.execute("DELETE FROM tenants"); con.commit(); con.close()
db.ensure_default_tenant()

# B — cancel_active_scan
t = db.first_tenant()
sid, _, _ = db.claim_or_resume_scan(t["id"], time.time(), 300, "2026-06-01")
chk("B: scan claimed + active", sid is not None and db.get_active_scan(t["id"]) is not None)
chk("B: cancel_active_scan returns True", db.cancel_active_scan(t["id"]) is True)
chk("B: active scan cleared after cancel", db.get_active_scan(t["id"]) is None)

# H — approval revert mechanism (executed -> pending via CAS), used by approval_approve when remediate fails
fid = db.upsert_flagged(t["id"], "x@example.com", {"botnet"}, "found", time.time())
aid = db.create_approval(t["id"], fid, "x@example.com", "suspend", "req@example.com", time.time())
db.set_approval_state(aid, "executed", "appr@example.com", now=time.time(), expect="pending")
reverted = db.set_approval_state(aid, "pending", "appr@example.com", now=time.time(), expect="executed")
chk("H: approval reverts executed->pending (CAS)", bool(reverted) and db.get_approval(aid)["state"] == "pending")

print(f"\nRESULT: {'PASS' if F == 0 else 'FAIL'} — bug-class audit fixes ({P} ok, {F} fail)")
sys.exit(0 if F == 0 else 1)
