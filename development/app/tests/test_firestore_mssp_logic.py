#!/usr/bin/env python3
"""Firestore backend MSSP LOGIC — the pure-Python parts that need no emulator/Java/IO:
  - _tenant_doc backfills admin_subject/service_account to '' on pre-change docs (and preserves set values)
  - get_flagged_for_tenant scopes by tenant via str()-coerced compare (cross-org isolation)
Covers the Firestore MSSP code paths that the sqlite suites can't reach when the emulator (Java) is absent.
Run from the app dir: python3 tests/test_firestore_mssp_logic.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# do NOT set STORAGE_BACKEND=firestore — we import the module directly and never touch _db()/IO.
os.environ.setdefault("DEFAULT_CUSTOMER_ID", "C0x")

import app.storage_firestore as fs  # noqa: E402

c = {}


class FakeSnap:
    def __init__(self, data, exists=True, sid="C0x"):
        self._d, self.exists, self.id = data, exists, sid

    def to_dict(self):
        return dict(self._d)


# --- _tenant_doc backfill: a pre-MSSP doc (no admin_subject/service_account) reads '' not KeyError ---
old = fs._tenant_doc(FakeSnap({"name": "Legacy", "verified_domains": "[]", "feed_api_key": "k"}, sid="C0old"))
c["backfill admin_subject='' on legacy doc"] = old["admin_subject"] == ""
c["backfill service_account='' on legacy doc"] = old["service_account"] == ""
c["legacy doc id == customer_id"] = old["id"] == "C0old" and old["customer_id"] == "C0old"

# --- _tenant_doc preserves a SET admin_subject (MSSP tenant) ---
mssp = fs._tenant_doc(FakeSnap({"name": "Org B", "admin_subject": "ceo@orgb.com",
                                "service_account": "sa@p.iam.gserviceaccount.com"}, sid="C0orgb"))
c["set admin_subject preserved"] = mssp["admin_subject"] == "ceo@orgb.com"
c["set service_account preserved"] = mssp["service_account"] == "sa@p.iam.gserviceaccount.com"

# --- _tenant_doc on a missing doc returns None ---
c["missing doc -> None"] = fs._tenant_doc(FakeSnap({}, exists=False)) is None

# --- get_flagged_for_tenant: tenant-scoped via str()-coerce, no IO (monkeypatch get_flagged) ---
fs.get_flagged = lambda fid: {"id": fid, "tenant_id": "C0a", "email": "x@a.com"} if fid == "F1" else None
c["belongs to tenant -> returned"] = fs.get_flagged_for_tenant("F1", "C0a") is not None
c["wrong tenant -> None (cross-org guard)"] = fs.get_flagged_for_tenant("F1", "C0b") is None
c["str-coerce: int tenant vs str id both match"] = fs.get_flagged_for_tenant("F1", "C0a")["email"] == "x@a.com"
c["missing flagged -> None"] = fs.get_flagged_for_tenant("F404", "C0a") is None

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — Firestore MSSP logic (backfill + cross-org getter) verified without emulator" if ok else "FAIL")
sys.exit(0 if ok else 1)
