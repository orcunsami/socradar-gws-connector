#!/usr/bin/env python3
"""
Firestore backend round-trip + isolation test against the Firestore EMULATOR (billing-free, no real
project, no credentials). SKIPS gracefully (exit 0) if FIRESTORE_EMULATOR_HOST is unset or the emulator
port is unreachable, so it never fails CI without the emulator.

Run with the emulator:
    gcloud emulators firestore start --host-port=localhost:8090 &
    FIRESTORE_EMULATOR_HOST=localhost:8090 GOOGLE_CLOUD_PROJECT=demo-test python3 tests/test_firestore.py
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_host = os.environ.get("FIRESTORE_EMULATOR_HOST", "")
if not _host:
    print("SKIP — FIRESTORE_EMULATOR_HOST not set (emulator not running). Firestore backend not exercised.")
    sys.exit(0)
try:
    h, p = _host.split(":")
    socket.create_connection((h, int(p)), 2).close()
except OSError:
    print(f"SKIP — emulator at {_host} unreachable.")
    sys.exit(0)

os.environ["STORAGE_BACKEND"] = "firestore"
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "demo-test")
os.environ["DEFAULT_CUSTOMER_ID"] = "C0fs"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["FEED_API_KEY"] = "fs-feed-key"

from app import db  # noqa: E402  (picks the firestore backend)
from app.storage_base import DuplicateTenantError  # noqa: E402

c = {}
db.init_db()                                              # seeds default tenant
t = db.first_tenant()
c["init+first_tenant"] = bool(t) and t["customer_id"] == "C0fs"
c["tenant id == customer_id (firestore)"] = t["id"] == "C0fs"
c["feed key round-trips"] = t["feed_api_key"] == "fs-feed-key"

# second tenant + isolation
db.create_tenant("C0other", "Other", ["other.com"], "https://x", "9", "k9", "2026-01-01")
c["list_tenants has 2"] = len(db.list_tenants()) == 2
try:
    db.create_tenant("C0fs", "dup", ["example.com"], "https://x", "1", "k", "2026-01-01")
    c["DuplicateTenantError raised"] = False
except DuplicateTenantError:
    c["DuplicateTenantError raised"] = True

# flagged CRUD + url-safe deterministic id
fid = db.upsert_flagged("C0fs", "victim@example.com", {"botnet", "pii"}, "found", 1.0)
c["flagged id url-safe (no @/|)"] = "@" not in fid and "|" not in fid
db.upsert_flagged("C0fs", "victim@example.com", {"botnet"}, "found", 2.0)   # upsert same -> 1 doc
flg = db.list_flagged("C0fs")
c["upsert idempotent (1 flagged)"] = len(flg) == 1 and flg[0]["id"] == fid
c["isolation: other tenant has 0 flagged"] = len(db.list_flagged("C0other")) == 0
got = db.get_flagged(fid)
c["get_flagged by id"] = got and got["email"] == "victim@example.com"
db.mark_remediated(fid, 3.0)
c["mark_remediated"] = db.get_flagged(fid)["status"] == "remediated"
c["flagged_counts"] = db.flagged_counts("C0fs").get("remediated") == 1

# scans + audit
sid = db.start_scan("C0fs", 10.0)
db.finish_scan(sid, 11.0, totals={"botnet": 1}, found=1, unique=1)
ls = db.last_scan("C0fs")
c["scan run persisted"] = ls and ls["found_count"] == 1
db.audit("C0fs", "admin@example.com", "scan", "ok", detail="x")
au = db.list_audit("C0fs")
c["audit persisted + isolated"] = len(au) >= 1 and len(db.list_audit("C0other")) == 0

# --- MSSP on the Firestore backend (per-tenant identity + cross-org getter) ---
tmssp = db.create_tenant("C0mssp", "MSSP Org", ["mssp-org.com"], "https://x", "5", "kk", "2026-01-01",
                         admin_subject="ceo@mssp-org.com", service_account="sa@proj.iam.gserviceaccount.com")
mt = db.get_tenant("C0mssp")
c["MSSP: admin_subject persists (firestore)"] = mt["admin_subject"] == "ceo@mssp-org.com"
c["MSSP: service_account persists (firestore)"] = mt["service_account"] == "sa@proj.iam.gserviceaccount.com"
# backfill: the env-seeded default tenant (created before MSSP fields) reads '' not KeyError
c["MSSP: legacy default tenant backfills admin_subject=''"] = db.get_tenant("C0fs")["admin_subject"] == ""
# cross-org by-id guard on firestore: C0fs's flagged id is invisible to C0mssp
c["MSSP: get_flagged_for_tenant scopes by tenant (firestore)"] = (
    db.get_flagged_for_tenant(fid, "C0mssp") is None and db.get_flagged_for_tenant(fid, "C0fs") is not None)

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — Firestore backend (emulator) round-trip + isolation verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
