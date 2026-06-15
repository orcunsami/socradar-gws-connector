#!/usr/bin/env python3
"""MSSP Layer 1: per-tenant admin_subject/service_account storage + migration + backward-compat.
No gcloud/network. Run from the app dir: python3 tests/test_mssp_schema.py"""
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/mssp.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0def"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "operator@example.com"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"

import app.config as cfg  # noqa: E402
import importlib
importlib.reload(cfg)
from app import db  # noqa: E402
from app.storage_sqlite import conn  # noqa: E402

c = {}
db.init_db()

# --- 1) schema has the two new columns ---
with conn() as cx:
    cols = [r["name"] for r in cx.execute("PRAGMA table_info(tenants)").fetchall()]
c["admin_subject column exists"] = "admin_subject" in cols
c["service_account column exists"] = "service_account" in cols

# --- 2) the env-seeded default tenant leaves them blank (inherits global) ---
dt = db.first_tenant()
c["default tenant admin_subject blank"] = dt["admin_subject"] == ""
c["default tenant service_account blank"] = dt["service_account"] == ""

# --- 3) 7-positional-arg create_tenant still works (backward-compat) ---
tid = db.create_tenant("C0seven", "Legacy Co", ["legacy.com"], "https://x", "1", "k", "2026-01-01")
leg = db.get_tenant(tid)
c["7-arg create works"] = leg is not None and leg["admin_subject"] == "" and leg["service_account"] == ""

# --- 4) MSSP path: create with per-org identity, round-trips verbatim ---
tid2 = db.create_tenant("C0orgb", "Org B", ["orgb.com"], "https://x", "2", "k", "2026-01-01",
                        admin_subject="super@orgb.com", service_account="sa-b@projb.iam.gserviceaccount.com")
b = db.get_tenant(tid2)
c["MSSP admin_subject persisted"] = b["admin_subject"] == "super@orgb.com"
c["MSSP service_account persisted"] = b["service_account"] == "sa-b@projb.iam.gserviceaccount.com"
c["feed_api_key still decrypts (encryption boundary intact)"] = b["feed_api_key"] == "k"

# --- 5) update_tenant can set admin_subject later (edit path) ---
db.update_tenant(tid, admin_subject="fixed@legacy.com")
c["update_tenant sets admin_subject"] = db.get_tenant(tid)["admin_subject"] == "fixed@legacy.com"

# --- 6) MIGRATION: a pre-change DB (old schema, no MSSP columns) + a row, then init_schema backfills ---
mig = tempfile.mkdtemp() + "/old.sqlite3"
raw = sqlite3.connect(mig)
raw.execute("""CREATE TABLE tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL, verified_domains TEXT NOT NULL, feed_base TEXT NOT NULL, feed_company_id TEXT NOT NULL,
    feed_api_key TEXT NOT NULL, feed_start_date TEXT NOT NULL, enabled_actions TEXT NOT NULL DEFAULT '[]',
    quarantine_group TEXT NOT NULL DEFAULT '', auto_baseline_at REAL NOT NULL DEFAULT 0, created_at REAL NOT NULL)""")
raw.execute("""INSERT INTO tenants (customer_id,name,verified_domains,feed_base,feed_company_id,feed_api_key,
    feed_start_date,created_at) VALUES ('C0old','Old','["old.com"]','https://x','9','k','2026-01-01',1.0)""")
raw.commit(); raw.close()
os.environ["DB_PATH"] = mig
importlib.reload(cfg)
import app.storage_sqlite as ss
importlib.reload(ss)
ss.init_schema()  # the ALTER migration must add the columns without touching the existing row
with ss.conn() as cx:
    mcols = [r["name"] for r in cx.execute("PRAGMA table_info(tenants)").fetchall()]
    old_row = cx.execute("SELECT * FROM tenants WHERE customer_id='C0old'").fetchone()
c["migration added admin_subject"] = "admin_subject" in mcols
c["migration added service_account"] = "service_account" in mcols
c["migrated old row reads admin_subject='' (not NULL)"] = dict(old_row)["admin_subject"] == ""
c["migrated old row data intact"] = dict(old_row)["customer_id"] == "C0old" and dict(old_row)["feed_company_id"] == "9"

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print("RESULT:", "PASS — MSSP Layer 1 (per-tenant identity schema + migration + backward-compat)" if ok else "FAIL")
sys.exit(0 if ok else 1)
