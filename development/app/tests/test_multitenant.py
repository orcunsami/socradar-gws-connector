#!/usr/bin/env python3
"""
Deterministic multi-tenant isolation proof — no gcloud, no network.

Mocks the directory (get_dwd_token + lookup_user) and the feed (fetch_all_sources) so the
isolation logic is proven independently of live credentials. Run from the app dir:
    python3 tests/test_multitenant.py

Proves: two tenants with different verified domains, scanning the SAME feed, see ONLY their
own in-domain users — flagged users, scans, and audit are isolated by tenant_id.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # app root on path

# isolated temp DB before importing app modules
_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "test.sqlite3")
os.environ["DEFAULT_CUSTOMER_ID"] = "C0example"
os.environ["FEED_FULL_SCAN"] = "false"   # this test mocks the legacy fetch_all_sources path
os.environ["DEFAULT_DOMAIN"] = "example.com"

from app import connector, db, service  # noqa: E402

FEED = {"test1@example.com": {"botnet"}, "test2@example.com": {"pii"},
        "test3@example.com": {"pii"}, "victim@acme-corp.com": {"botnet"}}


def main():
    db.init_db()
    # --- mock the directory + feed so no live token/network is needed ---
    connector.fetch_all_sources = lambda *a, **k: ({e: set(s) for e, s in FEED.items()},
                                                   {"botnet": 2, "pii": 2, "vip": 0}, {}, {})
    connector.get_dwd_token = lambda scopes, **kw: "mock-token"
    connector.lookup_user = lambda email, token: "found"   # pretend everything in-domain resolves

    t1 = db.first_tenant()                                  # example.com (seeded)
    db.update_tenant(t1["id"], feed_api_key="x")            # any non-empty key
    t2_id = db.create_tenant("C0betacorp", "Beta Corp", ["beta-corp.example"],
                             "https://platform.socradar.com", "132", "x", "2026-06-01")
    t2 = db.get_tenant(t2_id)

    r1 = service.run_scan(db.get_tenant(t1["id"]), "admin@example.com")
    r2 = service.run_scan(t2, "admin@beta-corp.example")

    f1 = [dict(r)["email"] for r in db.list_flagged(t1["id"])]
    f2 = [dict(r)["email"] for r in db.list_flagged(t2_id)]

    print(f"tenant1 (example.com): scan in_scope={r1['in_scope']} found={r1['found']} -> flagged {sorted(f1)}")
    print(f"tenant2 (beta-corp):    scan in_scope={r2['in_scope']} found={r2['found']} -> flagged {sorted(f2)}")

    # isolation assertions
    checks = {
        "tenant1 sees its 3 in-domain users": sorted(f1) == ["test1@example.com", "test2@example.com", "test3@example.com"],
        "tenant1 skipped the foreign acme-corp address": "victim@acme-corp.com" not in f1,
        "tenant2 sees ZERO foreign-domain users (same feed, different domain)": f2 == [],
        "tenant2 in_scope is 0": r2["in_scope"] == 0,
        "audit is per-tenant (tenant2 has its own scan entry)": len(db.list_audit(t2_id)) >= 1,
        "tenant1 audit does not contain tenant2 actions": all(
            "beta-corp" not in (dict(a)["actor"]) for a in db.list_audit(t1["id"])),
    }
    for label, ok in checks.items():
        print(("  PASS  " if ok else "  FAIL  ") + label)
    allok = all(checks.values())
    print("RESULT:", "PASS — multi-tenant isolation proven (no gcloud needed)" if allok else "FAIL")
    return 0 if allok else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
