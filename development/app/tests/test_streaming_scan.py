#!/usr/bin/env python3
"""Streaming scan engine (ADR-0001 / TASK-0011) — deterministic, no gcloud/network. Run from the app dir.

Proves the new full-coverage engine: streaming early-filter (only verified-domain emails retained),
full pagination (no 5,000 truncation), UNION sources across sources/pages, incremental high-water-mark
advance, per-invocation budget self-continuation + resume cursor, and the single-flight lease (busy +
zombie reclaim)."""
import datetime
import importlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/stream.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0stream"
os.environ["DEFAULT_DOMAIN"] = "corp.com"
os.environ["ADMIN_SUBJECT"] = "operator@corp.com"
os.environ["FEED_FULL_SCAN"] = "true"

import app.config as cfg
importlib.reload(cfg)
import app.connector as connector
import app.db as db
importlib.reload(db)
import app.service as service
importlib.reload(service)

# ---- mock feed: alice is in botnet AND pii (UNION test); bob is out-of-domain (filter test);
#      records span multiple pages (full-pagination test). 2 records/page. ----
# Explicit per-page SANITIZED record lists (what connector.stream_source yields). The generator only yields
# raw-non-empty pages and ENDS on a raw-empty page, so the page list simply ends (no trailing empty yield) —
# BUT a sanitized-empty page in the MIDDLE (vip page1: raw keyword-only records, no @-email) IS yielded and
# must NOT end the source (the silent-data-loss BLOCK the review found).
PAGES = {
    "botnet": [
        [{"email": "alice@corp.com", "source": "botnet", "password_present": True, "alarm_id": 1},
         {"email": "bob@other.com",  "source": "botnet", "password_present": True, "alarm_id": 2}],
        [{"email": "carol@corp.com", "source": "botnet", "password_present": False, "alarm_id": 3},
         {"email": "dave@corp.com",  "source": "botnet", "password_present": True, "alarm_id": 4}],
        [{"email": "eve@corp.com",   "source": "botnet", "password_present": True, "alarm_id": 5}],
    ],
    "pii": [
        [{"email": "alice@corp.com", "source": "pii", "password_present": False, "alarm_id": 90}],
    ],
    "vip": [
        [],   # page1: raw records existed but were all keyword-only (sanitized to empty) — must NOT end the source
        [{"email": "vipexec@corp.com", "source": "vip", "password_present": False, "alarm_id": 77}],
    ],
}
TOTALS = {"botnet": 5, "pii": 1, "vip": 2}


def mock_stream(base, cid, key, source, start_date, start_page=1, page_limit=None):
    pages = PAGES.get(source, [])
    total = TOTALS.get(source, 0)
    for i in range(start_page - 1, len(pages)):
        yield i + 1, pages[i], total


connector.stream_source = mock_stream
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.lookup_user = lambda email, token: "found"   # every in-domain email exists in the directory

db.init_db()
t = db.first_tenant()
db.update_tenant(t["id"], verified_domains=json.dumps(["corp.com"]))
t = db.first_tenant()

c = {}


def emails():
    return sorted(r["email"] for r in db.list_flagged(t["id"]))


def sources_of(email):
    r = [x for x in db.list_flagged(t["id"]) if x["email"] == email][0]
    return sorted(json.loads(r["sources"]))


def has_audit(action=None, result=None, sub=None):
    for a in db.list_audit(t["id"], 200):
        if action and a["action"] != action:
            continue
        if result and a["result"] != result:
            continue
        if sub and sub.lower() not in (a.get("detail") or "").lower():
            continue
        return True
    return False


# ===== full scan (budget unbounded) =====
r = service.run_scan(t, "tester")
c["scan ok"] = r.get("ok") is True and not r.get("more")
c["early-filter: only verified-domain emails flagged (bob@other dropped)"] = emails() == [
    "alice@corp.com", "carol@corp.com", "dave@corp.com", "eve@corp.com", "vipexec@corp.com"]
c["DATA-LOSS regression: sanitized-empty vip page1 did NOT end the source (vipexec on page2 flagged)"] = (
    "vipexec@corp.com" in emails())
c["UNION sources: alice has BOTH botnet+pii (across sources)"] = sources_of("alice@corp.com") == ["botnet", "pii"]
c["full coverage: result found=5 (no truncation)"] = r.get("found") == 5
c["no feed_truncated alert (full scan)"] = not has_audit(action="feed_truncated")
c["honest summary audit (full coverage)"] = has_audit(action="scan", result="ok", sub="full coverage")
t = db.first_tenant()
c["incremental high-water advanced to today"] = t["feed_high_water"] == datetime.date.today().isoformat()
c["next window = high_water - overlap (incremental delta)"] = service._effective_start_date(t) == (
    datetime.date.today() - datetime.timedelta(days=cfg.settings.feed_overlap_days)).isoformat()
last = db.last_scan(t["id"])
c["scan row finalized status=done"] = last["status"] == "done" and bool(last["finished_at"])

# ===== budget self-continuation + resume cursor =====
os.environ["SCAN_PAGES_PER_RUN"] = "1"
importlib.reload(cfg)
importlib.reload(db)
importlib.reload(service)
connector.stream_source = mock_stream
connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.lookup_user = lambda email, token: "found"
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/stream2.sqlite3"
importlib.reload(cfg)
importlib.reload(db)
importlib.reload(service)
db.init_db()
t2 = db.first_tenant()
db.update_tenant(t2["id"], verified_domains=json.dumps(["corp.com"]))
t2 = db.first_tenant()

runs, more = 0, True
while more and runs < 20:
    rr = service.run_scan(t2, "tester")
    more = bool(rr.get("more"))
    runs += 1
c["budget: scan self-continued across >1 invocation"] = runs > 1
c["budget: resumed to FULL coverage (same flagged set incl vipexec)"] = sorted(
    r["email"] for r in db.list_flagged(t2["id"])) == [
    "alice@corp.com", "carol@corp.com", "dave@corp.com", "eve@corp.com", "vipexec@corp.com"]
c["budget: UNION survived resume (alice botnet+pii)"] = sorted(
    json.loads([x for x in db.list_flagged(t2["id"]) if x["email"] == "alice@corp.com"][0]["sources"])) == ["botnet", "pii"]
last2 = db.last_scan(t2["id"])
c["budget: final status=done"] = last2["status"] == "done"

# ===== lookup_status downgrade protection (MAJOR fix): a transient error must not un-'find' a found user =====
import time as _t
fid_k = db.upsert_flagged(t2["id"], "keep@corp.com", {"botnet"}, "found", _t.time(), [])
db.upsert_flagged(t2["id"], "keep@corp.com", {"pii"}, "error_transient", _t.time(), [])
c["downgrade: 'found' survives a transient-error re-upsert"] = db.get_flagged(fid_k)["lookup_status"] == "found"
db.upsert_flagged(t2["id"], "keep@corp.com", {"pii"}, "not_found", _t.time(), [])
c["downgrade: a DEFINITIVE not_found still updates (only transient is protected)"] = (
    db.get_flagged(fid_k)["lookup_status"] == "not_found")

# ===== lease (self-contained): claim a fresh scan, then a SECOND claim while it is live -> busy =====
import time
nowt = time.time()
sid_a, _, mode_a = db.claim_or_resume_scan(t2["id"], nowt, 600, "2026-06-01")   # creates a 'running' row
c["lease: first claim -> new/resume (owns it)"] = sid_a is not None and mode_a in ("new", "resume")
c["lease: a SECOND claim while live (fresh heartbeat) -> busy"] = (
    db.claim_or_resume_scan(t2["id"], nowt, 600, "2026-06-01")[2] == "busy")

# ===== zombie reclaim: the SAME 'running' scan past the lease TTL -> resume =====
c["lease: stale heartbeat (zombie) -> reclaimed/resume"] = (
    db.claim_or_resume_scan(t2["id"], nowt + 10000, 600, "2026-06-01")[2] == "resume")

for k, v in c.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(c.values())
print(f"RESULT: {'PASS' if ok else 'FAIL'} — {sum(c.values())}/{len(c)} streaming-engine checks")
sys.exit(0 if ok else 1)
