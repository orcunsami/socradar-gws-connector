#!/usr/bin/env python3
"""Async scan + live progress (Option 1): with a per-request page budget the SERVICE runs a long scan in
small chunks. POST /scan returns fast with a scan id; POST /scans/{id}/tick advances ONE chunk and returns
live progress; the loop converges to done. No background thread (Cloud-Run-safe). Run from app dir."""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = tempfile.mkdtemp() + "/async.sqlite3"
os.environ["DEFAULT_CUSTOMER_ID"] = "C0a"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["ALLOWED_DOMAIN"] = "example.com"
os.environ["ADMIN_SUBJECT"] = "o@example.com"
os.environ["DEV_LOGIN"] = "true"
os.environ["APP_ENV"] = "dev"
os.environ["REMEDIATION_ADMINS"] = "o@example.com"
os.environ["FEED_FULL_SCAN"] = "true"
os.environ["SCAN_PAGES_PER_RUN"] = "1"   # chunk = 1 feed page -> forces multi-tick

import importlib  # noqa: E402
import app.config as cfg  # noqa: E402
importlib.reload(cfg)
from app import connector, db  # noqa: E402
import app.main as main  # noqa: E402
importlib.reload(main)
from fastapi.testclient import TestClient  # noqa: E402

connector.get_dwd_token = lambda scopes, **kw: "tok"
connector.lookup_user = lambda email, token: "found"

def fake_stream(base, cid, key, source, start_date, start_page=1, page_limit=None):
    # 2 non-empty pages per source, then the generator ends (source exhausted)
    for p in (1, 2):
        if p < start_page:
            continue
        yield (p, [{"email": f"{source}{p}@example.com", "alarm_id": None,
                    "source": source, "password_present": False}], 2)

connector.stream_source = fake_stream

db.init_db()
cl = TestClient(main.app)
cl.get("/auth/login", follow_redirects=False)
CSRF = re.search(r'name="csrf" value="([^"]+)"', cl.get("/flagged").text).group(1)

P = F = 0
def chk(name, cond):
    global P, F
    print(("  PASS: " if cond else "  FAIL: ") + name)
    if cond:
        P += 1
    else:
        F += 1

# POST /scan -> first chunk (1 page) + redirect to /flagged with the scan id
r = cl.post("/scan", data={"csrf": CSRF}, follow_redirects=False)
loc = r.headers.get("location", "")
chk("POST /scan -> 303 with &scan=<id>", r.status_code == 303 and "scan=" in loc)
sid = re.search(r"scan=(\d+)", loc).group(1)

# the flagged page renders the live banner while the scan is in flight
chk("flagged shows live banner (data-scan-live)", f'data-scan-live="{sid}"' in cl.get(f"/flagged?scan={sid}").text)

# drive the remaining chunks via tick; progress must advance and converge to done
ticks = 0
founds = []
done = False
while ticks < 25:
    p = cl.post(f"/scans/{sid}/tick", data={"csrf": CSRF}).json()
    ticks += 1
    founds.append(p.get("found", 0))
    if p.get("done"):
        done = True
        break

chk("tick loop converges to done", done)
chk("took multiple chunks (truly chunked, not one-shot)", ticks >= 3)
chk("found count grew across chunks", founds[-1] >= 3 and founds[-1] >= founds[0])
chk("all 3 sources' emails flagged + found", len(db.list_flagged(db.first_tenant()["id"])) >= 6)

# a tick AFTER done must NOT start a new scan (idempotent no-op)
before = len(db.recent_scans(db.first_tenant()["id"], 50))
cl.post(f"/scans/{sid}/tick", data={"csrf": CSRF})
after = len(db.recent_scans(db.first_tenant()["id"], 50))
chk("tick after done does not start a new scan", after == before)

# csrf is enforced on the tick endpoint
bad = cl.post(f"/scans/{sid}/tick", data={"csrf": "wrong"})
chk("tick rejects bad csrf (400)", bad.status_code == 400)

print(f"\nRESULT: {'PASS' if F == 0 else 'FAIL'} — async chunked scan + live progress ({P} ok, {F} fail, {ticks} ticks)")
sys.exit(0 if F == 0 else 1)
