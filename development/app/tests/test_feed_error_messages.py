#!/usr/bin/env python3
"""A feed 5xx (502/503/504) is a SOCRadar feed-SERVER outage (transient — wait), NOT a connector/config bug;
a 401/403 is a key/company-id problem (fix it). The audit message must distinguish them so an operator doesn't
think the connector is broken during a feed outage (real incident 2026-06-17: preprod.socradar.com 502 on every
path — confirmed by connector + Postman + an independent curl). No network. Run from the app dir."""
import io
import os
import sys
import tempfile
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 32)
os.environ.setdefault("DB_PATH", tempfile.mktemp(suffix=".sqlite3"))

from app import connector  # noqa: E402


def _raise(code):
    def _f(url, headers):
        raise urllib.error.HTTPError("http://x", code, "msg", {}, io.BytesIO(b"error code: 502"))
    return _f


P = F = 0
def chk(name, cond):
    global P, F
    print(("  PASS: " if cond else "  FAIL: ") + name)
    if cond:
        P += 1
    else:
        F += 1


# 5xx -> clear, non-alarming "feed-server outage, not the connector or your config"
connector._get = _raise(502)
try:
    connector.socradar_fetch("https://preprod.x", "132", "k", "botnet", "2026-01-01")
    chk("502 raised a ConnectorError", False)
except connector.ConnectorError as e:
    m = str(e)
    chk("502 -> 'temporarily unavailable'", "temporarily unavailable" in m)
    chk("502 -> 'feed-server outage' + 'not the connector or your config'",
        "feed-server outage" in m and "not the connector or your config" in m)
    chk("502 -> does NOT lead with a raw 'HTTP 502:' body dump", "HTTP 502:" not in m)

connector._get = _raise(503)
try:
    connector.socradar_fetch("https://x", "132", "k", "pii", "2026-01-01")
    chk("503 raised a ConnectorError", False)
except connector.ConnectorError as e:
    chk("503 -> same feed-outage wording", "temporarily unavailable" in str(e))

# 4xx auth -> a config hint (fix the key / company id), NOT a feed-outage message
connector._get = _raise(401)
try:
    connector.socradar_fetch("https://x", "132", "k", "botnet", "2026-01-01")
    chk("401 raised a ConnectorError", False)
except connector.ConnectorError as e:
    m = str(e)
    chk("401 -> 'check the feed API key / company id'", "check the feed API key / company id" in m)
    chk("401 -> NOT framed as a feed-server outage", "feed-server outage" not in m)

print(f"\nRESULT: {'PASS' if F == 0 else 'FAIL'} — feed 5xx vs 4xx error messaging ({P} ok, {F} fail)")
sys.exit(0 if F == 0 else 1)
