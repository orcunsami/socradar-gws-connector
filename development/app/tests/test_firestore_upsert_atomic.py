#!/usr/bin/env python3
"""Firestore upsert_flagged is now wrapped in a @firestore.transactional (atomic read-merge-write, parity with
sqlite's BEGIN IMMEDIATE). This exercises the transaction-wrapped code path WITHOUT a real emulator (no Java
here) via a fake client + a passthrough transactional, to prove the merge logic still: unions sources +
socradar_refs on conflict, refreshes last_seen, and never downgrades a 'found' user on a transient error_*.
Full backend behaviour is emulator-verified separately + live-verified separately. Run from the app dir."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 32)
os.environ.setdefault("DB_PATH", tempfile.mktemp(suffix=".sqlite3"))

import app.storage_firestore as fs  # noqa: E402


# --- minimal in-memory fake Firestore (only what upsert_flagged touches) ---
class _Snap:
    def __init__(self, data):
        self._d = data
    @property
    def exists(self):
        return self._d is not None
    def to_dict(self):
        return dict(self._d) if self._d else {}


class _Ref:
    def __init__(self, store, doc_id):
        self.store, self.id = store, doc_id
    def get(self, transaction=None):
        return _Snap(self.store.get(self.id))
    def set(self, data):
        self.store[self.id] = dict(data)
    def update(self, data):
        self.store.setdefault(self.id, {}).update(data)


class _Coll:
    def __init__(self, store):
        self.store = store
    def document(self, doc_id):
        return _Ref(self.store, doc_id)


class _Txn:
    def set(self, ref, data):
        ref.set(data)
    def update(self, ref, data):
        ref.update(data)


class _Client:
    def __init__(self):
        self.stores = {}
    def collection(self, name):
        return _Coll(self.stores.setdefault(name, {}))
    def transaction(self):
        return _Txn()


client = _Client()
fs._db = lambda: client
fs.firestore.transactional = lambda fn: fn   # passthrough: run the txn body inline with the fake txn

P = F = 0
def chk(name, cond):
    global P, F
    print(("  PASS: " if cond else "  FAIL: ") + name)
    if cond:
        P += 1
    else:
        F += 1


FLAGGED = fs._FLAGGED

# 1) insert (new doc) via the transaction
fid1 = fs.upsert_flagged("t1", "a@x.com", {"botnet"}, "found", 100.0, ["ref1"])
doc = client.stores[FLAGGED][fid1]
chk("insert: new flagged doc created", doc and doc["email"] == "a@x.com")
chk("insert: sources = botnet", set(json.loads(doc["sources"])) == {"botnet"})
chk("insert: status open + first_seen set", doc["status"] == "open" and doc["first_seen"] == 100.0)

# 2) conflict upsert (same email, different source) -> atomic read-merge-write UNIONs sources + refs
fid2 = fs.upsert_flagged("t1", "a@x.com", {"pii"}, "found", 200.0, ["ref2"])
chk("merge: deterministic id (same doc)", fid1 == fid2)
doc = client.stores[FLAGGED][fid1]
chk("merge: sources unioned (botnet+pii)", set(json.loads(doc["sources"])) == {"botnet", "pii"})
chk("merge: socradar_refs unioned", set(json.loads(doc["socradar_refs"])) == {"ref1", "ref2"})
chk("merge: last_seen refreshed", doc["last_seen"] == 200.0)
chk("merge: first_seen NOT changed", doc["first_seen"] == 100.0)

# 3) a transient error_* must NOT downgrade an already-found user (would block remediation)
fs.upsert_flagged("t1", "a@x.com", {"botnet"}, "error_timeout", 300.0)
doc = client.stores[FLAGGED][fid1]
chk("transient error_ does NOT downgrade found", doc["lookup_status"] == "found")

# 4) a genuinely new email -> separate doc
fidb = fs.upsert_flagged("t1", "b@x.com", {"vip"}, "not_found", 400.0)
chk("second email -> separate doc", fidb != fid1 and len(client.stores[FLAGGED]) == 2)

print(f"\nRESULT: {'PASS' if F == 0 else 'FAIL'} — Firestore upsert_flagged atomic merge ({P} ok, {F} fail)")
sys.exit(0 if F == 0 else 1)
