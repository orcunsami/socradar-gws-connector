#!/usr/bin/env python3
"""
Deterministic at-rest encryption test — no gcloud, no network.
Verifies: Fernet round-trip; legacy-plaintext tolerance; and that with FERNET_KEY set the feed key is
stored ENCRYPTED in the DB while the db facade returns it DECRYPTED. Run from the app dir.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.fernet import Fernet  # noqa: E402

_tmp = tempfile.mkdtemp()
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
os.environ["DB_PATH"] = os.path.join(_tmp, "enc.sqlite3")
os.environ["DEFAULT_CUSTOMER_ID"] = "C0enc"
os.environ["DEFAULT_DOMAIN"] = "example.com"
os.environ["FEED_API_KEY"] = "super-secret-feed-key-123"

from app import crypto, db, storage_sqlite  # noqa: E402

checks = {}
# 1. round-trip
ct = crypto.enc("hello")
checks["enc produces ciphertext != plaintext"] = ct != "hello"
checks["dec(enc(x)) == x"] = crypto.dec(ct) == "hello"
# 2. legacy plaintext tolerance (a pre-encryption value decrypts to itself)
checks["dec(legacy plaintext) returns as-is"] = crypto.dec("not-a-fernet-token") == "not-a-fernet-token"
# 3. empty/None no-op
checks["enc('') is no-op"] = crypto.enc("") == ""
# 4. DB stores ciphertext, facade returns plaintext
db.init_db()
raw = storage_sqlite.first_tenant()              # raw backend row (ciphertext)
facade = db.first_tenant()                        # facade (decrypted)
checks["DB stores feed key ENCRYPTED"] = raw["feed_api_key"] != "super-secret-feed-key-123"
checks["facade DECRYPTS feed key"] = facade["feed_api_key"] == "super-secret-feed-key-123"
# 5. update_tenant re-encrypts
db.update_tenant(facade["id"], feed_api_key="rotated-key-456")
checks["update stores ENCRYPTED"] = storage_sqlite.get_tenant(facade["id"])["feed_api_key"] != "rotated-key-456"
checks["update facade DECRYPTS"] = db.get_tenant(facade["id"])["feed_api_key"] == "rotated-key-456"

for k, v in checks.items():
    print(("  PASS  " if v else "  FAIL  ") + k)
ok = all(checks.values())
print("RESULT:", "PASS — at-rest feed-key encryption verified" if ok else "FAIL")
sys.exit(0 if ok else 1)
