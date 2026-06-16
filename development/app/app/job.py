"""Cloud Run JOB entrypoint (ADR-0001 Phase 2) — runs the scan OFF the HTTP request path, so the 60-min
Cloud Run *Service* request timeout (the root cause of the old 5,000-record truncation) does not apply: a
full multi-month backfill completes (or resumes) in one Job execution.

  python -m app.job                 # scan EVERY configured tenant (the simple built-in MSSP dispatcher)
  TENANT_ID=<id|customer_id> python -m app.job   # scan ONE tenant (per-tenant Job execution, for wave-staggering)

A Cloud Run Job has no request; on SIGTERM/timeout/crash the streaming engine's per-page cursor + the
per-tenant lease let the NEXT execution resume from exactly where it stopped (the scan row stays
running/paused). Exit code != 0 on any tenant failure so the Job's --max-retries re-runs and resumes.
The image is shared with the web Service; the Job just overrides the container command.
"""
from __future__ import annotations

import logging
import os
import sys

from . import db, service

log = logging.getLogger("socradar.gws.job")


def run(tenant_id: str | None = None) -> int:
    logging.basicConfig(level=logging.INFO)
    db.init_db()
    tenants = db.list_tenants()
    if tenant_id:
        tenants = [t for t in tenants
                   if str(t["id"]) == str(tenant_id) or str(t.get("customer_id")) == str(tenant_id)]
        if not tenants:
            log.error("job: tenant %s not found", tenant_id)
            return 2
    if not tenants:
        log.warning("job: no tenants configured — nothing to scan")
        return 0

    failures = 0
    for t in tenants:
        try:
            r = service.run_scan(t, "job")          # budget unset on a Job -> runs to completion
            if r.get("busy"):
                log.info("job: tenant %s busy (another worker holds the lease) — skipping", t["id"])
                continue
            # a budget-bounded deploy returns part-way (more=True) — a Job has no timeout, so finish it here
            while r.get("more"):
                r = service.run_scan(t, "job")
            if not r.get("ok"):
                failures += 1
                log.error("job: tenant %s scan FAILED: %s", t["id"], r.get("error"))
            else:
                log.info("job: tenant %s scan ok (in_scope=%s found=%s)",
                         t["id"], r.get("in_scope"), r.get("found"))
        except Exception as e:   # one tenant must never abort the whole fleet run
            failures += 1
            log.exception("job: tenant %s crashed: %s", t["id"], e)

    log.info("job: done — %d tenant(s), %d failure(s)", len(tenants), failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run(os.environ.get("TENANT_ID") or None))
