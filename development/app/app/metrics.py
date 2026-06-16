"""Measure-what-matters — operational security metrics derived from existing data (no new storage).

Zero Trust "measure what matters": dwell time (detection→remediation latency), coverage (fraction of
detected exposures actually remediated), detection speed / scan freshness, remediation success rate. These
are the metrics the framework says to instrument FIRST — they are the ones automation has the most leverage
to move when exploit windows shorten.
"""
from __future__ import annotations

import json
import time

from . import db


def _pct(rows, p):
    if not rows:
        return None
    s = sorted(rows)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def _median(rows):
    return _pct(rows, 50)


def compute(tenant_id, verify_chain: bool = True) -> dict:
    """verify_chain=False skips the O(N)-over-the-whole-audit-log integrity check — pass it on the dashboard
    hot path (every page load). The audit chain is a tamper-check, not an operational KPI, and is already
    verified on schedule (/tasks/verify-audit); the on-demand /metrics page computes it with verify_chain=True."""
    flagged = db.list_flagged(tenant_id)
    counts = {"open": 0, "remediated": 0, "partial": 0}
    dwell = []   # detection (first_seen) -> remediation (remediated_at), seconds
    for f in flagged:
        st = f.get("status", "open")
        counts[st] = counts.get(st, 0) + 1
        if f.get("remediated_at") and f.get("first_seen"):
            d = f["remediated_at"] - f["first_seen"]
            if d >= 0:
                dwell.append(d)

    total = len(flagged)
    found_like = total                       # every flagged row is a detected exposure
    handled = counts.get("remediated", 0) + counts.get("partial", 0)
    coverage = (handled / found_like) if found_like else None

    # remediation success rate from the audit trail. Count ONLY the canonical "remediate:*" rows: every
    # execution path (manual, semi-auto, approval, auto) runs through service.remediate, which writes that
    # row. The "auto:*" and "approval_approve:*" rows are WRAPPERS around the same execution — counting them
    # too double-counted each auto/approval action (inflating attempts and skewing the success rate).
    aud = db.list_audit(tenant_id, limit=500)
    rem = [a for a in aud if str(a.get("action", "")).startswith("remediate:")]
    rem_ok = sum(1 for a in rem if a.get("result") == "ok")
    rem_attempts = sum(1 for a in rem if a.get("result") in ("ok", "fail"))
    success_rate = (rem_ok / rem_attempts) if rem_attempts else None

    last = db.last_scan(tenant_id)
    scan_age = (time.time() - last["finished_at"]) if last and last.get("finished_at") else None

    anomalies = [a for a in aud if a.get("action") == "anomaly_detected"]

    out = {
        "flagged_total": total,
        "counts": counts,
        "coverage": coverage,                                   # 0..1, fraction handled
        "dwell_seconds": {"p50": _median(dwell), "p95": _pct(dwell, 95), "n": len(dwell)},
        "remediation_success_rate": success_rate,
        "remediation_attempts": rem_attempts,
        "last_scan_age_seconds": scan_age,
        "anomalies_recent": len(anomalies),
        "last_anomaly": anomalies[0] if anomalies else None,
    }
    if verify_chain:   # OFF on the dashboard hot path (unbounded O(N) full-chain recompute); ON for /metrics
        out["audit_integrity"] = db.verify_audit_chain(tenant_id)
    return out
