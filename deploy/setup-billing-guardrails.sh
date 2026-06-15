#!/usr/bin/env bash
#
# Link a billing account to the project and create a $10 ALERT budget before deploying.
#
# IMPORTANT — honesty: a GCP budget only ALERTS (email + optional Pub/Sub); it does NOT stop spending.
# Cost certainty for this test comes from: $300 free-trial credit ($0 real money) + this $10 alert +
# the SHORT same-session window + running deploy/cleanup.sh immediately after. (A hard auto-kill function
# was evaluated and rejected — cost data lags hours so it can't act in time, and it broadens blast radius.)
#
# Usage:
#   PROJECT=your-gcp-project \
#   BILLING_ACCOUNT_ID=XXXXXX-XXXXXX-XXXXXX \
#   bash deploy/setup-billing-guardrails.sh
#
set -euo pipefail
GC="${GCLOUD:-gcloud}"
PROJECT="${PROJECT:?set PROJECT}"
BILLING_ACCOUNT_ID="${BILLING_ACCOUNT_ID:?set BILLING_ACCOUNT_ID (from: gcloud billing accounts list)}"
BUDGET_USD="${BUDGET_USD:-10}"
# The budget amount must use the BILLING ACCOUNT's currency (EXP: a USD amount is rejected on an NZD account).
BUDGET_CURRENCY="${BUDGET_CURRENCY:-USD}"

echo "==> [1/3] Linking billing account to $PROJECT"
$GC billing projects link "$PROJECT" --billing-account="$BILLING_ACCOUNT_ID"

echo "==> [2/3] Enabling Cloud Billing Budget API"
$GC services enable billingbudgets.googleapis.com --project="$PROJECT" 2>/dev/null || true

echo "==> [3/3] Creating \$$BUDGET_USD ALERT budget (scoped to THIS project; alerts at 50/90/100%)"
echo "    NOTE: this ALERTS only — it does not cap spending. Real spend for this test is cents."
$GC billing budgets create \
  --billing-account="$BILLING_ACCOUNT_ID" \
  --display-name="cap${BUDGET_USD}-${PROJECT}" \
  --budget-amount="${BUDGET_USD}${BUDGET_CURRENCY}" \
  --filter-projects="projects/${PROJECT}" \
  --threshold-rule=percent=0.5 \
  --threshold-rule=percent=0.9 \
  --threshold-rule=percent=1.0 \
  || echo "    (budget create failed — try 'gcloud beta billing budgets create ...' or set it in Console)"

echo ""
$GC billing projects describe "$PROJECT" | grep billingEnabled
echo "Done. Billing on + \$$BUDGET_USD alert budget. Next: deploy/deploy-to-gcp.sh ; then deploy/cleanup.sh (with UNLINK_BILLING=1) to return to \$0."
