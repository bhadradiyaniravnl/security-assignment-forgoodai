#!/usr/bin/env bash
# Creates/updates the credproxy Secret from secrets/.env without printing values.
set -euo pipefail
cd "$(dirname "$0")/.."
f=secrets/.env
[ -f "$f" ] || { echo "missing $f (see secrets/.example.env)" >&2; exit 1; }
grep -q '^ANTHROPIC_API_KEY=sk-ant-' "$f" || { echo "ANTHROPIC_API_KEY not set in $f" >&2; exit 1; }
kubectl create namespace sbx-system --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n sbx-system create secret generic credproxy-secrets --from-env-file="$f" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if [ -f secrets/github-app.pem ]; then
  kubectl -n sbx-system create secret generic github-app --from-file=app.pem=secrets/github-app.pem \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  echo "github-app secret updated in sbx-system (mounted only in credproxy)"
fi
echo "credproxy-secrets updated in sbx-system (keys: $(cut -d= -f1 "$f" | grep -v '^#' | xargs))"
