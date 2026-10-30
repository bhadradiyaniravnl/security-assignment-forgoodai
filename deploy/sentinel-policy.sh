#!/usr/bin/env bash
# Deploy a sentinel detection policy: validate + diff it inside the sentinel (same code that will load
# it), apply it as the ConfigMap sentinel-detection, hot-reload, and confirm the sentinel runs exactly
# this file (digest match). An invalid file never reaches the cluster; if one does (applied by hand),
# the sentinel rejects it, raises a POL alert and keeps its last good policy.
#   deploy/sentinel-policy.sh [FILE]      default config/sentinel/detection.yaml
#   CHECK_ONLY=1 deploy/sentinel-policy.sh FILE    validate + diff only
set -euo pipefail
cd "$(dirname "$0")/.."
FILE=${1:-config/sentinel/detection.yaml}
CTL=(kubectl -n sbx-security exec -i deploy/sentinel -- python -m sbx.sentinel.ctl)
"${CTL[@]}" validate - < "$FILE"
[ "${CHECK_ONLY:-0}" = 1 ] && exit 0
kubectl -n sbx-security create configmap sentinel-detection --from-file=detection.yaml="$FILE" \
  --dry-run=client -o yaml | kubectl label --local -f - app.kubernetes.io/part-of=sentinel -o yaml \
  | kubectl apply -f - >/dev/null
want="sha256:$(shasum -a 256 "$FILE" | cut -d' ' -f1)"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  got=$("${CTL[@]}" reload | python3 -c 'import json,sys; print(json.load(sys.stdin)["active"])')
  [ "$got" = "$want" ] && { echo "deployed: sentinel is running $want"; exit 0; }
  sleep 1
done
echo "sentinel did not load $want (active: $got); see: kubectl -n sbx-security exec deploy/sentinel -- python -m sbx.sentinel.ctl alerts 5" >&2
exit 1
