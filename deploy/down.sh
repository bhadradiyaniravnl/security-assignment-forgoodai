#!/usr/bin/env bash
# Teardown: export evidence, delete the kind cluster. STOP_VM=1 also stops the Colima profile.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER="${CLUSTER:-sbx}"
COLIMA_PROFILE="${COLIMA_PROFILE:-sbx}"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  mkdir -p out/evidence
  kubectl -n sbx-system exec deploy/gateway -c gateway -- tar -C /evidence -cf - . 2>/dev/null \
    | tar -C out/evidence -xf - && echo "platform evidence exported to out/evidence"
  mkdir -p out/sentinel
  kubectl -n sbx-security exec deploy/sentinel -- tar -C /data -cf - . 2>/dev/null \
    | tar -C out/sentinel -xf - && echo "sentinel store exported to out/sentinel"
  kind delete cluster --name "$CLUSTER"
fi
if [ "${STOP_VM:-0}" = 1 ]; then colima stop "$COLIMA_PROFILE"; fi
