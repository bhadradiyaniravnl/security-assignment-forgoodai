#!/usr/bin/env bash
# Teardown: export evidence, delete the kind cluster. STOP_VM=1 also stops the Colima profile.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER="${CLUSTER:-sbx}"
COLIMA_PROFILE="${COLIMA_PROFILE:-sbx}"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  mkdir -p out/evidence
  pod="$(kubectl -n sbx-system get pod -l app=detector -o name 2>/dev/null | head -1 || true)"
  if [ -n "$pod" ]; then
    kubectl -n sbx-system exec "$pod" -- tar -C /evidence -cf - . | tar -C out/evidence -xf - || true
    echo "evidence exported to out/evidence"
  fi
  kind delete cluster --name "$CLUSTER"
fi
if [ "${STOP_VM:-0}" = 1 ]; then colima stop "$COLIMA_PROFILE"; fi
