#!/usr/bin/env bash
# Idempotent bring-up: Colima VM -> kind cluster -> Cilium/Hubble -> gVisor -> images -> manifests.
set -euo pipefail
cd "$(dirname "$0")/.."

COLIMA_PROFILE="${COLIMA_PROFILE:-sbx}"
CLUSTER="${CLUSTER:-sbx}"
CILIUM_VERSION="${CILIUM_VERSION:-1.20.1}"

log() { printf '\n==> %s\n' "$*"; }

log "Colima profile '$COLIMA_PROFILE'"
if ! colima status "$COLIMA_PROFILE" >/dev/null 2>&1; then
  colima start "$COLIMA_PROFILE" --cpu 6 --memory 8 --disk 60 --vm-type vz --arch aarch64 --runtime docker
fi
docker context use "colima-$COLIMA_PROFILE" >/dev/null

log "kind cluster '$CLUSTER'"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --config deploy/kind.yaml
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

log "Cilium $CILIUM_VERSION (kube-proxy replacement, Hubble relay)"
if ! kubectl -n kube-system get ds cilium >/dev/null 2>&1; then
  cilium install --version "$CILIUM_VERSION" \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost="$CLUSTER-control-plane" --set k8sServicePort=6443 \
    --set hubble.enabled=true --set hubble.relay.enabled=true \
    --set ipam.mode=kubernetes \
    --set socketLB.hostNamespaceOnly=true   # gVisor bypasses socket-LB hooks; use per-packet LB for pods
fi
cilium status --wait --wait-duration 8m >/dev/null

log "gVisor runtime"
if ! docker exec "$CLUSTER-control-plane" test -x /usr/local/bin/gvisor-bin/gvisor_sentry; then
  NODE="$CLUSTER-control-plane" deploy/runsc-install.sh
fi

log "Images"
deploy/images.sh

log "Manifests"
kubectl apply -k deploy/k8s >/dev/null
# One key per component (gateway, credproxy, detector) plus the control-plane key for GitHub ops.
# Generated into a file and passed with --from-env-file, so keys never appear on a command line.
ktmp="$(mktemp)"; trap 'rm -f "$ktmp"' EXIT
for k in gateway-key credproxy-key detector-key cp-key; do
  have="$(kubectl -n sbx-system get secret sbx-internal -o jsonpath="{.data.$k}" 2>/dev/null || true)"
  if [ -n "$have" ]; then printf '%s=%s\n' "$k" "$(printf %s "$have" | base64 -d)" >> "$ktmp"
  else printf '%s=%s\n' "$k" "$(openssl rand -hex 32)" >> "$ktmp"; fi
done
kubectl -n sbx-system create secret generic sbx-internal --from-env-file="$ktmp" --dry-run=client -o yaml \
  | kubectl apply -f - >/dev/null
rm -f "$ktmp"
if [ -f secrets/.env ]; then deploy/secrets.sh; else echo "secrets/.env missing: credproxy will not start (see secrets/.example.env)"; fi
kubectl -n lab-ext rollout status deploy --timeout=180s >/dev/null
kubectl -n sbx-system rollout restart deploy >/dev/null   # pick up rebuilt images
kubectl -n sbx-system rollout status deploy --timeout=180s >/dev/null

log "Ready"
kubectl get pods -A -o wide 2>/dev/null | grep -E "NAMESPACE|sbx-system|lab-ext" || true
