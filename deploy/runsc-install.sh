#!/usr/bin/env bash
# Installs gVisor (runsc) into the kind node and registers the "runsc" containerd handler.
set -euo pipefail
NODE="${NODE:-sbx-control-plane}"
GVISOR_RELEASE="${GVISOR_RELEASE:-20261019}"   # pinned release
URL="https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/aarch64/gvisor.tar.bz2"

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/gvisor.tar.bz2" "$URL"
curl -fsSL -o "$work/gvisor.tar.bz2.sha512" "$URL.sha512"
(cd "$work" && shasum -a 512 -c gvisor.tar.bz2.sha512)
mkdir -p "$work/x" && tar -xjf "$work/gvisor.tar.bz2" -C "$work/x"
# runsc, the containerd shim, and the gvisor-bin/ sidecars (sentry etc.) must sit side by side
docker cp "$work/x/runsc" "$NODE:/usr/local/bin/runsc"
docker cp "$work/x/containerd-shim-runsc-v1" "$NODE:/usr/local/bin/containerd-shim-runsc-v1"
docker cp "$work/x/gvisor-bin" "$NODE:/usr/local/bin/"

docker exec -i "$NODE" bash -s <<'IN_NODE'
set -euo pipefail
chmod -R 0755 /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1 /usr/local/bin/gvisor-bin
if ! grep -q 'runtimes.runsc' /etc/containerd/config.toml; then
  cat >> /etc/containerd/config.toml <<'TOML'

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
TOML
fi
systemctl restart containerd
runsc --version | head -1
IN_NODE

kubectl apply -f - <<'YAML'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
YAML
