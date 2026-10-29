#!/usr/bin/env bash
# M1 smoke test: verifies the L3/L4 boundary using the real manifests and stand-in pods.
#   - a gVisor session pod can reach only the gateway (stand-in) and nothing else
#   - lab-ext accepts traffic only from credproxy (stand-in)
#   - containment via per-session egressDeny takes effect
# Stand-ins carry the real labels (app=gateway / app=credproxy) and are removed afterwards.
set -uo pipefail
cd "$(dirname "$0")/.."
SID="smoke$RANDOM"
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS  $1 (got $3)"; pass=$((pass+1)); else echo "FAIL  $1 (expected $2, got $3)"; fail=$((fail+1)); fi
}
cleanup() {
  kubectl -n sbx-sessions delete pod "sandbox-$SID" --wait=false >/dev/null 2>&1
  kubectl -n sbx-sessions delete cnp "quarantine-$SID" >/dev/null 2>&1
  kubectl -n sbx-system delete pod smoke-gateway-$SID smoke-credproxy-$SID smoke-other-$SID --wait=false >/dev/null 2>&1
}
trap cleanup EXIT

kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: { name: smoke-gateway-$SID, namespace: sbx-system, labels: { app: gateway } }
spec:
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 10001, seccompProfile: { type: RuntimeDefault } }
  containers:
  - name: web
    image: sbx/services:dev
    imagePullPolicy: Never
    command: ["python", "-m", "http.server", "8080"]
    securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
---
apiVersion: v1
kind: Pod
metadata: { name: smoke-credproxy-$SID, namespace: sbx-system, labels: { app: credproxy } }
spec:
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 10001, seccompProfile: { type: RuntimeDefault } }
  containers:
  - name: c
    image: sbx/services:dev
    imagePullPolicy: Never
    command: ["sleep", "600"]
    securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
---
apiVersion: v1
kind: Pod
metadata: { name: smoke-other-$SID, namespace: sbx-system, labels: { app: other } }
spec:
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 10001, seccompProfile: { type: RuntimeDefault } }
  containers:
  - name: c
    image: sbx/services:dev
    imagePullPolicy: Never
    command: ["sleep", "600"]
    securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
---
apiVersion: v1
kind: Pod
metadata:
  name: sandbox-$SID
  namespace: sbx-sessions
  labels: { sbx/session: $SID, sbx/state: running }
spec:
  runtimeClassName: gvisor
  automountServiceAccountToken: false
  enableServiceLinks: false
  dnsPolicy: None
  dnsConfig: { nameservers: ["127.0.0.1"] }
  securityContext: { runAsNonRoot: true, runAsUser: 1000, seccompProfile: { type: RuntimeDefault } }
  containers:
  - name: agent
    image: sbx/sandbox:dev
    imagePullPolicy: Never
    command: ["sleep", "600"]
    securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
EOF
kubectl -n sbx-system wait --for=condition=Ready pod/smoke-gateway-$SID pod/smoke-credproxy-$SID pod/smoke-other-$SID --timeout=120s >/dev/null
kubectl -n sbx-sessions wait --for=condition=Ready "pod/sandbox-$SID" --timeout=120s >/dev/null

GW=$(kubectl -n sbx-system get pod smoke-gateway-$SID -o jsonpath='{.status.podIP}')
SINK=$(kubectl -n lab-ext get svc attacker-sink -o jsonpath='{.spec.clusterIP}')
PASTE=$(kubectl -n lab-ext get svc paste-mock -o jsonpath='{.spec.clusterIP}')
API=$(kubectl get svc kubernetes -o jsonpath='{.spec.clusterIP}')
DNS=$(kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')

sb()  { kubectl -n sbx-sessions exec "sandbox-$SID" -- "$@" 2>/dev/null; }
code(){ sb curl -s -o /dev/null -m 3 -w '%{http_code}' "$1" || true; }
pyc() { kubectl -n sbx-system exec "$1" -- python -c "import urllib.request,sys
try: print(urllib.request.urlopen('$2', data=b'receipt-$SID', timeout=3).status)
except Exception as e: print('000')" 2>/dev/null; }

# Cilium needs a moment to plumb a new endpoint.
for _ in $(seq 1 20); do [ "$(code "http://$GW:8080/")" = 200 ] && break; sleep 1; done

echo "--- sandbox (gVisor) egress"
check "kernel is gVisor"            "gvisor" "$(sb uname -r | grep -o gvisor)"
check "no service account token"    "absent" "$(sb sh -c 'test -e /var/run/secrets/kubernetes.io && echo present || echo absent')"
check "sandbox -> gateway:8080"     "200" "$(code "http://$GW:8080/")"
check "sandbox -> attacker-sink"    "000" "$(code "http://$SINK/")"
check "sandbox -> paste-mock"       "000" "$(code "http://$PASTE/")"
check "sandbox -> kube-apiserver"   "000" "$(sb curl -sk -o /dev/null -m 3 -w '%{http_code}' "https://$API/version" || true)"
check "sandbox DNS via kube-dns"    "fail" "$(sb sh -c "getent hosts example.com >/dev/null && echo ok || echo fail")"
check "sandbox -> kube-dns:53/tcp"  "000" "$(sb curl -s -o /dev/null -m 3 -w '%{http_code}' "telnet://$DNS:53" || true)"

echo "--- lab-ext ingress"
check "credproxy -> paste-mock"     "200" "$(pyc smoke-credproxy-$SID "http://$PASTE/upload")"
check "other pod -> paste-mock"     "000" "$(pyc smoke-other-$SID "http://$PASTE/upload")"
check "paste-mock recorded receipt" "1" "$(kubectl -n lab-ext logs deploy/paste-mock | grep -c "$(printf 'receipt-%s' "$SID" | base64)")"

echo "--- containment (per-session egressDeny)"
start=$(date +%s)
kubectl apply -f - >/dev/null <<EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: quarantine-$SID, namespace: sbx-sessions }
spec:
  endpointSelector: { matchLabels: { sbx/session: "$SID" } }
  egressDeny: [{ toEntities: [all] }]
  ingressDeny: [{ fromEntities: [all] }]
EOF
for _ in $(seq 1 20); do [ "$(code "http://$GW:8080/")" != 200 ] && break; sleep 0.5; done
check "gateway blocked after quarantine" "000" "$(code "http://$GW:8080/")"
echo "      containment took $(( $(date +%s) - start ))s"

echo; echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
