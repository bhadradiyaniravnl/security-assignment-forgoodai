#!/usr/bin/env bash
# S-P2: the sentinel independently counts what each sandbox sent to the gateway (Cilium L7 for the AI
# gateway, L4 connections for the egress proxy) and reconciles it with the gateway's own evidence.
# A gateway that under-reports (compromised, buggy) is caught and the session contained.
# Uses the gateway's LAB-ONLY fault injection to make it silently drop one session's evidence.
set -uo pipefail
cd "$(dirname "$0")/.."
CTL=bin/sbxctl
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 (got $3)"; pass=$((pass+1)); else echo "FAIL  $1 (expected $2, got $3)"; fail=$((fail+1)); fi; }
SC() { kubectl -n sbx-security exec deploy/sentinel -- python -m sbx.sentinel.ctl "$@"; }
sid_of() { sed -n 's/^session \([a-z0-9]*\) started.*/\1/p'; }
in_pod() { kubectl -n sbx-sessions exec "sandbox-$1" -- sh -c "$2" 2>/dev/null; }
gw_code() { in_pod "$1" 'curl -s -o /dev/null -m 2 -w "%{http_code}" http://gateway:8080/healthz' | head -c 3; }
wait_for() { for _ in $(seq 1 "${3:-40}"); do [ "$(eval "$1")" = "$2" ] && return 0; sleep 1; done; return 1; }
start() { local s; s=$($CTL run bugfix-agent -p repo=demo/app -p task="Reply with the word ok. Do not use any tools." | sid_of)
          wait_for "gw_code $s" 200 40; sleep 15; echo "$s"; }       # let the agent's own turn finish first
ai_calls() { in_pod "$1" "for i in \$(seq 1 $2); do curl -s -o /dev/null -m 20 http://gateway:8080/v1/messages/count_tokens \
  -H \"x-api-key: \$ANTHROPIC_API_KEY\" -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' \
  -d '{\"model\":\"claude-haiku-5-5\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}'; done"; }
egress_calls() { in_pod "$1" "for i in \$(seq 1 $2); do curl -s -o /dev/null -m 5 http://paste-mock.lab-ext/read-\$i; done"; }
s1_for() { SC alerts 400 | grep " S1 " | grep -c " $1 " | tr -d ' '; }
fault() { kubectl -n sbx-system exec deploy/gateway -c gateway -- sh -c "mkdir -p /tmp/sbx-fault && printf '%s\n' $* > /tmp/sbx-fault/drop-sessions"; }

echo "--- Hubble L7 visibility, with credentials redacted"
A=$(start)
ai_calls "$A" 2
L7=$(kubectl -n sbx-security exec deploy/sentinel -- hubble observe --server hubble-relay.kube-system.svc:80 \
     --from-pod "sbx-sessions/sandbox-$A" --type l7 --last 5 -o json 2>/dev/null)
check "Hubble sees the sandbox's HTTP requests to the AI gateway" yes "$(echo "$L7" | grep -q 'count_tokens' && echo yes || echo no)"
check "session token redacted in flow logs" yes "$(echo "$L7" | grep -q 'sbx_' && echo no || echo yes)"

echo "--- baseline: an honest gateway produces no S1"
ai_calls "$A" 6; egress_calls "$A" 6
sleep 40
check "no S1 for a fully logged session" 0 "$(s1_for "$A")"

echo "--- AI channel: the gateway silently drops a session's evidence"
B=$(start)
fault "$B"
ai_calls "$B" 8
wait_for "s1_for $B" 1 70
check "S1 raised from the AI-channel deficit" 1 "$(s1_for "$B")"
check "the gateway logged none of those calls" 0 "$(kubectl -n sbx-system exec deploy/gateway -c gateway -- sh -c "grep -c '\"$B\".*count_tokens' /evidence/gateway.jsonl || true" | tr -d ' ')"
check "session quarantined by the sentinel" yes "$(kubectl -n sbx-sessions get cnp "sentinel-q-$B" >/dev/null 2>&1 && echo yes || echo no)"
echo "      $(SC alerts 400 | grep " S1 " | grep " $B " | head -1 | cut -c1-150)"

echo "--- egress channel (one TCP connection = one request)"
C=$(start)
fault "$C"
egress_calls "$C" 8
wait_for "s1_for $C" 1 70
check "S1 raised from the egress-channel deficit" 1 "$(s1_for "$C")"

fault ""
for s in "$A" "$B" "$C"; do SC release "$s" >/dev/null; $CTL destroy "$s" >/dev/null 2>&1 || SBX_USER=secops $CTL destroy "$s" >/dev/null; done
echo; echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
