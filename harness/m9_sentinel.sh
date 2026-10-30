#!/usr/bin/env bash
# S-P1: the sentinel is a separate, continuously running detection & response plane.
# Proves: separate node + least privilege, verified evidence shipping, containment with the
# CONTROL PLANE DOWN, self-protection of its policies, S2 (platform pod egress), S6 (containment
# lifted by a compromised control plane), and its own fleet freeze.
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
has_cnp() { kubectl -n sbx-sessions get cnp "$1" >/dev/null 2>&1 && echo yes || echo no; }
alerts_for() { SC alerts 400 | grep -E " $1 " ; }
start_session() { local s; s=$($CTL run bugfix-agent -p repo=demo/app -p task="Reply with the word ok. Do not use any tools." | sid_of)
                  wait_for "gw_code $s" 200 40; echo "$s"; }

echo "--- placement and least privilege"
SNODE=$(kubectl -n sbx-security get pod -l app=sentinel -o jsonpath='{.items[0].spec.nodeName}')
check "sentinel on the security node" security "$(kubectl get node "$SNODE" -o jsonpath='{.metadata.labels.sbx/pool}')"
check "not on the platform node (credproxy)" yes "$([ "$SNODE" != "$(kubectl -n sbx-system get pod -l app=credproxy -o jsonpath='{.items[0].spec.nodeName}')" ] && echo yes || echo no)"
AS="--as=system:serviceaccount:sbx-security:sentinel"
check "sentinel can manage policies in sbx-sessions" yes "$(kubectl auth can-i create ciliumnetworkpolicies.cilium.io -n sbx-sessions $AS)"
check "sentinel cannot exec into sandboxes" no "$(kubectl auth can-i create pods/exec -n sbx-sessions $AS)"
check "sentinel cannot read platform Secrets" no "$(kubectl auth can-i get secrets -n sbx-system $AS)"
check "control plane cannot touch the security namespace" no "$(kubectl auth can-i delete pods -n sbx-security --as=system:serviceaccount:sbx-system:sbx-controller)"

echo "--- evidence shipped and verified outside the platform"
src_seq() { kubectl -n sbx-system exec deploy/gateway -c gateway -- sh -c "tail -1 /evidence/$1" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["seq"])'; }
pos() { SC status | python3 -c "import json,sys; print(json.load(sys.stdin)['positions'].get('$1'))"; }
wait_for "[ \$(pos gateway.jsonl) = \$(src_seq gateway.jsonl) ] && echo y" y 20
check "gateway evidence fully shipped" "$(src_seq gateway.jsonl)" "$(pos gateway.jsonl)"
check "control-plane evidence fully shipped" "$(src_seq control-plane.jsonl)" "$(pos control-plane.jsonl)"
check "no chain breaks or gaps" "[]" "$(SC status | python3 -c 'import json,sys; print(json.load(sys.stdin)["broken"])')"

echo "--- containment with the control plane DOWN"
A=$(start_session)
kubectl -n sbx-system scale deploy/control-plane --replicas=0 >/dev/null
kubectl -n sbx-system wait --for=delete pod -l app=control-plane --timeout=60s >/dev/null 2>&1
check "control plane is down" 0 "$(kubectl -n sbx-system get pods -l app=control-plane --no-headers 2>/dev/null | wc -l | tr -d ' ')"
SINK=$(kubectl -n lab-ext get svc attacker-sink -o jsonpath='{.spec.clusterIP}'); API=$(kubectl get svc kubernetes -o jsonpath='{.spec.clusterIP}')
CRED=$(kubectl -n sbx-system get svc credproxy -o jsonpath='{.spec.clusterIP}'); DNS=$(kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')
for t in "$SINK:80" "$SINK:443" "$API:443" "$DNS:53" "$CRED:9000" "$CRED:9001"; do in_pod "$A" "curl -s -o /dev/null -m 2 --noproxy '*' http://$t/" >/dev/null; done
wait_for "has_cnp sentinel-q-$A" yes 40
check "sentinel quarantined the session on its own" yes "$(has_cnp sentinel-q-$A)"
for _ in 1 2 3 4 5 6 7 8; do gw_code "$A" >/dev/null; sleep 1; done
check "session cut off (gateway unreachable)" 000 "$(gw_code "$A")"
wait_for "alerts_for $A | grep -q 'verified=True' && echo y" y 30
check "containment verified by Hubble (no control plane involved)" yes "$(alerts_for "$A" | grep -q 'verified=True' && echo yes || echo no)"
kubectl -n sbx-system scale deploy/control-plane --replicas=1 >/dev/null
kubectl -n sbx-system rollout status deploy/control-plane --timeout=120s >/dev/null
wait_for "$CTL ls >/dev/null 2>&1 && echo y" y 30

echo "--- self-protection: nobody else can lift a sentinel quarantine"
denied() { { "$@" 2>&1 || true; } | grep -q 'removed by the sentinel' && echo denied || echo allowed; }   # pipefail-safe
check "cluster admin cannot delete it" denied "$(denied kubectl -n sbx-sessions delete cnp "sentinel-q-$A")"
check "control-plane identity cannot delete it" denied "$(denied kubectl -n sbx-sessions delete cnp "sentinel-q-$A" --as=system:serviceaccount:sbx-system:sbx-controller)"
check "quarantine still in place" yes "$(has_cnp sentinel-q-$A)"

echo "--- S2: a platform pod misbehaving (gateway tries to reach the attacker sink)"
kubectl -n sbx-system exec deploy/gateway -c gateway -- curl -s -o /dev/null -m 3 http://attacker-sink.lab-ext/ >/dev/null 2>&1
wait_for "SC alerts 400 | grep -q 'S2 .*platform pod gateway' && echo y" y 30
check "S2 alert raised from Hubble (independent of the gateway's own logs)" yes "$(SC alerts 400 | grep -q 'S2 .*platform pod gateway' && echo yes || echo no)"

echo "--- S6: a compromised control plane lifts its own containment"
B=$(start_session)
$CTL contain "$B" >/dev/null
wait_for "SC status | python3 -c \"import json,sys; print('y' if '$B' in json.load(sys.stdin)['contained'] else 'n')\"" y 20
kubectl -n sbx-sessions delete cnp "quarantine-$B" >/dev/null                  # the platform's own quarantine...
kubectl -n sbx-sessions label pod "sandbox-$B" sbx/state=running --overwrite >/dev/null   # ...and its relabel, undone
for _ in $(seq 1 45); do gw_code "$B" >/dev/null; [ "$(has_cnp sentinel-q-$B)" = yes ] && break; sleep 2; done
check "S6 detected traffic after containment" yes "$(alerts_for "$B" | grep -q 'S6' && echo yes || echo no)"
check "sentinel re-quarantined the session" yes "$(has_cnp sentinel-q-$B)"
sleep 2
check "session cut off again" 000 "$(gw_code "$B")"

echo "--- sentinel fleet freeze (works without the control plane)"
C=$(start_session)
SC freeze "drill" >/dev/null
wait_for "gw_code $C" 000 15
check "freeze cuts every session" 000 "$(gw_code "$C")"
check "nobody else can lift the freeze" denied "$(denied kubectl -n sbx-sessions delete cnp sentinel-freeze)"
SC unfreeze >/dev/null
wait_for "gw_code $C" 200 20
check "unfreeze restores sessions that were not contained" 200 "$(gw_code "$C")"

echo "--- sentinel's own record"
check "sentinel chain verifies" True "$(kubectl -n sbx-security exec deploy/sentinel -- python -c 'from sbx.common.evidence import verify_chain; print(verify_chain("/data/sentinel.jsonl")[0])')"
for s in "$A" "$B"; do SC release "$s" >/dev/null; $CTL destroy "$s" >/dev/null 2>&1 || SBX_USER=secops $CTL destroy "$s" >/dev/null; done
$CTL destroy "$C" >/dev/null
echo; echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
