#!/usr/bin/env bash
# Sentinel detection policy: rules and response actions as configuration.
# Proves: deploy path (validate + diff, apply, hot reload, digest confirmed), the compiled-in floor
# (rejected before apply, and again by the sentinel if applied by hand: POL alert, last good policy
# kept), custom match rules on shipped evidence and on Hubble flows, response actions chosen by the
# policy (contain vs record), and monitor mode (alert recorded, nothing done).
set -uo pipefail
cd "$(dirname "$0")/../.." && source tests/lib.sh
POLICY=config/sentinel/detection.yaml
active() { SC policy | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])'; }
digest() { echo "sha256:$(shasum -a 256 "$1" | cut -d' ' -f1)"; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
MARK="policy-test-$(openssl rand -hex 3)"

echo "--- deploy the default policy"
check "deploy confirms the sentinel runs this exact file" 0 "$(deploy/sentinel-policy.sh "$POLICY" >/dev/null; echo $?)"
check "active digest = file digest" "$(digest "$POLICY")" "$(active)"
check "policy load recorded in the sentinel's chained log" yes "$(kubectl -n sbx-security exec deploy/sentinel -- grep -c "\"detection_policy_loaded\".*$(digest "$POLICY")" /data/sentinel.jsonl >/dev/null && echo yes || echo no)"

echo "--- the floor: a policy that would blind the sentinel"
python3 - "$POLICY" > "$TMP/bad.yaml" <<'EOF'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for r in d["spec"]["rules"]:
    if r["id"] == "D1": r["enabled"] = False
    if r["id"] == "S6": r["response"] = "record"
print(yaml.safe_dump(d, sort_keys=False))
EOF
OUT=$(CHECK_ONLY=1 deploy/sentinel-policy.sh "$TMP/bad.yaml" 2>&1); RC=$?
check "rejected before it reaches the cluster" 1 "$RC"
check "reason names the floor" yes "$(echo "$OUT" | contains 'floor: D1 must stay enabled' && echo yes || echo no)"
GOOD=$(active)
kubectl -n sbx-security create configmap sentinel-detection --from-file=detection.yaml="$TMP/bad.yaml" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null                      # bypass the script
SC reload >/dev/null
check "applied by hand: sentinel keeps its last good policy" "$GOOD" "$(active)"
wait_for "SC alerts 30 | contains 'POL .*rejected' && echo y" y 15
check "POL alert raised for the rejected policy" yes "$(SC alerts 30 | contains 'POL .*rejected' && echo yes || echo no)"

echo "--- custom rules + response actions, enforce vs monitor"
python3 - "$POLICY" "$MARK" > "$TMP/custom.yaml" <<'EOF'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])); mark = sys.argv[2]
d["metadata"]["version"] = 2
d["spec"]["rules"] += [
    {"id": "LAB-CONTAIN", "type": "match", "source": "gateway", "severity": "high", "response": "contain",
     "match": {"action": "egress_http", "dest_host": "paste-mock.lab-ext", "path": {"contains": f"/{mark}-contain"}},
     "summary": "lab marker read: {path}"},
    {"id": "LAB-MONITOR", "type": "match", "source": "gateway", "severity": "high", "response": "contain",
     "mode": "monitor", "match": {"action": "egress_http", "path": {"contains": f"/{mark}-monitor"}},
     "summary": "lab marker read: {path}"},
    {"id": "LAB-SINK-DIRECT", "type": "match", "source": "hubble-sessions", "severity": "medium", "response": "record",
     "match": {"verdict": "DROPPED", "dest_namespace": "lab-ext", "dest_port": {"in": [8080, 80]}},
     "summary": "direct connection to {dest_namespace}/{dest_pod}:{dest_port} dropped"},
]
print(yaml.safe_dump(d, sort_keys=False))
EOF
check "custom policy deployed" 0 "$(deploy/sentinel-policy.sh "$TMP/custom.yaml" >/dev/null; echo $?)"
A=$(start_session); B=$(start_session)
in_pod "$A" "curl -s -o /dev/null -m 5 http://paste-mock.lab-ext/$MARK-contain" >/dev/null
in_pod "$B" "curl -s -o /dev/null -m 5 http://paste-mock.lab-ext/$MARK-monitor" >/dev/null
SINK=$(kubectl -n lab-ext get svc attacker-sink -o jsonpath='{.spec.clusterIP}')     # sandboxes can't resolve it directly
in_pod "$B" "curl -s -o /dev/null -m 2 --noproxy '*' http://$SINK/" >/dev/null
wait_for "has_cnp sentinel-q-$A" yes 30
check "evidence rule, response 'contain': sentinel quarantined the session" yes "$(has_cnp sentinel-q-$A)"
check "  ...and cut it off" 000 "$(sleep 2; gw_code "$A")"
wait_for "SC alerts 60 | contains 'LAB-MONITOR.*$B' && echo y" y 30
check "monitor mode: alert recorded with the steps it would run" yes "$(SC alerts 60 | grep "LAB-MONITOR" | contains 'monitor: would quarantine+verify' && echo yes || echo no)"
check "monitor mode: nothing done" no "$(has_cnp sentinel-q-$B)"
wait_for "SC alerts 60 | contains 'LAB-SINK-DIRECT .*$B' && echo y" y 30
check "Hubble flow rule, response 'record': alert raised" yes "$(SC alerts 60 | contains "LAB-SINK-DIRECT .*$B" && echo yes || echo no)"
check "  ...and the session keeps running" 200 "$(gw_code "$B")"

echo "--- restore"
check "default policy redeployed" 0 "$(deploy/sentinel-policy.sh "$POLICY" >/dev/null; echo $?)"
check "custom lab rules gone" 0 "$(SC policy | python3 -c 'import json,sys; print(sum(k.startswith("LAB-") for k in json.load(sys.stdin)["custom"]))')"
for s in "$A" "$B"; do SC release "$s" >/dev/null; $CTL destroy "$s" >/dev/null 2>&1 || SBX_USER=secops $CTL destroy "$s" >/dev/null; done
finish
