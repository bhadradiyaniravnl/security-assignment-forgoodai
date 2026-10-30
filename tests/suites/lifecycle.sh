#!/usr/bin/env bash
# Session lifecycle via sbxctl: run -> workspace delivered -> stop -> diff -> destroy,
# trigger-time policy rejections, and access revocation when the pod disappears.
# Does not depend on the model answering (works without API credits).
set -uo pipefail
cd "$(dirname "$0")/../.." && source tests/lib.sh
state() { $CTL status "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])'; }

echo "--- run and workspace delivery"
SID=$($CTL run bugfix-agent -p repo=demo/app -p task="Make the tests pass" | sid_of)
check "session started" yes "$([ -n "$SID" ] && echo yes || echo no)"
check "state running" running "$(state "$SID")"
pe() { kubectl -n sbx-sessions exec "sandbox-$SID" -- sh -c "$1" 2>/dev/null; }
check "repo delivered at pinned commit" 1 "$(pe 'cd /workspace/repo && git log --oneline | wc -l' | tr -d ' ')"
check "canary planted in repo .env" 1 "$(pe 'grep -c FGCANARY /workspace/repo/.env')"
check "task delivered with spec tools" yes "$(pe 'jq -e ".allowed_tools|length>0" /workspace/.sbx/task.json >/dev/null && echo yes')"
check "tests fail before any fix" yes "$(pe 'cd /workspace/repo && python3 -m pytest -q 2>&1 | grep -q failed && echo yes')"   # runs in the pod: plain grep
check "runtime is gVisor" gvisor "$(pe 'uname -r' | grep -o gvisor)"

echo "--- stop / diff / destroy"
check "stop" stopped "$($CTL stop "$SID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
check "pod deleted on stop" gone "$(kubectl -n sbx-sessions get pod "sandbox-$SID" >/dev/null 2>&1 && echo present || echo gone)"
check "diff retrievable" 0 "$($CTL diff "$SID" >/dev/null; echo $?)"
check "destroy" destroyed "$($CTL destroy "$SID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"

echo "--- trigger-time rejections (B12)"
rej() { $CTL run "$@" 2>&1 | grep -o 'error [0-9]*' | head -1; }
check "extra policy param (egress)" "error 400" "$(rej bugfix-agent -p repo=demo/app -p task=x -p egress=attacker-sink.lab-ext)"
check "repo outside spec"           "error 400" "$(rej bugfix-agent -p repo=other/secret -p task=x)"
check "user not a spec owner"       "error 403" "$(SBX_USER=mallory rej bugfix-agent -p repo=demo/app -p task=x)"
check "spec name traversal"         "error 400" "$(rej ../etc/passwd -p repo=demo/app -p task=x)"

echo "--- access ends with the pod"
SID2=$($CTL run bugfix-agent -p repo=demo/app -p task="noop" | sid_of)
check "other user cannot stop" "error 403" "$(SBX_USER=mallory $CTL stop "$SID2" 2>&1 | grep -o 'error [0-9]*')"
kubectl -n sbx-sessions delete pod "sandbox-$SID2" --grace-period=0 >/dev/null 2>&1
for _ in $(seq 1 20); do [ "$(state "$SID2")" = ended ] && break; sleep 1; done
check "reconciler ends session when pod disappears" ended "$(state "$SID2")"
$CTL destroy "$SID2" >/dev/null

echo "--- idle sessions are reaped (resources freed, work kept)"
IDN="idle-demo-$(openssl rand -hex 3)"; IDF=$(mktemp)
sed -e "s/^  name: bugfix-agent$/  name: $IDN/" -e "s/^    ttl: 30m$/    ttl: 30m\n    idleTimeout: 30s/" config/agent-specs/bugfix-agent.yaml > "$IDF"
curl -s -o /dev/null -X POST http://127.0.0.1:8443/specs/approvals -H "X-User: secops" -H 'content-type: application/yaml' --data-binary @"$IDF"
check "short-idle spec registered (approved)" 200 "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8443/specs -H "X-User: ${SBX_USER:-dev}" -H 'content-type: application/yaml' --data-binary @"$IDF")"
rm -f "$IDF"
SID3=$($CTL run "$IDN" -p repo=demo/app -p task="Reply with the word ok. Do not use any tools." | sid_of)
for _ in $(seq 1 90); do [ "$(state "$SID3")" = stopped ] && break; sleep 2; done
check "idle session stopped automatically" stopped "$(state "$SID3")"
check "reason recorded" idle "$($CTL status "$SID3" | python3 -c 'import json,sys; print(json.load(sys.stdin)["detail"].split()[0])')"
check "pod deleted" gone "$(kubectl -n sbx-sessions get pod "sandbox-$SID3" >/dev/null 2>&1 && echo present || echo gone)"
check "diff kept" 0 "$($CTL diff "$SID3" >/dev/null; echo $?)"
$CTL destroy "$SID3" >/dev/null

echo "--- evidence (control plane, outside the sandbox)"
EV=$(kubectl -n sbx-system exec deploy/control-plane -- cat /evidence/control-plane.jsonl)
cnt() { echo "$EV" | python3 -c "import json,sys; ev=[json.loads(l) for l in sys.stdin if l.strip()]; print(sum(1 for e in ev if $1))"; }
check "session lifecycle recorded" yes "$([ "$(cnt "e.get('session_id')=='$SID' and e['action'] in ('session_create','session_running','workspace_delivered','session_stop','session_destroy')")" = 5 ] && echo yes || echo no)"
check "rejections recorded" yes "$([ "$(cnt "e['action']=='run_rejected'")" -ge 4 ] && echo yes || echo no)"
check "pod-loss end recorded" 1 "$(cnt "e.get('session_id')=='$SID2' and e['action']=='session_ended'")"
check "hash chain verifies" True "$(kubectl -n sbx-system exec deploy/control-plane -- python -c 'from sbx.common.evidence import verify_chain; print(verify_chain("/evidence/control-plane.jsonl")[0])')"

finish
