#!/usr/bin/env bash
# M6: spec governance. Org baseline at registration, author authorization, immutability,
# widening needs security approval, runs bind to the registered digest, and the API-server
# admission policy backstops the control plane.
set -uo pipefail
cd "$(dirname "$0")/.."
CTL=bin/sbxctl
API=http://127.0.0.1:8443
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 (got $3)"; pass=$((pass+1)); else echo "FAIL  $1 (expected $2, got $3)"; fail=$((fail+1)); fi; }
reg() { curl -s -o /tmp/claude-501-m6.json -w '%{http_code}' -X POST "$API/specs" -H "X-User: ${2:-$(whoami)}" \
          -H 'content-type: application/yaml' --data-binary @"$1"; }
reason() { python3 -c 'import json; d=json.load(open("/tmp/claude-501-m6.json")).get("detail",{}); print(" | ".join(d.get("reasons",[])) if isinstance(d,dict) else d)' 2>/dev/null; }

echo "--- bootstrapped specs passed the same gate"
check "bugfix-agent registered"      yes "$($CTL spec ls | grep -q '^bugfix-agent  ' && echo yes || echo no)"
check "bugfix-agent-open registered" yes "$($CTL spec ls | grep -q '^bugfix-agent-open ' && echo yes || echo no)"

echo "--- org baseline rejects unsafe specs (422 + reason)"
want() { case "$1" in   # bash 3.2 (macOS) has no associative arrays
  bad-wildcard-egress) echo "wildcards" ;;         bad-unapproved-egress) echo "approved destination" ;;
  bad-runc) echo "gvisor" ;;                        bad-unpinned-image) echo "pinned by digest" ;;
  bad-foreign-registry) echo "approved registry" ;; bad-unknown-secret) echo "credproxy catalogue" ;;
  bad-long-ttl) echo "<= 2h" ;;                     bad-policy-param) echo "policy keys" ;;
  bad-unbounded-param) echo "bounded" ;;            bad-repo-write) echo "read-only" ;;
  bad-broad-bash) echo "riskAcceptance" ;;          bad-unknown-field) echo "schema" ;;
  *) echo "<no expectation>" ;; esac; }
for f in specs/bad/*.yaml; do
  n=$(basename "$f" .yaml); code=$(reg "$f"); r=$(reason)
  ok=$([ "$code" = 422 ] && echo "$r" | grep -qF "$(want "$n")" && echo rejected || echo "$code: $r")
  check "$n" rejected "$ok"
done

echo "--- authorization, immutability, widening (unique spec name per run, so the test is repeatable)"
TMP=$(mktemp -d); WD="widen-demo-$(openssl rand -hex 3)"
for f in specs/examples/widen-demo-*.yaml; do sed "s/name: widen-demo$/name: $WD/" "$f" > "$TMP/$(basename "$f")"; done
check "non-author cannot register" 403 "$(reg $TMP/widen-demo-v1.yaml mallory)"
code=$(reg $TMP/widen-demo-v1.yaml); check "author registers $WD v1" 200 "$code"
code=$(reg $TMP/widen-demo-v1-mutated.yaml)
check "same version, new content rejected" "422 immutable" "$code $(reason | grep -q 'immutable' && echo immutable)"
code=$(reg $TMP/widen-demo-v2.yaml)
check "widening v2 without approval rejected" "422 approval" "$code $(reason | grep -q 'securityApproval' && echo approval)"
code=$(reg $TMP/widen-demo-v2-approved.yaml)
check "widening v2 with securityApproval accepted" 200 "$code"
check "approval recorded as a warning" yes "$(python3 -c 'import json; print("yes" if any("approved" in w for w in json.load(open("/tmp/claude-501-m6.json")).get("warnings",[])) else "no")')"
V2DIGEST=$(python3 -c 'import json; print(json.load(open("/tmp/claude-501-m6.json")).get("digest",""))')

echo "--- runs bind to the latest registered version"
SID=$($CTL run "$WD" -p repo=demo/app -p task="Reply ok. Use no tools." | sed -n 's/^session \([a-z0-9]*\) started.*/\1/p')
S=$($CTL status "$SID")
check "session uses $WD@2"  "$WD@2" "$(echo "$S" | python3 -c 'import json,sys; print(json.load(sys.stdin)["spec_name"])')"
check "session bound to v2 digest" "$V2DIGEST"  "$(echo "$S" | python3 -c 'import json,sys; print(json.load(sys.stdin)["spec_digest"])')"
$CTL destroy "$SID" >/dev/null

echo "--- admission backstop (API server, independent of the control plane)"
weak() { # name labels runtimeClass automountSAToken -> denial message (empty if admitted)
  out=$(kubectl -n sbx-sessions apply -f - 2>&1 <<EOF
apiVersion: v1
kind: Pod
metadata: { name: weak-$1, namespace: sbx-sessions, labels: { $2 } }
spec:
$( [ "$3" = none ] || echo "  runtimeClassName: $3" )
  automountServiceAccountToken: $4
  securityContext: { runAsNonRoot: true, runAsUser: 1000, seccompProfile: { type: RuntimeDefault } }
  containers:
  - { name: a, image: sbx/sandbox:dev, imagePullPolicy: Never, command: [sleep, "5"],
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } } }
EOF
)
  kubectl -n sbx-sessions delete pod "weak-$1" --wait=false >/dev/null 2>&1
  echo "$out" | grep -o "denied request: .*" | head -1
}
check "pod without gVisor (default runc) denied" gvisor "$(weak runc 'sbx/session: x' none false | grep -o gvisor)"
check "SA-token pod denied"   "service account" "$(weak sa 'sbx/session: x' gvisor true | grep -o 'service account')"
check "unlabelled pod denied" "sbx/session"     "$(weak nolabel 'app: x' gvisor false | grep -o 'sbx/session')"
check "compliant pod admitted" admitted          "$(r=$(weak ok 'sbx/session: x' gvisor false); [ -z "$r" ] && echo admitted || echo "$r")"

echo "--- evidence"
EV=$(kubectl -n sbx-system exec deploy/control-plane -- cat /evidence/control-plane.jsonl)
check "rejections recorded with reasons" yes "$(echo "$EV" | python3 -c 'import json,sys; ev=[json.loads(l) for l in sys.stdin if l.strip()]; print("yes" if sum(1 for e in ev if e["action"]=="spec_rejected" and e.get("reasons"))>=14 else "no")')"
check "registrations recorded" yes "$(echo "$EV" | python3 -c 'import json,sys; ev=[json.loads(l) for l in sys.stdin if l.strip()]; print("yes" if any(e["action"]=="spec_registered" and e.get("name","").startswith("widen-demo") and e.get("version")==2 for e in ev) else "no")')"
rm -rf /tmp/claude-501-m6.json "$TMP"
echo; echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
