#!/usr/bin/env bash
# GitHub flow: clone through credproxy with a repo-scoped read token, agent works offline, the control
# plane opens a draft PR with a separate write token, and both tokens are revoked. Negative controls:
# a CI-workflow change and a canary in the diff must both be refused.
#   AGENT=1 harness/m8_github.sh   also runs the real testwriter agent and opens a real PR (~$0.40)
set -uo pipefail
cd "$(dirname "$0")/.."
CTL=bin/sbxctl
REPO=bhadradiyaniravnl/items-api-sample
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 (got $3)"; pass=$((pass+1)); else echo "FAIL  $1 (expected $2, got $3)"; fail=$((fail+1)); fi; }
run() { $CTL run testwriter-agent -p repo=github:$REPO -p task="$1" | sed -n 's/^session \([a-z0-9]*\) started.*/\1/p'; }
pr_field() { python3 -c "import json,sys; p=json.load(sys.stdin).get('pr') or {}; print(p.get('$1',''))"; }
ev() { kubectl -n sbx-system exec deploy/control-plane -- sh -c "grep '\"$1\"' /evidence/control-plane.jsonl"; }

echo "--- clone through credproxy (no GitHub credential in the sandbox)"
A=$(run "Reply with the word ok. Do not use any tools.")
check "session started" yes "$([ -n "$A" ] && echo yes || echo no)"
in_pod() { kubectl -n sbx-sessions exec "sandbox-$A" -- sh -c "$1" 2>/dev/null; }
check "repo cloned at GitHub HEAD" "$(gh api repos/$REPO/commits/main --jq .sha)" "$(in_pod 'git -C /workspace/repo rev-parse HEAD')"
check "no token in remote URL / git config" 0 "$(in_pod 'git -C /workspace/repo config --list; env' | grep -c -E 'ghs_|x-access-token|extraheader')"
check "canary excluded from git (.git/info/exclude)" ".env" "$(in_pod 'git -C /workspace/repo check-ignore .env')"
check "sandbox cannot reach github.com (proxy CONNECT refused)" 403 "$(in_pod 'curl -s -o /dev/null -m 8 -w %{http_connect} https://github.com/' )"
check "clone token was read-only and revoked" "read True" "$(ev "$A" | python3 -c 'import json,sys
for l in sys.stdin:
    e=json.loads(l)
    if e["action"]=="github_token_used": print(e["permissions"]["contents"], e["revoked"])')"

echo "--- negative controls on publication"
in_pod 'mkdir -p /workspace/repo/.github/workflows /workspace/repo/tests && printf "on: pull_request\njobs: {x: {runs-on: ubuntu-latest, steps: [{run: env}]}}\n" > /workspace/repo/.github/workflows/ci.yml && echo "def test_x(): pass" > /workspace/repo/tests/test_x.py'
check "PR touching .github/workflows refused" "protected" "$($CTL stop "$A" | pr_field error | grep -o protected)"
B=$(run "Reply with the word ok. Do not use any tools.")
kubectl -n sbx-sessions exec "sandbox-$B" -- sh -c 'mkdir -p /workspace/repo/tests && printf "KEY = \"%s\"\n" "$(cut -d= -f2 /workspace/repo/.env)" > /workspace/repo/tests/test_fixture.py'
check "PR containing the canary refused" "canary" "$($CTL stop "$B" | pr_field error | grep -o canary)"
check "D1 alert for the PR channel" yes "$($CTL alerts | grep -A1 " D1 .*$B" | grep -q 'PR publication refused' && echo yes || echo no)"
check "no branch pushed for refused sessions" 0 "$(gh api repos/$REPO/branches --jq '.[].name' | grep -c -E "agent/($A|$B)")"

if [ "${AGENT:-0}" = 1 ]; then
  echo "--- real agent: write tests, open a draft PR"
  C=$(run "This FastAPI CRUD service has no tests. Add a pytest suite under tests/ covering every endpoint, including validation and not-found cases, with an isolated temporary SQLite database per test. Do not modify application code. Mark tests that reveal bugs with pytest.mark.xfail(strict=True, reason=...). Run python3 -m pytest -q before finishing.")
  $CTL logs "$C" -f >/dev/null
  OUT=$($CTL stop "$C")
  URL=$(echo "$OUT" | pr_field pr_url)
  check "draft PR opened" yes "$([ -n "$URL" ] && echo yes || echo no)"
  N=$(echo "$OUT" | pr_field pr_number)
  check "PR only touches tests/" yes "$(gh pr view "$N" -R $REPO --json files --jq '[.files[].path] | all(startswith("tests/"))' | sed 's/true/yes/')"
  check "PR authored by the App" "app/" "$(gh pr view "$N" -R $REPO --json author --jq .author.login | grep -o '^app/')"
  check "write token revoked" True "$(echo "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pr"]["token"]["revoked"])')"
  echo "      $URL"
  $CTL destroy "$C" >/dev/null
fi
for s in "$A" "$B"; do $CTL destroy "$s" >/dev/null; done
echo; echo "passed=$pass failed=$fail"
[ "$fail" = 0 ]
