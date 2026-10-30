#!/usr/bin/env bash
# Shared helpers for the test suites in tests/suites/. Each suite does:
#   cd "$(dirname "$0")/../.." && source tests/lib.sh
# Verdicts always come from outside the sandbox (kubectl, Hubble, evidence), never from the agent.

CTL=bin/sbxctl
pass=0; fail=0

# check NAME EXPECTED ACTUAL: print PASS/FAIL and count it
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 (got $3)"; pass=$((pass+1)); else echo "FAIL  $1 (expected $2, got $3)"; fail=$((fail+1)); fi; }
# sid_of: read `sbxctl run` output on stdin, print the session id
sid_of() { sed -n 's/^session \([a-z0-9]*\) started.*/\1/p'; }
# wait_for CMD EXPECTED [SECONDS]: poll CMD (eval'd) once a second until it prints EXPECTED
wait_for() { for _ in $(seq 1 "${3:-40}"); do [ "$(eval "$1")" = "$2" ] && return 0; sleep 1; done; return 1; }
# in_pod SID CMD: run CMD inside the session's sandbox pod (as the attacker would)
in_pod() { kubectl -n sbx-sessions exec "sandbox-$1" -- sh -c "$2" 2>/dev/null; }
# gw_code SID: HTTP status the sandbox gets from the gateway; 000 = cut off
gw_code() { in_pod "$1" 'curl -s -o /dev/null -m 2 -w "%{http_code}" http://gateway:8080/healthz' | head -c 3; }
# has_cnp NAME: yes/no, does that CiliumNetworkPolicy exist in sbx-sessions
has_cnp() { kubectl -n sbx-sessions get cnp "$1" >/dev/null 2>&1 && echo yes || echo no; }
# SC ARGS: the sentinel's operator CLI (status, alerts, policy, release, freeze, ...)
SC() { kubectl -n sbx-security exec deploy/sentinel -- python -m sbx.sentinel.ctl "$@"; }

# start_session: run a trivial bugfix-agent session and wait until its sandbox reaches the gateway
start_session() { local s; s=$($CTL run bugfix-agent -p repo=demo/app -p task="Reply with the word ok. Do not use any tools." | sid_of)
                  wait_for "gw_code $s" 200 40; echo "$s"; }

# contains GREP-ARGS: like `grep -q`, but reads all of stdin first. Under `set -o pipefail`, `cmd | grep -q`
# fails when grep exits on the first match and cmd (e.g. kubectl exec still writing) then dies of SIGPIPE.
contains() { grep "$@" >/dev/null; }

# finish: print the totals; exit status says whether every check passed
finish() { echo; echo "passed=$pass failed=$fail"; [ "$fail" = 0 ]; }
