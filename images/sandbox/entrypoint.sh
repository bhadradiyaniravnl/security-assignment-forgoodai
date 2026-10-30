#!/usr/bin/env bash
# Waits for the control plane to deliver the workspace and task, runs Claude Code on it, then serves
# follow-up messages: each one resumes the same conversation (`--continue`) in the same workspace.
# stdout (stream-json) is progress only; it is never used as security evidence.
# --allowedTools comes from the spec's agentTools: defense in depth, not the boundary.
set -uo pipefail
SBX=/workspace/.sbx
TASK=$SBX/task.json
INBOX=$SBX/inbox
echo '{"sbx":"waiting_for_task"}'
until [ -f "$TASK" ]; do sleep 1; done

mapfile -t tools < <(jq -r '.allowed_tools[]?' "$TASK")
cd /workspace/repo

turn() { # prompt, continue-flag
  # --setting-sources user + --strict-mcp-config: a repo's .claude/settings.json or .mcp.json cannot
  # widen tools, add hooks or attach MCP servers beyond what the spec grants.
  claude -p "$1" ${2:+--continue} --output-format stream-json --verbose --permission-mode acceptEdits \
    --setting-sources user --strict-mcp-config \
    ${tools[@]:+--allowedTools "${tools[@]}"}
}

echo '{"sbx":"agent_start","turn":0}'
turn "$(jq -r .task "$TASK")"
echo "{\"sbx\":\"agent_exit\",\"turn\":0,\"code\":$?}"
touch "$SBX/done"

# Follow-ups arrive as $INBOX/<n>.json, written atomically by the control plane. Processed in order;
# the pod stays alive between turns so the control plane can also collect the diff at any time.
mkdir -p "$INBOX"
n=1
while true; do
  msg="$INBOX/$n.json"
  if [ -f "$msg" ]; then
    echo "{\"sbx\":\"agent_start\",\"turn\":$n}"
    turn "$(jq -r .text "$msg")" continue
    echo "{\"sbx\":\"agent_exit\",\"turn\":$n,\"code\":$?}"
    n=$((n + 1))
  else
    sleep 1
  fi
done
