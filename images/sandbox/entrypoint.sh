#!/usr/bin/env bash
# Waits for the control plane to deliver the workspace and task, then runs Claude Code once.
# stdout (stream-json) is progress only; it is never used as security evidence.
# --allowedTools comes from the spec's agentTools: defense in depth, not the boundary.
set -uo pipefail
TASK=/workspace/.sbx/task.json
echo '{"sbx":"waiting_for_task"}'
until [ -f "$TASK" ]; do sleep 1; done

prompt="$(jq -r .task "$TASK")"
mapfile -t tools < <(jq -r '.allowed_tools[]?' "$TASK")
cd /workspace/repo
echo '{"sbx":"agent_start"}'
claude -p "$prompt" --output-format stream-json --verbose --permission-mode acceptEdits \
  ${tools[@]:+--allowedTools "${tools[@]}"}
rc=$?
echo "{\"sbx\":\"agent_exit\",\"code\":$rc}"
touch /workspace/.sbx/done
# Stay alive so the control plane can collect the diff before deleting the pod.
exec sleep infinity
