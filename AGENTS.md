# AGENTS.md: working with this repository

Guide for anyone, human or coding agent, who needs to run, test or change this project. `CLAUDE.md`
imports this file, so Claude Code loads it automatically.

## What this is

A security take-home: a small platform that runs Claude Code in disposable, gVisor-isolated
Kubernetes pods on a local kind cluster. The sandbox holds no real credentials. Model calls and
egress go through a gateway, and real secrets live only in a credentials proxy. Agent capabilities
come from reviewed agent specs, and a separate sentinel detects exfiltration attempts and contains them.

Read, in this order: [README.md](README.md) (one page) → [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
(the 2-page write-up) → [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (the technical reference).

## Rules for agents working here

- **Never print, log or commit secrets.** Real keys live only in `secrets/.env` and
  `secrets/github-app.pem`, which are gitignored. Ask the user to type secrets into those files
  themselves; never ask for a key in chat. `make hooks` enables a pre-commit guard.
- **Offensive tests stay inside the lab.** The only exfiltration targets are the in-cluster
  stand-ins `paste-mock.lab-ext` and `attacker-sink.lab-ext`. Never point anything at a real external host.
- **Don't push, open PRs, or change the GitHub App** unless the user asks.
- **Verdicts come from outside the sandbox** (evidence logs, Hubble, lab receipts), never from
  what the agent inside says it did.

## Run it on your machine

**Tested on:** macOS on Apple silicon (M2 Pro, 16 GB RAM). Everything runs in a dedicated Colima VM
(profile `sbx`, 6 CPU, 8 GB), so your other Docker contexts are left alone. Other platforms are untested;
on Linux/x86, set `HUBBLE_ARCH=amd64` in `images/services/Dockerfile` and replace the Colima step in `deploy/up.sh`.

### 1. Prerequisites

```bash
brew install colima docker kind kubectl cilium-cli hubble
```

You also need `git` and Python 3 (the system one is fine; the CLI and the harness use only the
standard library). The scripts pin and checksum-verify the cluster components: kind node v1.37,
Cilium 1.20.1, gVisor release-20261019, Hubble CLI v1.20.2 and Claude Code 2.1.1.

### 2. Credentials

| You have | What works |
|---|---|
| Nothing | `make up`, `make smoke`, and reading everything |
| An Anthropic API key | Everything except the real GitHub flow |
| + a GitHub App (optional) | `make github` too (clone a private repo, open a draft PR) |

The key exists only on your host (in a gitignored file) and inside the credproxy pod.

1. Create the key **inside a Console workspace**, ideally a dedicated one with a spend limit.
2. Save it without echoing it to the terminal:
   ```bash
   cp secrets/.example.env secrets/.env
   read -rs "K?Anthropic API key: " && sed -i '' "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=$K|" secrets/.env && unset K
   ```
3. Add `ANTHROPIC_WORKSPACE_ID=` only if the key is *not* workspace-scoped.
4. `make hooks` enables the pre-commit secret guard (only needed if you will commit).

<details><summary>Optional: the real GitHub flow (<code>testwriter-agent</code>)</summary>

1. Create a private repo from `samples/items-api` (from a `git init`-ed copy):
   `gh repo create <you>/items-api-sample --private --source . --push`.
   Then put your repo name in `BASELINE["github_repos"]` (`src/sbx/control_plane/baseline.py`) and in
   `config/agent-specs/testwriter-agent.yaml`.
2. Create a GitHub App (Settings → Developer settings → GitHub Apps): webhook off; repository
   permissions **Contents: Read & write** and **Pull requests: Read & write** only (no Workflows);
   installable only on your account.
3. Generate a private key, save it as `secrets/github-app.pem` (`chmod 600`), and add
   `GITHUB_APP_ID=<number>` to `secrets/.env`. Make sure the file ends with a newline.
4. Install the App on that one repository, then run `make secrets && kubectl -n sbx-system rollout restart deploy/credproxy && make github`.
</details>

### 3. Bring it up

```bash
make up          # ~10-15 min the first time; idempotent
make status      # every pod Running
bin/sbxctl spec ls
```

`make up` does the following:
1. starts the Colima VM;
2. creates a 3-node kind cluster with no default CNI and no kube-proxy;
3. installs Cilium with Hubble (credential headers redacted) and gVisor on the sandbox node;
4. builds and loads the images;
5. applies `deploy/k8s/`;
6. creates the per-component keys and the credproxy Secret;
7. deploys the sentinel's detection policy.

### 4. Use it

```bash
bin/sbxctl run bugfix-agent -p repo=demo/app -p task="Make the tests in tests/ pass" -f
bin/sbxctl send <sid> "now add a test for X" -f   # follow-up: resumes the same conversation
bin/sbxctl attach <sid>                          # history + live stream; typed lines are follow-ups; Ctrl-D detaches
bin/sbxctl stop <sid>                            # revoke, collect the trusted diff, delete the pod
bin/sbxctl diff <sid>
bin/sbxctl ls | status <sid> | alerts | destroy <sid>
bin/sbxctl contain <sid>                         # manual containment
SBX_USER=secops bin/sbxctl freeze "reason"       # fleet kill switch (unfreeze to lift)
```

Security operator commands:
```bash
kubectl -n sbx-security exec deploy/sentinel -- python -m sbx.sentinel.ctl status   # also: alerts | policy | release SID | freeze R | unfreeze
make sentinel-policy                             # validate + diff + deploy config/sentinel/detection.yaml (CHECK_ONLY=1 to only check)
SBX_USER=secops bin/sbxctl spec approve config/agent-specs/examples/widen-demo-v1.yaml   # approver approves a digest
bin/sbxctl spec register config/agent-specs/examples/widen-demo-v1.yaml                  # then the author registers it
```

### 5. Test it

| Command | What it proves | Cost |
|---|---|---|
| **`make security-test`** | **The assignment's one-command harness:** Phase B (deterministic: agent assumed compromised), Phase A (real agent under prompt injection), Phase C (legitimate task still works). Writes `out/report.md` | **~$1, ~10 min** |
| `make security-test ARGS="--skip A,C"` | Phase B only | ~2 min |
| `make test` | Every feature suite below except `github` | ~25 min, cents |
| `make smoke` | gVisor, Cilium boundary, lab ingress, quarantine | no model calls |
| `make e2e` | Gateways, credproxy, evidence, a real Claude Code call | cents |
| `make lifecycle` | `sbxctl` lifecycle, trigger-time rejections, reconciler, idle reaping | cents |
| `make containment` | Detection → automatic containment → independent verification, fleet freeze | cents |
| `make specs` | Spec governance: org baseline, authors, two-person approval, admission backstop | cents |
| `make sentinel` | Sentinel isolation, verified evidence shipping, containment with the control plane down, S2, S6 | cents |
| `make sentinel-completeness` | S1: a gateway that under-reports (fault-injected for the test only) is caught | ~$0 |
| `make sentinel-policy-test` | Detection policy: deploy and digest, floor, custom rules, monitor mode | cents |
| `make github` | Scoped GitHub App tokens, clone via credproxy, PR refusals (`AGENT=1` opens a real PR) | needs the App |

Other options: `ARGS="--trials 5 --matrix open:paste"` for more agent trials, and
`python3 tests/security_test.py --render` to re-render the report from `out/report.json`.

### 6. Tear it down

```bash
make down              # exports evidence to out/, deletes the kind cluster
STOP_VM=1 make down    # also stops the Colima VM
colima delete sbx      # removes the VM entirely
```

### Troubleshooting

- **The first `make up` stalls in the Cilium wait:** re-run `make up`; it is idempotent.
- **Sandboxes can't reach the gateway** (Hubble shows drops to the gateway as `world`): Cilium is
  missing `socketLB.hostNamespaceOnly=true`. Run `cilium upgrade --reuse-values --set socketLB.hostNamespaceOnly=true`
  and restart the Cilium DaemonSet.
- **`not scoped to a workspace` / `Workspace … not found`:** use a workspace-scoped key, or set `ANTHROPIC_WORKSPACE_ID`.
- **`credit balance is too low`:** add API credits; everything except model calls still works.
- **`127.0.0.1:8443` unreachable:** check `make status`; `deploy/kind.yaml` binds the control-plane NodePort to localhost.
- **Odd timestamps after the laptop slept:** `colima restart sbx` (Hubble and evidence use the VM clock).

## Changing the code

- **One Python package, one image.** All platform code is in `src/sbx/`. After a change, run
  `make images apply`, then `kubectl -n sbx-system rollout restart deploy`; for the sentinel, also
  `kubectl -n sbx-security rollout restart deploy/sentinel`. Then run the relevant suite.
- **Configuration is data, not code:** agent capabilities live in `config/agent-specs/`, and the
  sentinel's rules and responses in `config/sentinel/detection.yaml`. The code keeps only the
  compiled-in guardrails: the org baseline (`control_plane/baseline.py`) and the detection floor
  (`sentinel/detection_policy.py`).
- **Suites** are plain bash in `tests/suites/` that share `tests/lib.sh`. Keep verdicts external, use
  `contains` rather than `grep -q` in pipelines (pipefail-safe), and clean up the sessions you start.
- **Packaging for review:** `make dist` writes `out/sandboxed-agents.zip` from the last commit
  (`git archive`), so `secrets/` and `out/` are never included.

## Repo map

```
src/sbx/                  all platform code (one Python package, one image)
  control_plane/            sessions, spec registry + org baseline, Kubernetes driver, state store
  gateway/                  AI gateway (:8080) and egress forward proxy (:3128)
  credproxy/                the only holder of secrets: inference key, egress tunnel, GitHub App
  sentinel/                 independent detection and response (rules, detection policy, Hubble, actions)
  cli/                      sbxctl
  common/                   canary matcher, hash-chained evidence log, component keys, policy lookups
  lab/                      stand-ins: paste-mock / attacker-sink, git-lab
config/
  agent-specs/              what each agent may do; examples/ for the approval flow
  sentinel/detection.yaml   the sentinel's rules and response actions
deploy/                   up / down / images / secrets / sentinel-policy scripts, kind.yaml
  k8s/                      namespaces, RBAC, Cilium policies, admission, workloads, sentinel
images/                   sandbox (Claude Code + toolchain), sandbox-pyweb, services
tests/
  security_test.py          the one-command harness (phases A, B, C)
  suites/ + lib.sh          feature suites and their shared helpers
  fixtures/                 bad-specs/ (must be rejected), injections/ (prompt-injection variants)
samples/                  target repos: slugkit (bug-fix task), items-api (GitHub flow)
docs/                     THREAT_MODEL, ARCHITECTURE, SECURITY_REVIEW, BUILD_LOG, results/
bin/sbxctl                runs the CLI from the repo without installing anything
```
