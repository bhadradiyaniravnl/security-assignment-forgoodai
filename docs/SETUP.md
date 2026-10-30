# Setup

Tested on macOS 26 / Apple M2 Pro (arm64), 16 GB RAM. Everything runs in a dedicated Colima VM
(`sbx` profile: 6 CPU, 8 GB), so your other Docker contexts are left alone. The kind cluster has three
nodes: control plane, a `platform` worker, and a tainted `sandbox` worker, which is the only one with gVisor.

## 1. Prerequisites

```bash
brew install colima docker kind kubectl cilium-cli hubble
```

You also need Python 3 (the system one is fine; the CLI and harness use only the standard library) and `git`.

Pinned in the scripts: kind node v1.37, Cilium 1.20.1, gVisor release-20261019 (sha512-verified),
hubble CLI v1.20.2 (sha256-verified), Claude Code 2.1.1.

## 2. Credentials

The real key exists only on your host (in a gitignored file) and inside the credproxy pod.

1. Create a key **inside a Console workspace** (ideally a dedicated one with a spend limit).
2. Save it without echoing:
   ```bash
   cp secrets/.example.env secrets/.env
   read -rs "K?Anthropic API key: " && sed -i '' "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=$K|" secrets/.env && unset K
   ```
3. Add `ANTHROPIC_WORKSPACE_ID=` only if the key is *not* workspace-scoped.
4. Enable the pre-commit secret guard:
   ```bash
   make hooks
   ```

### Optional: GitHub flow (`testwriter-agent`)

1. **Create a private repo** with the sample app:
   `gh repo create <you>/items-api-sample --private --source samples/items-api-sample --push`
   (run it from a `git init`-ed copy). Then update `BASELINE["github_repos"]` and the spec to match your repo name.
2. **Create a GitHub App** (Settings → Developer settings → GitHub Apps):
   - Webhook off.
   - Repository permissions: **Contents: Read & write** and **Pull requests: Read & write** only. No Workflows access.
   - Installable "only on this account".
3. **Generate a private key** and save it as `secrets/github-app.pem` (`chmod 600`).
4. **Add the App ID** to `secrets/.env` as `GITHUB_APP_ID=<number>`. Make sure the file ends with a newline.
5. **Install the App** on that one repository only.
6. **Load and check:** `make secrets`, then `kubectl -n sbx-system rollout restart deploy/credproxy`, then `make github`.

## 3. Bring up

```bash
make up
```

This is idempotent and takes about 10–15 minutes the first time. It runs these steps:
1. starts the Colima profile `sbx`;
2. creates the kind cluster (no default CNI, no kube-proxy);
3. installs Cilium with Hubble relay and `socketLB.hostNamespaceOnly=true` (required for gVisor, see DESIGN §15);
4. installs gVisor into the node;
5. builds and loads the images;
6. applies `deploy/k8s` (namespaces, RBAC, network policies, admission policy, services);
7. creates the internal service key and the credproxy Secret.

Check it with:

```bash
make status
bin/sbxctl spec ls
```

## 4. Use it

```bash
bin/sbxctl run bugfix-agent -p repo=demo/app -p task="Make the tests in tests/ pass" -f
```

That starts a session and streams its progress. The other commands:

```bash
bin/sbxctl ls
bin/sbxctl stop <sid>      # revokes access, collects the diff, deletes the pod
bin/sbxctl diff <sid>
bin/sbxctl send <sid> "follow-up" -f   # resumes the same conversation; streams that turn
bin/sbxctl attach <sid>    # history + live stream; typed lines become follow-ups; Ctrl-D detaches
bin/sbxctl contain <sid>   # manual containment
SBX_USER=secops bin/sbxctl freeze "reason"   # fleet kill switch: contain all, deny all, block new runs
SBX_USER=secops bin/sbxctl unfreeze          # lift the network deny (frozen sessions stay contained)
kubectl -n sbx-security exec deploy/sentinel -- python -m sbx.sentinel.ctl status   # sentinel: also alerts | freeze R | unfreeze | release SID | policy
make sentinel-policy                                # edit policies/sentinel/detection.yaml, then validate + diff + deploy (CHECK_ONLY=1 to only check)
bin/sbxctl alerts          # detections + containment verification
bin/sbxctl destroy <sid>
SBX_USER=secops bin/sbxctl spec approve specs/examples/widen-demo-v1.yaml   # a security approver approves the digest
bin/sbxctl spec register specs/examples/widen-demo-v1.yaml                  # then the author registers it
```

## 5. Tests

| Command | What it proves | Model calls / cost |
|---|---|---|
| `make smoke` | L3/L4 boundary, gVisor, lab ingress, quarantine (12 checks) | none |
| `make e2e` | Gateways + credproxy + evidence, prompt/response retention, real `claude -p` (22) | ~$0.01 |
| `make lifecycle` | `sbxctl` lifecycle, trigger rejections, reconciler, **idle reaping** (26) | ~$0.01 |
| `make containment` | D1/D2 → auto-containment → verification, fleet freeze (25) | ~$0.01 |
| `make specs` | Baseline, authors, two-person approval, immutability, admission (36) | ~$0.01 |
| `make sentinel` | Sentinel: placement and least privilege, verified shipping, containment **with the control plane down**, self-protection, S2, S6, own freeze (24) | ~$0.01 |
| `make sentinel-s1` | S1: Hubble L7 sees sandbox requests with credentials redacted; an honest gateway raises nothing; a gateway dropping one session's evidence (lab fault injection) is caught on the AI and egress channels and the session quarantined (7) | ~$0 (count_tokens) |
| `make sentinel-policy-test` | Detection policy: deploy + digest check, floor rejects a blinding policy (before apply, and in the sentinel with a POL alert), custom evidence and Hubble rules, `contain` vs `record`, monitor mode (16) | ~$0.01 |
| `make github` | Scoped App tokens, clone via credproxy, workflow/canary PR refusals (10); `AGENT=1` opens a real PR | ~$0.01 / ~$0.40 |
| **`make security-test`** | **Phase B (18 deterministic cases), Phase A (agent under injection), Phase C (utility); writes `out/report.{md,json}`** | **~$1, ~10 min** |

`make security-test` options:

```bash
make security-test ARGS="--skip A,C"                         # deterministic only, ~2 min
make security-test ARGS="--trials 5 --matrix open:paste"     # more agent trials
python3 harness/security_test.py --render                    # re-render the report from out/report.json
```

## 6. Teardown

```bash
make down              # exports /evidence to out/evidence, deletes the kind cluster
STOP_VM=1 make down    # also stops the Colima profile
colima delete sbx      # removes the VM entirely
```

## Troubleshooting

- **Sandboxes can't reach the gateway** (Hubble shows drops to the gateway as `world`): Cilium is
  missing `socketLB.hostNamespaceOnly=true`. Fix it with
  `cilium upgrade --reuse-values --set socketLB.hostNamespaceOnly=true`, then restart the Cilium DaemonSet.
- **`not scoped to a workspace` / `Workspace … not found`:** use a workspace-scoped key, or set the right `ANTHROPIC_WORKSPACE_ID`.
- **`credit balance is too low`:** add API credits; everything except model calls still works.
- **The control plane is unreachable at 127.0.0.1:8443:** check `make status`. The NodePort is bound to localhost by `deploy/kind.yaml`.
- **Time:** Hubble timestamps and evidence use the node clock. Run `colima restart sbx` if the VM clock drifts after sleep.
