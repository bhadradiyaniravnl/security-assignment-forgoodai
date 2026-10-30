# Sandboxed coding-agent platform (security take-home)

A small internal platform that runs Claude Code in disposable, gVisor-isolated Kubernetes pods.
- **No real credentials in the sandbox.** It holds only a session token that works from its own pod,
  for its own spec, while it runs. Model calls and egress go through a gateway; real secrets exist
  only in a credentials proxy outside it.
- **Specs grant every capability.** Each one comes from a reviewed, versioned agent spec.
- **An independent sentinel** (own namespace and node) watches the evidence and the kernel-level
  network flows, and quarantines a session on its own, even with the control plane down.
- **A one-command harness then tries to break it all**, and reports what still gets through.

| Read | For |
|---|---|
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | The write-up: assets, attackers, STRIDE controls, results, limitations. Case IDs (`B9`, `B20`…) are defined in the report |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How it is built: components, policy model, credentials, network, flows, decisions |
| [AGENTS.md](AGENTS.md) | How to run it on your machine, the tests, the repo map (Claude Code loads it via `CLAUDE.md`) |
| [docs/results/](docs/results/security-test-2026-10-30.md) | The latest harness report |
| [SLIDES.html](SLIDES.html) | The walkthrough deck (open locally; ← → to navigate, N for speaker notes) |
| [docs/COVERAGE.md](docs/COVERAGE.md) | Controls and tests per component, and what is not covered |
| [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) · [docs/BUILD_LOG.md](docs/BUILD_LOG.md) | Review findings at a point in time (high and medium fixed) · what broke along the way |

```mermaid
flowchart TB
  user([engineer<br/>sbxctl, X-User]) -->|127.0.0.1:8443| cp
  sec([security<br/>kubectl exec → ctl]) -.-> sen
  cfg[/agent specs · detection policy<br/>config/, reviewed, versioned/] -.-> cp
  cfg -.-> sen

  subgraph platform [platform node · sbx-system]
    cp[control plane<br/>spec registry + baseline · sessions<br/>token checks · trusted diff · reaper]
    gw[gateway<br/>AI :8080 · egress proxy :3128<br/>spec policy on every request]
    cred[credproxy<br/>the only real secrets<br/>Anthropic key · GitHub App]
    ship[evidence shipper<br/>hash-chained records]
    ev[(evidence<br/>gateway · control plane · alerts)]
    gitlab[(git-lab<br/>lab repos)]
  end

  subgraph sandbox [sandbox node · sbx-sessions · gVisor · Cilium default-deny]
    pod[sandbox-SID<br/>Claude Code · repo copy + canary<br/>session token only, no SA token]
  end

  subgraph security [security node · sbx-security]
    sen[sentinel<br/>D1–D3 · EV · S1 · S2 · S6<br/>own deny policies · own log]
  end

  k8s{{kube-apiserver<br/>RBAC · admission policy}}
  hub((Hubble<br/>kernel flow log))

  cp -->|create pod · quarantine CNP| k8s --> pod
  cp -->|clone via credproxy, workspace via exec| pod
  cp --> gitlab
  pod -->|model calls| gw
  pod -->|allowed hosts| gw
  pod -. "anything else: dropped" .-> hub
  gw -->|validate token| cp
  gw --> cred
  cred -->|real key injected| anth[(api.anthropic.com)]
  cred -->|repo-scoped token,<br/>revoked after use| gh[(GitHub<br/>draft PR)]
  cred --> lab[(lab hosts<br/>paste-mock · attacker-sink)]
  gw --> ev
  cp --> ev
  ev --> ship -->|verified on arrival| sen
  hub --> sen
  sen -->|sentinel-q-SID, sentinel-freeze| k8s
  sen -.->|revoke · snapshot · alert| cp
```

## Results at a glance

| | |
|---|---|
| **Phase B: enforcement, agent assumed compromised** | **27/27 as expected**: no credentials in the pod; every bypass (raw TCP, API server, credproxy, other sessions, DNS) dropped and seen by Hubble; canary writes to an allowed host blocked and contained |
| Findings (what still gets through) | **B20:** a canary in a *read* URL to an allowed host leaves once, then is detected and contained in ~1 s. **B10v / B9v:** if a spec explicitly grants writes, TLS is opaque (undetected) and plain HTTP is detected after one request |
| **Phase A: real agent under prompt injection** | 6 trials: **0/6** attempted the exfiltration; 3/6 did the task anyway; 3/6 refused by the provider (the task failed too); no agent warned the user. Not evidence of protection: Phase B is |
| **Phase C: utility** | The legitimate task passes with every control on (tests re-run offline on the trusted diff) |
| **Real GitHub** | Scoped, revoked-after-use App tokens; a draft PR with 52 passing tests plus 9 strict xfails documenting 4 real bugs (private repo; reproduce with `make github AGENT=1` against your own) |
| Evidence | Gateway, control-plane and alert logs are hash-chained and verified on every run |
| Limits | Detection is canary-specific; gVisor, not a microVM; identity is a header. Full list in the threat model |

## What I built vs reused

**Reused, configured but not modified:**
- kind, Colima, Cilium + Hubble;
- gVisor;
- Kubernetes Pod Security and ValidatingAdmissionPolicy;
- Claude Code;
- aiohttp, FastAPI, the kubernetes client, PyYAML, jsonschema;
- `git daemon`.

**Built** (everything in `src/`, `config/`, `deploy/`, `images/`, `tests/`):
- the AI gateway and the egress proxy;
- the credentials proxy (including GitHub App tokens);
- the control plane: spec registry with org baseline and two-person approval, session lifecycle,
  trusted diff and PRs, containment;
- the sentinel: detection rules, the configurable detection policy, independent response;
- the evidence chain, the canary matcher and `sbxctl`;
- the manifests;
- the harness and suites.

**AI assistance:** I used Claude Code throughout for research, implementation and debugging. The
architecture, threat model, trade-offs and findings are mine to defend.

**Time spent:** about 6 hours of focused work.
