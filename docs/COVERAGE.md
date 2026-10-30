# Control coverage by component

Companion to [THREAT_MODEL.md](THREAT_MODEL.md): which controls protect each component, and the test that exercises them. Letters are the STRIDE
classes the row addresses; `B..` is a Phase B case, other names are suites in `tests/suites/`.

| Component | Controls | Tests |
|---|---|---|
| `sbxctl` and user identity | API bound to localhost; owner checks on every session op; `system:*` reserved; output sanitised (`safe()`); contained-session release and destroy are admin-only. **S T R E** | lifecycle, B19, review M6/M9 |
| Control plane API | Per-component key scopes (gateway key cannot reach GitHub routes); test-only session endpoint removed; declared parameters only; compare-and-set state transitions; per-pod resource limits. **S T R D E** | B12, B19, containment, review H4/M6/M8 |
| Spec registry and baseline | Strict schema; org baseline (gVisor, exact hosts, approved models, bounded TTL and bursts, read-only repos); two-person digest approval, approver ≠ author; immutable versions; widening needs re-approval; bad-spec fixtures rejected. **S T R E** | specs, B14, B15 |
| Workspace delivery and messages | Repo cloned and canary planted by the control plane (`O_NOFOLLOW`, 0600); files streamed in via exec args, never credentials; messages owner-only, ≤4000 chars, written atomically; running sessions only. **T R I E** | lifecycle, e2e, review M5 |
| State store and reconciler | Durable SQLite under a lock; pod loss ends the session and revokes its token; idle and lifetime reaper; contained retention; orphan sweep. **T R D** | lifecycle |
| Kubernetes driver and admission | Namespace-scoped RBAC for the controller; ValidatingAdmissionPolicy refuses non-gVisor pods, SA tokens, missing session label, wrong node pool, hostPath/Secret/projected volumes. **S T E** | B13, B15, B21, specs |
| Sandbox pod and agent runtime | gVisor; non-root, read-only root fs, all capabilities dropped, seccomp; sized emptyDirs; CPU/memory/TTL limits; no SA token; `--setting-sources user --strict-mcp-config`; spec models pinned via env; allowedTools from the spec. **T R I D E** | B4, B13, Phase C, review M10 |
| AI gateway | Placeholder token bound to pod IP and spec; client credentials stripped; Messages endpoints only, custom tools only, no server tools/MCP/URL sources; model allowlist and budget; per-IP in-flight cap; streaming tool_use inspection; bodies retained with canary redaction. **S T R I D E** | B6, B7, B16–B18, e2e |
| Egress proxy | Exact-host allowlist; write-capable hosts read-only unless the spec write-allows; CONNECT counts as a write; canary scan on plain HTTP; header, body and response caps; per-IP connection cap. **S T R I D E** | B1–B3, B9, B10, B20, containment |
| Credentials proxy | Only holder of the inference key and GitHub App key; per-grant re-check against session policy with uncached lookups for GitHub; `Accept-Encoding: identity` so the gateway can inspect; repo-scoped per-operation tokens, revoked after use; FQDN egress allowlist; separate node from sandboxes. **S T R I D E** | B6b, B21, github |
| Evidence log and shipper | Hash-chained JSONL with sequence numbers; shipped to the sentinel, which verifies chain and continuity on arrival and keeps its own copy; snapshots and transcripts taken at containment. **S T R I D** | sentinel (EV), e2e chain checks |
| Sentinel | Own namespace and node; SA limited to Cilium policies and pod list; ingest from the gateway pod only; rules fed by shipped evidence *and* Hubble; S1 reconciles kernel request counts with gateway claims; own deny policies protected by admission; containment verified by Hubble; detection policy validated against a compiled floor, rejected policies raise POL and keep the last good one. **S T R I D E** | sentinel, sentinel-completeness, sentinel-policy |
| Network fabric and nodes | Cilium default-deny in `sbx-sessions`; sandboxes reach only gateway :8080/:3128 while `running`; no DNS from sandboxes; Hubble L7 with credential redaction; three pools (sandbox tainted, platform, security). **S T I D E** | smoke, B5, B6b, B6c, B21 |
| Lab services and samples | git-lab reachable only by the control plane (`git://`, read-only); sinks and paste-mock are in-cluster stand-ins so no real destination is ever targeted. **S T I** | smoke, B1–B3 |
| Build, deploy, supply chain | Pinned versions with sha256/sha512 checks for gVisor and Hubble; one services image; secrets only in gitignored `secrets/` and a pre-commit guard; `make dist` from `git archive`; fault injection off by default. **S T I D E** | smoke; open lows in [SECURITY_REVIEW.md](SECURITY_REVIEW.md) |
| GitHub integration | App with Contents and Pull requests only, no Workflows; draft PRs; diff recomputed by the control plane; protected paths refused; canary in diff or body refused with D1; summary quoted inert. **S T R I D E** | github, review H2/H3 |

**Not covered or thin:** hardware-level isolation (gVisor, not a microVM), user identity (header), TLS
payload inspection for write-allowed hosts, detection beyond the canary (real secrets, slow or split
exfiltration), and the open lows in the review (shared port 8000, image rules at admission, budget
atomicity, supply-chain digests).
