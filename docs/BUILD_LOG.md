# Build log: what broke, what we learned

What happened while building it, kept because the lessons are part of the result. The design itself is in
[ARCHITECTURE.md](ARCHITECTURE.md), and the threats and findings are in [THREAT_MODEL.md](THREAT_MODEL.md).

## Platform problems and their fixes

| Problem | Cause | Fix |
|---|---|---|
| Sandbox traffic to any Service IP dropped as `world` | Cilium's kube-proxy replacement translates Service IPs in socket-level (`connect`) hooks; gVisor's netstack never calls the host `connect()` | `socketLB.hostNamespaceOnly=true`: pods use per-packet load balancing (`deploy/up.sh`) |
| gVisor install failed | Releases now ship as `gvisor.tar.bz2`, and the `gvisor-bin/` sidecars must sit next to `runsc` | Pinned release-20261019, sha512 verified (`deploy/runsc-install.sh`) |
| Containment took ~45 s | Relabelling a pod waits for Cilium identity propagation | A per-session `egressDeny` policy instead: ≤ 1 s |
| Plain-HTTP requests bypassed the proxy | curl ignores upper-case `HTTP_PROXY` (httpoxy); Cilium dropped them, which shows the bypass is closed | Sandboxes also get lower-case `http_proxy`/`https_proxy` |
| Corrupted model responses; tool_use invisible to the gateway | gzip bodies relayed without `Content-Encoding` | credproxy asks upstream for `identity`, because the gateway must inspect bodies |
| Spec denials on every run | Claude Code also calls fallback models not in the spec | The sandbox sets `ANTHROPIC_MODEL`, `ANTHROPIC_SMALL_FAST_MODEL` and `ANTHROPIC_DEFAULT_HAIKU_MODEL` from the spec |
| A legitimate PR publish was refused | A cached policy lookup raced the agent's last API call (it failed closed) | GitHub operations always use an uncached lookup |
| Workspace delivery and `destroy` failed late in long runs (500) | The Kubernetes Python client's `stream()` swaps the shared client's `request` method for a websocket one, so other threads' API calls went down the websocket path, and a failed exec left it swapped | Each exec uses its own API client (`control_plane/k8s.py`) |
| Sentinel checks "failed" although the alert existed | `cmd \| grep -q` under `set -o pipefail`: grep exits on the first match, and the writer dies of SIGPIPE | A `contains` helper that reads all input (`tests/lib.sh`) |
| Phase C reported every task as failed | `git apply` inside another repo's work tree silently skips paths and exits 0 | The harness uses `patch -p1` |
| Repeat findings were never alerted again | Alert ids are deduped across restarts, and S2/POL ids had no time or version component | 10-minute bucket (S2), ConfigMap version (POL) in the id |
| Containment-verification flakes | A fixed 8 s snapshot of Hubble | Poll for up to 60 s; with no traffic at all, record "inconclusive" instead of claiming success |

## Findings about agents and detection

- **Claude Code side channel.** Even with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, it sends
  `CONNECT api.anthropic.com` through `HTTPS_PROXY`. That is denied and raises a medium D2 on every run. It is a
  known false positive, kept below the burst threshold.
- **Agent self-reports are unreliable.** In a multi-turn session the agent said it had never opened, and later
  never edited, `slug.py`. The gateway's tool_use evidence and the trusted diff showed both. Ground truth comes
  from platform evidence, never from the agent, which is why PR bodies quote its summary as untrusted text.
- **Injection hurts availability, not just confidentiality.** The provider's usage-policy check refused about half
  of the injected runs, which also broke the legitimate task. No agent warned the user about the injected
  instructions; one quietly deleted them.
- **D3 false positive.** An `Edit` that quoted the injected block in order to delete it fired D3. D3 now counts
  host and `.env` references only in tools that act (Bash, WebFetch, MCP); a canary in any tool input still fires.

## Incident: a real key in a tracked file (contained)

A real API key was saved into the tracked `secrets/.example.env` and committed locally; it was never pushed.
The response:
1. rewrote the history and purged the objects;
2. rotated the key;
3. added a pre-commit guard (`.githooks/pre-commit`, `make hooks`) that blocks `secrets/*`, filled-in
   templates and key-shaped strings.

The lesson matches the platform's own design: secrets must be structurally unable to reach the place
where they leak, not merely discouraged.

## Measurements

- **Containment:** about 1 s from detection to the sentinel's deny policy (18 ms from token revoke to
  quarantine in the control-plane path). Verification needs Hubble drops after the quarantine and no
  traffic forwarded.
- **Clean-room rebuild:** `make down && make up` about 5 min with cached images; first build 10–15 min.
- **A real agent fix of `slugkit`:** about 18 s, 7 turns, $0.09; the diff touches only `slug.py`.
- **Real GitHub run:** 52 passing tests plus 9 strict xfails documenting 4 real bugs
  ([PR #1](https://github.com/bhadradiyaniravnl/items-api-sample/pull/1)).
