# Security review (2026-10-30)

A full-codebase review run against the implemented platform:
- **Gateway, credproxy and common code:** reviewed inline and verified against the live cluster.
- **Control plane, CLI, detector (since replaced by the sentinel), manifests and images:** reviewed by an independent reviewer.

**Attacker models:**
1. the agent inside the sandbox (prompt-injected or fully compromised);
2. a compromised platform pod;
3. another local API user.

All high and medium findings are **fixed**, and each fix has a regression test. Low findings remain
open and are tracked below.

**Verification after the fixes:** full redeploy (`make up`, migrating to per-component keys), then every suite:

| Suite | Result |
|---|---|
| smoke | 12/12 |
| e2e | 19/19 |
| lifecycle | 21/21 |
| containment | 17/17 |
| specs | 35/35 |
| github | 14/14 |
| `security-test` Phase B | 22/22 (adds B16–B19) |
| `security-test` Phase C | pass |

Report: [results/security-test-2026-10-30.md](results/security-test-2026-10-30.md).

## High

| # | Finding | Verified how | Fix | Regression test |
|---|---|---|---|---|
| H1 | **The AI gateway forwarded provider-side capabilities and any API path.** Server tools (`web_fetch`, `web_search`, code execution), the MCP connector and URL-sourced content let the agent make Anthropic's infrastructure fetch `https://attacker/?d=<canary>`, outside our egress controls. `/v1/models` and `/v1/messages/batches` were reachable with the org key, so batches skipped the model allowlist and the token budget. Evidence labelled all of these "allow, spec_allowlist". | Live: `web_fetch` was declared and accepted (200), `/v1/models` returned 200, and `batches` was forwarded unchecked. | `request_policy()` (`gateway/ai.py`):<ul><li>only `POST /v1/messages` and `/count_tokens`;</li><li>a top-level `model` from the spec is required;</li><li>only `custom` tools;</li><li>`mcp_servers` and `container` are rejected;</li><li>content `source` must be `base64`, `text` or `content` (no `url` or `file`).</li></ul>Credproxy repeats the endpoint allowlist. The new deny reasons count toward D2. | B16, B17, B18 |
| H2 | **The PR protected-path check could be bypassed, and the diff was untrusted.** `changed_paths()` parsed only unquoted `diff --git` lines, so real git output for non-ASCII paths, header-less hunks and mixed diffs got through `git apply`. The diff was produced by git *inside the agent's pod*: setting `diff.external` let the agent return arbitrary text (e.g. a `requirements.txt` edit) as "the diff" that was checked, hashed into evidence and published. | Locally with real git: quoted workflow path, header-less and mixed diffs, `diff.external` forgery. | The control plane copies the working-tree files out (tar, `.git` excluded) and diffs them against **its own pristine `.git` from clone time**, with an isolated git config (`--no-ext-diff --no-textconv`, no system or global config, no hooks). Credproxy checks protected paths on what git actually **staged** (`diff --cached --raw -z`) and rejects symlinks and submodules. | m8: forged diff ignored and quoted workflow refused |
| H3 | **The PR body was an unscanned exfiltration channel.** The agent's summary went into the PR body as markdown. An image or `<img>` with the canary in its URL would be fetched by GitHub's image proxy; hidden HTML could also mislead reviewers. | Code path (summary was not scanned; markdown was rendered). | The summary is canary-scanned: a hit refuses the PR and raises D1. It's rendered inside a ```text fence (no links, images, HTML or mentions), backticks are neutralised, length is capped, and the task text is escaped. | m8: canary in agent summary refuses the PR |
| H4 | **`/internal/sessions` bypassed the spec registry and baseline.** Any pod holding the shared internal key could register a running session with any user and policy, which credproxy then honoured. | Code path (test-only endpoint). | The endpoint is removed, along with the unused `/internal/revoke`. **Per-component keys with endpoint scopes:**<ul><li>the gateway may validate tokens and read policy;</li><li>credproxy may read policy;</li><li>the detector may read policy and raise alerts;</li><li>credproxy accepts only the gateway's key for inference and egress.</li></ul>`up.sh` builds the keys from a file, so they never appear on a command line. | B19 |

## Medium

| # | Finding | Fix | Regression test |
|---|---|---|---|
| M5 | **A repo-committed `.env` symlink** (e.g. to `/evidence/control-plane.jsonl` or `/data/cp.db`) made canary planting overwrite control-plane files. | `_plant()`: unlink, then `O_CREAT\|O_EXCL\|O_NOFOLLOW`, mode 0600. | Unit check (victim file intact) |
| M6 | **Session-state races.**<ul><li>Containment during `stop` was overwritten, the frozen pod was deleted, and a PR could still open.</li><li>Containment during start was reverted to "running".</li><li>The owner (the person the alert names) could destroy a contained session.</li><li>The SQLite connection was shared across threads without a lock.</li></ul> | **Compare-and-set** transitions (`store.transition`) for run, stop, contain and reconcile. Publish happens only while the session is still `stopping`. A contain during stop keeps the pod and the state. Only `SBX_SECURITY_ADMINS` can release (destroy) contained sessions. The store is serialised with a lock. | m4: owner can't destroy contained; B-cases release as secops |
| M7 | **Spec governance was self-asserted.**<ul><li>Any `securityApproval` or `riskAcceptance` string passed.</li><li>`X-User: system:*` counted as a spec author (verified live).</li><li>The widening check ignored image, output, owners and MCP; a new spec name skipped it entirely.</li><li>`repo.allow` accepted broad patterns.</li></ul> | <ul><li>`system:` is reserved (400).</li><li>**Two-person rule:** a security approver approves the *exact digest* (`POST /specs/approvals`, `sbxctl spec approve`), and the author, who must be a different person, registers it. This is required for new specs, any widening and unrestricted Bash.</li><li>Widening is computed over the whole compiled policy.</li><li>`repo.allow` must be an exact repo or `org/*`.</li><li>Shipped specs are bootstrapped from the reviewed repo.</li></ul> | m6 (approval flow, self-approval, reserved identity) |
| M8 | **One sandbox could exhaust the shared gateway.** The chunk size was checked after buffering; connections and response buffering were unbounded; no platform pod had resource limits. | Chunk size checked before reading; 30 s body timeout; 16 egress connections and 8 in-flight AI requests per sandbox IP; 32 MB response cap; CPU and memory requests and limits on every platform pod. | Code review; existing suites |
| M9 | **Terminal escape injection in `sbxctl`.** Agent output and diffs were printed raw (OSC 52 clipboard writes, hidden lines, spoofed prompts). | `safe()` renders C0/C1 control characters as visible `\xNN` escapes, keeping only `\n` and `\t`. Applied to logs, diff, status and alerts. | Unit check |
| M10 | **Repo-supplied `.claude/settings.json` or `.mcp.json`** could widen the agent's tools beyond the spec. | Claude Code runs with `--setting-sources user --strict-mcp-config`. | Phase C (agent still completes the task) |

## Low (open)

| Finding | Note |
|---|---|
| Public and internal control-plane routes share port 8000, which is reachable from the host | Split internal routes onto a pod-only port; mTLS in production. |
| Admission doesn't constrain image, `hostAliases` or `dnsPolicy` | Add an image-prefix and digest rule. Restrict pod creation to the controller identity (designed). |
| Supply chain: base images pinned by tag; gVisor and Hubble checksums come from the same origin; npm install has no lockfile | Pin by digest, embed known checksums, add an npm lockfile/integrity. |
| Token-budget check is not atomic with spend (parallel requests can overspend) | Reserve budget before forwarding. |
| A forged `{"sbx":"agent_exit"}` in agent output can end `sbxctl -f` early | Cosmetic: the progress stream is untrusted by design. The CLI now sanitises it, but can't authenticate it. |

## Lessons for the write-up

- **Allowed destinations include the model provider's own capabilities.** Server-side tools and URL sources
  are egress the network layer never sees (H1).
- **Anything the agent produces is attacker-controlled, including metadata that looks like ours.** The diff text,
  the summary, stdout markers and repo-supplied config all carry agent influence. The fix pattern each time was
  to recompute it from trusted state (H2), render it inert (H3, M9), or refuse to load it (M10).
- **"Prototype shortcut" endpoints are real attack surface** (H4). The scoped-key change also shrinks what a
  compromised gateway or detector can do.
