# Agent-Zero-DB Distill — OpenClaw lessons baked into CrayFisher

> Single-file distillation of the OpenClaw security analysis project
> (Sungkyunkwan ASC, "OpenClaw analysis"). Source: Agent-Zero-DB repo snapshot
> 2026-05-03 / GHSA corpus 2026-04-11. This file is in-tree — CrayFisher does
> **not** read Agent-Zero-DB at runtime.

## Why this is here

The OpenClaw project (`github.com/openclaw/openclaw`, a TypeScript multi-channel
AI assistant with Docker-in-Docker sandbox) is currently the largest publicly
audited LLM Agent codebase. A coordinated external audit dropped 469 GHSA
advisories over 3 months (2026-02 to 2026-04). The Agent-Zero-DB team built
five structural insights from that corpus that generalize to any agent target.
CrayFisher embeds those insights directly so the same patterns are used to hunt
on new targets.

## G1–G4 — Why incomplete fixes recur (structural hypotheses)

These four hypotheses each predict a specific class of regression. They drive
the incomplete-fix patterns (§next section) and the `incomplete-fix.md` policy.

| ID | Hypothesis | Pre-condition in target |
|---|---|---|
| **G1** | Trust label promotion — labels like `System:`, `MEDIA:`, `heartbeat` are checked at one entry point but other paths can promote arbitrary content into the same label | Trust represented by string labels, not types |
| **G2** | Scope clamp dispersion — permission scope checks distributed across many endpoints, missed on new endpoint or refactor | `operator.admin`-style hierarchical scope without centralized middleware |
| **G3** | Denylist expansion model — env-var / SSRF / base-URL blocking uses denylists; each new ecosystem (package manager, build tool) adds a new bypass | Any `not in [list]` style check on attacker-controllable string |
| **G4** | Workspace policy multi-vector — same policy enforced per-channel/per-plugin/per-tool with separate code paths; one vector blocked, others remain | Multiple ingress/egress paths share a logical policy but have separate implementations |

When CrayFisher scans a target and any of these pre-conditions are present, the
matching incomplete-fix pattern automatically becomes an active hunt mode.

## Five incomplete-fix patterns

These five patterns came out of grepping the 469-advisory corpus. The Pattern
catalog is the single most actionable artifact from Agent-Zero-DB: it converts
"incomplete fix happens a lot" from a vibe into deterministic detection rules.

### A — Re-emergence (same CVE, root cause untouched)
**Heuristic:** advisory summary matches `incomplete fix|incomplete patch|bypass for|variant of` OR cites an earlier CVE/GHSA id.

**Examples:** `GHSA-7xr2-q9vf-x4r5` (CVE-2026-32013 symlink traversal re-emergence), `GHSA-vfw7-6rhc-6xxg` (CVE-2026-4039 CLI backend env injection re-emergence).

**60%+ of OpenClaw incomplete fixes are this pattern.** When CrayFisher detects
a target has recently patched a security CVE, the patch commit + adjacent
functions in the same file are *automatic priority reading*.

### B — Adjacent miss (same module, sibling function)
**Heuristic:** patched function plus untouched sibling function in the same
file with overlapping signature.

**Citation chain example:** `GHSA-7437` → `GHSA-cm8v` → `GHSA-m866` (three-deep
chain in the same module). Root cause is architectural, not function-local —
flag the module for a root cause review task.

### C — Deeper trigger (1st patch blocked surface, deeper layer still reachable)
**Heuristic:** validation/auth/sanitization call exists, but a parser /
pre-auth body / middleware path reaches the same sink before the check.

**Examples:** `GHSA-2w79-r9g8-wmcr` (voice-call WS frame parsing before start
validation), `GHSA-w6m8-cqvj-pg5v` (Feishu webhook pre-auth body parsing DoS).

### D — Bypass variant (denylist, new token)
**Heuristic:** `not in [allowlist]` or `denylist.includes(x)` pattern over a
string from outside; new token / casing / unicode lookalike not in the list.

**Examples:** `GHSA-rhfg-j8jq-7v2h` (SSRF in multiple channel base URLs),
`GHSA-vfw7-6rhc-6xxg` (CLI env injection variant). Env vars routinely missed:
`HGRCPATH`, `CARGO_BUILD_RUSTC_WRAPPER`, `PIP_INDEX_URL`, `UV_INDEX_URL`,
`MAKEFLAGS`, `GIT_DIR`. The full known-bypass seed list lives in
[openclaw-ghsa-seed.json](openclaw-ghsa-seed.json) →
`env_denylist_known_bypass_seeds`. `tools/env_denylist_fuzz.py` consumes it.

### E — Workspace multi-vector
**Heuristic:** same logical policy keyword appears in multiple file paths
(channel/plugin/tool dirs) with different enforcement bodies.

**Example:** `GHSA-5fc7-f62m-8983` (Feishu `upload_file/upload_image` bypasses
the workspace-only filesystem policy that text messages enforce).

## Component frequency snapshot (Agent-Zero-DB tagging)

The OpenClaw corpus was tagged by component. These tags map cleanly onto
agent-framework concepts and tell Recon where to look first.

| Tag | Count | Agent-framework analogue |
|---|---:|---|
| prompt-injection-like (trust boundary mixing) | 154 | Any message construction site mixing user/tool data with system prompt |
| node-pairing-scope | 140 | Auth/session middleware with hierarchical scopes |
| approval-bypass | 137 | Tool-call approval gates, "ask before run" toggles |
| voice-media | 121 | Pre-auth body parsing / transcription preflight |
| channel-allowlist | 114 | Inbound routing allowlist |
| sandbox | 72 | Container / process sandbox boundary |
| ssrf | 54 | Marketplace, provider URL, tool fetch |
| webhook-replay | 54 | Webhook signature/nonce |
| path-traversal | 48 | `readFile`/`writeFile` on tool args |
| exec-env-injection | 24 | Host env var denylist |
| plugin-supply-chain | 8 | Marketplace / plugin loader integrity |

## OpenClaw architecture template (18 components, 4 trust tiers)

Agent-Zero-DB's component map was 18 nodes spanning: Gateway Control Plane,
Protocol schema, Auth/Scope, Pairing Manager, Channel Ingress, Routing, Agent
Runtime, Plugin SDK, Plugins, Tool Executor, Approval Layer, Host Exec Env
Policy, Sandbox, Media Pipeline, Marketplace, Control UI, Canvas/A2UI, Node
Companions.

Trust tier collapse (this generalizes):

```
[low]  external channel inbound (webhook, msg)
  ↓ sender allowlist
[low→mid] paired device inbound
  ↓ pairing scope
[mid]  write scope
  ↓ no escalation expected
[mid→high] admin scope
  ↓ approval gate
[high] host exec / sandbox spawn / plugin install
  ↓ env denylist / sandbox policy
[host] machine
```

GHSA observation: **every arrow (↓) had at least one promotion bug found.** When
mapping a new target, build this same trust ladder, then look for a finding on
every arrow. Absence of findings on an arrow is suspicious, not safe.

`tools/architecture_map.py` produces this same structure from a target repo.

## Reporter concentration as a signal

One researcher (`tdjackey`) submitted 135 of 469 advisories (28.8%). Two
research labs (KeenSecurityLab, AntAISecurityLab) contributed another 73
combined. **This is the signature of a structurally exploitable codebase.** When
scanning a new target, check its GHSA history — if a single reporter dominates,
their patch-commit neighborhoods are the highest-yield hunting ground.

## What CrayFisher inherits from this distill

- [openclaw-ghsa-seed.json](openclaw-ghsa-seed.json) — 21KB compact corpus:
  Critical-13 + incomplete-fix exemplars + per-component samples + aggregates.
- 5 incomplete-fix patterns embedded in
  [../04-validate/policies/incomplete-fix.md](../04-validate/policies/incomplete-fix.md)
  and [../../rules/semgrep/incomplete-fix-heuristics.yaml](../../rules/semgrep/incomplete-fix-heuristics.yaml).
- CWE priority weighting in
  [../00-meta/agent-cwe-priority.md](../00-meta/agent-cwe-priority.md).
- Env-denylist bypass seeds consumed by `tools/env_denylist_fuzz.py`.
- Trust ladder model in
  [../03-taint/ai-agent-flows.md](../03-taint/ai-agent-flows.md).

## What this distill does NOT carry

- Per-advisory PoC code (Agent-Zero-DB keeps these locally only).
- Reporter-specific attack chains.
- OpenClaw-specific filenames beyond the architecture template.
- Live GHSA feed — see `tools/ghsa_lookup.py` for online fallback.

If a target diverges substantially from the OpenClaw template (e.g., a pure
Python LangChain library with no channel/sandbox layer), pattern E and the
sandbox-related Critical-13 subclass become inapplicable. The CWE Top 10 and
Patterns A/B/C/D still generalize.
