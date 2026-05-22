# Agent CWE & OWASP-LLM Priority

> Empirical distribution of AI Agent vulnerabilities, derived from the 469-record
> OpenClaw GHSA corpus (collected 2026-04-11). These weights drive triage priority
> across all of CrayFisher's phases.

## 1. Why this exists

CrayFisher is Agent-first. When multiple findings compete for limited triage
budget, the agent picks them in the order this document declares. The numbers
are not opinion — they come from one of the largest publicly-audited LLM agent
codebases (OpenClaw, `github.com/openclaw/openclaw`, 469 advisories over a
3-month batch).

Two layered taxonomies are tracked:

- **OWASP LLM Top 10** — coarse class. Used to label findings and to bias
  confidence in [judgment-agent.md](../agents/judgment-agent.md).
- **CWE Top 10 (Agent context)** — fine-grained pattern. Used by
  [criteria-gate.md](../04-validate/criteria-gate.md) §2 and by Semgrep rule
  prioritization in [semgrep-interpret.md](../02-static/semgrep-interpret.md).

## 2. OWASP LLM distribution (Agent-Zero-DB corpus, n=469)

| Class | Count | Share | Priority |
|---|---:|---:|---|
| **LLM06 Excessive Agency** | 200 | **42.6%** | P0 |
| **LLM01 Prompt Injection** | 120 | **25.6%** | P0 |
| LLM07 Insecure Plugin Design | 48 | 10.2% | P1 |
| (unclassified) | 40 | 8.5% | — |
| LLM05 Supply Chain | 27 | 5.8% | P1 |
| LLM02 Insecure Output Handling | 24 | 5.1% | P2 |
| Other | 10 | 2.2% | P2 |

**Implication.** LLM06 + LLM01 = **68.2%**. Two-thirds of real-world AI Agent
vulnerabilities live at the intersection of *what the agent is allowed to do*
and *what crosses the trust boundary into the prompt*. Findings in these classes
get +0.10 confidence in Phase 4 verdict.

## 3. CWE Top 10 (Agent context)

| Rank | CWE | Count | Generic name | What it looks like in Agent code |
|---:|---|---:|---|---|
| 1 | **CWE-863** | **87** | Incorrect Authorization | Scope/permission self-escalation across endpoints. `operator.read → operator.admin` chains; pairing-token mints admin. Single biggest class. |
| 2 | CWE-78 | 33 | OS Command Injection | Tool layer calls `exec`/shell with concatenated input. Often via `shell.run` tool exposed to the LLM. |
| 3 | CWE-22 | 32 | Path Traversal | Filesystem boundary check missing on tool args (`readFile`, `writeFile`, workspace-relative paths). |
| 4 | CWE-59 | 20 | Symlink Following | Sandbox/workspace boundary; TOCTOU + symlink trap on the FS bridge between sandbox container and host. |
| 5 | CWE-284 | 20 | Improper Access Control | Co-located with 863; missing role check on a single endpoint. |
| 6 | CWE-285 | 20 | Improper Authorization | Co-located with 863; check exists but is wrong. |
| 7 | CWE-269 | 19 | Improper Privilege Management | Pairing/scope promotion logic; sub-agent inheriting orchestrator privilege. |
| 8 | CWE-400 | 19 | Resource Exhaustion / DoS | Pre-auth body parsing, unbounded prompt context, unvalidated tool result size. |
| 9 | CWE-184 | 18 | Incomplete Blocklist | Env var denylist that misses `PYTHONWARNINGS`, `UV_INDEX_URL`, `HGRCPATH`, `CARGO_BUILD_RUSTC_WRAPPER`, `MAKEFLAGS`, `GIT_DIR`, … one new var per quarter. |
| 10 | CWE-918 | 17 | SSRF | Marketplace fetch, provider base URL, channel webhook target. |
| (11) | CWE-367 | 16 | TOCTOU | Sandbox FS bridge concurrent access; check-then-use race in approval gate. |

These eleven CWE classes account for **~280 of 469** (~60%) of the corpus.

## 4. "Critical 13" breakdown (severity = critical)

| Subclass | Count | Note |
|---|---:|---|
| **Scope/pairing self-escalation** | **9** | All in Gateway control plane. `operator.pairing` → `operator.admin` is the canonical chain. Maps to [agent-authorization.md](../04-validate/policies/agent-authorization.md). |
| Sandbox escape | 2 | TOCTOU + heartbeat context inheritance. Maps to [sandbox-escape.md](../04-validate/policies/sandbox-escape.md). |
| Approval bypass | 1 | RCE via node invoke approval. Maps to [excessive-agency.md](../04-validate/policies/excessive-agency.md). |
| Inbound allowlist bypass | 1 | Empty caller ID + suffix-match exploit. |

When a finding plausibly belongs to any of the first two subclasses, treat it
as **maximum priority** regardless of detection signal strength.

## 5. Component frequency (Agent-Zero-DB heuristic tags)

These are the *modules* where bugs cluster in agent codebases. Recon should
inspect these areas first.

| Component tag | Count | Mapping to Phase 3 grep targets |
|---|---:|---|
| prompt-injection-like (trust boundary mixing) | 154 | Any `messages[0].role == 'system'` interpolation |
| node-pairing-scope (pairing/scope model) | 140 | Auth middleware, scope clamps |
| approval-bypass (timeout/strict eval) | 137 | `strictInlineEval`, `execApprovals`, approval timeout fallback |
| voice/media (preflight/transcription) | 121 | Pre-auth body parsing |
| channel-allowlist (sender allowlist bypass) | 114 | Inbound routing, `allowFrom`, `dmPolicy` |
| sandbox (escape/FS boundary) | 72 | TOCTOU, symlink, Docker socket mounts |
| ssrf | 54 | Marketplace, provider base URL |
| webhook-replay | 54 | Webhook signature/nonce |
| path-traversal | 48 | `readFile`/`writeFile`/`appendFile` calls |
| exec-env-injection | 24 | Host exec env denylist sites |
| plugin-supply-chain | 8 | Marketplace download + install loaders |

## 6. Confidence weighting

Used by [judgment-agent.md](../agents/judgment-agent.md) when computing
`confidence_base` for a candidate finding:

```
base = recon_confidence  ∈ [0.0, 1.0]

# Apply only when defender verdict is PARTIAL or CONFIRMED.
# REBUTTED short-circuits this — the defender wins regardless of class.
if defender_verdict in {PARTIAL, CONFIRMED}:
    if owasp_class in {LLM06, LLM01}:        base += 0.10  # top quartile
    if cwe in {CWE-863, CWE-78, CWE-22, CWE-59}: base += 0.05  # top 4 CWE
    if subclass == "scope-self-escalation":  base += 0.10  # Critical-13 dominant
    if subclass == "sandbox-escape":         base += 0.10  # Critical-13 second
    base = min(base, 1.0)

confidence_base = base
```

The maximum cumulative boost is +0.25. This is intentionally smaller than the
recon-confidence range so it never overrides a *fully unfounded* claim — it
only re-orders the gray zone.

## 7. How phases consume this file

- **Phase 1 (Recon)** — `detect_stack.py` emits `is_agent_target`. When true,
  the recon-agent reads §3 §4 §5 of this doc into the system prompt before
  starting the A1–A10 sweep.
- **Phase 2 (Static)** — Semgrep rule files are loaded in priority order:
  `agent-frameworks.yaml` → `agent-defaults.yaml` → `trust-layer-promotion.yaml` →
  `incomplete-fix-heuristics.yaml`. Generic web rules come last.
- **Phase 3 (Taint)** — Component-frequency table (§5) drives initial grep
  targets in [ai-agent-flows.md](../03-taint/ai-agent-flows.md).
- **Phase 4 (Validate)** — CWE Top 10 + Critical-13 subclasses are the lookup
  keys for [criteria-gate.md](../04-validate/criteria-gate.md) §2 and for the
  policy table.
- **Phase 5 (Report)** — `Agent Class` row in
  [cve-report.md](../05-report/cve-report.md) is filled from §2.

## 8. Refresh policy

This file is a *frozen distillation* of the OpenClaw corpus at the
[Agent-Zero-DB](../../knowledge/agent-zero-db-distill.md) snapshot date. It is
not a live feed. When `tools/ghsa_lookup.py` finds drift > 10% on any row,
emit a warning and queue a manual refresh.
