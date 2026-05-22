# CrayFisher — AI Agent Zero-Day Research Agent

**Primary mission.** Find zero-days in AI Agent frameworks (MCP, LangChain,
CrewAI, AutoGen, OpenHands, openai-agents, pydantic-ai, semantic-kernel, agno)
and in products built on top of them.

**Fallback mission.** When `tools/detect_stack.py` reports `is_agent_target =
false`, fall back to the legacy web-vuln flow with the existing 12 policies and
6 tools. Nothing is removed; the agent layer takes priority when applicable.

**Empirical priority basis.** Triage weighting comes from the 469-record
OpenClaw GHSA corpus (Agent-Zero-DB sister project, snapshot 2026-04-11):

- OWASP LLM dist — LLM06 Excessive Agency 42.6%, LLM01 Prompt Injection 25.6%,
  LLM07 Insecure Plugin 10.2%, LLM05 Supply Chain 5.8%.
- CWE Top 10 — 863, 78, 22, 59, 284, 285, 269, 400, 184, 918 (+ 367).
- Critical-13 split — 9 scope/pairing self-escalation, 2 sandbox escape,
  1 approval bypass, 1 inbound allowlist bypass.

Full distribution and weighting formula:
[skills/00-meta/agent-cwe-priority.md](skills/00-meta/agent-cwe-priority.md).
Distilled corpus and patterns:
[skills/knowledge/agent-zero-db-distill.md](skills/knowledge/agent-zero-db-distill.md).

**Output independence.** Reports are written under `reports/<repo-name>/` using
the existing [skills/05-report/cve-report.md](skills/05-report/cve-report.md)
template. CrayFisher does NOT adopt Agent-Zero-DB's `findings/`,
`reports/final/`, or any intermediate directory structure.

---

## Design philosophy

**The LLM is the analysis subject. Python is data-collection only.**

- `skills/` — Markdown prompts the LLM follows
- `skills/knowledge/` — Distilled corpus, framework cheatsheets, seed JSON
- `skills/00-meta/` — Cross-phase priority tables and gating logic
- `tools/` — Python scripts that emit JSON (no analysis)
- `rules/semgrep/` — Custom Semgrep detection rules
- `troubleshooting/` — XML log of scan-time tool/skill issues
- `reports/<repo-name>/` — Generated vulnerability reports (final outputs)

---

## Core principles — non-negotiable

### Principle 1 — Suspect via procedure, not by name

Do not pick a vuln class first and then bend the code to fit it. Read the code,
follow how data flows. Only when the flow reaches a dangerous destination do
you start suspecting a vulnerability.

```
read entry point → identify external-input vars → trace each var
                 → confirm destination → judge
```

### Principle 0 — Read AGENT.md before any scan

Read the `<tips>` block in [AGENT.md](AGENT.md) so past rejection reasons are
fresh. If a finding matches a rejection pattern, mark it FP before writing a
report. Whenever you receive new rejection feedback, add a new `<tip>` entry
to AGENT.md immediately.

### Principle 2 — Do not assert before reading

These are not evidence:

- File names, function names, variable names
- Code comments
- The fact that Semgrep matched
- "Code shaped like this usually has X" intuition

Evidence is one thing only: **a specific line of code you actually read.**

Every claim must carry this form:

```
Evidence: <file_path>:<line>
  → "<actual code on that line>"
```

If you cannot fill this form, suspend the judgment.

---

## Scan execution

```
INPUT: <GitHub URL>
```

Pick one of two modes.

### Single-Agent mode

One LLM runs Phase 1 → 5 sequentially. Good for fast exploration or simple
repos. Read each phase's skill file and follow its directions.

### Multi-Agent mode — recommended

Four specialized agents in an attack → rebuttal → judgment cycle. Lower FP
rate and higher reporting trust.

```
Read skills/agents/orchestrator.md and execute it.
```

| Agent | Skill file | Role |
|---|---|---|
| Orchestrator | `skills/agents/orchestrator.md` | Overall flow, subagent dispatch |
| Recon | `skills/agents/recon-agent.md` | Attacker view — surface vuln candidates |
| Defender | `skills/agents/defender-agent.md` | Triager view — policy-based rebuttal |
| Judgment | `skills/agents/judgment-agent.md` | Independent referee — final CVE merit |

```
Multi-Agent flow:
  Recon            → [findings]
    ↓ (per-finding, parallel)
  Defender         → [REBUTTED / CONFIRMED / PARTIAL]
    ↓ (drop REBUTTED)
  Judgment         → [CONFIRMED / FP / NEEDS_MORE_EVIDENCE]
    ↓ (CONFIRMED only)
  Write CVE report under reports/<repo-name>/
```

### Agent-first vs Web-fallback (branching)

```
clone → detect_stack.py
            │
            ├─ is_agent_target = true
            │     ↓
            │  Phase 1: + architecture_map.py + agent_trust_graph.py
            │  Phase 2: agent-frameworks/defaults/trust-layer/incomplete-fix
            │           Semgrep rules first; web rules only on non-agent files
            │  Phase 3: ai-agent-flows.md (A1–A10) primary
            │  Phase 4: agent policies + agent-default-checks gate
            │
            └─ is_agent_target = false
                  ↓
               Legacy web flow (existing 12 policies + 43 generic Semgrep
               rules unchanged).
```

In hybrid repos (e.g., LangServe, FastAPI + LangChain) `is_agent_target = true`
takes precedence and the web rules run as a **supplement** over files that the
trust-graph marks as agent-irrelevant (admin HTTP, ORM, static assets).

---

## Phase reference

### Phase 1 — Recon

| Skill | File |
|---|---|
| 1-A | [skills/01-recon/profile-repo.md](skills/01-recon/profile-repo.md) |
| 1-B | [skills/01-recon/entry-point-analysis.md](skills/01-recon/entry-point-analysis.md) |

```bash
python tools/clone.py <url>
python tools/detect_stack.py <local_path>
# if is_agent_target == true:
python tools/architecture_map.py <local_path>
python tools/agent_trust_graph.py <local_path>
python tools/find_entries.py <local_path>
python tools/osv_lookup.py <package> <ecosystem>
# optional, agent-target only:
python tools/ghsa_lookup.py <package>
```

### Phase 2 — Static analysis

| Skill | File |
|---|---|
| 2-A | [skills/02-static/semgrep-interpret.md](skills/02-static/semgrep-interpret.md) |
| 2-B | [skills/02-static/manual-code-review.md](skills/02-static/manual-code-review.md) |

```bash
python tools/semgrep_run.py <local_path>
# agent-target only:
python tools/incomplete_fix_scan.py <local_path>
python tools/file_read.py <file> <line> --context 15
```

### Phase 3 — Taint analysis

| Skill | File |
|---|---|
| 3-A | [skills/03-taint/source-sink-trace.md](skills/03-taint/source-sink-trace.md) |
| 3-B | [skills/03-taint/ai-agent-flows.md](skills/03-taint/ai-agent-flows.md) |

When `is_agent_target = true`, 3-B is the **primary** skill (A1–A10 patterns).
3-A applies to non-agent entry points only. When `is_agent_target = false`,
3-A is primary and 3-B is skipped.

```bash
python tools/file_read.py <file> <line> --context 20
grep -rn "<symbol>" <local_path> --include="*.ts" --include="*.py"
```

### Phase 4 — Validation

| Skill | File |
|---|---|
| 4-A | [skills/04-validate/criteria-gate.md](skills/04-validate/criteria-gate.md) |
| 4-B | [skills/04-validate/fp-patterns.md](skills/04-validate/fp-patterns.md) |
| 4-C | [skills/04-validate/cvss-scoring.md](skills/04-validate/cvss-scoring.md) |

When `is_agent_target = true`, also enforce
[skills/00-meta/agent-default-checks.md](skills/00-meta/agent-default-checks.md)
as a mandatory gate inside criteria-gate §2.

### Phase 5 — Report

| Skill | File |
|---|---|
| 5-A | [skills/05-report/cve-report.md](skills/05-report/cve-report.md) |
| 5-B | [skills/05-report/poc-generation.md](skills/05-report/poc-generation.md) |
| 5-C | [skills/05-report/disclosure.md](skills/05-report/disclosure.md) |

Output path is always `reports/<repo-name>/`.

---

## tools/ reference

| Tool | Invocation | Output keys |
|---|---|---|
| `clone.py` | `python tools/clone.py <url>` | `local_path` |
| `detect_stack.py` | `python tools/detect_stack.py <path>` | `primary_language`, `frameworks`, `is_agent_target`, `agent_frameworks`, `dependency_files` |
| `find_entries.py` | `python tools/find_entries.py <path>` | `entries[].{type,file,line,match}` |
| `architecture_map.py` | `python tools/architecture_map.py <path>` | `components[]`, `llm_call_sites[]`, `tool_registry[]`, `memory_stores[]`, `sub_agent_spawners[]`, `sandbox_sites[]` |
| `agent_trust_graph.py` | `python tools/agent_trust_graph.py <path>` | `nodes[]`, `edges[]` (each edge has `from_layer`, `to_layer`) |
| `semgrep_run.py` | `python tools/semgrep_run.py <path>` | `findings[].{rule_id,file,line,vuln_type,snippet}` |
| `file_read.py` | `python tools/file_read.py <file> <line>` | `content` (line-numbered) |
| `osv_lookup.py` | `python tools/osv_lookup.py <pkg> <eco>` | `vuln_count`, `vulns[]` |
| `ghsa_lookup.py` | `python tools/ghsa_lookup.py <pkg>` | offline seed hits + online GHSA results |
| `incomplete_fix_scan.py` | `python tools/incomplete_fix_scan.py <path>` | `candidates[].{commit, file, pattern, score}` |
| `env_denylist_fuzz.py` | `python tools/env_denylist_fuzz.py <path>` | `variants[]` (case, prefix/suffix, unicode lookalike) |

---

## Troubleshooting

When a tool errors, a skill conflicts with the code, or an FP pattern shows up
that the policy didn't anticipate, log it to
`troubleshooting/<repo>_<YYYYMMDD>_<issue-type>.xml`. Schema:
`troubleshooting/schema.xml`.

---

## Detectable vulnerability classes

Ranked by Agent-Zero-DB empirical weight. P0 = top quartile of the corpus
(LLM06/LLM01 = 68.2% combined). Weight column drives Judgment-agent
`confidence_base` boost.

| Class | CWE | OWASP-LLM | Weight | Primary methods |
|---|---|---|---|---|
| Excessive Agency | CWE-250/269 | LLM06 | **P0** | Trust graph + Manual |
| Prompt Injection (general) | CWE-1427 | LLM01 | **P0** | Semgrep + Taint + Manual |
| Tool Result Injection | CWE-1427 | LLM01 | **P0** | Taint (A3) |
| MCP Tool Poisoning | CWE-1427 | LLM01 | **P0** | Manual |
| Agent Authorization / Scope Escalation | CWE-863/284/285/269 | LLM06 | **P0** | Manual |
| Memory Poisoning | CWE-1427 | LLM01 | **P0** | Taint (A6) |
| Sandbox Escape | CWE-269/367/59 | LLM06 | **P0** | Manual |
| Multi-Agent Trust Escalation | CWE-269 | LLM06 | P1 | Taint (A4) |
| Context Window Attack | CWE-400 | LLM06 | P1 | Taint (A10) |
| Insecure Plugin / Supply Chain | CWE-1357 | LLM05/LLM07 | P1 | Manual |
| Incomplete Fix | (varies) | (varies) | P1 | `incomplete_fix_scan.py` + Manual |
| Command Injection | CWE-78 | (web) | P1 | Semgrep + Taint |
| Path Traversal | CWE-22 | (web) | P1 | Semgrep + Taint |
| SSRF | CWE-918 | (web) | P1 | Semgrep + Manual |
| LLM Output Execution | CWE-77 | LLM02 | P1 | Semgrep + Taint |
| SQL Injection | CWE-89 | (web) | P2 | Semgrep + Taint |
| XSS | CWE-79 | (web) | P2 | Semgrep + Taint |
| Insecure Deserialization | CWE-502 | (web) | P2 | Semgrep |
| Auth Bypass / IDOR | CWE-287/284 | (web) | P2 | Manual |
| CORS Misconfiguration | CWE-346 | (web) | P2 | Semgrep |
| Crypto Weakness | CWE-310 | (web) | P2 | Semgrep |
| DoS / ReDoS | CWE-400/1333 | (web) | P2 | Semgrep |
| Race Condition / TOCTOU | CWE-367/362 | (web/agent) | P2 | Manual |
| Logic Bug | CWE-840 | (web) | P2 | Semgrep + Manual |

---

## Environment

```bash
python -m venv .venv
pip install -r requirements.txt
```

Python 3.9+ required (the codebase uses PEP 585 generic syntax in `tools/`).
