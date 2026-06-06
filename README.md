# CrayFisher

**AI Agent Zero-Day Research Agent.**

CrayFisher hunts zero-days in LLM agent frameworks (MCP, LangChain,
CrewAI, AutoGen, OpenHands, openai-agents, pydantic-ai, semantic-kernel,
agno, Claude Agent SDK) and in products built on top of them. When the
target is not an agent, it falls back to a generic web-vuln flow.

Triage priority comes from the 469-record OpenClaw GHSA corpus distilled
into [skills/knowledge/](skills/knowledge/) and
[skills/00-meta/agent-cwe-priority.md](skills/00-meta/agent-cwe-priority.md):
LLM06 Excessive Agency (42.6%) and LLM01 Prompt Injection (25.6%)
dominate, CWE-863 Incorrect Authorization is the single biggest CWE,
and 9 of the empirical Critical-13 advisories are scope/pairing
self-escalation.

Multi-agent pipeline: Recon → Defender → Judgment. See
[CLAUDE.md](CLAUDE.md) for the mission, configuration, and command
reference.

```
INPUT: <GitHub URL>
  ↓
clone → detect_stack (is_agent_target?)
  ↓ true                                   ↓ false
architecture_map + agent_trust_graph       (legacy web flow)
  ↓
agent Semgrep rules → A1–A10 taint
  ↓
exploit-chaining (3-C): compose primitives → RCE / LPE chains
  ↓
agent + web + exploit-chain policies (criteria-gate)
  ↓
reports/<repo-name>/CVE_REPORT_*.md
```

Beyond isolated findings, CrayFisher composes confirmed primitives into
**critical chains** (RCE, LPE, sandbox escape) — the class that dominates the
empirical Critical-13 — while requiring every link *and* every composition edge
to carry a code citation, so chaining raises rather than lowers the evidence bar.
See [skills/03-taint/exploit-chaining.md](skills/03-taint/exploit-chaining.md)
and [skills/00-meta/critical-chain-catalog.md](skills/00-meta/critical-chain-catalog.md).
