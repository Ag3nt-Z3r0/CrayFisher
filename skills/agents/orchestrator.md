# Orchestrator Agent — Execution Guide

## Role

Invoke the three specialized subagents in order and validate each
vulnerability candidate through the attack → rebuttal → judgment cycle.
The orchestrator's only responsibilities are running Python `tools/` and
collecting subagent results.
The orchestrator does not perform vulnerability analysis itself.

## Pre-flight

```bash
# 1. Read AGENT.md (be familiar with rejection patterns)
# 2. Clone the repo
python tools/clone.py <github_url>
```

---

## How to invoke agents

Use Claude Code's **Agent tool** to invoke each agent.
Pass the prompt to each agent in this form:

```
[contents of the agent's system prompt file]

---
INPUT:
<JSON data>
```

---

## Phase 1: Invoke the recon agent

### Subagent prompt

```
Use the contents of skills/agents/recon-agent.md as the system prompt.

INPUT:
{
  "local_path": "<cloned path>",
  "github_url": "<original URL>"
}
```

### Expected output

`recon_result.json`:
```json
{
  "agent": "recon",
  "findings": [ { "id": "FIND-001", ... } ]
}
```

Save the result to `reports/<repo-name>/recon_result.json`.

---

## Phase 2: Invoke the defender agent (can run per-finding in parallel)

Invoke the defender agent for each finding.
If there are 5 or more findings, invoke them in parallel.

### Subagent prompt

```
Use the contents of skills/agents/defender-agent.md as the system prompt.

INPUT:
{
  "local_path": "<cloned path>",
  "finding": { <full FIND-001 JSON> }
}
```

### Expected output

`defender_FIND-001.json`:
```json
{
  "agent": "defender",
  "finding_id": "FIND-001",
  "verdict": "CONFIRMED|REBUTTED|PARTIAL",
  ...
}
```

Save the result to `reports/<repo-name>/defender_<finding_id>.json`.

---

## Phase 3: Invoke the judgment agent

Drop findings that received a `REBUTTED` verdict.
Invoke the judgment agent for the remaining findings.

### Subagent prompt

```
Use the contents of skills/agents/judgment-agent.md as the system prompt.

INPUT:
{
  "local_path": "<cloned path>",
  "finding": { <full FIND-001 JSON> },
  "defense": { <full defender_FIND-001 JSON> }
}
```

### Expected output

`judgment_FIND-001.json`:
```json
{
  "agent": "judgment",
  "finding_id": "FIND-001",
  "final_verdict": "CONFIRMED|FP|...",
  "next_action": "CVE_REPORT|DISCARD|INVESTIGATE_FURTHER",
  ...
}
```

Save the result to `reports/<repo-name>/judgment_<finding_id>.json`.

---

## Phase 4: Final aggregation

Aggregate the judgment-agent results and emit a summary table.

```markdown
## Scan Summary: <repo-name>

| ID | Type | Verdict | Confidence | CVSS | Next Action |
|----|------|------|--------|------|---------|
| FIND-001 | SQLI | CONFIRMED | 0.80 | 8.1 | CVE_REPORT |
| FIND-002 | XSS | FP | 0.25 | - | DISCARD |
```

For each finding with `next_action: CVE_REPORT`:
```
Read skills/05-report/cve-report.md and write the report.
Save: reports/<repo-name>/CVE-CANDIDATE-<id>.md
```

---

## Execution example

```
INPUT: https://github.com/<owner>/<repo>

Orchestrator execution sequence:
1. python tools/clone.py https://github.com/<owner>/<repo>
   → local_path = /tmp/crayfisher-<random>/<repo>

2. Agent call: recon agent
   prompt = [recon-agent.md contents] + INPUT {local_path}
   → save recon_result.json

3. Inspect findings list
   → FIND-001, FIND-002, FIND-003 discovered

4. Agent calls (parallel): defender agent × 3
   → defender_FIND-001.json: CONFIRMED
   → defender_FIND-002.json: REBUTTED (ORM parameterization confirmed)
   → defender_FIND-003.json: PARTIAL

5. Drop REBUTTED → continue with FIND-001, FIND-003

6. Agent calls (parallel): judgment agent × 2
   → judgment_FIND-001.json: CONFIRMED, CVE_REPORT
   → judgment_FIND-003.json: CONFIRMED_LOW, CVE_REPORT

7. Write CVE reports: FIND-001, FIND-003
```

---

## Error handling

| Situation | Action |
|------|------|
| Subagent responded without JSON | Treat that finding as `NEEDS_MORE_EVIDENCE` |
| Recon agent returns 0 findings | Emit a "no vulnerabilities" report and exit |
| Clone failed | Report the error to the user and abort |
| Judgment agent returns INVESTIGATE_FURTHER | Add the finding to the pending list and include it in the summary |
