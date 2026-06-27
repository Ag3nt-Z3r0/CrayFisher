# Skill 03-D: Variant Analysis — Find One Bug, Find Ten

> **Provenance.** Adapted from Trail of Bits' `variant-analysis` skill
> (<https://github.com/trailofbits/skills/tree/main/plugins/variant-analysis>),
> aligned to CrayFisher's evidence rules and agent-framework target space.

## Purpose

After **any** finding is confirmed (by 3-A, 3-B, or 3-C), search the *whole*
codebase for sibling instances of the **same root cause**. Agent frameworks are
the ideal target for this: the same flawed pattern is usually copy-pasted across
every tool handler, every message-builder, every memory call site. One confirmed
`wrapExternalContent`-missing tool almost always has neighbors.

This skill runs **after** a finding is confirmed and **before** 3-C composes
chains — variants discovered here become new primitives for chaining.

> **Why this skill exists.** A single CVE is one report; a *class* of the same
> bug across 8 call sites is a systemic finding with a far stronger remediation
> story and CVSS. It also catches the case where a maintainer fixed *one*
> instance and left the rest (overlaps with, but is broader than,
> [incomplete-fix.md](../04-validate/policies/incomplete-fix.md): incomplete-fix
> is "they patched X, did they patch X' on the same line/commit?"; variant
> analysis is "X exists *here*, where else does the same shape exist at all?").

---

## Hard rule — a variant is a *separate* finding and owes its own evidence

Each variant you report must independently satisfy
`Evidence: <file>:<line> → "<code>"`. "It's the same as FIND-001 so it's
probably vulnerable too" is **not** evidence — it is exactly the rationalization
[fp-check-gate.md](../04-validate/fp-check-gate.md) rejects. Read every variant's
own source→sink path. A pattern *match* is a candidate, not a finding.

---

## Five-step procedure

### Step 1 — Understand the root cause (not the symptom)

From the confirmed finding, write the root cause in one sentence, and the
**minimal conditions** that make it exploitable:

```
FIND-001 root cause: tool returns externally-fetched bytes as a tool result
                     without wrapExternalContent()  → A3 tool-result injection
Conditions for exploitability:
  (a) the returned bytes are attacker-influenceable
  (b) the result is fed back into a subsequent LLM turn
  (c) a dangerous tool is reachable in the same session
```

If you cannot state the root cause precisely, you are not ready to search —
go back to the trace.

### Step 2 — Build an *exact-match* query for the known instance

Construct a search that matches **only** the one known location. This proves the
pattern is specific before you generalize it.

```bash
# Start narrow — should return exactly ONE hit (the original):
grep -rn "return { text: rawContent }" <path> --include="*.ts"
```

If it matches more than the original already, good — but verify each before
celebrating. If it matches zero, your pattern is wrong.

### Step 3 — Identify abstraction points

Decide what to keep literal vs. what to turn into a wildcard/metavariable:

- **Keep specific:** function/decorator names unique to the bug
  (`wrapExternalContent`, `@function_tool`), literal sentinel values that matter.
- **Abstract:** variable names, the specific tool, whitespace, the exact string
  being returned.

```
specific:  return { text: <X> }          where <X> is NOT wrapped
abstract:  <X> = any expression that traces back to external input
```

### Step 4 — Iteratively generalize (one change at a time)

Loosen exactly one element, re-run, **classify every new match**, repeat. Stop
when the false-positive rate of new matches exceeds ~50% (the ToB halt rule) —
past that you are reading noise.

```bash
# Loosen the return shape:
grep -rn "return.*text:.*\${" <path> --include="*.ts" | grep -v "wrapExternal\|wrapWeb"
# Loosen to all sibling sink families (semantically related constructs):
grep -rn "content:.*\${\|text:.*\${\|message:.*\${" <path> --include="*.ts"
# For data-flow-dependent variants, escalate the tool:
python tools/semgrep_run.py <path>     # reuse taint rules
```

Tool selection by needed precision (ToB guidance):

| Need | Tool |
|---|---|
| Quick surface sweep | `grep -rn` / ripgrep |
| Simple pattern, incomplete code | Semgrep pattern rule |
| Data-flow / source→sink | Semgrep taint / `semgrep_run.py` |
| Cross-function reachability | manual call-graph read (`file_read.py` + grep symbol) |

**Enumerate semantically-related constructs, not just the exact name.** If the
bug was in `wrapExternalContent`, also check `wrapWebContent`,
`sanitizeToolOutput`, and every other call site that *should* have a wrapper but
might use a different (or no) one. The most common real variant is "they used
the wrapper everywhere except this one new tool added last month".

### Step 5 — Triage and rank the results

For each surviving match, record:

```
VARIANT-of-FIND-001 #n
  location:     <file>:<line>
  evidence:     <file>:<line> → "<code>"   (READ, not matched)
  same root cause? yes/no  (why)
  exploitable?  yes/no/needs-trace  (cite the missing condition)
  confidence:   per fp-patterns.md
  priority:     high/med/low
```

Drop any match where you cannot confirm the root cause by reading code.

---

## Output

```json
{
  "phase": "3-D",
  "origin_finding": "FIND-001",
  "root_cause": "tool result returned raw without wrapExternalContent (A3)",
  "search_evolution": ["exact-match grep", "loosened return shape", "all sink families"],
  "variants": [
    {
      "id": "FIND-007",
      "location": "src/tools/web_search.ts:142",
      "evidence": "src/tools/web_search.ts:142 → \"return { text: results.join('\\n') }\"",
      "same_root_cause": true,
      "exploitable": "yes",
      "missing_protection": "no wrapExternalContent on attacker-controllable results",
      "confidence_base": 0.65,
      "priority": "high"
    }
  ],
  "systemic": true,
  "remediation_note": "single fix: enforce wrapExternalContent at the tool-result boundary, not per-tool"
}
```

---

## Hand-off

- New variants re-enter Phase 4 validation independently
  ([criteria-gate.md](../04-validate/criteria-gate.md) →
  [fp-check-gate.md](../04-validate/fp-check-gate.md)).
- New variants are also fresh primitives for
  [03-taint/exploit-chaining.md](exploit-chaining.md) (Step 1 collection).
- When variants cluster around a *recently patched* commit, also run
  [policies/incomplete-fix.md](../04-validate/policies/incomplete-fix.md).
- A `systemic: true` result should be written as **one** report covering the
  class with every instance enumerated, not N near-duplicate reports.
