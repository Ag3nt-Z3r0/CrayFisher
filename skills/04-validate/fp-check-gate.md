# Skill 04-D: FP-Check Gate — Systematic False-Positive Verification

> **Provenance.** Adapted from Trail of Bits' `fp-check` skill
> (<https://github.com/trailofbits/skills/tree/main/plugins/fp-check>), aligned
> to CrayFisher's Principle 2 and the multi-agent defender/judgment flow.

## Purpose

Turn a *suspected* finding into a **TRUE POSITIVE** or **FALSE POSITIVE**
verdict with documented evidence. This is **verification, not discovery** — do
not hunt for new bugs here; take a candidate from Phase 3 and try to break it.

CrayFisher's standing problem is over-reporting (see
[fp-patterns.md](fp-patterns.md) and the rejection history in
[AGENT.md](../../AGENT.md)). This gate is the disciplined, mandatory pass that
catches the FP *before* a report is written.

**Where it runs.** After [criteria-gate.md](criteria-gate.md) (4-A) and before
[cvss-scoring.md](cvss-scoring.md) (4-C) / report. In Multi-Agent mode it is the
defender's core procedure and the judgment agent's checklist. It is
**mandatory** for any finding that is high-impact (RCE/LPE/sandbox-escape), is a
`CHAIN`, or scored ≥ 0.70 confidence — these are exactly the findings whose
FP cost is highest.

---

## Step 0 — Restate the claim (always, before any verdict)

You cannot verify a claim you have not stated. Write all of these; if you cannot
fill one, that gap *is* the likely FP:

```
Exact claim:        <bug type> at <file>:<line>
Alleged root cause: why the bug exists
Trigger mechanism:  how an attacker activates it (which entry point, what input)
Claimed impact:     severity + concrete consequence
Threat model:       attacker capabilities + execution context (pre-auth? local? remote?)
Bug class:          category → which class-specific checks apply
Data flow:          how input reaches the vulnerable code (source → … → sink)
Caller constraints:  what upstream validation/guards exist (READ them)
Architectural defenses: layered protections in the system (READ them)
Historical context:  recent changes / prior fixes near this code
```

Running Step 0 across a batch of candidates *first* eliminates the obvious FPs
immediately — do it before any deep work.

---

## Route selection — Standard vs Deep

**Standard** (linear checklist, no task tracking) when ALL hold:
- the claim is clear and specific,
- it involves a single component,
- the bug class is well-established (cmdi, SQLi, XSS, path traversal, SSRF,
  the A1–A10 single-hop patterns),
- no concurrency / race,
- source→sink is straightforward.

**Deep** (task-based, explicit phase dependencies) when ANY hold:
- the claim is ambiguous or multi-interpretable,
- data flows across 3+ modules/services,
- race / TOCTOU / concurrency is involved,
- it is a logic bug without a clear spec,
- it is a **CHAIN** (every link AND edge must be verified — see
  [exploit-chain.md](policies/exploit-chain.md)),
- standard verification was inconclusive.

---

## Critical rejection criteria — STOP and mark FP if you catch yourself doing any

These are the rationalizations that produce CrayFisher's FPs. Recognizing one is
an immediate FP unless you go back and supply the missing read:

- **Pattern recognition alone** — "this code *looks* unsafe." Unsafe-looking ≠
  vulnerable. (Principle 2.)
- **Skipping full data-flow tracing** "for efficiency" — every hop needs a
  citation.
- **Assuming a sibling applies here** — "the other call site was vulnerable so
  this one is." Each instance owes its own trace (this is why
  [variant-analysis.md](../03-taint/variant-analysis.md) re-verifies every
  variant).
- **Reporting without checking upstream validation** — you must READ the
  caller's guards, not assume their absence *or* their presence.
- **Severity bias** — wanting it to be critical is not evidence.

These line up with CrayFisher's existing FP catalogue
([fp-patterns.md](fp-patterns.md)) and the AGENT.md `<tip>` rejection patterns —
consult both; if the finding matches a known rejection shape, it is FP.

---

## Class-specific verification (examples — extend per bug class)

| Bug class | Must-read before TRUE verdict |
|---|---|
| cmdi / RCE | the exact exec/spawn call + whether the tainted var is shell-interpolated vs argv array |
| path traversal | the join + any normalization/allowlist; is the base dir actually escapable? |
| SSRF | URL construction + whether it can leave localhost/allowlist |
| prompt-injection (A1/A3) | is the wrapper/sanitizer applied on the *representation that reaches the LLM*? (catalog T6) |
| excessive-agency | the **default** value at the declaration (`agent-default-checks.md`), not the configurable one |
| CHAIN | every link's `Evidence:` AND every edge's `edge_proof` (catalog §5) |

---

## Batch triage (multiple candidates)

1. Run **Step 0 for every candidate** — kills the obvious FPs up front.
2. Route each independently (standard vs deep).
3. Process standard-routed first, then deep-routed.
4. **Then** check for exploit chains combining the survivors → hand to
   [exploit-chaining.md](../03-taint/exploit-chaining.md).

---

## Verdict format

```
## FP-Check: <file>:<line>  (<bug class>)

Step 0:  <one-line claim restatement>
Route:   standard | deep
Reads performed:
  - <file>:<line> → "<code>"   (source)
  - <file>:<line> → "<code>"   (each hop / each guard)
  - <file>:<line> → "<code>"   (sink)
Rejection check: none triggered | <which rationalization caught>
Verdict: TRUE POSITIVE | FALSE POSITIVE
  reason: <evidence-grounded; for FP, the exact guard/constraint that defeats it>
```

Batch summary:

```
TRUE POSITIVES:  <n> — [FIND-001 cmdi, FIND-007 A3, …]
FALSE POSITIVES: <n> — [FIND-003 (input is argv array, not shell), …]
```

Only TRUE POSITIVES proceed to [cvss-scoring.md](cvss-scoring.md) and a report.
A FALSE POSITIVE that revealed a new rejection shape → add a `<tip>` to
[AGENT.md](../../AGENT.md) immediately (Principle 0).
