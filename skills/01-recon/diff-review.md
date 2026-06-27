# Skill 01-C: Differential Security Review (change / PR / release mode)

> **Provenance.** Adapted from Trail of Bits' `differential-review` skill
> (<https://github.com/trailofbits/skills/tree/main/plugins/differential-review>),
> aligned to CrayFisher's Principle-2 evidence discipline.

## Purpose

Review a **change set** (a commit range, a PR, or "everything since the last
release") instead of the whole repo. Active agent frameworks ship fast; the
freshest, least-reviewed code — and the **regressions** where a maintainer
quietly removed a guard — is where zero-days live. This skill is the entry mode
that scopes Phases 2–4 to the diff.

**When to use.** The input names a base ref / PR / tag, or the user asks to
"review recent changes / this PR / the latest release". Otherwise run the normal
whole-repo flow (1-A → 1-B). This mode does **not** replace whole-repo scanning;
it is a sharper, cheaper pass for a moving target.

> **Why this skill exists.** CrayFisher's `incomplete_fix_scan.py` matches
> *commit messages* (H1/H2 heuristics). This skill is complementary and broader:
> it reads the *code* of a change to ask "what did this diff break?" — including
> **regressions** (a previous security fix being undone), which message-matching
> never catches.

---

## Procedure

### Step 0 — Collect the diff

```bash
python tools/diff_collect.py <local_path> [--base <ref>] [--head <ref>]
```

Default base = previous tag, else `HEAD~1`. Output is a **location list** — the
`risk_hint`, `categories_touched`, and `removed_protection_lines` are signals,
not verdicts. Judge nothing until you read the code (Principle 2).

### Step 1 — Pre-analysis & triage (never skip)

Classify each changed file HIGH / MEDIUM / LOW by what it touches. Start from
`diff_collect` signals, then confirm by reading:

- **HIGH** — auth/authz, crypto, value/secret handling, input validation,
  external calls, sandbox/approval logic, **any removed protection line**.
- A **refactor is HIGH until proven otherwise** (`is_possible_refactor: true`):
  refactors silently break invariants. Read it, don't trust the churn.
- **MEDIUM** — exec/agent surface touched without a removed guard.
- **LOW** — docs, tests, formatting (still skim for secrets).

### Step 2 — Regression hunt (the highest-value step)

For each entry in `removed_protection_lines`, find out *who removed it and
whether it mattered*:

```bash
# Who/when removed the guard, and the surrounding old code:
git -C <local_path> log -p -S '<removed code snippet>' -- <file> | head -120
git -C <local_path> blame <base> -- <file> | grep -n '<snippet>'
```

A regression is reportable only when all hold (each cited):
- the removed line was a real protection (validation/authz/crypto/agent guard),
- nothing in the new code re-establishes the same protection (read the new code),
- the now-unprotected path is reachable from an entry point (hand to 1-B / 3-x).

```
Evidence (removal):   <commit-sha> removed <file>:<oldline> → "<removed code>"
Evidence (no replacement): <file>:<newline> → "<code that should guard but doesn't>"
```

This catches "commit X re-introduced GHSA-… by deleting the escape call" — a
prime [incomplete-fix](../04-validate/policies/incomplete-fix.md) / variant case.

### Step 3 — Code analysis (depth scaled to size)

For HIGH/MEDIUM files, read the changed hunks **and enough surrounding context to
trace the data**. Use the normal evidence discipline:

```bash
python tools/file_read.py <local_path>/<file> <line> --context 40
```

Scale depth to repo size (from 1-A `total_lines`): SMALL = read deeply;
LARGE = surgical (changed functions + their callers only). Feed every tainted
flow you find into 3-A/3-B as usual.

### Step 4 — Blast radius (reachability of the change)

A change is only as dangerous as what reaches it. For each changed function,
find its transitive callers:

```bash
grep -rn "<changed_function_name>" <local_path> --include="*.ts" --include="*.py"
```

Record: is the changed code reachable from an attacker-controlled entry point?
Reachable-from-entry HIGH changes get full Phase 3 treatment; unreachable ones
are deprioritized (note why).

### Step 5 — Deep context + adversarial modeling (HIGH only)

For HIGH changes, build the architectural context
([audit deep-read style] — purpose, inputs/assumptions, invariants the change
might break) and model a concrete attacker scenario: *who* sends *what* to reach
the changed code, and what they get. Generic "this could be risky" is not a
finding — produce a concrete path or drop it.

### Step 6 — Hand-off (no separate report format)

This skill produces **candidates**, not reports. Each candidate enters the
normal pipeline:

- tainted flows → 3-A / 3-B,
- removed-guard regressions → [policies/incomplete-fix.md](../04-validate/policies/incomplete-fix.md)
  + [03-taint/variant-analysis.md](../03-taint/variant-analysis.md) (the same
    guard is often missing in sibling call sites),
- everything → Phase 4 ([criteria-gate](../04-validate/criteria-gate.md) →
  [fp-check-gate](../04-validate/fp-check-gate.md)), then a report via
  [cve-report.md](../05-report/cve-report.md).

---

## Output (candidate list)

```json
{
  "phase": "1-C",
  "base": "v1.4.0",
  "head": "HEAD",
  "triage": { "high": 3, "medium": 5, "low": 12 },
  "candidates": [
    {
      "id": "DIFF-001",
      "kind": "regression",
      "file": "src/agent/exec.ts",
      "removed_guard": "abc123 removed src/agent/exec.ts:88 → \"if (!isAllowed(cmd)) throw\"",
      "no_replacement_evidence": "src/agent/exec.ts:90 → \"runShell(cmd)\"  (no allowlist check)",
      "entry_reachable": true,
      "route_to": ["incomplete-fix", "variant-analysis", "3-A"],
      "confidence_base": 0.65
    },
    {
      "id": "DIFF-002",
      "kind": "new-vuln",
      "file": "src/tools/web.ts",
      "evidence": "src/tools/web.ts:142 → \"return { text: rawHtml }\"",
      "blast_radius": "called by agent loop (src/loop.ts:30)",
      "route_to": ["3-B (A3)"],
      "confidence_base": 0.60
    }
  ]
}
```
