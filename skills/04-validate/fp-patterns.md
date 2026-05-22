# Skill 04-B: Confidence Scoring

## Purpose
Compute the confidence of a finding that passed 04-A.
Confidence reflects not "how sure you feel" but "how much code you actually read to confirm it".

---

## Confidence baselines

| Confirmation level | Baseline confidence |
|---------|-----------|
| Full source→sink path confirmed by reading code | 0.70 |
| Part of the path is trace-incomplete (flow broken somewhere) | 0.45 |
| Semgrep finding + only the matched line read | 0.40 |
| Found via manual review, no path trace | 0.35 |

---

## Confidence adjustments

Apply an adjustment only when you confirmed it by reading code.
Do not apply "this probably exists".

### Increase (+)

| Condition | Adjustment | How to confirm |
|------|------|---------|
| Source is specific (`req.body.X`, `request.args['Y']`) | +0.10 | Read the extraction code |
| Path has 3+ hops (all confirmed in code) | +0.08 | Each hop has a code citation |
| Same file already has another confirmed vuln | +0.05 | — |
| Sink is `eval`, `exec`, `os.system`, `subprocess` | +0.10 | Read the call site |

### Decrease (-)

| Condition | Adjustment | How to confirm |
|------|------|---------|
| Trace broke somewhere on the path | -0.15 | Record where and why |
| Read 1 guard in the source code | -0.10 | Read the validation code |
| Read 2 guards in the source code | -0.18 | Read the validation code |
| Read 3+ guards in the source code | -0.25 | Read the validation code |
| Path is a test file | -0.20 | Confirm the file path |
| Read a dead-code marker in the code | -0.15 | Read the marker |
| Read an encoding function on the taint path | -0.12 | Read inside that function |
| SSRF but the code only reaches localhost | -0.15 | Read the URL construction |
| Source is Semgrep security-audit ruleset | -0.12 | Confirm the rule_id |

---

## Final verdict

| Confidence | Action |
|--------|------|
| ≥ 0.70 | Write report |
| 0.25–0.69 | Write report + state confidence |
| < 0.25 | Treat as FP — no report |

---

## Output format

```
## Confidence: <file>:<line>

Baseline confidence: 0.XX (level: <full source→sink / partial trace / Semgrep only>)

Adjustments:
  +0.10 — specific source confirmed (<file>:<line> → "<code>")
  -0.10 — 1 guard confirmed (<file>:<line> → "<code>")

Final confidence: 0.XX → Action: write report / FP
```
