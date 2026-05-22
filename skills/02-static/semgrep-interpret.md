# Skill 02-A: Semgrep Result Interpretation

## Purpose

Use Semgrep's locations as starting points and read the code to decide
whether each is a real bug. A Semgrep match is a "read here" hint, not
evidence.

---

## Procedure

### Step 1 — Run Semgrep

```bash
python tools/semgrep_run.py <local_path>
```

**Rule load order** (driven by `is_agent_target` from
`tools/detect_stack.py`):

When `is_agent_target = true`:

1. `rules/semgrep/agent-frameworks.yaml`
2. `rules/semgrep/agent-defaults.yaml`
3. `rules/semgrep/trust-layer-promotion.yaml`
4. `rules/semgrep/incomplete-fix-heuristics.yaml`
5. `rules/semgrep/js-vuln.yaml` and `rules/semgrep/python-vuln.yaml` —
   apply only to files the trust-graph marks as agent-irrelevant (admin
   HTTP, ORM, static assets). This is the *supplement* mode.

When `is_agent_target = false`:

1. `rules/semgrep/js-vuln.yaml` and `rules/semgrep/python-vuln.yaml`
   (the legacy web-vuln flow, unchanged).

### Step 2 — Walk findings one at a time

Sort by CVSS descending; process **one** finding at a time. Never
adjudicate multiple findings in parallel.

```bash
python tools/file_read.py <local_path>/<file> <line> --context 20
```

### Step 3 — Answer the four questions in order

For each Semgrep hit, after reading the line:

**Q1. What is this line actually doing?**
One sentence in your own words. Do not paraphrase the Semgrep message.

**Q2. Where does the value entering this line come from?**
Read the variable's declaration / parameter origin. Write "unconfirmed"
if you did not actually read it.

```bash
grep -n "<variable_name>" <local_path>/<file>
python tools/file_read.py <local_path>/<file> <definition_line> --context 10
```

**Q3. What transforms does that value go through before this line?**
Read the intermediate functions. Never assume "probably validates" on a
function you did not read.

**Q4. Is this code path actually reachable?**
Find the caller.

```bash
grep -rn "<function_name>\s*(" <local_path> --include="*.ts" --include="*.py" --include="*.js"
```

Confirm the caller chain starts at an external request handler.

### Step 4 — Verdict

Only adjudicate when Q1–Q4 each carry a code citation.

**Valid (confirmed):**

- External input reaches this line — confirmed in code.
- No sanitization breaks the chain — confirmed in code.

**Hold (incomplete trace):**

- Input origin not confirmed in code.
- An intermediate function remains unread.

**FP:**

- One of the following, each backed by a code citation:
  - Parameterized query (`?`, `$1`, `:name`) — cite the line.
  - TypeScript type constrained to `number`, `boolean`, or union
    literal — cite the type declaration.
  - A validation / encoding function runs before the sink — cite the
    function definition you actually read.
  - The sink receives a hardcoded constant — cite the line.
  - Test file or dead-code marker — cite the marker.

---

## Output

```
## Semgrep Finding #N: <rule_id>
Location: <file>:<line>

**Q1 — What this line does:**
<one sentence>
Evidence: <file>:<line> → "<code>"

**Q2 — Input origin:**
<confirmed / unconfirmed>
Evidence: <file>:<line> → "<code>"  (if confirmed)

**Q3 — Intermediate transforms:**
<none / present — describe>
Evidence: <file>:<line> → "<code>"

**Q4 — Reachability:**
<present / absent / unconfirmed>
Evidence: <file>:<line> → "<code>"

**Verdict: valid / hold / FP**
Reason: <which of Q1–Q4 drove the verdict>
```
