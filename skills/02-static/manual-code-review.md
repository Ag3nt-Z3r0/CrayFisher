# Skill 02-B: Manual Code Review

## Purpose
Find vulnerabilities that Semgrep cannot detect by reading the code directly.
This skill is not about hunting for a specific vuln class — it is about reading how the code handles data and noticing what looks wrong.

---

## Procedure

### Step 1 — Read each entry-point handler in full

Read the high-risk entry-point files identified in 01-B.
```bash
python tools/file_read.py <handler_file> <entry_line> --context 60
```

Hold only these three questions while reading:
1. What data in this code is untrusted?
2. Where is that data used?
3. Is the way it is used dangerous?

If the code does not let you answer these three questions, do not jump to a conclusion.

### Step 2 — When you spot a suspicious point: stop, read, trace

When you see one of the following while reading, stop immediately and start tracing.

**Triggers to stop:**
- External data is passed as an argument to a function call
- External data is interpolated/concatenated into a string
- External data is assigned to another variable

**Tracing procedure:**
```bash
# Find the definition of the relevant function
grep -rn "function <name>\|const <name>\|def <name>" <local_path> --include="*.ts" --include="*.py"
# Read the location you found
python tools/file_read.py <file> <line> --context 40
```
If that function calls yet another function, read it too.
**Do not assume "this function is probably safe" without reading it.**

### Step 3 — Decide only after tracing is complete

Record a vulnerability only when the trace satisfies every one of these:

- [ ] You confirmed the external-input variable in the code (cite file:line)
- [ ] You confirmed the path by which that variable reaches a dangerous destination, in the code (cite each hop)
- [ ] You confirmed in the code that no handling along that path blocks the input (cite the evidence for "none")

If any of the three cannot be filled with a code citation, log "trace incomplete" and move on.

### Step 4 — Verify auth / authorization in the code

Do not assume "this endpoint probably requires auth".
Read the middleware chain directly and confirm whether auth handling is in place.

```bash
# Find the router config file or where middleware is registered
grep -rn "app\.use\|router\.use\|middleware\|guard\|interceptor" <local_path> -l
python tools/file_read.py <middleware_file> <line> --context 30
```

If you cannot confirm an auth middleware in the code, write "assumed no auth" explicitly.

---

## Output format

```
## Manual Review Finding #N

**Suspicious point:**
Evidence: <file>:<line> → "<code>"

**Trace path:**
1. <file>:<line> → "<code>" — <what happens at this step>
2. <file>:<line> → "<code>" — <what happens at this step>
3. <file>:<line> → "<code>" — ← dangerous point

**Blocking handling:**
None — Evidence: <how you confirmed "none": read the whole function and X was absent>

**Verdict: valid / trace incomplete**
If incomplete, state where the trace broke.
```
