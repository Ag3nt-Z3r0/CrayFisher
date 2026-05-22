# Skill 03-A: Source → Sink Taint Trace

## Purpose
Confirm by reading code how external input reaches a dangerous function.
The output of this skill must be "data flow confirmed directly in the code".
"This is probably how it flows" is not a result.

---

## Trace procedure

### Step 1 — Starting point: read the entry-point handler

Read the candidate file:line passed in from 01-B or 02-A.
```bash
python tools/file_read.py <local_path>/<handler_file> <entry_line> --context 30
```

**What this read must produce:**
A list of variable names the handler extracts from an external source.
Record only the patterns you actually saw in the code:

```
req.body.X      req.query.X     req.params.X
request.args['X']   request.form['X']   request.json['X']
process.argv[N]     sys.argv[N]
```

Do not call something "external input" if you did not read it as one of these patterns.

### Step 2 — Trace each external variable one at a time

**Procedure for tracing variable A:**

1. Find the first line in the handler where variable A is used
2. Read that line — is variable A used as an argument to a function call?
3. Yes → find and read the definition of that function

```bash
# Find function definition
grep -rn "function <callee>\|const <callee>\s*=\|def <callee>" <local_path> \
  --include="*.ts" --include="*.py" --include="*.js"
python tools/file_read.py <definition_file> <definition_line> --context 30
```

4. Read how the argument is used inside that function
5. If there is another function call, return to step 3
6. The trace completes when it reaches one of the dangerous destinations below

**Dangerous destinations (must be confirmed directly in code):**

| Destination | Vuln type |
|--------|-----------|
| `os.system(`, `subprocess.run(`, `exec(` | Command Injection |
| `eval(`, `new Function(`, `vm.runIn` | Code Injection |
| `pickle.loads(`, `yaml.load(` | Deserialization |
| Variable interpolated directly into a DB query string (e.g., `.query(`) | SQL Injection |
| `path.join(` + `readFile` / `readFileSync` with an external path | Path Traversal |
| External URL in `fetch(url)`, `axios.get(url)` | SSRF |
| `innerHTML =`, `document.write(` | XSS |
| `messages.create(`, `chat.completions.create(`, `chain.invoke(` | Prompt Injection |
| External string in `new RegExp(`, `re.compile(` | ReDoS ← check policy |
| External number in `Buffer.alloc(n)`, `new Array(n)` | DoS (alloc) ← check policy |
| `extractall()`, `fromstring()` without a size cap | DoS (Bomb) ← check policy |

**When you reach a DoS sink**: before marking the trace complete, read
the `<policy type="dos">` in `skills/04-validate/criteria-gate.md` and
confirm that no `<not_reportable>` condition applies first.
If one applies, do not mark the trace complete — drop it to FP immediately.

### Step 3 — When the trace breaks

When one of the situations below occurs, stop the trace and log "flow broken".
Do not bridge the gap with a guess.

- A variable is passed as a function argument and you cannot find that function's definition
- A variable is passed into a function imported from another module whose source you cannot read
- The call goes through dynamic dispatch (`this[methodName]()`) and you cannot tell which function it is

Record where and why the trace broke, and state explicitly "downstream path cannot be confirmed".

### Step 4 — After confirming the dangerous destination: check for blocking handling

Walk back through the code you read along the path.

**Criteria to accept that blocking handling exists:**
- You read it directly in the code
- You read the internal implementation of that function

**Criteria to accept that blocking handling is absent:**
- You read every function on the path and the handling was not there

"This function is called `validate`, so it must validate" is not confirmation of blocking handling.
You must read the function's internal code.

---

## Output format

```
## Taint Trace #N

**Starting point:**
<file>:<line> → "<code>" (external source confirmed)

**Trace path:**
1. <file>:<line> → "<code>" — variable passed
2. <file>:<line> → "<code>" — function-internal handling
3. <file>:<line> → "<code>" — ← reached dangerous destination

**Blocking handling:**
None — read every function on the path, confirmed no validation / encoding

**Result: flow confirmed / flow broken**
If broken: <where and why it broke>
```
