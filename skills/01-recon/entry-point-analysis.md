# Skill 01-B: Entry Point Analysis

## Purpose
Identify the entry points where external input arrives, and read how each handler actually takes in and uses that input.

---

## Procedure

### Step 1 — Automatic detection
```bash
python tools/find_entries.py <local_path>
```
Take the `entries` list from the output. This is **just a list of locations**. Do not judge anything yet.

### Step 2 — Read each entry-point handler directly

Pick the reading scope by entry-point type:

| Type | Reading scope |
|------|-------------|
| `http_route` POST/PUT | Entire handler function (at least 40 lines) |
| `tool_handler` (MCP) | Tool registration code + entire handler function |
| `http_route` GET | Entire handler function (at least 20 lines) |
| `agent_hook` | Entire hook function + the code that registers it |
| `cli_command` | Entire command handler |

```bash
python tools/file_read.py <local_path>/<file> <line> --context 40
```

### Step 3 — Answer each question as you read the code

Every time you read a handler, answer the questions below.
**Every answer cites a `file:line`. Do not write "present/absent" without a citation.**

**Q1. What external parameters does this handler accept?**
- List every variable name extracted from `req.body`, `req.query`, `req.params`, `request.args`, and similar external sources
- Citation: `<file>:<line> → const { X, Y } = req.body`

**Q2. Where is each parameter passed?**
- Read the path it flows into: function-call arguments, DB queries, file paths, external APIs, etc.
- If it is passed into another function, find that function's definition and read it

**Q3. What handling does the parameter go through before reaching its destination?**
- Record only the validation / encoding / type conversion you actually saw in the code
- If there is none, write "none". Do not write "there is probably some"

### Step 4 — Additional manual detection (types the automated scan may miss)

```bash
grep -rn "on('connection'" <local_path> --include="*.ts" --include="*.js" -l
grep -rn "\.subscribe\|\.consume\|on_message" <local_path> -l
grep -rn "process\.on\('message'\|ipcMain\.on" <local_path> -l
```
Apply Steps 2–3 the same way when something is found.

---

## Output format

```
## Entry Points: <repo-name>

### <file:line> — <type> (<route or handler name>)

**External parameters:**
- `X` — Evidence: <file>:<line> → "<code>"
- `Y` — Evidence: <file>:<line> → "<code>"

**Destination of each parameter:**
- `X` → <function name / DB query / API> (<file>:<line>)
  - Destination code: "<code>"
  - Intermediate handling: <cite the code if any, else "none">

**Next steps:**
- 03-A Taint trace start: `X` (<file>:<line>)
- Suspicion level: high/medium/low (one-line reason)
```

---

## Notes

- Do not infer "this handler probably requires auth" from a filename or path alone.
- If you have not actually read a middleware in the code, the default assumption is "no auth middleware".
