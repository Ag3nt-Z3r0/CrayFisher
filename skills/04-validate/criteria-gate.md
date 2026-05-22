# Skill 04-A: 5-Criterion Validation Gate

## Purpose

Take each candidate finding from Phase 03 and run it through five
criteria. Every criterion must be proven pass/fail with a direct code
citation. Never mark a criterion "pass" without a citation.

---

## Procedure

For each candidate, run criteria ① → ⑤ in order. The first failed
criterion drops the candidate to FP. Move on to the next candidate.

When `is_agent_target = true` (from `tools/detect_stack.py`), criterion
② additionally enforces the agent-default checklist in
[../00-meta/agent-default-checks.md](../00-meta/agent-default-checks.md),
and criterion ⑤ uses `tools/ghsa_lookup.py` instead of (or in addition
to) `osv_lookup.py`.

---

### ① Can external input actually reach this code path?

**How to check.** Look at the Phase 03 trace. Is there a "flow
confirmed" verdict with a code citation at every hop?

- Yes → ① pass. Record the cited source location.
- No → check directly:

```bash
# Is there an entry point that calls this code?
grep -rn "<function_name>\|<file_stem>" <local_path> \
     --include="*.ts" --include="*.py" -l
```

Read the caller file and confirm it is an inbound request handler / CLI
arg / file ingest path.

**Record:**

```
① pass / fail
Evidence: <file>:<line> → "<code>"  (source location cited)
```

---

### ② Triggerable in the default configuration?

**How to check.** Was the surrounding conditional read during the Phase
03 trace? If so:

```bash
python tools/file_read.py <file> <condition_line> --context 15
```

Confirm:

- Is there an env var or feature flag gate?
- Does the code path require `process.env.ENABLE_X` or
  `config.featureFlag = true`?
- Is the block marked `@deprecated`, `// TODO: remove`, or `// dead code`?

**Additional agent checks (only when `is_agent_target = true`):**

Run through every item in
[../00-meta/agent-default-checks.md](../00-meta/agent-default-checks.md).
A single permissive default among these is enough to pass criterion ②
on its own:

- `DEFAULT_ASK = "off"` / `askBeforeRun = false`
- `autoApprove = true` / `auto_approve = True`
- `human_input_mode = "NEVER"`
- `permission_mode = "auto"`
- `toolsAllow` is `undefined` / `None`
- `sandbox = "auto"` without a sandbox-availability gate

If any of the above is the literal default value at its declaration
site, record the location and ② passes.

**Record:**

```
② pass / fail
Read condition: <file>:<line> → "<code>"
Conclusion: no gate / gate present (description)
Agent default match (if any): <key> = <value> at <file>:<line>
```

---

### ③ Can the attacker actually control this value?

**How to check.** Revisit the source from ①.

```bash
python tools/file_read.py <source_file> <source_line> --context 10
```

- Does the value come from a hardcoded constant? → ③ fail
- Does the SQL query use `?`, `$1`, `:name`, `@param` placeholders? → ③ fail
- Is the TypeScript type constrained to `number`, `boolean`, `bigint`,
  or a union literal?

  ```bash
  python tools/file_read.py <type_def_file> <type_line> --context 5
  ```

  Read the declaration. If a separate type file exists, read that too.

**For agent targets:** consult the trust graph emitted by
`tools/agent_trust_graph.py`. If the source variable is layered USER or
TOOL, attacker control is established by the graph; cite the node.

**Record:**

```
③ pass / fail
Attacker controllable: yes / no (reason)
Evidence: <file>:<line> → "<code>"
Trust layer (if agent target): USER | TOOL | DEVELOPER | SYSTEM
```

---

### ④ Does the vulnerability have meaningful impact?

**How to check.** Re-read the sink. Open the policy file for this vuln
type and apply its rules.

| Vuln class | Policy file |
|---|---|
| DoS / ReDoS | `skills/04-validate/policies/dos.md` |
| SQL Injection | `skills/04-validate/policies/sqli.md` |
| Command Injection | `skills/04-validate/policies/cmdi.md` |
| Path Traversal | `skills/04-validate/policies/path-traversal.md` |
| SSRF | `skills/04-validate/policies/ssrf.md` |
| XSS | `skills/04-validate/policies/xss.md` |
| Prompt Injection (general) | `skills/04-validate/policies/prompt-injection.md` |
| Auth Bypass / IDOR | `skills/04-validate/policies/auth.md` |
| CORS | `skills/04-validate/policies/cors.md` |
| Crypto Weakness | `skills/04-validate/policies/crypto.md` |
| Insecure Deserialization | `skills/04-validate/policies/deserialization.md` |
| Logic Bug / Race Condition | `skills/04-validate/policies/logic-bug.md` |
| **Excessive Agency** | `skills/04-validate/policies/excessive-agency.md` |
| **MCP Tool Poisoning** | `skills/04-validate/policies/mcp-tool-poisoning.md` |
| **Tool Result Injection (A3)** | `skills/04-validate/policies/tool-result-injection.md` |
| **Agent Authorization / Scope** | `skills/04-validate/policies/agent-authorization.md` |
| **Sandbox Escape** | `skills/04-validate/policies/sandbox-escape.md` |
| **Supply Chain / Plugin** | `skills/04-validate/policies/supply-chain-plugin.md` |
| **Context Window Attack (A10)** | `skills/04-validate/policies/context-window-attacks.md` |
| **Incomplete Fix** | `skills/04-validate/policies/incomplete-fix.md` |

**Judgment procedure:**

1. Read the policy file.
2. Does the finding satisfy at least one `<reportable>` condition with a
   code citation?
3. Does any `<not_reportable>` condition apply? If yes, ④ fails immediately.
4. Confirm every `<verify>` item by re-reading the code.

Each condition must be backed by code reading. Never pass ④ on
"intuition that this kind of code is usually risky".

**Agent-target override.** When `is_agent_target = true` and the
finding's `vuln_type` is in `{EXCESSIVE_AGENCY, AGENT_AUTHZ,
SANDBOX_ESCAPE}`, the agent policy is consulted *before* the generic
policy. If both apply, both must pass.

**Record:**

```
④ pass / fail
Policy file: skills/04-validate/policies/<type>.md
Applied condition: <reportable condition id>
Evidence: <file>:<line> → "<code>"
```

---

### ⑤ Is this not a duplicate of a known CVE?

```bash
python tools/osv_lookup.py <main_package> <ecosystem>
# When is_agent_target == true, also:
python tools/ghsa_lookup.py <main_package>
python tools/incomplete_fix_scan.py <local_path>
```

- Same file, same function, same pattern as an existing CVE? → ⑤ fail (duplicate).
- Same pattern, different location? → ⑤ pass (new finding plausible).
- `incomplete_fix_scan.py` marks this commit / file as an
  Agent-Zero-DB pattern A–E match? → ⑤ pass *and* set `vuln_type =
  INCOMPLETE_FIX` (consult `policies/incomplete-fix.md`).

**Record:**

```
⑤ pass / fail
OSV result: none / present (ID + same-file? y/n)
GHSA result (if agent target): none / present (GHSA-id)
Incomplete-fix match (if any): pattern A | B | C | D | E
```

---

## Final verdict format

```
## Validation: <file>:<line> <vuln_type>

| Criterion | Verdict | Evidence |
|---|---|---|
| ① Reachability | pass/fail | <file>:<line> → "<code>" |
| ② Default config | pass/fail | <file>:<line> → "<code>" (+ agent default match if any) |
| ③ Attacker control | pass/fail | <file>:<line> → "<code>" (trust layer if agent target) |
| ④ Meaningful impact | pass/fail | <file>:<line> → "<code>" (+ policy file) |
| ⑤ Not a duplicate CVE | pass/fail | OSV / GHSA result |

**Final: valid vuln / FP**
FP reason: <failed criterion + code evidence>
```
