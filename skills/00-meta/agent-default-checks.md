# Agent default-config checks

> Mandatory checklist consulted by
> [criteria-gate.md](../04-validate/criteria-gate.md) §2 when
> `is_agent_target = true`. A single match here is enough to pass criterion
> ② (triggerable in default config), because each of these literal defaults
> is a known unsafe shape from the Agent-Zero-DB corpus.

## Why this is a separate file

The list grows as new agent frameworks appear. Keeping it out of
`criteria-gate.md` lets the gate stay generic and lets framework experts add
checks here without touching the gate procedure.

## Checklist

For each item, the criterion ② evidence record should include both the
**file:line** of the declaration and the **literal value** assigned. If the
value isn't literal, criterion ② is *not* automatically satisfied — fall
back to the standard read-the-conditional approach.

### 1 — `DEFAULT_ASK = "off"` / `askBeforeRun = false`

Indicates the product runs tools without user confirmation by default.
Maps to OWASP LLM06.

```
Match shape:
  Python:  DEFAULT_ASK = "off"
           ASK_BEFORE_RUN = False
  TS:      const DEFAULT_ASK = "off"
           askBeforeRun: false
```

### 2 — `autoApprove = true` / `auto_approve = True`

Same intent as above, different naming convention. Always set to true by
default if present.

```
Match shape:
  Python:  auto_approve = True
           autoApprove = True
  TS:      autoApprove: true
           const autoApprove = true
```

### 3 — `human_input_mode = "NEVER"`

AutoGen-style executor agent default. `"NEVER"` means tool calls never
ask for human approval.

```
Match shape:
  Python:  AssistantAgent(..., human_input_mode="NEVER", ...)
           UserProxyAgent(..., human_input_mode="NEVER", ...)
           ConversableAgent(..., human_input_mode="NEVER", ...)
```

### 4 — `permission_mode = "auto"`

OpenHands / Claude Agent SDK style. `"auto"` means runtime decides
without prompting.

```
Match shape:
  Python:  permission_mode = "auto"
           permission_mode: "auto"
  TS:      permissionMode: "auto"
           permissionMode: "bypassPermissions"
```

### 5 — `toolsAllow` / `allowed_tools` is `undefined` / `None` / unset

Absence here means "every tool is allowed". If the catalog has any
dangerous tool, this is excessive agency by default.

```
Match shape:
  Python:  allowed_tools = None
           tools_allow = None
  TS:      toolsAllow: undefined
           toolsAllow: null
           let toolsAllow;          // declared, no assignment
```

### 6 — `sandbox = "auto"` without availability gate

`"auto"` falls back to host execution silently when no sandbox runtime
is installed. The condition is satisfied only when there is *no
companion check* that aborts in the fallback case.

```
Match shape:
  Any:     sandbox = "auto"
           sandbox: "auto"

Not matched (still safe):
  Code path:  if sandbox == "auto" and not docker_available:
                  raise SystemExit(...)
```

### 7 — Tool allowlist sourced from `process.env` / `os.environ`

A denylist that can be relaxed by an env var the attacker may set
(supply chain, container metadata service, sub-process).

```
Match shape:
  Python:  os.environ.get("TOOLS_ALLOW")
           os.environ["TOOLS_ALLOW"]
  TS:      process.env.TOOLS_ALLOW
```

### 8 — System prompt assembled with f-string + non-literal interpolation

System messages built from any non-literal source. The presence alone is
suspicious; combined with the rest of the trust graph it becomes the A5
pattern.

```
Match shape:
  Python:  {"role": "system", "content": f"...{x}..."}
           SystemMessage(content=f"...{x}...")
  TS:      { role: "system", content: `...${x}...` }
```

## How to extend

When a new framework introduces a similar dangerous default:

1. Add a new numbered item here with the match shape.
2. Add a corresponding rule to
   [../../rules/semgrep/agent-defaults.yaml](../../rules/semgrep/agent-defaults.yaml)
   with `metadata.default_check: true`.
3. Cross-reference from
   [agent-cwe-priority.md](agent-cwe-priority.md) if it changes the priority
   distribution materially.

## Output expectation

`criteria-gate.md` §2 emits a record like:

```
② pass
Agent default match: human_input_mode="NEVER" at src/agent.py:42
Read condition: src/agent.py:42 → "AssistantAgent(name='exec', human_input_mode=\"NEVER\")"
Conclusion: triggerable under default config (no approval gate)
```
