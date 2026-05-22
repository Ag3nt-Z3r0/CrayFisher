# Skill 03-B: AI Agent Security Flow Analysis

## Purpose

Find Agent-specific vulnerabilities in LLM / MCP / agent-framework code.
Unlike generic taint, here **the LLM's own output is also a fresh taint
source.**

When `is_agent_target = true`, 03-B is the **primary** taint skill. 03-A
applies only to non-agent entry points (admin HTTP, ORM, static assets).

---

## Agent Trust Layer Model

Trust is hierarchical. Lower in the table = less trusted:

```
[1] System Prompt       — operator-controlled, highest trust
[2] Developer Messages  — hardcoded in code, high trust
[3] User Turn           — user input, low trust
[4] Tool Results        — external world, lowest trust (attacker-controllable)
```

**Core vulnerability pattern**: lower-trust content **promoted** into a
higher-trust layer.

The trust graph emitted by [`tools/agent_trust_graph.py`](../../tools/agent_trust_graph.py)
captures this directly: every `kind: "promotion"` edge is a candidate.

---

## Agent-specific vuln classes (10 patterns)

### [A1] Indirect Prompt Injection

**Definition.** Attacker plants instructions inside external content
(web page, file, email, DB row) that the agent will later process; those
instructions hijack the agent.

**Grep patterns:**

```bash
# Tools that fetch external content and return it without wrapping
grep -rn "wrapExternalContent\|wrapWebContent" <path> --include="*.ts" | grep "return"
grep -rn "text:.*\`.*\${" <path> --include="*.ts" | grep -v "wrapExternal\|wrapWeb"
```

**Read the code for:**

- Does the tool fetch external content and return it as tool result?
- Is `wrapExternalContent()` (or equivalent) applied before return?
- Is a dangerous tool (`exec`, `file_write`) registered in the same agent?

**Red flags.** `text: \`...\${rawContent}\``; `return { text: externalData }`.

---

### [A2] Stored Prompt Injection

**Definition.** Attacker writes poisoned content into DB / memory / file;
the agent retrieves it later and the injection runs in a higher-trust
context.

**Grep patterns:**

```bash
grep -rn "INSERT INTO\|\.push\|\.set\|\.store" <path> --include="*.ts" | head -30
grep -rn "memory\.search\|recall\|retrieve\|getHistory\|loadContext" <path> --include="*.ts"
```

**Read the code for:**

- On write: is the input stored raw without an LLM summary / transform?
- On read: is the stored text inserted into the LLM context without
  `wrapExternalContent`?
- Is there sanitization between write and read?

---

### [A3] Tool Result Injection

**Definition.** A tool result (exec, web_fetch, file_read, …) is folded
back into the next LLM turn, so injection inside the result hijacks the
follow-up call.

**Grep patterns:**

```bash
grep -rn "role.*tool\|tool_result\|toolResult\|ToolResultBlock" <path> --include="*.ts"
grep -rn "wrapToolResult\|sanitizeToolOutput\|escapeToolContent" <path> --include="*.ts"
```

**Read the code for:**

- Is the tool result added to `messages` as `content: rawOutput`?
- Does shell / exec output land in the next LLM call unchanged
  (recursive injection)?
- Can web_fetch / file_read return attacker-controllable bytes?

---

### [A4] Multi-Agent Trust Escalation

**Definition.** A low-trust subagent returns output to a higher-trust
orchestrator and the output is trusted unconditionally.

**Grep patterns:**

```bash
grep -rn "subagent\|Subagent\|spawn.*agent\|runAgent\|delegateTo" <path> --include="*.ts"
grep -rn "result.*message\|output.*inject\|agentResponse.*prompt" <path> --include="*.ts"
```

**Read the code for:**

- Is the subagent's output inserted into the orchestrator LLM's user /
  system turn?
- Is the output sanitized / schema-parsed before insertion?
- Does the subagent have access to external input?

**Hot scenario.** External-input subagent → manipulated output →
orchestrator calls `exec`.

---

### [A5] Instruction Hierarchy Bypass

**Definition.** System-prompt instructions are overridden by conflicting
instructions injected via user turn or tool result.

**Grep patterns:**

```bash
grep -rn "messages.*system\|systemPrompt\|extraSystemPrompt" <path> --include="*.ts"
grep -rn "prependEvents\|systemLines\|buildReplyPrompt" <path> --include="*.ts"
```

**Read the code for:**

- Does the system prompt say "do not trust external content"?
- Does user-turn or tool-result content land prefixed with `System:` ?
- When two instructions conflict, which does the model prioritize by
  design?

---

### [A6] Memory Poisoning

**Definition.** Attacker writes poisoned content into the agent's long-
or short-term memory; the agent reads it back in a later session.

**Grep patterns:**

```bash
grep -rn "memory\.add\|memory\.store\|addMemory\|saveMemory\|promoteTo" <path> --include="*.ts"
grep -rn "memory\.search\|memory\.get\|loadMemory\|recallMemory" <path> --include="*.ts"
```

**Read the code for:**

- Write path: does external input land in memory verbatim?
- Read path: is stored content passed to the LLM without
  `wrapExternalContent`?
- Are write thresholds (score, recall count, etc.) actually reachable?

---

### [A7] Tool Chain Exploitation

**Definition.** Attacker uses one tool to cause the agent to invoke
another, dangerous tool in sequence.

**Grep patterns:**

```bash
grep -rn "profiles.*coding\|tool.*register\|toolCatalog\|allowedTools" <path> --include="*.ts"
grep -rn "tool.*sequence\|toolChain\|autoApprove\|askBeforeRun" <path> --include="*.ts"
```

**Read the code for:**

- Are `exec` / `file_write` registered in the same session as
  `web_fetch` / `memory_search`?
- Does tool A's output flow directly into tool B's argument
  automatically?
- Is `ask=off` / `autoApprove=true` the default?

---

### [A8] Goal Hijacking

**Definition.** An injected instruction replaces the agent's original
objective, so the agent does the attacker's work.

**Grep patterns:**

```bash
grep -rn "goal\|objective\|task.*user\|userGoal" <path> --include="*.ts"
grep -rn "run_task\|taskBody\|agentTask" <path> --include="*.ts"
```

**Read the code for:**

- Is the agent's initial task / goal set from external input (webhook,
  API)?
- Is the task body directly inserted into a user / system turn?
- Is there content validation on the task body?

---

### [A9] Critic / Evaluator Manipulation

**Definition.** In a multi-agent system, the evaluator agent's verdict
is compromised by injected content in what it's asked to evaluate.

**Grep patterns:**

```bash
grep -rn "critic\|judge\|evaluate\|review.*agent\|verif.*agent" <path> --include="*.ts" -i
```

**Read the code for:**

- Does the evaluator receive the candidate content directly in user turn?
- Is the evaluator's verdict used to drive a follow-up action
  automatically?
- Does the evaluator have dangerous tools registered too?

---

### [A10] Context Window Manipulation

**Definition.** Attacker sends large benign content to push the leading
system prompt out of the model's effective context, or dilutes it with
specific patterns.

**Grep patterns:**

```bash
grep -rn "maxTokens\|contextLimit\|truncate\|trimContext\|maxContext" <path> --include="*.ts"
grep -rn "\.join\|concat.*content\|append.*history" <path> --include="*.ts"
```

**Read the code for:**

- Is there a length cap on external content?
- Does a long input land *before* the system prompt?
- Can context truncation / compression drop the system prompt?

---

## Detection procedure

### Step 1 — Agent architecture

```bash
python tools/detect_stack.py <local_path>
python tools/architecture_map.py <local_path>
python tools/agent_trust_graph.py <local_path>
```

Confirm:

- LLM call sites (`llm_call_sites[]`)
- Tool registry (`tool_registry[]`)
- Sub-agent spawners (`sub_agent_spawners[]`)
- Memory stores (`memory_stores[]`)
- Sandbox / approval (`sandbox_sites[]`, `approval_gates[]`)

### Step 2 — Trust-boundary map

Use the trust-graph output to answer:

```
Q1: Where does external input (HTTP, chat, file, voice) enter?
Q2: What transforms does it pass before landing in LLM messages?
Q3: Which trust layer does it land in (system / user / tool)?
Q4: Are dangerous tools (exec, file_write) registered in the same session?
Q5: Is a human-approval gate present (ask=always, etc.)?
```

Every `kind: "promotion"` edge in the graph is a candidate.

### Step 3 — Wrapper / sanitizer consistency

When the correct protection exists in some places but not others —
register a candidate immediately.

```bash
grep -rn "wrapExternalContent\|wrapWebContent" <path> --include="*.ts"
grep -rn "sanitizeInboundSystemTags" <path> --include="*.ts"
```

Compare: which call sites have it, which do not.

### Step 4 — Default-value analysis

Cross-check against [`../00-meta/agent-default-checks.md`](../00-meta/agent-default-checks.md):

```bash
grep -rn "DEFAULT_ASK\|DEFAULT_SECURITY\|groupPolicy\|toolsAllow\|dmPolicy" <path> --include="*.ts"
grep -rn "'open'\|'off'\|'full'\|'allowlist'" <path> --include="*.ts" | grep -i "default\|=\s*['\"]"
```

Dangerous default patterns:

- `DEFAULT_ASK = 'off'` → tools run without confirmation
- `groupPolicy = 'open'` → all members granted
- `toolsAllow = undefined` → every registered tool allowed
- `sandbox = 'auto'` + `sandboxAvailable = false` → host execution
- `permission_mode = 'auto'` (OpenHands / Claude Agent SDK)
- `human_input_mode = 'NEVER'` (AutoGen)

---

## Output

```json
{
  "agent_architecture": {
    "llm_calls": ["<file>:<line>"],
    "tool_registry": "<file>:<line>",
    "memory_system": "<file> or null",
    "multi_agent": true,
    "trust_layers_identified": ["system_prompt", "user_turn", "tool_result"]
  },
  "findings": [
    {
      "id": "FIND-XXX",
      "vuln_class": "A1|A2|A3|A4|A5|A6|A7|A8|A9|A10",
      "vuln_type": "PROMPT_INJECTION|TOOL_RESULT_INJECTION|MEMORY_POISONING|MULTI_AGENT_ESCALATION|...",
      "title": "...",
      "trust_escalation": "tool_result → user_turn",
      "source": "<file>:<line> → \"code\"",
      "sink": "<file>:<line> → \"code\"",
      "taint_path": ["step1", "step2"],
      "dangerous_tools_reachable": ["exec", "file_write"],
      "human_gate_present": false,
      "confidence_base": 0.70
    }
  ]
}
```

---

## A1–A10 → Semgrep rule → policy mapping

When a candidate matches one of A1–A10, the recon agent stamps it with
the vuln-type below, the defender consults the named policy file, and
Phase 2 Semgrep loads the listed rule IDs first.

| Pattern | vuln_type | Primary policy | Supporting Semgrep rules |
|---|---|---|---|
| **A1** Indirect Prompt Injection | `PROMPT_INJECTION` | [policies/prompt-injection.md](../04-validate/policies/prompt-injection.md) | `mcp-tool-result-returned-raw`, `langchain-system-prompt-concat-input` |
| **A2** Stored Prompt Injection | `PROMPT_INJECTION` | [policies/prompt-injection.md](../04-validate/policies/prompt-injection.md) | `langchain-memory-write-untrusted` |
| **A3** Tool Result Injection | `TOOL_RESULT_INJECTION` | [policies/tool-result-injection.md](../04-validate/policies/tool-result-injection.md) | `tool-result-fed-back-to-llm-py`, `tool-result-fed-back-to-llm-ts`, `mcp-tool-result-returned-raw` |
| **A4** Multi-Agent Trust Escalation | `MULTI_AGENT_ESCALATION` | [policies/agent-authorization.md](../04-validate/policies/agent-authorization.md) | `subagent-output-into-orchestrator-prompt` |
| **A5** Instruction Hierarchy Bypass | `PROMPT_INJECTION` | [policies/prompt-injection.md](../04-validate/policies/prompt-injection.md) | `system-message-fstring-py`, `system-message-fstring-ts`, `tool-output-into-system-py`, `dev-message-from-request-py`, `trust-label-string-write-ts` |
| **A6** Memory Poisoning | `MEMORY_POISONING` | [policies/prompt-injection.md](../04-validate/policies/prompt-injection.md) | `langchain-memory-write-untrusted` |
| **A7** Tool Chain Exploitation | `EXCESSIVE_AGENCY` | [policies/excessive-agency.md](../04-validate/policies/excessive-agency.md) | `default-ask-off-py`, `default-ask-off-ts`, `auto-approve-true-py`, `auto-approve-true-ts`, `tools-allow-undefined-ts`, `tools-allow-none-py`, `langchain-tool-from-unvalidated-input`, `langchain-tool-fs-no-sandbox`, `openai-agents-tool-arg-to-shell` |
| **A8** Goal Hijacking | `PROMPT_INJECTION` | [policies/prompt-injection.md](../04-validate/policies/prompt-injection.md) | `system-message-fstring-py`, `system-message-fstring-ts` |
| **A9** Critic / Evaluator Manipulation | `MULTI_AGENT_ESCALATION` | [policies/agent-authorization.md](../04-validate/policies/agent-authorization.md) | `subagent-output-into-orchestrator-prompt` |
| **A10** Context Window Manipulation | `CONTEXT_WINDOW_ATTACK` | [policies/context-window-attacks.md](../04-validate/policies/context-window-attacks.md) | `langchain-agent-executor-no-max-iterations`, `openai-agents-runner-no-max-turns` |

Additional cross-cutting policies that apply regardless of A-class:

| When to consult | Policy |
|---|---|
| Tool description / name / schema sourced from untrusted | [policies/mcp-tool-poisoning.md](../04-validate/policies/mcp-tool-poisoning.md) |
| Scope / authorization model in play (`operator.admin`, …) | [policies/agent-authorization.md](../04-validate/policies/agent-authorization.md) |
| Product claims sandboxing | [policies/sandbox-escape.md](../04-validate/policies/sandbox-escape.md) |
| Plugin / extension loader present | [policies/supply-chain-plugin.md](../04-validate/policies/supply-chain-plugin.md) |
| Adjacent to a previously-patched CVE / GHSA | [policies/incomplete-fix.md](../04-validate/policies/incomplete-fix.md) |
