# Skill 03-E: Agentic CI Injection — AI Agents in GitHub Actions

> **Provenance.** Adapted from Trail of Bits' `agentic-actions-auditor` skill
> (<https://github.com/trailofbits/skills/tree/main/plugins/agentic-actions-auditor>),
> aligned to CrayFisher's evidence rules.

## Purpose

Find prompt-injection-to-compromise vulnerabilities where **attacker-controlled
GitHub event data reaches an AI coding agent running in CI/CD**. This is a
distinct attack surface from the in-process agent flows in 3-B: the entry point
is a workflow trigger, the "tool" is the whole runner (secrets, checkout,
`gh` token), and the injection lands in an agent action's `prompt`.

CrayFisher's mission includes "products built on top of" agent frameworks —
many ship `.github/workflows/` that wire `anthropics/claude-code-action`,
`google-gemini/gemini-cli-action`, `openai/codex-action`, or
`actions/ai-inference` to issues/PRs. An external contributor who can open an
issue or PR can then inject instructions into the agent → arbitrary code
execution on a runner that holds repository secrets.

Run this skill whenever Phase 1 finds a `.github/workflows/` directory, **for
both agent and web targets** (it is trigger-driven, independent of
`is_agent_target`).

---

## Threat model (the core asymmetry)

The runner is trusted (secrets, write token, checkout); the *input* that drives
the agent is not. Anyone who can open an issue/PR/comment controls
`github.event.issue.body`, `...pull_request.title`, `...comment.body`, etc. If
any of those reach an AI agent's prompt — directly, via `env:`, or via a
`gh issue view` the prompt tells the agent to run — the attacker is writing the
agent's instructions.

---

## Data collection

```bash
python tools/ci_agent_scan.py <local_path>
```

Emits, per workflow file: `triggers`, `ai_actions[]` (which AI action + its
`with:` inputs), `event_expressions[]` (every `${{ github.event… }}` with line),
`env_event_vars[]` (env vars whose value is an event expression),
`permissions`, and `risky_config[]` (sandbox/allowlist tokens). Treat this as a
**location list** — judge nothing until you read the workflow.

Then read each flagged workflow:

```bash
python tools/file_read.py <local_path>/.github/workflows/<f>.yml <line> --context 15
```

Resolve nested `uses:` composite actions and reusable workflows **one level
deep** before concluding an action is safe.

---

## The nine vectors (A–I)

Read the captured context and check each. Cite `file:line` for every claim.

### Injection paths (attacker data → agent prompt)

- **A — Env-var intermediary.** An `env:` block holds a `${{ github.event… }}`
  expression; the agent reads that env var (directly or because the prompt says
  to). *Clean-looking YAML with no `${{ }}` in the `prompt:` field is NOT safe —
  the data arrives invisibly through the environment.*
- **B — Direct expression injection.** `${{ github.event.issue.body }}` (or
  title/comment/PR body) appears directly inside a `prompt:`/`args:` field.
- **C — CLI data fetch.** The prompt instructs the agent to run
  `gh issue view`, `gh pr view`, `gh api …` that pulls attacker content at
  runtime.
- **E — Error/log injection.** Build output, prior-step logs, or
  `workflow_dispatch` inputs are passed into the agent prompt.
- **G — Eval of AI output.** The agent's output is piped to `eval`, `bash -c`,
  or shell expansion — compounds any of the above into direct RCE.

### Trigger & checkout

- **D — `pull_request_target` + checkout of PR head.** `pull_request_target`
  (and `issue_comment`, `workflow_run`) run with **base-branch secrets** while
  checking out attacker-controlled head code/config. High severity even before
  the agent.

### Configuration weaknesses

- **F — Subshell expansion in allowlist.** Tool allowlist permits commands that
  support `$()`/backtick expansion (`echo`, `grep`, `cat`) — "restricted" tools
  still enable exfiltration.
- **H — Dangerous sandbox config.** `danger-full-access`, `Bash(*)`, `--yolo`,
  `--dangerously-skip-permissions`, `unsafe` safety strategy, sandbox disabled.
- **I — Wildcard allowlist.** `allowed_users: "*"` (or equivalent) lets *any*
  GitHub user trigger the agent.

---

## Rejected rationalizations (false negatives ToB warns about)

Do **not** clear a finding on any of these:

| Rationalization | Why it's wrong |
|---|---|
| "Only maintainers can trigger it" | `pull_request_target` / `issue_comment` fire on *external* input regardless of write access |
| "No `${{ }}` in the prompt, so it's clean" | env-var intermediary (Vector A) passes data invisibly |
| "Tools are restricted to `echo`/`grep`" | subshell expansion (Vector F) exfiltrates anyway |
| "It's sandboxed" | misconfig (Vector H) disables it; even a good sandbox leaks secrets the agent can read |

---

## Severity & mapping

Primary class **Prompt Injection → RCE / secret exfiltration**:
**CWE-1427 (injection) + CWE-94/77 (when output is eval'd) + CWE-77** ·
**OWASP LLM01 → LLM06**. A confirmed `pull_request_target`+checkout+agent path
that reaches secrets is typically **Critical** (S:C, host/repo compromise).
These paths are natural inputs to [exploit-chaining.md](exploit-chaining.md)
(entry link = the trigger; terminal = runner RCE / secret read).

Validate in Phase 4 with
[policies/prompt-injection.md](../04-validate/policies/prompt-injection.md) and
the FP gate [fp-check-gate.md](../04-validate/fp-check-gate.md).

---

## Output

```json
{
  "phase": "3-E",
  "findings": [
    {
      "id": "FIND-CI-001",
      "workflow": ".github/workflows/triage.yml",
      "vector": "A",
      "ai_action": "anthropics/claude-code-action",
      "trigger": "issue_comment",
      "source": ".github/workflows/triage.yml:14 → \"BODY: ${{ github.event.comment.body }}\"",
      "sink": ".github/workflows/triage.yml:31 → \"prompt: Review the issue in $BODY\"",
      "secrets_in_scope": true,
      "checkout_head": false,
      "vuln_type": "PROMPT_INJECTION",
      "cwe": ["CWE-1427", "CWE-77"],
      "owasp_class": "LLM01",
      "confidence_base": 0.70
    }
  ]
}
```

---

## Hand-off

- Findings re-enter Phase 4 via prompt-injection policy + FP gate.
- Trigger→secret paths feed [exploit-chaining.md](exploit-chaining.md).
- Remediation: pin actions, drop `pull_request_target`+head-checkout, pass
  untrusted data only through files the agent treats as data (never the prompt),
  least-privilege `permissions:`, real allowlists, keep the sandbox on.
