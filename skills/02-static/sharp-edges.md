# Skill 02-C: Sharp Edges — Footgun API & Dangerous-Default Detection

> **Provenance.** Adapted from Trail of Bits' `sharp-edges` skill
> (<https://github.com/trailofbits/skills/tree/main/plugins/sharp-edges>),
> aligned to CrayFisher's evidence discipline and agent-framework target space.

## Purpose

Find **insecure API designs** in the target — places where the framework makes
the *wrong* usage easy and the *safe* usage hard. The guiding principle:

> **Secure usage should be the path of least resistance.** When it isn't, the
> footgun *is* the vulnerability.

This is a different lens from taint (3-x), which follows attacker data. Sharp
edges are found by reading the **API surface a downstream developer consumes**.
This matters acutely for CrayFisher's mission: an AI-agent *framework* (MCP,
LangChain, CrewAI, …) that ships a dangerous default or a stringly-typed trust
knob propagates that flaw into **every product built on it** — high-impact,
high-blast-radius, exactly the "products built on top of frameworks" target.

Run it in Phase 2 alongside [manual-code-review.md](manual-code-review.md),
focused on public/exported APIs, config schemas, and tool/agent registration.

---

## What counts as a sharp edge (6 categories)

1. **Algorithm / mode selection** — the API lets the caller pick a weak
   primitive, or takes the choice from untrusted input.
   *Classic:* JWT `alg` read from the token header → attacker sets `"alg":
   "none"`. *Agent:* model/guardrail selectable from a request field.
2. **Dangerous defaults** — the secure behavior requires opt-*in*; the default
   is unsafe or semantically ambiguous.
   *Agent:* `permission_mode="auto"`, `human_input_mode="NEVER"`,
   `askBeforeRun=false`, `sandbox="auto"` with silent host fallback,
   `allowed_tools` unset = all. (Cross-check
   [../00-meta/agent-default-checks.md](../00-meta/agent-default-checks.md).)
3. **Primitive vs. semantic types** — keys, nonces, ciphertexts, tokens all the
   same raw type, so callers swap parameters; or trust labels passed as bare
   strings.
4. **Configuration cliffs** — one setting flips the whole system from secure to
   wide-open (a single `debug=true`, `verify=false`, `*` allowlist).
5. **Silent failures** — verification returns a boolean nobody checks, errors
   are swallowed, or "success" masks a partial failure. A verify function that
   *returns* `false` instead of *throwing* is a sharp edge.
6. **Stringly-typed security** — security decisions keyed on free-form strings:
   approval keyed on a tool's `description` containing "read-only"; trust level
   parsed from a string field. (See
   [../04-validate/policies/mcp-tool-poisoning.md](../04-validate/policies/mcp-tool-poisoning.md)
   `auto-approve-on-tool-description`.)

---

## Four-phase workflow

### Phase 1 — Surface identification

Map the security-relevant API the framework exposes to its users:

```bash
# Exported/public entry points, config schemas, registration APIs
grep -rn "export function\|export class\|def \|@tool\|registerTool\|server.tool\|@function_tool" <path> --include="*.ts" --include="*.py"
grep -rn "DEFAULT_\|default=\|: *=\|os.environ.get\|process.env" <path>
grep -rn "interface .*Options\|class .*Config\|TypedDict\|pydantic" <path>
```

List each choice point a downstream developer faces (an option, a default, a
mode flag, a registration call).

### Phase 2 — Edge-case probing (read the code, per choice point)

For each, read the implementation and ask:
- What happens at `0` / `""` / `null` / negative / missing? (Step into the code.)
- What is the **default** when the option is omitted? (Read the default literal.)
- Can the value come from untrusted input? (Trace one hop.)
- Are two confusable types interchangeable here?

### Phase 3 — Threat-model three developers

A sharp edge is real if **any** of these gets burned with no warning:
- **Malicious developer** — actively chooses the weak option (rarely the point).
- **Lazy developer** — copies the quickstart, accepts every default.
- **Confused developer** — misreads the API and picks the wrong-but-plausible
  option.

The lazy and confused developers are the target: if the default / easy path is
unsafe, it *will* ship insecure in real products.

### Phase 4 — Validation

Confirm exploitability with evidence before reporting:
- Reproduce the footgun path in the code (cite the default literal / the
  untrusted-source hop / the swallowed error).
- Confirm no guard makes the unsafe choice safe anyway (read it).
- A footgun that only fires when a developer *deliberately* disables a clearly
  documented safety is weaker — note it, don't inflate it.

---

## Evidence discipline (Principle 2 — unchanged)

Every sharp-edge claim carries the concrete line:

```
Evidence: <file>:<line> → "<the default literal / the untrusted read / the bool-not-throw>"
Why it's a footgun: <which of the 6 categories; which developer gets burned>
Impact when burned: <what the downstream product exposes>
```

## Rejected rationalizations (do NOT clear a real sharp edge on these)

Documentation ("it's documented"), flexibility ("advanced users need it"),
"developer responsibility", "unlikely scenario", "it's just configuration", and
backwards compatibility **do not** excuse an unsafe default or an injectable
mode selector.

---

## Mapping to CrayFisher classes

| Sharp edge | CrayFisher vuln_type | Policy |
|---|---|---|
| Dangerous default (ask/sandbox/perm) | `EXCESSIVE_AGENCY` | [excessive-agency.md](../04-validate/policies/excessive-agency.md) + [agent-default-checks](../00-meta/agent-default-checks.md) |
| Stringly-typed approval / trust label | `MCP_TOOL_POISONING` / `AGENT_AUTHZ` | [mcp-tool-poisoning.md](../04-validate/policies/mcp-tool-poisoning.md) / [agent-authorization.md](../04-validate/policies/agent-authorization.md) |
| Algorithm/mode from untrusted input | `PROMPT_INJECTION` / `CRYPTO` | [prompt-injection.md](../04-validate/policies/prompt-injection.md) / [crypto.md](../04-validate/policies/crypto.md) |
| Silent-failure verify | `LOGIC_BUG` / `AUTH_BYPASS` | [logic-bug.md](../04-validate/policies/logic-bug.md) / [auth.md](../04-validate/policies/auth.md) |

## Output

```json
{
  "phase": "2-C",
  "findings": [
    {
      "id": "SHARP-001",
      "category": "dangerous-default",
      "api": "Agent(permission_mode=...)",
      "evidence": "src/agent.py:30 → \"permission_mode: str = 'auto'\"",
      "burned_developer": "lazy",
      "impact": "tools run with no approval in default config",
      "vuln_type": "EXCESSIVE_AGENCY",
      "confidence_base": 0.65
    }
  ]
}
```

Findings enter Phase 4 ([criteria-gate](../04-validate/criteria-gate.md) →
[fp-check-gate](../04-validate/fp-check-gate.md)) like any other.
