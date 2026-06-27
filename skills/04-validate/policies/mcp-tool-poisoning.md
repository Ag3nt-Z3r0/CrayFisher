```xml
<policy type="mcp-tool-poisoning">

  <!--
    MCP Tool Poisoning — the *tool definition* (name, description, schema)
    is treated as developer-trust content but is sourced from untrusted
    data. Maps to CWE-1427 + OWASP LLM01.
    Distinct from prompt-injection: the attack vector is the tool catalog,
    not the user turn.
  -->

  <reportable>
    <condition id="tool-description-from-untrusted">
      The `description` field of a registered tool is interpolated from
      external data (HTTP fetch, file content, environment variable, DB
      row) at registration time.
      Verify: locate the tool registration call. Confirm the description
      argument is non-literal and the source is outside the operator's
      control. Trace the source one hop.
    </condition>
    <condition id="tool-name-from-untrusted">
      The tool `name` is interpolated from untrusted data, allowing an
      attacker to shadow a legitimate tool or impersonate a privileged
      one.
      Verify: same as above, applied to the name argument. Confirm the
      LLM call site selects tools by name match.
    </condition>
    <condition id="tool-schema-allows-overbroad-types">
      Tool input schema accepts `string` / `any` / `additionalProperties:
      true` where a narrower shape was meant, allowing an LLM-passed
      payload to smuggle structured data.
      Verify: read the JSON schema next to the tool registration. Compare
      to what the tool body actually uses.
    </condition>
    <condition id="tool-catalog-mutable-at-runtime">
      The set of registered tools is mutated after server start by an
      external trigger (HTTP request, file watch, plugin install).
      Verify: locate any call that adds tools post-init. Trace the input
      authority for that call.
    </condition>
    <condition id="auto-approve-on-tool-description">
      The agent's auto-approve logic keys on the tool's `description`
      string (e.g., "if description contains 'read-only', skip approval").
      Verify: locate the approval logic and confirm it uses the
      description / name / metadata as a trust signal.
    </condition>
    <condition id="tools-list-no-pinning">
      LINE JUMPING (ToB, catalog T1). The client loads tool descriptions
      from a `tools/list` response into the model context with NO
      trust-on-first-use pinning and NO change-detection on updated
      descriptions, so a malicious/compromised server injects instructions
      that run BEFORE (and independent of) any per-tool approval gate.
      Verify: locate where the client handles the `tools/list` /
      `ListToolsRequest` response and inserts descriptions into the prompt
      / context. Confirm there is no signature/TOFU pin and no diff check
      on description changes. The injection executes at catalog-load time,
      so per-call ask/allow gates do NOT mitigate it — do not accept "but
      tools require approval" as a rebuttal.
    </condition>
    <condition id="ansi-in-model-visible-content">
      ANSI DECEPTION (ToB, catalog T3). A string that is BOTH shown to the
      user as a trust/approval signal AND fed to the model (tool
      description, tool result, file/commit preview) is rendered without
      stripping ANSI/control bytes, so a payload can be made invisible to
      the human reviewer while the LLM still reads it.
      Verify: locate the render/print path for tool descriptions or
      results. Confirm no sanitization of `\x1b[` / `\x1b]` / `\e[` /
      conceal (`\e[8m`) / cursor-move sequences before display. Severity is
      amplified because human approval is defeated.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="tool-catalog-literal" reason="all tool metadata hardcoded">
      All tool registrations use string-literal name and description; the
      schema is hardcoded; the catalog is built once at startup from code.
      Verify: read every tool registration call; confirm literal args only.
    </condition>
    <condition id="approval-not-keyed-on-metadata" reason="approval gate trust-correct">
      Approval logic ignores tool metadata and uses a fixed allowlist
      keyed only on canonical tool identifier set by the operator at
      build time.
      Verify: read the approval predicate; confirm metadata fields are
      not referenced.
    </condition>
    <condition id="catalog-signed" reason="integrity verified">
      Tool catalog entries are cryptographically signed and the signature
      is verified before the catalog is loaded.
      Verify: read the loader code; confirm a signature check executes
      before tools are made available and the verification rejects on
      mismatch.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you enumerate every tool registration call site (search for `setRequestHandler`, `server.tool`, `@tool`, `register_function`, `@function_tool`, `@kernel_function`)?</item>
    <item>Did you check whether any of `name`, `description`, or `inputSchema` is non-literal at any registration site?</item>
    <item>Did you confirm the approval logic doesn't read the description / name as a trust signal?</item>
    <item>Did you check whether the tool catalog can be mutated post-init by an external trigger?</item>
    <item>(Client side) Did you check the `tools/list` handler for TOFU pinning / description change-detection (line jumping, T1)?</item>
    <item>Did you check whether descriptions / tool results reaching both the user and the model are ANSI-sanitized (T3)?</item>
  </verify>

  <!--
    T1 (line jumping) and T3 (ANSI deception) are published ToB disclosures;
    full context + provenance + reference mitigation (mcp-context-protector)
    in skills/knowledge/tob-mcp-agent-attack-catalog.md.
  -->

</policy>
```
