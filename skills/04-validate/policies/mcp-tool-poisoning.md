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
  </verify>

</policy>
```
