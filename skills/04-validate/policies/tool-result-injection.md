```xml
<policy type="tool-result-injection">

  <!--
    A3 from ai-agent-flows.md — tool output (a TOOL-layer artifact) is
    folded back into the next LLM turn without sanitization, allowing
    attacker-controlled tool output to inject instructions.
    Maps to CWE-1427 + OWASP LLM01. Distinct from generic prompt injection
    because the source is the tool layer, not the user turn.
  -->

  <reportable>
    <condition id="tool-output-pushed-as-tool-role">
      Tool output is appended to `messages` (or the framework equivalent)
      with role `tool` / `tool_result` / `toolResult`, then a new LLM
      call is made with this messages array.
      Verify: locate the messages-append site and trace the LLM call
      that immediately follows. Confirm no sanitization in between.
    </condition>
    <condition id="tool-output-pushed-as-user-role">
      Tool output is appended with role `user` (a common shortcut in
      manual ReAct loops), promoting external bytes into the user layer.
      Verify: same trace, look for `role: "user"` + tool-result variable.
    </condition>
    <condition id="external-fetch-result-as-tool-output">
      The tool body returns the raw response of an attacker-influenceable
      external call (HTTP fetch, marketplace download, web scrape, RSS).
      Verify: read the tool body to confirm the response is returned
      with no extraction / templating.
    </condition>
    <condition id="orchestrator-feeds-subagent-output-to-llm">
      A subagent's output is wrapped only with role `user` or `system`
      and re-injected into a parent agent's prompt.
      Verify: trace the parent prompt construction. Confirm subagent
      output is not stripped to a structured value (JSON parse + schema).
    </condition>
  </reportable>

  <not_reportable>
    <condition id="output-parsed-and-clamped" reason="structured parse">
      Tool output is parsed against a strict schema (JSON Schema /
      Pydantic / Zod) and only typed fields are passed forward.
      Verify: read the parse step, confirm the schema is strict (no
      `additionalProperties: true`, no `Any` types), confirm rejection
      on parse failure.
    </condition>
    <condition id="output-displayed-only" reason="not re-injected">
      Tool output is shown to the user but never re-added to the LLM
      conversation.
      Verify: trace the tool-result variable to its terminal destination
      and confirm it never reaches a `messages.append` / `messages.push`
      / `add_message` call.
    </condition>
    <condition id="tool-source-trusted" reason="output is operator-controlled">
      The tool body returns output whose bytes are fully under the
      operator's control (e.g., reads from a hardcoded local file, runs
      a deterministic compute on operator-supplied data).
      Verify: confirm no inbound from network/user/file-the-attacker-
      can-touch.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you locate the exact line where the tool result is added to messages, and the next LLM call that consumes those messages?</item>
    <item>Did you check whether the tool body itself touches any attacker-controllable byte source (network, untrusted file, sub-tool)?</item>
    <item>Did you confirm there's no schema parse / sanitizer between tool return and message append?</item>
    <item>For multi-agent setups, did you check whether subagent output is wrapped only by role, not by schema validation?</item>
  </verify>

</policy>
```
