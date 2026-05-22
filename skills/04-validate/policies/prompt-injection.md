```xml
<policy type="prompt-injection">

  <reportable>
    <condition id="external-content-in-prompt">
      Content fetched from an external source (web crawl, DB record, file,
      another API's response) is inserted into the messages array or
      input of an LLM API call.
      Verify: read the LLM API call site and confirm the external-content
      variable is included in messages.
    </condition>
    <condition id="tool-call-dangerous">
      A tool/function the LLM can invoke includes irreversible actions
      such as file delete, shell execution, or DB mutation.
      Verify: read the tool definition and confirm what action it performs.
    </condition>
    <condition id="llm-output-executed">
      The LLM response becomes, without validation, an argument to eval(),
      exec(), subprocess, or another API call.
      Verify: trace the destination of the response variable in code.
    </condition>
    <condition id="system-prompt-user-controlled">
      Part of the system prompt is composed from user input or external
      data.
      Verify: read the system-message construction code and check whether
      external variables are included.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="fixed-system-prompt" reason="fixed prompt">
      The system prompt is a fully hardcoded constant.
      Verify: read the system message in code and confirm it is a constant
      string. Note: if external content enters the user message, that
      must still be checked separately.
    </condition>
    <condition id="display-only-output" reason="output isolated">
      The LLM response is only displayed to the user and is never used in
      any system action.
      Verify: trace the response variable and confirm it never flows into
      code beyond rendering.
    </condition>
    <condition id="no-dangerous-tools" reason="no dangerous tools">
      Every tool the agent can call is read-only or fully reversible.
      Verify: read every tool definition and confirm what each one does.
    </condition>
    <condition id="sandboxed-execution" reason="sandboxed">
      LLM-output execution is isolated inside a sandbox (Docker, E2B,
      Firecracker).
      Verify: read the execution-environment configuration and confirm
      the level of isolation.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you directly read the code that inserts external content into LLM messages?</item>
    <item>Is there code that separates the system prompt from the user message?</item>
    <item>Did you confirm in code what every tool the LLM can call actually does?</item>
    <item>Did you trace the entire post-LLM processing pipeline of the response?</item>
  </verify>

</policy>
```
