```xml
<policy type="excessive-agency">

  <!--
    OWASP LLM06 — Excessive Agency.
    Single largest class in Agent-Zero-DB corpus (42.6%, 200/469 advisories).
    Definition: the agent is permitted to take an action whose
    consequence the operator did not intend, in the default configuration.

    Empirical priority weight: P0 (+0.10 confidence in judgment).
    Maps to CWE-250 (Execution with Unnecessary Privileges) + CWE-269.
  -->

  <reportable>
    <condition id="irreversible-sink-no-approval">
      The agent can reach an irreversible action sink (file delete, table
      drop, payment, push, deploy, network outbound to attacker-controlled
      host) without an explicit approval check in the default config.
      Verify: trace the tool's body from registration site to the sink.
      Confirm no `askBeforeRun` / `human_input_mode` / `permission_mode`
      gate exists, or the default value of that gate is permissive.
    </condition>
    <condition id="default-config-permissive">
      A user who installs the agent and runs it with no flags can trigger
      the irreversible action.
      Verify: read the constants file / default config file. The condition
      is satisfied when `DEFAULT_ASK="off"` or `autoApprove=true` or
      `human_input_mode="NEVER"` or `permission_mode="auto"` is the literal
      value in code, not just an option.
    </condition>
    <condition id="privilege-broader-than-task">
      The tool is granted access to broader OS / network / FS scope than
      its declared task requires (e.g., a "search the web" tool that can
      also write files).
      Verify: read the tool implementation. The condition is satisfied
      when the implementation calls APIs unrelated to the declared task.
    </condition>
    <condition id="silent-tool-chain-escalation">
      Tool A's output is fed unsanitized into Tool B, and the chain
      composed from low-trust input reaches an irreversible action.
      Verify: build the trust graph (`tools/agent_trust_graph.py`) and
      look for a path from a USER/TOOL node into an
      irreversible-sink-bearing tool.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="approval-required-by-default" reason="approval gate present">
      Default config requires explicit user approval before tool execution
      (e.g., `human_input_mode="ALWAYS"`, `permission_mode="prompt"`,
      `askBeforeRun: true`).
      Verify: read the default value at the constant declaration site.
    </condition>
    <condition id="all-tools-read-only" reason="no irreversible sink">
      Every tool exposed to the agent is read-only or fully reversible
      (e.g., HTTP GET, FS read, idempotent search).
      Verify: enumerate every tool registration in the registry; read
      each tool's body and confirm no write/exec/network-egress.
    </condition>
    <condition id="sandbox-clamps-impact" reason="sandboxed">
      All tool execution is contained inside a sandbox that cannot affect
      host state (e.g., Firecracker, e2b, gVisor; not bare Docker with
      host volume mounts).
      Verify: read the sandbox configuration. Confirm no host bind-mounts,
      no host socket, no host network.
    </condition>
    <condition id="action-undoable-and-bounded" reason="bounded blast radius">
      Action is undoable AND impact is bounded to a private workspace
      that the operator already owns (e.g., write inside `./workspace/`
      with a quota).
      Verify: read the write-path code and the quota/clamp enforcement.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you list every tool registered with the agent, and read each tool's body?</item>
    <item>Did you read the default value of the approval / permission knob, not just confirm the knob exists?</item>
    <item>Did you trace at least one path from a low-trust input to an irreversible sink, citing file:line at every hop?</item>
    <item>Did you check whether the sandbox boundary actually clamps the action, or whether the action escapes the sandbox by design (e.g., shared filesystem)?</item>
  </verify>

</policy>
```
