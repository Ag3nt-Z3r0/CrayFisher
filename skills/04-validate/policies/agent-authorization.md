```xml
<policy type="agent-authorization">

  <!--
    Agent authorization / scope self-escalation.
    Largest CWE in Agent-Zero-DB corpus: CWE-863 (87 advisories) plus
    CWE-284/285 (40 combined) and CWE-269 (19). 9 of the 13 Critical
    advisories in OpenClaw are this pattern.
    Empirical priority weight: P0. Critical-13 subclass.
  -->

  <reportable>
    <condition id="scope-promotion-without-recheck">
      The agent's session holds a hierarchical scope (e.g., `read` <
      `write` < `admin`, or `operator.pairing` < `operator.admin`), and
      at least one code path lets a session with a lower scope reach an
      endpoint or action that requires a higher scope without an explicit
      re-check.
      Verify: enumerate the scope tiers from the constant definition or
      type. For each tier transition the schema permits, locate the
      enforcement point. Confirm at least one transition has no enforcement.
    </condition>
    <condition id="subagent-inherits-orchestrator-privilege">
      A subagent (Worker, Task, sub-Crew) inherits the orchestrator's
      tool set / scope, but the input that decides what the subagent
      can do is partly attacker-controllable.
      Verify: locate the subagent spawning site; check the tools/scope
      arguments. Trace whether any is influenced by tool output / user
      input.
    </condition>
    <condition id="reconnect-mints-higher-scope">
      A reconnect / re-pair / refresh endpoint issues a token whose scope
      exceeds the requesting session's current scope.
      Verify: read the reconnect handler. Confirm it does not clamp the
      issued scope to the requester's current scope.
    </condition>
    <condition id="scope-encoded-in-untrusted-channel">
      Scope is encoded in a value the attacker can write (a query param,
      header, cookie, or token field that isn't integrity-protected) and
      is honored without server-side verification.
      Verify: read the auth middleware. Confirm the scope value is
      verified against a server-side state, not just decoded from the
      token bytes.
    </condition>
    <condition id="pairing-token-mints-admin">
      A token issued by a pairing / device-enroll flow grants more
      privilege than the scope intended for that flow (e.g., a pairing
      token can be used to call admin endpoints).
      Verify: read the pairing-token mint site; trace which scopes the
      issued token carries; compare to admin-endpoint expectations.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="centralized-clamp" reason="single point of enforcement">
      Every privileged endpoint goes through a single middleware that
      reads scope from a server-side session and enforces it.
      Verify: read the middleware. Confirm every privileged route uses
      it (grep route table for opt-outs).
    </condition>
    <condition id="scope-statically-bound" reason="no dynamic promotion">
      Scope is bound to session creation and is not mutable afterward.
      Reconnect / refresh re-derives scope from the original auth, not
      from the current session.
      Verify: read the session lifecycle; confirm scope mutation API
      is absent or properly gated.
    </condition>
    <condition id="documented-promotion" reason="intended capability">
      The scope promotion is documented as intended behavior and the
      operator has opted into it (e.g., admin explicitly elevates a
      session via an out-of-band action).
      Verify: confirm the operator-side action is required and the
      attacker has no path to trigger it.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you enumerate every scope tier from the source-of-truth declaration?</item>
    <item>Did you read every privileged endpoint and confirm it enforces scope through the centralized middleware?</item>
    <item>Did you check reconnect / refresh / pairing endpoints for scope-widening behavior?</item>
    <item>Did you verify that subagent / sub-task spawning does not inherit a broader scope than its task requires?</item>
  </verify>

</policy>
```
