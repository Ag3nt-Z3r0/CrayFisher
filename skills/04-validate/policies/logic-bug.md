```xml
<policy type="logic-bug">

  <reportable>
    <condition id="race-condition-toctou">
      Between a check on a file, DB record, or shared state and its
      subsequent use, another request can mutate that state.
      Verify: read the code to confirm no atomic operation (DB
      transaction, lock, SELECT FOR UPDATE) exists between the check and
      the use.
    </condition>
    <condition id="negative-balance-bypass">
      A balance, quantity, counter, or similar numeric value can be
      debited or transferred without a lower-bound check.
      Verify: read the whole function and confirm there is no
      `>= 0` or `>= amount` check before the decrement.
    </condition>
    <condition id="state-machine-skip">
      A state can be transitioned to directly, without code enforcing the
      ordering (order → payment → shipping).
      Verify: read the state-update handler and confirm it does not
      validate the previous state.
    </condition>
    <condition id="signature-bypass">
      Signature/token verification is skipped on some code paths.
      Verify: read the code to confirm every branch (if/else/exception
      handler) performs verification. Pay attention to exception handlers
      that might bypass verification.
    </condition>
    <condition id="insecure-direct-reference">
      A user-supplied object type/class name is instantiated directly
      from code. (Includes Mass Assignment / Prototype Pollution.)
      Verify: read code for patterns like `new req.body.type()` or
      `obj[userKey] = value`.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="atomic-operation" reason="concurrency protected">
      A DB transaction, SELECT FOR UPDATE, or atomic CAS operation
      prevents the race.
      Verify: read the transaction/lock code to confirm the check-then-use
      pair is one atomic operation.
    </condition>
    <condition id="server-controlled-state" reason="server-only control">
      The state value in question is set only by the server, with no
      client input.
      Verify: trace the state-set code back to the source and confirm no
      client input is involved.
    </condition>
    <condition id="idempotent-safe" reason="idempotent design">
      An idempotent operation that produces the same result when repeated.
      Verify: read the code (UPSERT, IF NOT EXISTS, etc.) that guarantees
      the same outcome on repeated calls.
    </condition>
    <condition id="trusted-internal-caller" reason="trusted caller">
      The affected function is not externally exposed and is called only
      by internal server code.
      Verify: review the entry-point list and use grep to confirm the
      function is not wired into any external HTTP handler.
    </condition>
  </not_reportable>

  <verify>
    <item>For race conditions: can two requests actually run concurrently in this environment? (Check whether it is single-process.)</item>
    <item>For logic bypass: did you read every execution path (including exception handlers) in code?</item>
    <item>Can the attacker actually trigger the state transition or numeric manipulation via a real request?</item>
    <item>Did you trace back to the source to confirm whether the value is set server-side or supplied by the client?</item>
  </verify>

</policy>
```
