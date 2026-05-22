```xml
<policy type="dos">

  <reportable>
    <condition id="unauth-reachable">
      The issue occurs on an endpoint reachable without authentication.
      Verify: read the middleware/guard chain and confirm the path is
      reachable without auth.
    </condition>
    <condition id="single-request">
      A single or very small number of requests can impact the entire
      service.
      Verify: read the code to compare input size against processing
      complexity (O(n²) or worse).
    </condition>
    <condition id="redos-proven">
      A regex constructed with user input contains catastrophic-backtracking
      structure.
      Verify: read the regex pattern in code and confirm a nested
      quantifier such as (a+)+ / (a|a)+ / (\w+)+ is built from user input.
      "User input goes into a regex" is not sufficient.
    </condition>
    <condition id="unbounded-alloc">
      A user input value is used directly as a memory-allocation size or
      a loop count.
      Verify: inspect calls like Buffer.alloc(userInput) or
      new Array(userInput) directly. Read the whole function and confirm
      no upper-bound check (if n > MAX) exists.
    </condition>
    <condition id="bomb">
      Zip/XML bomb: no code limits decompression or entity-expansion size.
      Verify: confirm no size-limit code exists before or after
      extractall() / fromstring().
    </condition>
  </reportable>

  <not_reportable>
    <condition id="auth-required" reason="inside trust model">
      Triggering it requires an authenticated user account.
    </condition>
    <condition id="admin-only" reason="inside trust model">
      Requires staff / superuser / admin privileges to reach.
    </condition>
    <condition id="intended-slowness" reason="intended design">
      Slow password hashing (PBKDF2, bcrypt, argon2) — slowness is by
      design.
    </condition>
    <condition id="single-session" reason="bounded impact">
      Only the attacker's own session/process is affected — not a
      service-wide outage.
    </condition>
    <condition id="non-default-config" reason="config-dependent">
      Only occurs in a feature that is disabled in the default
      configuration.
    </condition>
    <condition id="linear-complexity" reason="normal behavior">
      O(n) complexity with a reasonable upper bound on n.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you trace the path by which attacker-controlled input reaches the problematic pattern?</item>
    <item>For ReDoS: did you read the regex pattern string directly from the code?</item>
    <item>For memory/loop bounds: did you read the entire function to confirm there is no upper-bound check?</item>
    <item>Is the impact server-wide, or limited to a single worker/process?</item>
  </verify>

</policy>
```
