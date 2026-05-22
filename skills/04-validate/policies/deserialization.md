```xml
<policy type="deserialization">

  <reportable>
    <condition id="user-controlled-input">
      User-controlled data (request body, file upload, cookie, etc.) is
      passed directly to pickle.loads(), yaml.load(), unserialize(),
      ObjectInputStream, etc.
      Verify: read the arguments to the deserialization call and trace
      that argument back to confirm it originates from external input.
    </condition>
    <condition id="no-class-restriction">
      No code restricts the allowed classes/types after deserialization.
      Verify: read the surrounding function to confirm no whitelist-style
      type check (isinstance, allowedClasses, etc.) is present before or
      after the deserialization call.
    </condition>
    <condition id="magic-method-reachable">
      During deserialization, magic methods such as __reduce__, __wakeup,
      or readObject form a gadget chain that leads to arbitrary code
      execution.
      Verify: grep for dangerous magic-method implementations in the
      codebase or its dependencies.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="safe-format" reason="safe format">
      A format that cannot execute code is used, such as JSON, MessagePack,
      or Protocol Buffers.
      Verify: read the code to confirm the parsing function is
      json.loads(), JSON.parse(), etc. Additionally, confirm there is no
      eval() after json.loads.
    </condition>
    <condition id="yaml-safe-load" reason="safe loader">
      yaml.safe_load() or YAML::safe_load is used.
      Verify: read the YAML-loading call directly. yaml.load(input,
      Loader=yaml.SafeLoader) is also safe.
    </condition>
    <condition id="trusted-source-only" reason="trusted source">
      The deserialization input only comes from internal systems that an
      attacker cannot control (server-to-server RPC, internal cache).
      Verify: trace the data source back to confirm it is not external
      input.
    </condition>
    <condition id="class-whitelist" reason="whitelist enforced">
      Allowed classes during deserialization are explicitly whitelisted.
      Verify: read the restriction code, such as resolveClass(),
      allowedClasses, or RestrictedUnpickler.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you trace the argument of the deserialization call back to its source to confirm external input?</item>
    <item>For yaml.load(), did you read the Loader parameter in code? (omitting it is dangerous)</item>
    <item>Did you read the whole function to confirm there is no class/type restriction?</item>
    <item>Does an exploitable gadget chain actually exist in the codebase?</item>
  </verify>

</policy>
```
