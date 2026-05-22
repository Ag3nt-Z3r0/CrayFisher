```xml
<policy type="cmdi">

  <reportable>
    <condition id="shell-true-with-input">
      A string containing user input is passed to subprocess.run(..., shell=True)
      or os.system().
      Verify: read the code to confirm shell=True is set and that the
      argument string contains a user-controlled variable.
    </condition>
    <condition id="string-exec">
      User input is passed to eval(), exec(), new Function(), or
      vm.runInContext().
      Verify: read the call site and trace the origin of the argument.
    </condition>
    <condition id="template-exec">
      User input is interpolated into a string that composes a shell command.
      Verify: read the code for patterns like `git clone ${userUrl}` or
      f"convert {user_file}".
    </condition>
  </reportable>

  <not_reportable>
    <condition id="list-args-no-shell" reason="no shell interpretation">
      subprocess.run([cmd, arg1, arg2]) form — list arguments with
      shell=False (the default). Shell metacharacters are not interpreted,
      so command injection is not possible.
      Verify: read the code to confirm the argument is a list literal and
      that shell is absent or False.
    </condition>
    <condition id="fixed-command" reason="not attacker-controlled">
      The entire command is hardcoded and no user input is passed as an
      argument.
    </condition>
    <condition id="whitelist-command" reason="whitelist validated">
      The command runs only when user input matches an allowed list.
      Verify: read the whitelist code and check for bypasses (case,
      whitespace, paths, etc.). If bypasses are demonstrably impossible
      from the code, it is FP.
    </condition>
    <condition id="admin-only" reason="inside trust model">
      Feature reachable only by superusers / server administrators.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you read the code to confirm shell=True or a string-argument form is used?</item>
    <item>Did you trace the path by which user input becomes part of the command string?</item>
    <item>If the input passes through an escape/sanitize function, did you read that function's body?</item>
    <item>Did you check whether the argument is coerced to a numeric/boolean type?</item>
  </verify>

</policy>
```
