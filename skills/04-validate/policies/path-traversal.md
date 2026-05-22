```xml
<policy type="path-traversal">

  <reportable>
    <condition id="unsanitized-join">
      User input is passed to path.join() or os.path.join() with no
      handling for `../` or absolute-path normalization.
      Verify: read the join call site and trace the origin of the
      user-input variable.
    </condition>
    <condition id="sensitive-path-reachable">
      The file read/write path can reach sensitive locations such as
      `/etc/`, `~/.ssh/`, `.env`, or the source-code directory.
      Verify: confirm whether root-relative traversal is possible by
      repeating `../`.
    </condition>
    <condition id="arbitrary-write">
      User input controls the path and enables arbitrary file write.
      (Higher severity than read — may lead to code execution.)
    </condition>
  </reportable>

  <not_reportable>
    <condition id="basename-only" reason="traversal not possible">
      os.path.basename() or path.basename() strips the directory portion.
      Verify: read the basename-handling code — the directory portion is
      removed before the subsequent join.
    </condition>
    <condition id="realpath-chroot" reason="path normalized">
      realpath() / resolve() is followed by an allowed-directory prefix
      check.
      Verify: read the code for the form
      `if (!resolved.startsWith(ALLOWED_DIR))`.
    </condition>
    <condition id="static-whitelist" reason="whitelist enforced">
      Filenames are selected only from an allowed list (e.g., serving
      static assets).
    </condition>
    <condition id="non-sensitive-dir" reason="bounded impact">
      The maximum reachable scope is confined to a public directory.
      Verify: confirm the serve root is fixed in code and cannot be
      escaped.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you read the code where input containing `../` is interpreted as an actual filesystem path?</item>
    <item>Did you read the entire function to confirm there is no path-normalization or prefix-check code?</item>
    <item>Did you confirm in code the highest directory that is reachable?</item>
  </verify>

</policy>
```
