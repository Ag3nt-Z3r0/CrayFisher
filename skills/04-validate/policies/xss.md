```xml
<policy type="xss">

  <reportable>
    <condition id="stored-xss">
      User input is stored in the DB and later rendered in another user's
      browser without escaping.
      Verify: read both the storage path and the rendering path in code.
      Confirm the rendering side performs no escape/sanitization.
    </condition>
    <condition id="dom-xss-unescaped">
      User input is assigned directly to innerHTML, document.write(), or
      dangerouslySetInnerHTML.
      Verify: read the assignment and trace the origin of the input.
    </condition>
    <condition id="template-unescaped">
      User input flows into a template engine's raw/unescaped output
      (`{{{ }}}` instead of `{{ }}`, `| safe`, etc.).
      Verify: read the relevant template code.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="auto-escape-template" reason="auto-escaped">
      Default output of Django templates, Jinja2, React JSX, and Vue
      templates is auto-escaped.
      Verify: read the template/component file and confirm no explicit
      bypass like `| safe`, `mark_safe()`, or `dangerouslySetInnerHTML`
      is used.
    </condition>
    <condition id="csp-present" reason="CSP defense">
      A Content-Security-Policy header strictly restricts script-src.
      Verify: read the middleware or response-header code and inspect
      the script-src value. If `unsafe-inline` is absent and nonces or
      hashes are used, FP is possible. CSP alone is not sufficient for
      a definitive FP — the code-level recommendation still stands.
    </condition>
    <condition id="non-html-response" reason="not rendered by browser">
      The response Content-Type is application/json, text/plain, or
      another non-HTML type.
      Verify: read the response-header code. Additionally consider
      whether the browser may sniff it as HTML (check
      X-Content-Type-Options).
    </condition>
    <condition id="self-xss-only" reason="bounded impact">
      Only the attacker's own session is affected (self-XSS) — does not
      reach other users' browsers.
      Verify: input is not stored and is returned only as reflected XSS,
      and there is no CSRF-token-less path that lets another user trigger
      the response.
    </condition>
  </not_reportable>

  <verify>
    <item>For stored XSS: did you read both the storage code and the rendering code?</item>
    <item>If input passes through an escape function, did you read inside that function?</item>
    <item>Did you confirm the rendered output actually reaches another user's browser?</item>
    <item>Even with HttpOnly cookies protecting the session, is another attack chain possible?</item>
  </verify>

</policy>
```
