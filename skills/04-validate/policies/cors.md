```xml
<policy type="cors">

  <reportable>
    <condition id="origin-reflected-with-credentials">
      The request's Origin header value is reflected into
      Access-Control-Allow-Origin, and Access-Control-Allow-Credentials: true
      is also set.
      Verify: read both header settings in the CORS configuration.
      Only this combination leads to actual credential theft.
    </condition>
    <condition id="wildcard-with-credentials">
      Access-Control-Allow-Origin: * and Credentials: true are set together.
      (Browsers block it, but the configuration itself is incorrect —
      record as low severity.)
    </condition>
    <condition id="null-origin-trusted">
      Code trusts an Origin: null value.
      Verify: read the null-origin handling code. Sandboxed iframe attacks
      become possible.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="credentials-false" reason="no credentials sent">
      The Access-Control-Allow-Credentials header is absent or false.
      Without credentials, a CORS misconfiguration cannot exfiltrate
      authenticated data.
      Verify: read the response-header configuration and check the
      Credentials header.
    </condition>
    <condition id="whitelist-origins" reason="fixed allowlist">
      ACAO is set only when Origin matches a fixed allowlist.
      Verify: read the allowlist code and confirm no dynamic reflection
      occurs.
    </condition>
    <condition id="non-sensitive-api" reason="no sensitive data">
      The endpoint returns only public data and requires no authentication.
      Even loose CORS leaves nothing sensitive to steal.
    </condition>
    <condition id="same-site-cookie" reason="cookie protected">
      The session cookie has SameSite=Strict or SameSite=Lax set.
      Verify: read the cookie configuration. This limits the practical
      impact of a CORS bug. Note: this condition does not apply when
      authentication uses Authorization headers instead of cookies.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you directly read the code that decides the ACAO header value?</item>
    <item>Did you read the code that sets the Credentials header?</item>
    <item>Did you confirm whether this API returns sensitive data only after authentication?</item>
    <item>If Origin reflection is present, did you check for bypasses that skip the allowlist check?</item>
  </verify>

</policy>
```
