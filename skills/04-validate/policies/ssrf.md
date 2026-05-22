```xml
<policy type="ssrf">

  <reportable>
    <condition id="user-controlled-url">
      User input becomes the URL argument to fetch(), requests.get(),
      axios(), etc.
      Verify: read the URL-construction code and confirm a user variable
      reaches the host/path portion.
    </condition>
    <condition id="internal-reachable">
      Requests can reach internal services (AWS metadata, internal API
      servers, DB ports, etc.).
      Verify: read the whole function and confirm there is no scheme/host
      restriction.
    </condition>
    <condition id="credential-forwarded">
      Auth tokens or cookies are forwarded along with the outbound
      request. (Credential theft becomes possible — raises impact.)
    </condition>
  </reportable>

  <not_reportable>
    <condition id="scheme-host-whitelist" reason="URL whitelist">
      The URL is validated against an allowed host list or regex.
      Verify: read the whitelist code and check for bypasses (DNS
      rebinding, URL-parser inconsistencies).
    </condition>
    <condition id="path-only" reason="host not controllable">
      User input only controls the path of a fixed host.
      Verify: code is of the form `URL = HARDCODED_HOST + userPath`;
      read the HARDCODED_HOST value in code.
    </condition>
    <condition id="localhost-only" reason="bounded impact">
      The only reachable destination is 127.0.0.1/localhost itself.
      Verify: confirm in code that the server only calls itself and
      cannot reach external services.
    </condition>
    <condition id="dns-resolved-before" reason="DNS-rebinding mitigated">
      The URL is DNS-resolved and the resulting IP is validated, with
      RFC1918 ranges blocked.
      Verify: read the resolved-IP check code.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you read the code where user input controls the host portion of the URL?</item>
    <item>Did you confirm in code that there is a URL-scheme restriction (https only, etc.)?</item>
    <item>Is the response body returned to the user? (Blind SSRF vs. response reflection.)</item>
    <item>Did you check reachability to internal AWS metadata (169.254.169.254) or internal API servers?</item>
  </verify>

</policy>
```
