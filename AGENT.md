# AGENT.md — Security-team feedback and rejection-reason log

## Purpose

Whenever a real security team (Django Security Team, HackerOne triager,
GHSA reviewer, etc.) rejects a report, the reason is recorded here in a
`<tip>` block.

**Update rules:**

- A rejection becomes a new `<tip>`.
- If the rejection matches an existing `<tip>`, bump `<count>`.
- If a skill file needs an update because of the lesson, record it in
  `<skill_update>` with the file name and what to change.

The agent reads this file before writing any report and checks whether
the candidate matches an existing rejection pattern.

---

```xml
<tips>

  <!-- ══════════════════════════════════════════════════════════
       DoS-related rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="dos-auth-required" category="dos" source="django-security-team" count="1">
    <reject_reason>
      DoS triggerable only by authenticated users is not a security
      vulnerability.
    </reject_reason>
    <detail>
      In the Django trust model an authenticated user is an in-scope
      actor. Resource exhaustion reachable only from a logged-in view is
      "abuse by a trusted user" and is treated as an operational issue,
      not a security bug.
    </detail>
    <lesson>
      Read auth middleware / decorators (@login_required, JWTGuard, etc.)
      and confirm the entry point is reachable without authentication.
      Skip otherwise.
    </lesson>
    <skill_update>skills/04-validate/criteria-gate.md — policy not_reportable auth-required</skill_update>
  </tip>

  <tip id="dos-admin-only" category="dos" source="django-security-team" count="1">
    <reject_reason>
      DoS reachable only by staff / superuser accounts is rejected.
    </reject_reason>
    <detail>
      Django admin is operator-only. Any DoS on /admin/ is classified as
      "admin abuse" and rejected.
    </detail>
    <lesson>
      If the entry point sits behind /admin/, @staff_member_required, or
      permission_classes=[IsAdminUser], do not file a DoS report.
    </lesson>
  </tip>

  <tip id="dos-intended-slow" category="dos" source="django-security-team" count="1">
    <reject_reason>
      Slow password hashing (PBKDF2, bcrypt, argon2) is intentional
      security design.
    </reject_reason>
    <detail>
      "Looping requests at login slows the server" is a missing
      rate-limit issue, not a flaw in the hashing function.
    </detail>
    <lesson>
      Do not flag password hash functions as sinks. Missing rate limiting
      on login is a separate (config) category.
    </lesson>
  </tip>

  <tip id="dos-redos-no-proof" category="dos" source="django-security-team" count="1">
    <reject_reason>
      "User input enters a regex" alone is not a ReDoS report. You must
      prove catastrophic backtracking actually occurs.
    </reject_reason>
    <detail>
      `re.compile(user_input)` or `new RegExp(userInput)` is not by
      itself a ReDoS. The pattern the user supplies must actually form
      a catastrophic structure like `(a+)+`, `(a|a)+`, `(\w|\w)+`. A
      simple string-search regex does not qualify.
    </detail>
    <lesson>
      Before reporting:
        1. Is the user input the regex *pattern* (not the searched string)?
        2. Can the user nest quantifiers in the pattern?
        3. Can you construct an input that exhibits exponential time?
      If you cannot reach step 3, do not file.
    </lesson>
    <skill_update>skills/04-validate/criteria-gate.md — policy reportable redos-proven</skill_update>
  </tip>

  <tip id="dos-linear-ok" category="dos" source="django-security-team" count="1">
    <reject_reason>
      O(n) with a reasonable upper bound on n is rejected.
    </reject_reason>
    <detail>
      MAX_CONTENT_LENGTH, max_length, etc. cap input size; linear time
      under that cap is bounded impact.
    </detail>
    <lesson>
      For memory / CPU concerns, locate the bound-checking code. Also
      read settings.py / .env for global caps.
    </lesson>
  </tip>

  <tip id="dos-xml-documented" category="dos" source="django-security-team" count="1">
    <reject_reason>
      XML Billion Laughs / Quadratic blowup is addressed by recommending
      defusedxml; pointing at the stdlib alone may be rejected.
    </reject_reason>
    <detail>
      Python's xml.etree.ElementTree XML-bomb behavior is a documented
      limitation. Filing it standalone may be closed as "documented
      design limitation".
    </detail>
    <lesson>
      When XML parsing is found: check for defusedxml or size limits. If
      missing, fold into the remediation section instead of opening a
      separate report.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Logic-bug / configuration rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="logic-trusted-input" category="logic" source="django-security-team" count="1">
    <reject_reason>
      "Attacker controls the database / filesystem" is not an accepted
      precondition.
    </reject_reason>
    <detail>
      "If the attacker writes malicious data to the DB then…" already
      assumes DB access, which subsumes the bug. Not accepted.
    </detail>
    <lesson>
      Attack scenarios may only assume control over HTTP requests or
      other public interfaces.
    </lesson>
  </tip>

  <tip id="logic-settings-misconfigured" category="logic" source="django-security-team" count="1">
    <reject_reason>
      Obvious deployer mistakes (DEBUG=True in prod, ALLOWED_HOSTS=["*"],
      default SECRET_KEY) are deployment errors, not framework vulns.
    </reject_reason>
    <detail>
      These are documented warnings in Django; reports about them are
      rejected as misconfiguration.
    </detail>
    <lesson>
      File findings from settings.py only as security-hardening
      recommendations, not CVE reports.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       SQLi rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="sqli-orm-default" category="sqli" source="general" count="1">
    <reject_reason>
      Default ORM methods (.filter(), .where(), .findOne()) are
      auto-parameterized and rejected.
    </reject_reason>
    <detail>
      Django ORM, SQLAlchemy, Prisma, TypeORM, etc. generate
      parameterized queries internally. `.filter(name=user_input)` is
      not SQL Injection.
    </detail>
    <lesson>
      For ORM calls, confirm whether raw(), execute(), RawSQL() or similar
      *raw* methods are involved. `.filter()` with `user_input` alone is
      not reportable.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       SSRF rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="ssrf-path-only" category="ssrf" source="general" count="1">
    <reject_reason>
      User-controlled path under a fixed host is rejected as SSRF.
    </reject_reason>
    <detail>
      URL = "https://api.example.com/" + userInput cannot reach internal
      hosts. Path traversal is a separate category.
    </detail>
    <lesson>
      Before filing SSRF, confirm the URL's *host* is attacker-
      controlled in code. Hardcoded host = not SSRF.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       XSS rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="xss-auto-escape" category="xss" source="general" count="1">
    <reject_reason>
      Auto-escaping renderers (Django templates, Jinja2, React JSX) make
      XSS reports invalid.
    </reject_reason>
    <detail>
      `{{ variable }}` (Django), `{variable}` (React) auto-escape. Without
      `|safe`, `dangerouslySetInnerHTML`, `mark_safe()`, etc., there is no
      XSS.
    </detail>
    <lesson>
      Find an auto-escape-disabling marker in the same code path before
      filing.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Auth / IDOR rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="auth-public-resource" category="auth" source="general" count="1">
    <reject_reason>
      IDOR against a resource intended to be public is rejected.
    </reject_reason>
    <detail>
      Public profiles, public posts, public APIs are designed for
      anyone to read. Filing IDOR on them returns "intended design".
    </detail>
    <lesson>
      Before filing IDOR: confirm the resource contains sensitive data
      and access is auth-gated by design.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       CORS rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="cors-no-credentials" category="cors" source="general" count="1">
    <reject_reason>
      Missing or false `Access-Control-Allow-Credentials` rejects CORS
      reports.
    </reject_reason>
    <detail>
      Without credentials, browsers do not send cookies / tokens on
      cross-origin requests. Wildcard origin + credentials=false is not
      exploitable.
    </detail>
    <lesson>
      Always read the credentials header configuration before filing.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Crypto rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="crypto-non-security-hash" category="crypto" source="general" count="1">
    <reject_reason>
      MD5/SHA1 used for cache keys / dedup / file integrity is rejected.
    </reject_reason>
    <detail>
      Not every MD5 is a vuln. Only security uses (signing, auth, HMAC)
      qualify. Filename hashing, cache keys, ETags do not.
    </detail>
    <lesson>
      Trace the hash result to its consumer in code before filing.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Prompt Injection rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="prompt-display-only" category="prompt-injection" source="general" count="1">
    <reject_reason>
      LLM response that is only rendered to the user (no system action)
      is rejected.
    </reject_reason>
    <detail>
      Prompt-injection severity requires the LLM output to drive an
      action. Pure UI rendering may have social-engineering value but
      no direct system impact.
    </detail>
    <lesson>
      Trace the LLM-response variable's next destination. If it doesn't
      reach exec / eval / DB write / API call, lower the report severity.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Deserialization rejections
       ══════════════════════════════════════════════════════════ -->

  <tip id="deser-safe-format" category="deserialization" source="general" count="1">
    <reject_reason>
      JSON parsing cannot execute code; deserialization reports on it
      are rejected.
    </reject_reason>
    <detail>
      `json.loads()`, `JSON.parse()` only parse data. The dangerous
      formats are pickle, yaml.load (unsafe), PHP unserialize, Java
      ObjectInputStream, etc.
    </detail>
    <lesson>
      Read the parser function name in code. JSON = do not file.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       AI Agent rejections (seeded from Agent-Zero-DB corpus)
       ══════════════════════════════════════════════════════════ -->

  <tip id="mcp-display-only" category="mcp-tool-poisoning" source="general" count="1">
    <reject_reason>
      A non-literal tool description / name with no path into an LLM
      catalog that any client actually consumes is rejected.
    </reject_reason>
    <detail>
      Tool poisoning requires that the poisoned metadata reaches an LLM
      via a client that actually advertises the tool. A server that
      defines tools but is never connected to a live client by default
      is not exploitable.
    </detail>
    <lesson>
      Trace tool registration to a default-running server transport
      (StdioServerTransport, sse, websocket). If the server isn't
      actually exposed in the default flow, do not file.
    </lesson>
  </tip>

  <tip id="tool-poisoning-needs-execution-path" category="mcp-tool-poisoning" source="general" count="1">
    <reject_reason>
      Tool metadata injection without a path into an LLM call that
      consumes that metadata is rejected.
    </reject_reason>
    <detail>
      The metadata must be assembled into a prompt the LLM sees. If the
      catalog is built but never serialized into a real LLM request, the
      surface doesn't exist.
    </detail>
    <lesson>
      Locate the prompt-assembly site that consumes the tool catalog.
      Confirm it actually executes in the default flow.
    </lesson>
  </tip>

  <tip id="excessive-agency-needs-irreversible-sink" category="excessive-agency" source="general" count="1">
    <reject_reason>
      `autoApprove = true` / `DEFAULT_ASK = off` alone, without a reachable
      irreversible action sink, is rejected.
    </reject_reason>
    <detail>
      Excessive Agency requires both the permissive default *and* a
      tool that does something irreversible (file delete, FS write
      outside workspace, network egress to attacker-controlled host,
      payment, deploy, git push).
    </detail>
    <lesson>
      List every tool exposed in the default catalog. Read each tool's
      body. Do not file unless at least one is irreversible and reachable
      under the permissive default.
    </lesson>
  </tip>

  <tip id="incomplete-fix-no-adjacent-evidence" category="incomplete-fix" source="general" count="1">
    <reject_reason>
      "This looks like an incomplete fix" without a concrete prior
      advisory citation is rejected.
    </reject_reason>
    <detail>
      Patterns A–E require a prior CVE / GHSA / commit pointer. Without
      it, the finding is speculation, not an incomplete-fix report.
    </detail>
    <lesson>
      Use `tools/incomplete_fix_scan.py` to anchor the prior advisory.
      If none exists, file the finding (if real) under its own vuln
      class, not as an incomplete fix.
    </lesson>
  </tip>

  <tip id="agent-authz-documented-elevation" category="agent-authorization" source="general" count="1">
    <reject_reason>
      Scope promotion that the documentation explicitly describes and
      that requires an operator-side action is rejected.
    </reject_reason>
    <detail>
      e.g., an admin runs a documented "promote-to-admin" CLI on a
      specific session. Not a vulnerability if the attacker can't trigger
      the action.
    </detail>
    <lesson>
      For every promotion path, find the documented trigger. Confirm the
      attacker has no remote path to it.
    </lesson>
  </tip>

  <tip id="context-window-attack-theoretical" category="context-window-attack" source="general" count="1">
    <reject_reason>
      "External content can be large" without a concrete demonstration
      that the system prompt is evicted is rejected.
    </reject_reason>
    <detail>
      You must produce or trace an input that would cause the leading
      system message to drop out of the model's effective window. Pure
      size concerns are not enough.
    </detail>
    <lesson>
      Build the input. Show the truncation policy and the byte budget.
      If you cannot demonstrate eviction, file only as a hardening
      recommendation.
    </lesson>
  </tip>

  <tip id="sandbox-no-claim" category="sandbox-escape" source="general" count="1">
    <reject_reason>
      Reports of "sandbox escape" against a product that does not claim
      sandboxing are rejected.
    </reject_reason>
    <detail>
      If the product runs tools on the host by design (and says so), the
      relevant class is excessive-agency, not sandbox-escape.
    </detail>
    <lesson>
      Confirm the product README / docs claim sandboxing before filing
      under sandbox-escape. Otherwise refile as excessive-agency.
    </lesson>
  </tip>

  <tip id="tool-arg-validated-by-schema" category="tool-result-injection" source="general" count="1">
    <reject_reason>
      Tool argument that flows through a strict schema validator before
      sink is rejected as injection.
    </reject_reason>
    <detail>
      A strict schema (Pydantic, Zod, JSON Schema with
      `additionalProperties: false` and narrow types) breaks the
      attacker's ability to smuggle structured payloads.
    </detail>
    <lesson>
      Read the schema definition. Confirm `additionalProperties: false`
      and that every property has a narrow type (not `Any` / `string`
      where structure was intended).
    </lesson>
  </tip>

  <tip id="subagent-output-schema-parsed" category="tool-result-injection" source="general" count="1">
    <reject_reason>
      Subagent output parsed through a strict schema before re-injection
      into the parent prompt is rejected.
    </reject_reason>
    <detail>
      Schema-validated values are typed and bounded; they no longer
      carry attacker-controlled instructions.
    </detail>
    <lesson>
      Show the schema and the parse step. If both are strict, the
      promotion path is broken.
    </lesson>
  </tip>

  <tip id="memory-poisoning-no-readback" category="memory-poisoning" source="general" count="1">
    <reject_reason>
      Memory write whose contents nothing reads back is rejected.
    </reject_reason>
    <detail>
      A poisoned memory entry only matters if a subsequent LLM call
      retrieves it. If the memory store is write-only in practice, the
      attack has no effect.
    </detail>
    <lesson>
      Trace memory reads. Confirm that the poisoned entry can be reached
      by a real retrieval path used in the default flow.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Template for new rejection reasons
       ══════════════════════════════════════════════════════════
  <tip id="<unique-id>" category="<dos|sqli|xss|logic|auth|mcp-tool-poisoning|excessive-agency|...>" source="<security-team-name>" count="1">
    <reject_reason>One-line summary</reject_reason>
    <detail>Longer description</detail>
    <lesson>What to check next time</lesson>
    <skill_update>Skill file and change (optional)</skill_update>
  </tip>
       ══════════════════════════════════════════════════════════ -->

</tips>
```
