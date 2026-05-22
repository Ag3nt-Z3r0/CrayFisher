```xml
<policy type="auth-bypass-idor">

  <reportable>
    <condition id="missing-ownership-check">
      A resource ID is passed directly via URL/parameter, and no code
      verifies that the resource belongs to the currently authenticated user.
      Verify: read the entire handler and confirm no ownership check of
      the form `WHERE id = ? AND user_id = ?` or
      `resource.owner === currentUser` is present.
    </condition>
    <condition id="auth-middleware-bypass">
      The auth middleware is not applied to a particular route or method.
      Verify: read the router/middleware configuration and identify the
      excluded paths.
    </condition>
    <condition id="jwt-payload-trusted">
      The JWT payload is trusted without signature verification, or the
      `none` algorithm is accepted.
      Verify: read the JWT verification code and check the algorithm
      parameter and signature-check logic.
    </condition>
    <condition id="privilege-escalation">
      A regular user can elevate their privileges by directly editing a
      role/permission field.
      Verify: read the user-update handler and confirm whether the role
      field is mutable.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="public-resource" reason="intended public access">
      The resource is explicitly designed to allow public access.
      Verify: design intent is evident in the code (comments, route name,
      permission configuration).
    </condition>
    <condition id="ownership-in-query" reason="ownership check enforced">
      The DB query always includes a user_id condition.
      Verify: read the query code and confirm the
      `WHERE user_id = currentUser.id` form.
    </condition>
    <condition id="sequential-but-authenticated" reason="predictable but auth required">
      IDs are sequential, but access itself requires authentication and
      an ownership check is also performed post-auth.
    </condition>
    <condition id="admin-intentional" reason="intended admin capability">
      Admin access to all resources is an intended feature.
      Verify: read the admin authorization check.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you read the entire handler and confirm no ownership check is present?</item>
    <item>Did you read the router configuration to confirm the auth middleware applies to this route?</item>
    <item>Is there a parameter into which you can actually substitute another user's resource ID?</item>
    <item>Is ORM scope / row-level security enforced at the DB layer?</item>
  </verify>

</policy>
```
