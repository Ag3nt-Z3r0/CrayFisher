```xml
<policy type="sqli">

  <reportable>
    <condition id="raw-concat">
      User input is directly interpolated/concatenated into a SQL string.
      Verify: directly read the code where a user variable is inserted
      into the query string via `"SELECT ... WHERE id=" + userId` or an
      f-string/template literal.
    </condition>
    <condition id="raw-execute">
      A string containing user input is passed to cursor.execute(),
      db.query(), knex.raw(), etc. without placeholders.
      Verify: read the call and confirm the argument is built via string
      interpolation.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="parameterized" reason="placeholders used">
      Placeholders such as ?, $1, :name, @param are used.
      Verify: read the code for the form
      `cursor.execute(sql, [userInput])`. All default query builders of
      ORMs (SQLAlchemy, Django ORM, Prisma, TypeORM) qualify.
    </condition>
    <condition id="orm-default" reason="ORM auto-parameterized">
      Only the ORM's default find/filter/where methods are used.
      Verify: code uses `.filter(id=userId)` or
      `.where({ id: userId })` form — no raw().
    </condition>
    <condition id="read-only" reason="bounded impact">
      Only SELECT is reachable; no INSERT/UPDATE/DELETE path exists.
      Note: SELECT can still be reportable if it enables data
      exfiltration.
    </condition>
    <condition id="fixed-structure" reason="not attacker-controlled">
      Table and column names are fixed; only the value is user-supplied,
      and placeholders are used for it.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you directly read the line of code where string interpolation occurs?</item>
    <item>Did you read into the function to confirm it actually executes a DB query, rather than being a wrapper?</item>
    <item>Did you check whether ORM raw() or literal() is used?</item>
    <item>Is the input coerced to a type (parseInt, etc.) before it reaches the SQL context?</item>
  </verify>

</policy>
```
