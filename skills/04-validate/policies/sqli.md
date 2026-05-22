```xml
<policy type="sqli">

  <reportable>
    <condition id="raw-concat">
      사용자 입력이 SQL 문자열에 직접 보간/연결된다.
      확인: `"SELECT ... WHERE id=" + userId` 또는 f-string/template literal 형태로
      사용자 변수가 쿼리 문자열에 삽입되는 것을 코드에서 직접 읽음.
    </condition>
    <condition id="raw-execute">
      cursor.execute(), db.query(), knex.raw() 등에 플레이스홀더 없이
      사용자 입력이 포함된 문자열이 전달된다.
      확인: 해당 호출 코드를 읽고 인자가 문자열 보간임을 확인.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="parameterized" reason="플레이스홀더 사용">
      ?, $1, :name, @param 플레이스홀더를 사용한다.
      확인: cursor.execute(sql, [userInput]) 형태를 코드에서 읽음.
      ORM(SQLAlchemy, Django ORM, Prisma, TypeORM)의 기본 쿼리 빌더는 모두 해당.
    </condition>
    <condition id="orm-default" reason="ORM 자동 파라미터화">
      ORM의 기본 find/filter/where 메서드만 사용된다.
      확인: .filter(id=userId), .where({ id: userId }) 형태 — raw() 없음.
    </condition>
    <condition id="read-only" reason="영향 제한">
      SELECT만 가능하고 INSERT/UPDATE/DELETE 경로가 없다.
      단, SELECT도 데이터 유출이 가능하면 보고 가능.
    </condition>
    <condition id="fixed-structure" reason="공격자 제어 불가">
      테이블명·컬럼명이 고정이고 값(value)만 사용자 입력인데 플레이스홀더를 사용.
    </condition>
  </not_reportable>

  <verify>
    <item>문자열 보간이 발생하는 코드 줄을 직접 읽었는가?</item>
    <item>해당 함수가 실제로 DB 쿼리를 실행하는지, 래퍼 함수인지 내부까지 읽었는가?</item>
    <item>ORM raw() 또는 literal() 사용 여부를 확인했는가?</item>
    <item>입력 값이 SQL 컨텍스트에 도달하기 전에 타입 변환(parseInt 등)이 있는가?</item>
  </verify>

</policy>
```
