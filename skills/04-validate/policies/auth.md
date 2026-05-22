```xml
<policy type="auth-bypass-idor">

  <reportable>
    <condition id="missing-ownership-check">
      리소스 ID가 URL/파라미터로 직접 전달되고, 해당 리소스가
      현재 인증된 사용자의 것인지 확인하는 코드가 없다.
      확인: 핸들러 코드 전체를 읽어 `WHERE id = ? AND user_id = ?` 형태 또는
      `resource.owner === currentUser` 형태의 소유권 검사가 없음을 확인.
    </condition>
    <condition id="auth-middleware-bypass">
      인증 미들웨어가 특정 경로 또는 메서드에 적용되지 않는다.
      확인: 라우터/미들웨어 설정 코드를 읽어 제외된 경로를 확인.
    </condition>
    <condition id="jwt-payload-trusted">
      JWT 서명 검증 없이 payload를 신뢰하거나, `none` 알고리즘을 허용한다.
      확인: JWT 검증 코드를 읽어 algorithm 파라미터와 서명 검증 로직을 확인.
    </condition>
    <condition id="privilege-escalation">
      일반 사용자가 role/permission 필드를 직접 수정하여 권한을 올릴 수 있다.
      확인: 사용자 업데이트 핸들러에서 role 필드 수정 가능 여부를 코드로 확인.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="public-resource" reason="의도된 공개">
      해당 리소스가 명시적으로 공개 접근을 허용하도록 설계되었다.
      확인: 설계 의도가 코드(주석, 라우트명, 권한 설정)에서 확인됨.
    </condition>
    <condition id="ownership-in-query" reason="소유권 검사 포함">
      DB 쿼리에서 user_id 조건이 항상 포함된다.
      확인: 쿼리 코드를 읽어 WHERE user_id = currentUser.id 형태를 확인.
    </condition>
    <condition id="sequential-but-authenticated" reason="예측 가능하나 인증 필요">
      ID가 순차적이지만 접근 자체에 인증이 필요하고,
      인증 후 소유권 검사도 있다.
    </condition>
    <condition id="admin-intentional" reason="의도된 관리자 기능">
      관리자가 모든 리소스에 접근 가능한 것이 의도된 기능이다.
      확인: 관리자 권한 확인 코드를 읽음.
    </condition>
  </not_reportable>

  <verify>
    <item>핸들러 코드 전체를 읽어 소유권 검사 코드가 없음을 확인했는가?</item>
    <item>인증 미들웨어가 이 라우트에 적용되는지 라우터 설정 코드를 읽었는가?</item>
    <item>다른 사용자의 리소스 ID를 실제로 대입할 수 있는 파라미터가 있는가?</item>
    <item>ORM scope / row-level security가 DB 레벨에서 적용되는가?</item>
  </verify>

</policy>
```
