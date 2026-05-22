```xml
<policy type="dos">

  <reportable>
    <condition id="unauth-reachable">
      인증 없이 접근 가능한 엔드포인트에서 발생한다.
      확인: 미들웨어/guard 체인을 코드로 읽어 인증 없이 도달 가능함을 확인.
    </condition>
    <condition id="single-request">
      단일 요청 또는 극소수 요청으로 서비스 전체에 영향을 줄 수 있다.
      확인: 입력 크기 vs 처리 복잡도를 코드로 확인 (O(n²) 이상).
    </condition>
    <condition id="redos-proven">
      사용자 입력으로 생성된 정규식에 catastrophic backtracking 구조가 있다.
      확인: 정규식 패턴을 코드에서 읽고, (a+)+ / (a|a)+ / (\w+)+ 류 중첩 수량자가
      사용자 입력으로 구성됨을 확인. "사용자 입력이 regex에 들어간다"는 불충분.
    </condition>
    <condition id="unbounded-alloc">
      사용자 입력 값이 그대로 메모리 할당 크기 또는 루프 횟수가 된다.
      확인: Buffer.alloc(userInput), new Array(userInput) 등 직접 확인.
      상한 검사(if n > MAX) 없음을 해당 함수 전체를 읽어 확인.
    </condition>
    <condition id="bomb">
      Zip/XML Bomb: 압축 해제 또는 엔티티 확장 크기 제한이 코드에 없다.
      확인: extractall() / fromstring() 전후 크기 제한 코드 없음을 확인.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="auth-required" reason="신뢰 모델 내부">
      트리거하려면 인증된 사용자 계정이 필요하다.
    </condition>
    <condition id="admin-only" reason="신뢰 모델 내부">
      staff / superuser / admin 권한이 있어야 도달 가능.
    </condition>
    <condition id="intended-slowness" reason="의도된 설계">
      비밀번호 해싱(PBKDF2, bcrypt, argon2)이 느린 것.
    </condition>
    <condition id="single-session" reason="영향 제한">
      공격자 자신의 세션/프로세스만 영향 — 서비스 전체 중단 아님.
    </condition>
    <condition id="non-default-config" reason="설정 의존">
      기본 설정에서 비활성화된 기능에서만 발생.
    </condition>
    <condition id="linear-complexity" reason="정상 동작">
      O(n) 복잡도이고 n의 상한이 합리적으로 제한됨.
    </condition>
  </not_reportable>

  <verify>
    <item>공격자가 직접 제어하는 입력이 문제 패턴에 도달하는 경로를 추적했는가?</item>
    <item>ReDoS라면: 해당 정규식 패턴 문자열을 코드에서 직접 읽었는가?</item>
    <item>메모리/루프라면: 상한 검사 코드가 없음을 함수 전체 읽기로 확인했는가?</item>
    <item>서버 전체 영향인가, 단일 워커/프로세스인가?</item>
  </verify>

</policy>
```
