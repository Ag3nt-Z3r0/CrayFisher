```xml
<policy type="logic-bug">

  <reportable>
    <condition id="race-condition-toctou">
      파일, DB 레코드, 공유 상태를 확인(check)한 후 사용(use) 사이에
      다른 요청이 그 상태를 변경할 수 있다.
      확인: check와 use 사이에 atomic 연산(DB 트랜잭션, 락, SELECT FOR UPDATE)이
      없음을 코드에서 읽어 확인.
    </condition>
    <condition id="negative-balance-bypass">
      잔액, 수량, 카운터 등 수치 값의 하한 검사 없이 차감 또는 이전이 가능하다.
      확인: 차감 연산 전 `>= 0` 또는 `>= amount` 검사 코드 없음을 함수 전체에서 읽어 확인.
    </condition>
    <condition id="state-machine-skip">
      상태 전이 순서(order → payment → shipping)를 강제하는 코드 없이
      임의 상태로 직접 전이할 수 있다.
      확인: 상태 업데이트 핸들러에서 이전 상태 검증 코드 없음을 읽어 확인.
    </condition>
    <condition id="signature-bypass">
      서명/토큰 검증이 일부 코드 경로에서 건너뛰어진다.
      확인: 모든 분기(if/else/exception handler)에서 검증이 수행됨을 코드로 확인.
      예외 핸들러에서 검증을 우회하는 경로가 없는지 읽어야 함.
    </condition>
    <condition id="insecure-direct-reference">
      사용자가 공급한 객체 타입/클래스 이름을 코드에서 그대로 인스턴스화한다.
      (Mass Assignment / Prototype Pollution 포함)
      확인: `new req.body.type()`, `obj[userKey] = value` 등 코드를 읽어 확인.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="atomic-operation" reason="동시성 보호">
      DB 트랜잭션, SELECT FOR UPDATE, 원자적 CAS 연산으로 경쟁 조건이 방지된다.
      확인: 트랜잭션/락 코드를 읽어 check-then-use가 하나의 원자 연산임을 확인.
    </condition>
    <condition id="server-controlled-state" reason="서버 단독 제어">
      문제의 상태 값이 클라이언트 입력 없이 서버만 설정한다.
      확인: 상태 설정 코드에서 클라이언트 입력이 없음을 소스까지 추적.
    </condition>
    <condition id="idempotent-safe" reason="멱등 설계">
      중복 실행해도 결과가 동일한 멱등 연산이다.
      확인: 중복 호출 시 동일 결과를 보장하는 코드(UPSERT, IF NOT EXISTS 등)를 읽음.
    </condition>
    <condition id="trusted-internal-caller" reason="신뢰 호출자">
      문제 함수가 외부에 노출되지 않고 서버 내부 코드에서만 호출된다.
      확인: 진입점 목록을 확인하고, 해당 함수가 외부 HTTP 핸들러에 연결되지 않음을 grep으로 확인.
    </condition>
  </not_reportable>

  <verify>
    <item>경쟁 조건이라면 두 요청이 실제로 동시에 실행될 수 있는 환경인가? (단일 프로세스인지 확인)</item>
    <item>논리 우회라면 모든 실행 경로(예외 핸들러 포함)를 코드에서 읽었는가?</item>
    <item>공격자가 상태 전이 또는 수치 조작을 실제로 요청으로 트리거할 수 있는가?</item>
    <item>서버 측에서 설정한 값인지, 클라이언트가 공급하는 값인지 소스까지 추적했는가?</item>
  </verify>

</policy>
```
