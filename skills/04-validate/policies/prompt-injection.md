```xml
<policy type="prompt-injection">

  <reportable>
    <condition id="external-content-in-prompt">
      외부 소스(웹 크롤, DB 레코드, 파일, 타 API 응답)에서 가져온 내용이
      LLM API 호출의 messages 배열 또는 input에 삽입된다.
      확인: LLM API 호출 코드를 읽고, 외부 콘텐츠 변수가 messages에 포함됨을 확인.
    </condition>
    <condition id="tool-call-dangerous">
      LLM이 실행할 수 있는 tool/function에 파일 삭제, 셸 실행, DB 수정 등
      되돌릴 수 없는 작업이 포함된다.
      확인: tool 정의 코드를 읽고 실제 수행 작업을 확인.
    </condition>
    <condition id="llm-output-executed">
      LLM 응답이 검증 없이 eval(), exec(), subprocess, 다른 API 호출의 인자가 된다.
      확인: 응답 변수의 목적지를 코드에서 추적.
    </condition>
    <condition id="system-prompt-user-controlled">
      시스템 프롬프트의 일부가 사용자 입력 또는 외부 데이터로 구성된다.
      확인: system 메시지 구성 코드를 읽어 외부 변수 포함 여부 확인.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="fixed-system-prompt" reason="고정 프롬프트">
      시스템 프롬프트가 완전히 하드코딩된 상수이다.
      확인: system 메시지를 코드에서 읽어 상수 문자열임을 확인.
      단, user 메시지에 외부 콘텐츠가 들어오면 별도 확인 필요.
    </condition>
    <condition id="display-only-output" reason="출력 격리">
      LLM 응답이 사용자에게 표시되기만 하고, 어떤 시스템 작업에도 사용되지 않는다.
      확인: 응답 변수가 렌더링 외의 코드에 전달되지 않음을 추적.
    </condition>
    <condition id="no-dangerous-tools" reason="도구 위험도 없음">
      에이전트가 실행할 수 있는 모든 tool이 읽기 전용 또는 되돌릴 수 있는 작업만 한다.
      확인: 모든 tool 정의를 읽어 수행 작업을 확인.
    </condition>
    <condition id="sandboxed-execution" reason="샌드박스">
      LLM 출력 실행이 샌드박스(Docker, E2B, Firecracker) 내에서 격리된다.
      확인: 실행 환경 설정 코드를 읽어 격리 수준을 확인.
    </condition>
  </not_reportable>

  <verify>
    <item>외부 콘텐츠가 LLM messages에 삽입되는 코드를 직접 읽었는가?</item>
    <item>시스템 프롬프트와 사용자 메시지를 분리하는 코드가 있는가?</item>
    <item>LLM이 호출할 수 있는 모든 tool의 실제 동작을 코드로 확인했는가?</item>
    <item>LLM 응답 이후 처리 파이프라인 전체를 추적했는가?</item>
  </verify>

</policy>
```
