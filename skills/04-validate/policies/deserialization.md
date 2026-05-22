```xml
<policy type="deserialization">

  <reportable>
    <condition id="user-controlled-input">
      사용자가 제어하는 데이터(요청 바디, 파일 업로드, 쿠키 등)가
      pickle.loads(), yaml.load(), unserialize(), ObjectInputStream 등에 직접 전달된다.
      확인: 역직렬화 함수 인자를 코드에서 읽고, 그 인자가 외부 입력임을 소스까지 추적.
    </condition>
    <condition id="no-class-restriction">
      역직렬화 후 허용 클래스/타입을 제한하는 코드가 없다.
      확인: 역직렬화 함수 전후에 화이트리스트 타입 검사(isinstance, allowedClasses 등)가
      없음을 함수 전체를 읽어 확인.
    </condition>
    <condition id="magic-method-reachable">
      역직렬화 과정에서 __reduce__, __wakeup, readObject 등 매직 메서드가
      임의 코드 실행으로 이어지는 가젯 체인이 존재한다.
      확인: 코드베이스 또는 의존 패키지에서 위험한 매직 메서드 구현을 grep으로 탐색.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="safe-format" reason="안전한 포맷">
      JSON, MessagePack, Protocol Buffers 등 코드 실행이 불가능한 포맷을 사용한다.
      확인: 파싱 함수가 json.loads(), JSON.parse() 등임을 코드에서 읽음.
      단, json.loads 이후 eval()이 없는지 추가 확인.
    </condition>
    <condition id="yaml-safe-load" reason="안전한 로더">
      yaml.safe_load() 또는 YAML::safe_load를 사용한다.
      확인: yaml 로딩 함수를 코드에서 직접 읽음.
      yaml.load(input, Loader=yaml.SafeLoader)도 안전.
    </condition>
    <condition id="trusted-source-only" reason="신뢰 소스">
      역직렬화 대상이 공격자가 제어할 수 없는 내부 시스템(서버간 RPC, 내부 캐시)에서만 온다.
      확인: 데이터 소스를 소스까지 추적해 외부 입력이 아님을 확인.
    </condition>
    <condition id="class-whitelist" reason="화이트리스트 적용">
      역직렬화 허용 클래스를 명시적 화이트리스트로 제한한다.
      확인: resolveClass(), allowedClasses, RestrictedUnpickler 등 제한 코드를 읽음.
    </condition>
  </not_reportable>

  <verify>
    <item>역직렬화 함수의 인자가 외부 입력임을 소스까지 추적했는가?</item>
    <item>yaml.load()라면 Loader 파라미터를 코드에서 읽었는가? (생략 시 위험)</item>
    <item>클래스/타입 제한 코드가 없음을 해당 함수 전체에서 읽어 확인했는가?</item>
    <item>공격 가능한 가젯 체인이 실제로 코드베이스에 존재하는가?</item>
  </verify>

</policy>
```
