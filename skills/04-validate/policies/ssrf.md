```xml
<policy type="ssrf">

  <reportable>
    <condition id="user-controlled-url">
      사용자 입력이 fetch(), requests.get(), axios() 등의 URL 인자가 된다.
      확인: URL 구성 코드를 읽고 사용자 변수가 호스트/경로 부분에 포함됨을 확인.
    </condition>
    <condition id="internal-reachable">
      내부 서비스(AWS 메타데이터, 내부 API 서버, DB 포트 등)에 요청이 가능하다.
      확인: scheme, host 제한 코드가 없음을 함수 전체에서 읽어 확인.
    </condition>
    <condition id="credential-forwarded">
      인증 토큰 또는 쿠키가 외부 요청에 함께 전달된다.
      (자격 증명 탈취 가능 — 영향도 상향)
    </condition>
  </reportable>

  <not_reportable>
    <condition id="scheme-host-whitelist" reason="URL 화이트리스트">
      허용된 호스트 목록 또는 정규식으로 URL을 검증한다.
      확인: 화이트리스트 코드를 읽고 우회 가능성(DNS rebinding, URL 파싱 차이)을 확인.
    </condition>
    <condition id="path-only" reason="호스트 제어 불가">
      사용자 입력이 고정 호스트의 경로(path)만 제어한다.
      확인: URL = HARDCODED_HOST + userPath 형태이고 HARDCODED_HOST를 코드에서 읽음.
    </condition>
    <condition id="localhost-only" reason="영향 제한">
      접근 가능한 목적지가 127.0.0.1/localhost 자신뿐이다.
      확인: 서버가 자신에게만 요청하고 외부 서비스 접근 불가함을 코드로 확인.
    </condition>
    <condition id="dns-resolved-before" reason="DNS rebinding 방지">
      URL을 DNS 해석 후 IP 주소로 검증하며 RFC1918 범위를 차단한다.
      확인: 해석된 IP 검사 코드를 읽음.
    </condition>
  </not_reportable>

  <verify>
    <item>사용자 입력이 URL의 호스트 부분을 제어하는 코드를 읽었는가?</item>
    <item>URL scheme 제한(https only 등)이 있는지 코드로 확인했는가?</item>
    <item>응답 내용이 사용자에게 반환되는가? (blind SSRF vs response reflection)</item>
    <item>내부 AWS 메타데이터(169.254.169.254) 또는 내부 API 서버 접근 가능성을 확인했는가?</item>
  </verify>

</policy>
```
