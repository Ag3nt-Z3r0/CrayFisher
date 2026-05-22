```xml
<policy type="cors">

  <reportable>
    <condition id="origin-reflected-with-credentials">
      요청의 Origin 헤더 값을 그대로 Access-Control-Allow-Origin에 반사하고,
      Access-Control-Allow-Credentials: true 가 함께 설정된다.
      확인: CORS 설정 코드에서 두 헤더 모두 코드로 읽음.
      이 조합만이 실제 인증 정보 탈취로 이어짐.
    </condition>
    <condition id="wildcard-with-credentials">
      Access-Control-Allow-Origin: * 와 Credentials: true 가 함께 설정된다.
      (브라우저가 차단하지만 설정 자체가 잘못됨 — 낮은 위험도로 기록)
    </condition>
    <condition id="null-origin-trusted">
      Origin: null 을 신뢰하는 코드가 있다.
      확인: null origin 처리 코드를 읽음. 샌드박스 iframe 공격 가능.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="credentials-false" reason="인증 정보 포함 불가">
      Access-Control-Allow-Credentials 헤더가 없거나 false다.
      Credentials 없으면 CORS 취약점으로 인증 정보 탈취 불가.
      확인: 응답 헤더 설정 코드를 읽어 Credentials 헤더를 확인.
    </condition>
    <condition id="whitelist-origins" reason="고정 허용 목록">
      Origin이 고정된 허용 목록과 일치할 때만 ACAO 헤더를 설정한다.
      확인: 허용 목록 코드를 읽고 동적 반사가 없음을 확인.
    </condition>
    <condition id="non-sensitive-api" reason="민감 데이터 없음">
      해당 엔드포인트가 공개 데이터만 반환하고 인증이 필요 없다.
      CORS 설정이 느슨해도 탈취할 민감 정보가 없음.
    </condition>
    <condition id="same-site-cookie" reason="쿠키 보호">
      세션 쿠키에 SameSite=Strict 또는 SameSite=Lax가 설정되어 있다.
      확인: 쿠키 설정 코드를 읽음. CORS 취약점의 실제 영향을 제한.
      단, Authorization 헤더 기반 인증이면 이 조건은 해당 없음.
    </condition>
  </not_reportable>

  <verify>
    <item>ACAO 헤더 값을 결정하는 코드를 직접 읽었는가?</item>
    <item>Credentials 헤더 설정 코드를 읽었는가?</item>
    <item>이 API가 인증 후에만 민감한 데이터를 반환하는지 확인했는가?</item>
    <item>Origin 반사 로직이 있다면 허용 목록 검사를 건너뛸 수 있는 우회 가능성을 확인했는가?</item>
  </verify>

</policy>
```
