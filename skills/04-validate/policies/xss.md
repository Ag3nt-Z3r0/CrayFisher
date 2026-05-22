```xml
<policy type="xss">

  <reportable>
    <condition id="stored-xss">
      사용자 입력이 DB에 저장되고, 이후 다른 사용자의 브라우저에서 이스케이프 없이 렌더링된다.
      확인: 저장 경로 + 렌더링 경로 두 곳 모두 코드에서 읽음.
      렌더링 쪽에서 이스케이프/sanitization 없음을 확인.
    </condition>
    <condition id="dom-xss-unescaped">
      사용자 입력이 innerHTML, document.write(), dangerouslySetInnerHTML에 직접 설정된다.
      확인: 해당 할당 코드와 입력 출처를 코드에서 읽음.
    </condition>
    <condition id="template-unescaped">
      템플릿 엔진의 raw/unescaped 출력(`{{ }}` 대신 `{{{ }}}`, `| safe` 등)에
      사용자 입력이 들어간다.
      확인: 해당 템플릿 코드를 읽음.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="auto-escape-template" reason="자동 이스케이프">
      Django 템플릿, Jinja2, React JSX, Vue 템플릿의 기본 출력은 자동 이스케이프된다.
      확인: `| safe`, `mark_safe()`, `dangerouslySetInnerHTML` 등 명시적 해제 코드가
      없음을 템플릿/컴포넌트 파일에서 읽어 확인.
    </condition>
    <condition id="csp-present" reason="CSP 방어">
      Content-Security-Policy 헤더가 script-src를 엄격하게 제한한다.
      확인: 미들웨어 또는 응답 헤더 설정 코드를 읽고 script-src 값을 확인.
      `unsafe-inline` 없고 nonce 또는 hash 기반이면 FP 가능.
      단, CSP만으로는 완전한 FP 판정 불가 — 코드 수정 권고는 유지.
    </condition>
    <condition id="non-html-response" reason="브라우저 미렌더링">
      응답 Content-Type이 application/json, text/plain 등 HTML이 아니다.
      확인: 응답 헤더 설정 코드를 읽음.
      단, 브라우저가 sniffing으로 HTML로 해석할 가능성 확인 (X-Content-Type-Options 헤더).
    </condition>
    <condition id="self-xss-only" reason="영향 제한">
      공격자 자신의 세션에만 영향 (self-XSS) — 다른 사용자 브라우저에는 도달 불가.
      확인: 입력이 저장되지 않고 즉시 반환되는 reflected XSS이며,
      CSRF 토큰 없이 다른 사용자가 이 반응을 유도하는 경로가 없음을 확인.
    </condition>
  </not_reportable>

  <verify>
    <item>Stored XSS라면: 저장 코드와 렌더링 코드 두 곳 모두 읽었는가?</item>
    <item>이스케이프 함수를 통과한다면 그 함수 내부를 읽었는가?</item>
    <item>렌더링 결과가 실제로 다른 사용자의 브라우저에 도달하는지 확인했는가?</item>
    <item>HttpOnly 쿠키로 보호된 세션이라도 다른 공격 체인이 가능한가?</item>
  </verify>

</policy>
```
