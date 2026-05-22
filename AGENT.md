# AGENT.md — 보안팀 피드백 & 리젝 사유 학습 기록

## 이 파일의 목적

실제 보안팀(Django Security Team, HackerOne 트리아저 등)이 리포트를 리젝한 사유를
`<tips>` 블록에 즉시 기록한다.

**업데이트 규칙:**
- 리포트가 리젝되면 그 사유를 `<tip>` 항목으로 추가한다.
- 리젝 사유가 기존 `<tip>`과 동일하면 `<count>`를 올린다.
- skills/ 파일을 수정해야 하는 경우 `<skill_update>` 태그에 파일명과 내용을 기록한다.

에이전트는 취약점을 보고하기 전에 이 파일을 읽고,
해당 발견이 아래 리젝 패턴에 해당하는지 확인한다.

---

```xml
<tips>

  <!-- ══════════════════════════════════════════════════════════
       DoS 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="dos-auth-required" category="dos" source="django-security-team" count="1">
    <reject_reason>
      인증된 사용자만 트리거할 수 있는 DoS는 보안 취약점으로 인정하지 않는다.
    </reject_reason>
    <detail>
      Django 보안 모델에서 인증된 사용자는 신뢰 범위 내 행위자다.
      로그인 후에야 접근 가능한 뷰에서 발생하는 리소스 소진 문제는
      "신뢰된 사용자의 남용"이며 보안 취약점이 아니라 운영 문제로 처리된다.
    </detail>
    <lesson>
      코드에서 인증 미들웨어/decorator(@login_required, JWTGuard 등)를 읽어
      인증 없이 접근 가능한지 확인하지 않으면 DoS 리포트는 즉시 리젝된다.
    </lesson>
    <skill_update>skills/04-validate/criteria-gate.md — policy not_reportable auth-required</skill_update>
  </tip>

  <tip id="dos-admin-only" category="dos" source="django-security-team" count="1">
    <reject_reason>
      staff / superuser 계정만 접근 가능한 기능의 DoS는 리젝된다.
    </reject_reason>
    <detail>
      Django admin 인터페이스는 신뢰된 관리자 전용이다.
      /admin/ 경로에서 발생하는 모든 DoS 가능성은 "관리자 남용"으로 분류되어 리젝된다.
    </detail>
    <lesson>
      진입점이 /admin/, @staff_member_required, permission_classes=[IsAdminUser] 뒤에
      있으면 DoS 리포트를 작성하지 않는다.
    </lesson>
  </tip>

  <tip id="dos-intended-slow" category="dos" source="django-security-team" count="1">
    <reject_reason>
      비밀번호 해싱(PBKDF2, bcrypt, argon2)이 느린 것은 의도된 보안 설계이다.
    </reject_reason>
    <detail>
      "로그인 엔드포인트에 반복 요청을 보내면 서버가 느려진다"는 리포트는
      rate limiting 부재 문제이지 해싱 함수 자체의 취약점이 아니다.
    </detail>
    <lesson>
      비밀번호 해싱 함수를 싱크로 탐지하지 않는다.
      로그인 엔드포인트의 rate limiting 부재는 별도 카테고리(config 이슈)로 처리한다.
    </lesson>
  </tip>

  <tip id="dos-redos-no-proof" category="dos" source="django-security-team" count="1">
    <reject_reason>
      "사용자 입력이 정규식에 들어간다"는 사실만으로는 ReDoS 리포트가 리젝된다.
      catastrophic backtracking이 실제로 발생하는 패턴임을 증명해야 한다.
    </reject_reason>
    <detail>
      `re.compile(user_input)` 또는 `new RegExp(userInput)` 을 발견했다고
      바로 ReDoS 취약점이 아니다. 사용자가 입력할 수 있는 패턴이
      실제로 (a+)+, (a|a)+, (\w|\w)+ 류의 catastrophic 구조를 만들 수 있어야 한다.
      단순 문자열 검색용 정규식은 해당 없다.
    </detail>
    <lesson>
      ReDoS 보고 전 확인 사항:
      1. 사용자 입력이 정규식 '패턴' 자체가 되는가? (검색 대상 문자열이 아닌)
      2. 사용자가 중첩 수량자를 포함한 패턴을 만들 수 있는가?
      3. 실제로 지수적 시간이 걸리는 입력 예시를 만들 수 있는가?
      3번까지 확인하지 못하면 보고하지 않는다.
    </lesson>
    <skill_update>skills/04-validate/criteria-gate.md — policy reportable redos-proven</skill_update>
  </tip>

  <tip id="dos-linear-ok" category="dos" source="django-security-team" count="1">
    <reject_reason>
      O(n) 복잡도이고 n에 합리적인 상한이 있으면 리젝된다.
    </reject_reason>
    <detail>
      MAX_CONTENT_LENGTH, max_length 등으로 입력 크기가 제한되어 있거나,
      처리 복잡도가 선형(O(n))이면 서비스 영향이 제한적이라 판단된다.
    </detail>
    <lesson>
      메모리/CPU 소비가 우려되면 상한 검사 코드가 없음을 반드시 코드로 확인한다.
      설정 파일(settings.py, .env)도 읽어서 전역 상한이 있는지 확인한다.
    </lesson>
  </tip>

  <tip id="dos-xml-documented" category="dos" source="django-security-team" count="1">
    <reject_reason>
      XML Billion Laughs / Quadratic blowup는 defusedxml 사용 권고로 대응하며,
      표준 라이브러리 사용 자체를 취약점으로 처리하지 않는 경우가 있다.
    </reject_reason>
    <detail>
      Python xml.etree.ElementTree의 XML Bomb 취약성은 Python 문서에
      명시된 알려진 한계다. defusedxml 미사용을 별도 리포트로 올리면
      "문서화된 설계 한계"로 리젝될 수 있다.
    </detail>
    <lesson>
      xml 파싱 발견 시: defusedxml 또는 크기 제한 코드가 있는지 확인한다.
      없다면 별도 리포트보다는 "Remediation에 defusedxml 권고" 형태로 포함시킨다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       로직 버그 / 설정 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="logic-trusted-input" category="logic" source="django-security-team" count="1">
    <reject_reason>
      공격자가 데이터베이스 또는 파일 시스템을 직접 제어할 수 있다는 가정은 인정되지 않는다.
    </reject_reason>
    <detail>
      "DB에 악의적 데이터를 넣으면..." 시나리오는 공격자가 이미 DB 접근 권한을
      가진 것이고, 이 경우 더 직접적인 공격이 가능하므로 취약점으로 인정되지 않는다.
    </detail>
    <lesson>
      공격 시나리오는 공격자가 실제로 HTTP 요청 또는 공개 인터페이스를 통해
      입력을 제어하는 경로만 포함한다.
    </lesson>
  </tip>

  <tip id="logic-settings-misconfigured" category="logic" source="django-security-team" count="1">
    <reject_reason>
      개발자가 명백히 잘못된 설정을 선택한 경우(DEBUG=True in production 등)는
      프레임워크 취약점이 아니라 배포 실수로 처리된다.
    </reject_reason>
    <detail>
      ALLOWED_HOSTS=["*"], DEBUG=True, SECRET_KEY가 기본값인 경우 등은
      Django가 명시적으로 경고하는 설정이며 프레임워크 취약점으로 리젝된다.
    </detail>
    <lesson>
      settings.py에서 발견한 문제는 "보안 설정 권고" 형태로만 포함시킨다.
      CVE 취약점으로 보고하지 않는다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       SQLi 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="sqli-orm-default" category="sqli" source="general" count="1">
    <reject_reason>
      ORM 기본 메서드(.filter(), .where(), .findOne() 등)는 자동으로 파라미터화되어 리젝된다.
    </reject_reason>
    <detail>
      Django ORM, SQLAlchemy, Prisma, TypeORM 등의 기본 쿼리 메서드는
      내부적으로 파라미터화된 쿼리를 생성한다.
      `.filter(name=user_input)` 형태는 SQL Injection이 아니다.
    </detail>
    <lesson>
      ORM 메서드 발견 시: raw(), execute(), RawSQL() 등 날쿼리 메서드가 아닌지 확인한다.
      `.filter()`에 `user_input`이 들어가는 것만으로는 보고하지 않는다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       SSRF 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="ssrf-path-only" category="ssrf" source="general" count="1">
    <reject_reason>
      사용자 입력이 고정 호스트의 경로(path)만 제어하면 SSRF로 리젝된다.
    </reject_reason>
    <detail>
      URL = "https://api.example.com/" + userInput 형태는
      공격자가 호스트를 바꿀 수 없으므로 내부 서비스 접근이 불가능하다.
      경로 순회(path traversal)는 별도로 검토해야 하지만 SSRF 카테고리는 아니다.
    </detail>
    <lesson>
      SSRF 보고 전: URL의 호스트 부분을 공격자가 제어하는지 코드에서 확인한다.
      호스트가 하드코딩이면 SSRF가 아니다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       XSS 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="xss-auto-escape" category="xss" source="general" count="1">
    <reject_reason>
      Django 템플릿, Jinja2, React JSX 등 자동 이스케이프 렌더러를 사용하면 XSS로 리젝된다.
    </reject_reason>
    <detail>
      Django 템플릿의 {{ variable }}, React의 {variable} 등은 자동으로 HTML 이스케이프된다.
      |safe 필터, dangerouslySetInnerHTML, mark_safe() 없이는 XSS가 아니다.
    </detail>
    <lesson>
      템플릿에서 변수 출력 발견 시: 자동 이스케이프 비활성화 마커를 코드에서 읽어 확인한다.
      없으면 XSS 보고하지 않는다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Auth / IDOR 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="auth-public-resource" category="auth" source="general" count="1">
    <reject_reason>
      명시적으로 공개 접근을 허용하도록 설계된 리소스의 IDOR은 리젝된다.
    </reject_reason>
    <detail>
      공개 프로필, 공개 게시물, 공개 API 같은 기능은 설계상 누구나 접근 가능하다.
      이를 IDOR로 보고하면 "의도된 설계"로 즉시 리젝된다.
    </detail>
    <lesson>
      IDOR 보고 전: 해당 리소스가 민감한 데이터를 포함하는지, 
      접근이 인증 후에만 가능한지 코드에서 확인한다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       CORS 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="cors-no-credentials" category="cors" source="general" count="1">
    <reject_reason>
      Access-Control-Allow-Credentials가 없거나 false이면 CORS 취약점으로 리젝된다.
    </reject_reason>
    <detail>
      Credentials 헤더 없이는 브라우저가 쿠키/토큰을 교차 출처 요청에 포함시키지 않는다.
      Origin이 와일드카드여도 Credentials=false이면 인증 정보 탈취가 불가능하다.
    </detail>
    <lesson>
      CORS 발견 시: 반드시 Credentials 헤더 설정 코드를 읽어 true인지 확인한다.
      false이거나 없으면 보고하지 않는다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Crypto 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="crypto-non-security-hash" category="crypto" source="general" count="1">
    <reject_reason>
      MD5/SHA1이 캐시 키, 중복 탐지, 파일 무결성 등 비보안 목적에 사용되면 리젝된다.
    </reject_reason>
    <detail>
      모든 MD5 사용이 취약점은 아니다. 보안 목적(서명, 인증, HMAC)에만 약한 해시가 문제다.
      파일명 해시, 캐시 키 생성, ETag 등은 보안 취약점이 아니다.
    </detail>
    <lesson>
      MD5/SHA1 발견 시: 해시 결과가 어디에 사용되는지 코드에서 추적한다.
      인증/서명이 아니면 보고하지 않는다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Prompt Injection 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="prompt-display-only" category="prompt-injection" source="general" count="1">
    <reject_reason>
      LLM 응답이 사용자에게 표시만 되고 어떤 시스템 작업에도 사용되지 않으면 리젝된다.
    </reject_reason>
    <detail>
      Prompt Injection의 실제 위협은 LLM이 조작된 내용을 '실행'할 때다.
      응답이 UI 텍스트로만 렌더링되면 사회공학적 위험은 있지만 직접적 시스템 영향은 없다.
    </detail>
    <lesson>
      LLM 응답 변수의 다음 목적지를 코드에서 추적한다.
      렌더링 외에 exec, eval, DB write, API call 등으로 이어지지 않으면 보고 수위를 낮춘다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       Deserialization 관련 리젝 사유
       ══════════════════════════════════════════════════════════ -->

  <tip id="deser-safe-format" category="deserialization" source="general" count="1">
    <reject_reason>
      JSON 파싱은 코드 실행이 불가능하므로 역직렬화 취약점으로 리젝된다.
    </reject_reason>
    <detail>
      json.loads(), JSON.parse() 등은 데이터만 파싱하며 임의 코드 실행이 불가능하다.
      pickle, yaml.load(unsafe), PHP unserialize, Java ObjectInputStream 등이 위험하다.
    </detail>
    <lesson>
      역직렬화 발견 시: 파싱 함수명을 코드에서 직접 읽어 위험한 포맷인지 확인한다.
      JSON이면 보고하지 않는다.
    </lesson>
  </tip>

  <!-- ══════════════════════════════════════════════════════════
       새 리젝 사유 추가 템플릿
       ══════════════════════════════════════════════════════════
  <tip id="<고유 ID>" category="<dos|sqli|xss|logic|auth|other>" source="<보안팀명>" count="1">
    <reject_reason>한 줄 요약</reject_reason>
    <detail>상세 설명</detail>
    <lesson>다음번에 어떻게 확인해야 하는가</lesson>
    <skill_update>수정이 필요한 skill 파일과 내용 (선택)</skill_update>
  </tip>
       ══════════════════════════════════════════════════════════ -->

</tips>
```
