```xml
<policy type="crypto">

  <reportable>
    <condition id="gcm-no-auth-tag">
      AES-GCM 복호화 시 authTag 검증을 건너뛰거나 setAuthTag 호출이 없다.
      확인: decipher.setAuthTag() 호출 없이 decipher.final() 이 호출되는 코드를 읽음.
    </condition>
    <condition id="weak-cipher-sensitive-data">
      DES, RC4, ECB 모드, MD5/SHA1(서명/인증 목적)이 민감한 데이터 처리에 사용된다.
      확인: 알고리즘 문자열('des-ecb', 'rc4', 'md5' 등)을 코드에서 읽고,
      처리 대상 데이터가 민감한 것(비밀번호, 세션 토큰, 결제 정보 등)임을 확인.
    </condition>
    <condition id="hardcoded-key-iv">
      암호화 키 또는 IV가 소스코드에 하드코딩되어 있다.
      확인: createCipher 또는 createDecipheriv 인자를 코드에서 읽음.
    </condition>
    <condition id="static-iv">
      IV(초기화 벡터)가 항상 같은 고정 값을 사용한다.
      확인: IV 생성 코드를 읽어 randomBytes 없이 상수임을 확인.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="non-security-hash" reason="보안 목적 아님">
      MD5/SHA1이 캐시 키, 중복 탐지, 파일 무결성 확인 등 비보안 목적으로 사용된다.
      확인: 해시 결과의 사용 목적을 코드에서 읽음.
      인증/서명에 사용되지 않으면 보안 취약점 아님.
    </condition>
    <condition id="password-hashing-bcrypt" reason="의도된 설계">
      bcrypt, argon2, PBKDF2, scrypt 로 비밀번호를 해싱한다.
      이것은 취약점이 아니라 올바른 설계임.
    </condition>
    <condition id="no-sensitive-data" reason="영향 제한">
      약한 알고리즘이지만 암호화 대상이 민감하지 않은 공개 데이터다.
      확인: 암호화 대상 데이터를 코드에서 확인.
    </condition>
    <condition id="deprecated-but-unused-path" reason="미사용 코드">
      약한 알고리즘이 있지만 해당 코드 경로가 실제로 실행되지 않는다.
      확인: 호출자가 없음을 grep으로 확인.
    </condition>
  </not_reportable>

  <verify>
    <item>알고리즘 이름 문자열을 코드에서 직접 읽었는가?</item>
    <item>암호화/복호화 대상 데이터가 민감한지 코드에서 확인했는가?</item>
    <item>GCM이라면 setAuthTag 호출 여부를 코드에서 읽었는가?</item>
    <item>키/IV 생성 코드를 읽어 랜덤 생성 또는 하드코딩 여부를 확인했는가?</item>
  </verify>

</policy>
```
