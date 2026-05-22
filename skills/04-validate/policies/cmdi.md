```xml
<policy type="cmdi">

  <reportable>
    <condition id="shell-true-with-input">
      subprocess.run(..., shell=True) 또는 os.system() 에 사용자 입력이 포함된
      문자열이 전달된다.
      확인: shell=True 여부와 인자에 사용자 변수 포함 여부를 코드에서 읽음.
    </condition>
    <condition id="string-exec">
      eval(), exec(), new Function(), vm.runInContext() 에 사용자 입력이 전달된다.
      확인: 해당 호출 코드와 인자의 출처를 직접 읽음.
    </condition>
    <condition id="template-exec">
      셸 명령을 조합하는 문자열 보간에 사용자 입력이 포함된다.
      확인: `git clone ${userUrl}`, f"convert {user_file}" 형태를 코드에서 읽음.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="list-args-no-shell" reason="셸 해석 없음">
      subprocess.run([cmd, arg1, arg2]) 형태 — 리스트 인자이고 shell=False(기본값).
      셸 메타문자가 해석되지 않으므로 Command Injection 불가.
      확인: 인자가 리스트 리터럴이고 shell 키워드가 없거나 False임을 코드에서 읽음.
    </condition>
    <condition id="fixed-command" reason="공격자 제어 불가">
      명령어 전체가 하드코딩되어 있고 사용자 입력이 인자로 전달되지 않는다.
    </condition>
    <condition id="whitelist-command" reason="화이트리스트 검증">
      사용자 입력이 허용된 명령어 목록과 일치할 때만 실행된다.
      확인: 화이트리스트 코드를 읽고 우회 가능성(대소문자, 공백, 경로 등)을 확인.
      우회 불가능함이 코드로 확인되면 FP.
    </condition>
    <condition id="admin-only" reason="신뢰 모델 내부">
      superuser / 서버 관리자만 접근 가능한 기능.
    </condition>
  </not_reportable>

  <verify>
    <item>shell=True 또는 string 인자 형태임을 코드에서 읽었는가?</item>
    <item>사용자 입력이 명령어 문자열의 일부가 되는 경로를 추적했는가?</item>
    <item>escape/sanitize 함수를 통과한다면 그 함수 내부를 읽었는가?</item>
    <item>인자 타입이 숫자/불리언으로 강제 변환되는지 확인했는가?</item>
  </verify>

</policy>
```
