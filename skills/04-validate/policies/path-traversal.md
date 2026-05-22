```xml
<policy type="path-traversal">

  <reportable>
    <condition id="unsanitized-join">
      path.join() 또는 os.path.join() 에 사용자 입력이 전달되고,
      `../` 또는 절대경로 정규화 처리가 없다.
      확인: 해당 join 호출 코드와 사용자 입력 변수의 출처를 읽음.
    </condition>
    <condition id="sensitive-path-reachable">
      파일 읽기/쓰기 경로가 `/etc/`, `~/.ssh/`, `.env`, 소스코드 디렉터리 등
      민감한 위치에 도달 가능하다.
      확인: 루트 기준 경로 탐색이 가능한지 `../` 반복으로 확인.
    </condition>
    <condition id="arbitrary-write">
      사용자 입력으로 경로를 제어하여 임의 파일 쓰기가 가능하다.
      (읽기보다 높은 위험 — 코드 실행으로 이어질 수 있음)
    </condition>
  </reportable>

  <not_reportable>
    <condition id="basename-only" reason="경로 탐색 불가">
      os.path.basename(), path.basename() 으로 디렉터리 부분이 제거된다.
      확인: basename 처리 코드를 읽음 — 이후 join에서 디렉터리 부분이 없어짐.
    </condition>
    <condition id="realpath-chroot" reason="경로 정규화">
      realpath() / resolve() 후 허용 디렉터리 prefix 검사가 있다.
      확인: `if (!resolved.startsWith(ALLOWED_DIR))` 형태 코드를 읽음.
    </condition>
    <condition id="static-whitelist" reason="화이트리스트">
      파일명이 허용된 목록에서만 선택된다 (정적 에셋 서빙 등).
    </condition>
    <condition id="non-sensitive-dir" reason="영향 제한">
      접근 가능한 최대 범위가 공개 디렉터리 내부로 한정된다.
      확인: serve 루트가 코드에서 고정되어 있고 탈출 불가함을 확인.
    </condition>
  </not_reportable>

  <verify>
    <item>../를 포함한 입력이 실제 파일 시스템 경로로 해석되는 코드를 읽었는가?</item>
    <item>경로 정규화 또는 prefix 검사 코드가 없음을 해당 함수 전체에서 확인했는가?</item>
    <item>도달 가능한 최상위 디렉터리를 코드에서 확인했는가?</item>
  </verify>

</policy>
```
