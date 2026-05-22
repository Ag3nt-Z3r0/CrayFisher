# Skill 01-A: Repository Profiling

## 목적
대상 저장소를 클론하고 공격 표면 분석에 필요한 기술 스택·의존성·규모를 파악한다.

## 입력
- `TARGET_URL`: 분석할 GitHub 저장소 URL

## 실행

### Step 1 — 클론
```bash
python tools/clone.py <TARGET_URL>
```
결과에서 `local_path` 를 추출한다. 이후 모든 단계에서 이 경로를 사용한다.

### Step 2 — 스택 감지
```bash
python tools/detect_stack.py <local_path>
```

### Step 3 — 판단
출력 JSON을 읽고 아래 항목을 정리한다.

| 항목 | 확인 내용 |
|------|-----------|
| `primary_language` | 주요 분석 대상 언어 결정 |
| `frameworks` | 해당 프레임워크의 알려진 취약 패턴 선택 |
| `dependency_files` | 주요 패키지 → `tools/osv_lookup.py` 대상 |
| `total_lines` | 10만 줄 초과 시 파일 범위 좁히기 필요 |

#### AI 에이전트 프레임워크 감지 시 주목할 점
- `mcp` 감지 → `skills/03-taint/ai-agent-flows.md` 우선 실행
- `langchain` / `crewai` / `autogen` → Prompt Injection 경로 집중 분석
- `openai-agents` → `Runner.run()` 인자 추적

### Step 4 — OSV 주요 패키지 조회 (상위 5개)
`dependency_files` 에서 주요 패키지를 추출하여 각각 조회한다.
```bash
python tools/osv_lookup.py <package_name> <ecosystem>
# ecosystem: npm | PyPI | Go | Maven | RubyGems | crates.io
```

## 출력
다음 형식으로 프로파일 요약을 작성한다.

```
## Repo Profile: <저장소명>

- URL: <url>
- Primary Language: <language>
- Frameworks: <list>
- Total Files / Lines: <N> / <N>
- AI Agent Framework: <있음/없음 + 종류>
- 주요 의존성 CVE: <있으면 id + summary>
- 다음 단계: [01-B, 02-A, ...]
```
