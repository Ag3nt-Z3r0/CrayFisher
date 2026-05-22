# vuln-agent — LLM 주도 제로데이 리서치 에이전트

## 설계 철학

**LLM이 분석 주체, Python은 데이터 수집 도구.**

- `skills/` — LLM이 따르는 분석 프롬프트 (MD 파일)
- `tools/` — 데이터 수집만 담당하는 Python 스크립트 (JSON 출력)
- `rules/semgrep/` — 커스텀 Semgrep 탐지 룰
- `troubleshooting/` — 스캔 중 발생한 이슈 로그 (XML)
- `reports/` — 생성된 취약점 보고서

---

## 핵심 원칙 — 반드시 지킬 것

### 원칙 1: 절차로 의심한다

취약점 유형을 먼저 떠올리고 코드를 꿰맞추지 않는다.
코드를 읽으면서 데이터가 어떻게 흐르는지 따라간다.
흐름이 위험한 목적지에 닿을 때 비로소 취약점을 의심한다.

```
진입점 읽기 → 외부 입력 변수 식별 → 각 변수 추적 → 목적지 확인 → 판단
```

### 원칙 0: 스캔 시작 전 AGENT.md를 읽는다

`AGENT.md` 의 `<tips>` 블록을 읽어 과거 리젝 사유를 숙지한다.
발견된 취약점이 리젝 패턴에 해당하면 보고서를 작성하기 전에 FP로 처리한다.
새로운 리젝 피드백을 받으면 즉시 `AGENT.md` 에 `<tip>` 항목을 추가한다.

### 원칙 2: 읽기 전에 주장하지 않는다

아래는 증거가 아니다:
- 파일명, 함수명, 변수명
- 코드 주석
- Semgrep이 발견했다는 사실 자체
- "이런 코드에서는 보통 X 취약점이 있다"는 경험칙

증거는 오직 하나: **직접 읽은 코드의 특정 줄**

모든 판단에는 아래 형식의 증거를 첨부한다:
```
근거: <file_path>:<line>
  → "<실제 코드 내용>"
```
이 형식을 채울 수 없으면 판단을 보류한다.

---

## 스캔 실행 방법

```
INPUT: <GitHub URL>
```

두 가지 모드 중 선택한다.

### 단일 에이전트 모드 (Single-Agent)

하나의 LLM이 Phase 1~5를 순서대로 실행한다.
빠른 탐색이나 단순한 저장소에 적합하다.

각 phase의 skill 파일을 읽고 지시 사항을 따른다.

### 멀티 에이전트 모드 (Multi-Agent) — 권장

4개의 전문 에이전트가 공격 → 반박 → 판정 사이클로 검증한다.
FP 비율을 낮추고 CVE 보고의 신뢰도를 높이는 데 적합하다.

```
skills/agents/orchestrator.md 를 읽고 실행한다.
```

| 에이전트 | Skill 파일 | 역할 |
|---------|-----------|------|
| 오케스트레이터 | `skills/agents/orchestrator.md` | 전체 흐름 조율, 서브에이전트 호출 |
| 정찰 에이전트 | `skills/agents/recon-agent.md` | 공격자 시각 — 취약점 후보 발굴 |
| 방어자 에이전트 | `skills/agents/defender-agent.md` | 트리아저 시각 — policy 기반 반박 |
| 판정 에이전트 | `skills/agents/judgment-agent.md` | 독립 심판 — 최종 CVE 가치 판정 |

```
멀티 에이전트 흐름:
정찰 에이전트 → [finding 목록]
  ↓ (finding별 병렬)
방어자 에이전트 → [REBUTTED / CONFIRMED / PARTIAL]
  ↓ (REBUTTED 제외)
판정 에이전트 → [CONFIRMED / FP / NEEDS_MORE_EVIDENCE]
  ↓ (CONFIRMED만)
CVE 보고서 작성
```

### Phase 1 — Recon

| Skill | 파일 |
|-------|------|
| 1-A | `skills/01-recon/profile-repo.md` |
| 1-B | `skills/01-recon/entry-point-analysis.md` |

```bash
python tools/clone.py <url>
python tools/detect_stack.py <local_path>
python tools/find_entries.py <local_path>
python tools/osv_lookup.py <package> <ecosystem>
```

### Phase 2 — Static Analysis

| Skill | 파일 |
|-------|------|
| 2-A | `skills/02-static/semgrep-interpret.md` |
| 2-B | `skills/02-static/manual-code-review.md` |

```bash
python tools/semgrep_run.py <local_path>
python tools/file_read.py <file> <line> --context 15
```

### Phase 3 — Taint Analysis

| Skill | 파일 |
|-------|------|
| 3-A | `skills/03-taint/source-sink-trace.md` |
| 3-B | `skills/03-taint/ai-agent-flows.md` |

> AI 에이전트 프레임워크(MCP, LangChain, CrewAI 등) 감지 시 3-B를 반드시 실행한다.

```bash
python tools/file_read.py <file> <line> --context 20
grep -rn "<symbol>" <local_path> --include="*.ts" --include="*.py"
```

### Phase 4 — Validation

| Skill | 파일 |
|-------|------|
| 4-A | `skills/04-validate/criteria-gate.md` |
| 4-B | `skills/04-validate/fp-patterns.md` |
| 4-C | `skills/04-validate/cvss-scoring.md` |

### Phase 5 — Report

| Skill | 파일 |
|-------|------|
| 5-A | `skills/05-report/cve-report.md` |
| 5-B | `skills/05-report/poc-generation.md` |
| 5-C | `skills/05-report/disclosure.md` |

보고서 저장: `reports/<repo-name>/`

---

## tools/ 레퍼런스

| 도구 | 실행 | 출력 키 |
|------|------|---------|
| `clone.py` | `python tools/clone.py <url>` | `local_path` |
| `detect_stack.py` | `python tools/detect_stack.py <path>` | `primary_language`, `frameworks`, `dependency_files` |
| `find_entries.py` | `python tools/find_entries.py <path>` | `entries[].{type,file,line,match}` |
| `semgrep_run.py` | `python tools/semgrep_run.py <path>` | `findings[].{rule_id,file,line,vuln_type,snippet}` |
| `file_read.py` | `python tools/file_read.py <file> <line>` | `content` (라인 번호 포함) |
| `osv_lookup.py` | `python tools/osv_lookup.py <pkg> <eco>` | `vuln_count`, `vulns[]` |

---

## 트러블슈팅

스캔 중 도구 오류, 예상치 못한 FP 패턴, skill 지시와 코드 불일치 발생 시
`troubleshooting/<repo>_<YYYYMMDD>_<issue-type>.xml` 으로 기록한다.
스키마: `troubleshooting/schema.xml`

---

## 탐지 가능한 취약점 유형

| 유형 | CWE | 주요 탐지 방법 |
|------|-----|-------------|
| SQL Injection | CWE-89 | Semgrep + Taint |
| Command Injection | CWE-78 | Semgrep + Taint |
| Path Traversal | CWE-22 | Semgrep + Taint |
| SSRF | CWE-918 | Semgrep + Manual |
| XSS | CWE-79 | Semgrep + Taint |
| Insecure Deserialization | CWE-502 | Semgrep |
| Auth Bypass / IDOR | CWE-287/284 | Manual |
| CORS Misconfiguration | CWE-346 | Semgrep |
| Crypto Weakness | CWE-310 | Semgrep |
| DoS / ReDoS | CWE-400/1333 | Semgrep |
| Prompt Injection | CWE-1427 | Semgrep + Taint + Manual |
| MCP Tool Poisoning | CWE-1427 | Manual |
| LLM Output Execution | CWE-77 | Semgrep + Taint |
| Race Condition | CWE-362 | Manual |
| Logic Bug | CWE-840 | Semgrep + Manual |

---

## 환경 설정

```bash
python -m venv .venv
pip install -r requirements.txt
```
