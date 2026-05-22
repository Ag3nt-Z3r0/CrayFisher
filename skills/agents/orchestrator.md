# 오케스트레이터 에이전트 (Orchestrator) — 실행 지침

## 역할

3개의 전문 서브에이전트를 순서대로 호출하여 취약점 후보를 공격→반박→판정 사이클로 검증한다.
Python `tools/` 실행 및 서브에이전트 결과 수집이 오케스트레이터의 유일한 책임이다.
직접 취약점 분석을 수행하지 않는다.

## 사전 준비

```bash
# 1. AGENT.md 읽기 (리젝 패턴 숙지)
# 2. 저장소 클론
python tools/clone.py <github_url>
```

---

## 에이전트 호출 방법

Claude Code의 **Agent 도구**로 각 에이전트를 호출한다.
각 에이전트에게 아래 형식으로 프롬프트를 전달한다:

```
[에이전트 시스템 프롬프트 파일 내용]

---
INPUT:
<JSON 데이터>
```

---

## Phase 1: 정찰 에이전트 호출

### 서브에이전트 프롬프트 구성

```
skills/agents/recon-agent.md 파일의 내용을 시스템 프롬프트로 사용.

INPUT:
{
  "local_path": "<clone된 경로>",
  "github_url": "<원본 URL>"
}
```

### 기대 출력

`recon_result.json`:
```json
{
  "agent": "recon",
  "findings": [ { "id": "FIND-001", ... } ]
}
```

결과를 `reports/<repo-name>/recon_result.json` 에 저장한다.

---

## Phase 2: 방어자 에이전트 호출 (finding별 병렬 실행 가능)

각 finding에 대해 방어자 에이전트를 호출한다.
finding이 5개 이상이면 병렬로 호출한다.

### 서브에이전트 프롬프트 구성

```
skills/agents/defender-agent.md 파일의 내용을 시스템 프롬프트로 사용.

INPUT:
{
  "local_path": "<clone된 경로>",
  "finding": { <FIND-001 전체 JSON> }
}
```

### 기대 출력

`defender_FIND-001.json`:
```json
{
  "agent": "defender",
  "finding_id": "FIND-001",
  "verdict": "CONFIRMED|REBUTTED|PARTIAL",
  ...
}
```

결과를 `reports/<repo-name>/defender_<finding_id>.json` 에 저장한다.

---

## Phase 3: 판정 에이전트 호출

`REBUTTED` 판정을 받은 finding은 제외한다.
나머지 finding에 대해 판정 에이전트를 호출한다.

### 서브에이전트 프롬프트 구성

```
skills/agents/judgment-agent.md 파일의 내용을 시스템 프롬프트로 사용.

INPUT:
{
  "local_path": "<clone된 경로>",
  "finding": { <FIND-001 전체 JSON> },
  "defense": { <defender_FIND-001 전체 JSON> }
}
```

### 기대 출력

`judgment_FIND-001.json`:
```json
{
  "agent": "judgment",
  "finding_id": "FIND-001",
  "final_verdict": "CONFIRMED|FP|...",
  "next_action": "CVE_REPORT|DISCARD|INVESTIGATE_FURTHER",
  ...
}
```

결과를 `reports/<repo-name>/judgment_<finding_id>.json` 에 저장한다.

---

## Phase 4: 최종 취합

판정 에이전트 결과를 취합하여 요약 테이블을 출력한다.

```markdown
## 스캔 결과 요약: <repo-name>

| ID | 유형 | 판정 | 신뢰도 | CVSS | 다음 행동 |
|----|------|------|--------|------|---------|
| FIND-001 | SQLI | CONFIRMED | 0.80 | 8.1 | CVE_REPORT |
| FIND-002 | XSS | FP | 0.25 | - | DISCARD |
```

`next_action: CVE_REPORT` 인 finding에 대해:
```
skills/05-report/cve-report.md 를 읽고 보고서를 작성한다.
저장: reports/<repo-name>/CVE-CANDIDATE-<id>.md
```

---

## 실행 예시

```
INPUT: https://github.com/<owner>/<repo>

오케스트레이터 실행 순서:
1. python tools/clone.py https://github.com/<owner>/<repo>
   → local_path = /tmp/vuln-agent/<repo>

2. Agent 호출: 정찰 에이전트
   prompt = [recon-agent.md 내용] + INPUT {local_path}
   → recon_result.json 저장

3. findings 목록 확인
   → FIND-001, FIND-002, FIND-003 발견됨

4. Agent 호출 (병렬): 방어자 에이전트 × 3
   → defender_FIND-001.json: CONFIRMED
   → defender_FIND-002.json: REBUTTED (ORM 파라미터화 확인)
   → defender_FIND-003.json: PARTIAL

5. REBUTTED 제외 → FIND-001, FIND-003 진행

6. Agent 호출 (병렬): 판정 에이전트 × 2
   → judgment_FIND-001.json: CONFIRMED, CVE_REPORT
   → judgment_FIND-003.json: CONFIRMED_LOW, CVE_REPORT

7. CVE 보고서 작성: FIND-001, FIND-003
```

---

## 오류 처리

| 상황 | 처리 |
|------|------|
| 서브에이전트가 JSON 없이 응답 | 해당 finding을 `NEEDS_MORE_EVIDENCE`로 처리 |
| 정찰 에이전트 finding이 0개 | "취약점 없음" 보고서 생성 후 종료 |
| clone 실패 | 사용자에게 오류 보고 후 중단 |
| 판정 에이전트가 INVESTIGATE_FURTHER 반환 | 해당 finding을 보류 목록에 추가하고 요약에 포함 |
