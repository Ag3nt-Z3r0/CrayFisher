# Skill 01-B: Entry Point Analysis

## 목적
외부 입력이 들어오는 진입점을 식별하고, 각 핸들러가 실제로 어떤 입력을 어떻게 다루는지 읽는다.

---

## 절차

### Step 1 — 자동 탐지
```bash
python tools/find_entries.py <local_path>
```
출력에서 `entries` 목록을 얻는다. 이것은 **위치 목록**일 뿐이다. 아직 아무것도 판단하지 않는다.

### Step 2 — 각 진입점 핸들러를 직접 읽는다

진입점 유형별로 읽는 범위를 결정한다:

| 유형 | 읽어야 할 범위 |
|------|-------------|
| `http_route` POST/PUT | 핸들러 함수 전체 (최소 40줄) |
| `tool_handler` (MCP) | tool 등록 코드 + 핸들러 함수 전체 |
| `http_route` GET | 핸들러 함수 전체 (최소 20줄) |
| `agent_hook` | 훅 함수 전체 + 훅을 등록하는 코드 |
| `cli_command` | 커맨드 핸들러 전체 |

```bash
python tools/file_read.py <local_path>/<file> <line> --context 40
```

### Step 3 — 코드를 읽으면서 각 질문에 답한다

핸들러 하나를 읽을 때마다 아래 질문에 답한다.
**각 답변에는 파일:라인을 인용한다. 인용 없이 "있다/없다"라고 쓰지 않는다.**

**Q1. 이 핸들러가 받는 외부 파라미터는 무엇인가?**
- `req.body`, `req.query`, `req.params`, `request.args` 등 외부 소스에서 추출하는 변수명을 모두 나열한다
- 인용: `<file>:<line> → const { X, Y } = req.body`

**Q2. 각 파라미터는 어디로 전달되는가?**
- 함수 호출의 인자, DB 쿼리, 파일 경로, 외부 API 등으로 흘러가는 경로를 읽는다
- 다른 함수로 전달된다면 그 함수 정의를 찾아서 읽는다

**Q3. 파라미터가 그 목적지에 닿기 전에 어떤 처리를 거치는가?**
- 코드에서 직접 확인한 검증/인코딩/타입 변환만 기록한다
- 없다면 "없음"이라고 명시한다. "아마 있을 것이다"라고 쓰지 않는다

### Step 4 — 추가 수동 탐지 (자동 탐지가 놓칠 수 있는 유형)

```bash
grep -rn "on('connection'" <local_path> --include="*.ts" --include="*.js" -l
grep -rn "\.subscribe\|\.consume\|on_message" <local_path> -l
grep -rn "process\.on\('message'\|ipcMain\.on" <local_path> -l
```
발견 시 Step 2~3 동일하게 적용한다.

---

## 출력 형식

```
## Entry Points: <저장소명>

### <파일:라인> — <유형> (<경로 또는 핸들러명>)

**외부 파라미터:**
- `X` — 근거: <file>:<line> → "<코드>"
- `Y` — 근거: <file>:<line> → "<코드>"

**각 파라미터의 목적지:**
- `X` → <함수명/DB쿼리/API> (<file>:<line>)
  - 목적지 코드: "<코드>"
  - 중간 처리: <있으면 코드 인용, 없으면 "없음">

**다음 단계:**
- 03-A Taint 추적 시작점: `X` (<file>:<line>)
- 의심 수준: 높음/중간/낮음 (그 이유를 한 줄로)
```

---

## 주의

- 핸들러 파일명이나 경로 이름만 보고 "이 핸들러는 인증이 필요할 것이다" 같은 추측을 쓰지 않는다.
- 미들웨어가 있다는 사실을 코드에서 읽지 않았다면 "인증 미들웨어 없음"이 기본 가정이다.
