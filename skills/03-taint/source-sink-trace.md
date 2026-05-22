# Skill 03-A: Source → Sink Taint 추적

## 목적
외부 입력이 위험한 함수에 도달하는 경로를 코드를 읽으면서 확인한다.
이 skill의 결과는 "코드에서 직접 확인한 데이터 흐름"이어야 한다.
"아마 이렇게 흐를 것이다"는 결과가 아니다.

---

## 추적 절차

### Step 1 — 시작점: 진입점 핸들러를 읽는다

01-B 또는 02-A에서 넘어온 후보 파일:라인을 읽는다.
```bash
python tools/file_read.py <local_path>/<handler_file> <entry_line> --context 30
```

**이 읽기에서 얻어야 하는 것:**
핸들러가 외부 소스에서 추출하는 변수명 목록.
아래 패턴 중 코드에서 보이는 것만 기록한다:

```
req.body.X      req.query.X     req.params.X
request.args['X']   request.form['X']   request.json['X']
process.argv[N]     sys.argv[N]
```

이 패턴 중 코드에서 읽지 않은 것은 "외부 입력"이라고 쓰지 않는다.

### Step 2 — 각 외부 변수를 한 번에 하나씩 추적한다

**변수 A를 추적하는 절차:**

1. 핸들러 코드에서 변수 A가 처음 사용되는 줄을 찾는다
2. 그 줄을 읽는다 — 변수 A가 함수 호출의 인자로 쓰이는가?
3. Yes → 그 함수 정의를 찾아서 읽는다

```bash
# 함수 정의 찾기
grep -rn "function <callee>\|const <callee>\s*=\|def <callee>" <local_path> \
  --include="*.ts" --include="*.py" --include="*.js"
python tools/file_read.py <definition_file> <definition_line> --context 30
```

4. 함수 내부에서 인자가 어떻게 사용되는지 읽는다
5. 또 다른 함수 호출이 있으면 3번으로 돌아간다
6. 아래 위험 목적지 중 하나에 도달하면 추적을 완료한다

**위험 목적지 (코드에서 직접 확인해야 함):**

| 목적지 | 취약점 유형 |
|--------|-----------|
| `os.system(`, `subprocess.run(`, `exec(` | Command Injection |
| `eval(`, `new Function(`, `vm.runIn` | Code Injection |
| `pickle.loads(`, `yaml.load(` | Deserialization |
| DB 쿼리 문자열 보간 (`.query(` 등에 변수 직접 삽입) | SQL Injection |
| `path.join(` + `readFile` / `readFileSync` 에 외부 경로 | Path Traversal |
| `fetch(url)`, `axios.get(url)` 에 외부 URL | SSRF |
| `innerHTML =`, `document.write(` | XSS |
| `messages.create(`, `chat.completions.create(`, `chain.invoke(` | Prompt Injection |
| `new RegExp(`, `re.compile(` 에 외부 문자열 | ReDoS ← policy 확인 |
| `Buffer.alloc(n)`, `new Array(n)` 에 외부 숫자 | DoS (alloc) ← policy 확인 |
| `extractall()`, `fromstring()` 크기 제한 없음 | DoS (Bomb) ← policy 확인 |

**DoS 싱크에 도달했을 때**: 추적을 완료로 표시하기 전에
`skills/04-validate/criteria-gate.md` 의 `<policy type="dos">` 를 읽고
`<not_reportable>` 조건에 해당하지 않는지 먼저 확인한다.
해당하면 추적 완료가 아니라 즉시 FP로 처리한다.

### Step 3 — 추적이 끊어지는 경우

아래 상황 중 하나가 발생하면 추적을 멈추고 "흐름 끊김"으로 기록한다.
추측으로 이어 붙이지 않는다.

- 변수가 함수 인자로 전달되었는데 그 함수 정의를 찾을 수 없다
- 변수가 다른 모듈에서 import된 함수로 전달되고, 그 모듈의 소스를 읽을 수 없다
- 동적 디스패치(`this[methodName]()`)로 호출되어 어떤 함수인지 알 수 없다

끊긴 위치와 이유를 기록하고, "이후 경로는 확인 불가"라고 명시한다.

### Step 4 — 위험 목적지 도달 확인 후: 차단 처리 여부 확인

도달 경로에서 읽은 코드들을 되돌아보며 확인한다.

**차단 처리가 있다고 인정하는 기준:**
- 코드에서 직접 읽었다
- 해당 함수의 내부 구현까지 읽었다

**차단 처리가 없다고 인정하는 기준:**
- 경로의 모든 함수를 읽었고 해당 처리가 없었다

"이 함수 이름이 `validate`이니까 검증할 것이다"는 차단 처리 확인이 아니다.
반드시 그 함수의 내부 코드를 읽는다.

---

## 출력 형식

```
## Taint Trace #N

**시작점:**
<file>:<line> → "<코드>" (외부 소스 확인)

**추적 경로:**
1. <file>:<line> → "<코드>" — 변수 전달
2. <file>:<line> → "<코드>" — 함수 내부 처리
3. <file>:<line> → "<코드>" — ← 위험 목적지 도달

**차단 처리:**
없음 — 경로의 모든 함수를 읽었고 검증/인코딩 없음을 확인

**결과: 흐름 확인됨 / 흐름 끊김**
끊긴 경우: <어디서 왜 끊겼는지>
```
