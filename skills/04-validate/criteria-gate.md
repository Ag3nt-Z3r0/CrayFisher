# Skill 04-A: 5-기준 검증 Gate

## 목적
03까지 올라온 취약점 후보를 5개 기준으로 검증한다.
각 기준은 코드 인용으로 통과/실패를 증명해야 한다.
코드 인용 없이 기준을 "통과"로 표시하지 않는다.

---

## 검증 절차

후보 하나를 가져와서 아래 5개 기준을 순서대로 검증한다.
기준 하나가 실패하면 즉시 FP로 처리하고 다음 후보로 넘어간다.

---

### ① 외부 입력이 이 코드 경로에 실제로 도달할 수 있는가?

**확인 방법:**
03-A 추적 결과를 본다. "흐름 확인됨" 판정이 있고 추적 경로에 코드 인용이 있는가?

- 있다 → ① 통과. 인용된 소스 위치를 기록한다.
- 없다 → 아래를 직접 확인한다:

```bash
# 이 파일을 호출하는 진입점이 있는가?
grep -rn "<function_name>\|<file_stem>" <local_path> --include="*.ts" --include="*.py" -l
```

호출자 파일을 읽어서 그 호출자가 외부 요청 핸들러인지 확인한다.

**기록:**
```
① 통과/실패
근거: <file>:<line> → "<코드>" (소스 위치 인용)
```

---

### ② 기본 설정으로 트리거 가능한가?

**확인 방법:**
03 추적 중에 이 경로를 둘러싼 조건문을 읽었는가? 조건문이 있다면:

```bash
python tools/file_read.py <file> <condition_line> --context 15
```

읽어서 확인:
- 환경변수 플래그나 설정 플래그가 있는가?
- `process.env.ENABLE_X` 또는 `config.featureFlag` 가 `true`여야 실행되는가?
- `@deprecated`, `// TODO: remove`, `// dead code` 주석이 해당 함수/블록에 있는가?

**기록:**
```
② 통과/실패
읽은 조건 코드: <file>:<line> → "<코드>"
결론: 조건 없음 / 조건 있음 (내용)
```

---

### ③ 공격자가 이 입력 값을 실제로 제어할 수 있는가?

**확인 방법:**
①에서 확인한 소스를 다시 본다.

아래를 코드에서 직접 확인한다:

```bash
python tools/file_read.py <source_file> <source_line> --context 10
```

- 값이 하드코딩된 상수에서 오는가? → ③ 실패
- SQL 쿼리에 `?`, `$1`, `:name`, `@param` 플레이스홀더가 있는가? → ③ 실패
- TypeScript 타입이 `number`, `boolean`, `bigint`, union literal로 제약되어 있는가?
  ```bash
  python tools/file_read.py <type_def_file> <type_line> --context 5
  ```
  읽어서 확인. 타입 선언 파일이 있다면 그것도 읽는다.

**기록:**
```
③ 통과/실패
공격자 제어 가능 여부: 가능 / 불가 (이유)
근거: <file>:<line> → "<코드>"
```

---

### ④ 이 취약점이 실제로 의미 있는 영향을 가져오는가?

**확인 방법:**
싱크 코드를 다시 읽는다. 해당 취약점 유형의 policy 파일을 읽어 판단 기준을 확인한다.

| 취약점 유형 | Policy 파일 |
|------------|------------|
| DoS / ReDoS | `skills/04-validate/policies/dos.md` |
| SQL Injection | `skills/04-validate/policies/sqli.md` |
| Command Injection | `skills/04-validate/policies/cmdi.md` |
| Path Traversal | `skills/04-validate/policies/path-traversal.md` |
| SSRF | `skills/04-validate/policies/ssrf.md` |
| XSS | `skills/04-validate/policies/xss.md` |
| Prompt Injection | `skills/04-validate/policies/prompt-injection.md` |
| Auth Bypass / IDOR | `skills/04-validate/policies/auth.md` |
| CORS | `skills/04-validate/policies/cors.md` |
| Crypto Weakness | `skills/04-validate/policies/crypto.md` |
| Insecure Deserialization | `skills/04-validate/policies/deserialization.md` |
| Logic Bug / Race Condition | `skills/04-validate/policies/logic-bug.md` |

**판단 절차:**
1. 해당 유형의 policy 파일을 읽는다.
2. `<reportable>` 조건 중 하나를 코드 인용으로 충족하는가?
3. `<not_reportable>` 조건 중 하나라도 해당하면 즉시 ④ 실패.
4. `<verify>` 항목을 모두 코드에서 확인한다.

각 조건은 코드를 읽어서 확인한다. "이런 상황이면 보통 위험하다"는 근거로 통과 판정을 내리지 않는다.

**기록:**
```
④ 통과/실패
Policy 파일: skills/04-validate/policies/<type>.md
적용 조건: <reportable condition id>
근거: <file>:<line> → "<코드>"
```

---

### ⑤ 이미 알려진 CVE와 동일 패턴이 아닌가?

```bash
python tools/osv_lookup.py <main_package> <ecosystem>
```

- 동일 파일, 동일 함수, 동일 패턴의 기존 CVE가 있는가?
- 유사 패턴이지만 코드 위치가 다르면 → 통과 (신규 취약점 가능)

**기록:**
```
⑤ 통과/실패
OSV 결과: 없음 / 있음 (ID + 파일 동일 여부)
```

---

## 최종 판정 형식

```
## Validation: <file>:<line> <vuln_type>

| 기준 | 판정 | 근거 코드 |
|------|------|---------|
| ① 도달 가능성 | 통과/실패 | <file>:<line> → "<코드>" |
| ② 기본 설정  | 통과/실패 | <file>:<line> → "<코드>" |
| ③ 공격자 제어 | 통과/실패 | <file>:<line> → "<코드>" |
| ④ 충분한 영향 | 통과/실패 | <file>:<line> → "<코드>" |
| ⑤ CVE 중복  | 통과/실패 | OSV 결과 |

**최종: 유효 취약점 / FP**
FP 이유: <실패한 기준과 코드 근거>
```
