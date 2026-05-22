# Skill 03-B: AI 에이전트 보안 흐름 분석

## 목적
LLM·MCP·에이전트 프레임워크 코드에서 에이전트 특화 취약점을 찾는다.
일반 taint 분석과 다른 점: **LLM의 출력 자체가 새로운 taint source가 될 수 있다.**

---

## 에이전트 신뢰 계층 모델

에이전트에서 신뢰는 계층적이다. 아래로 갈수록 신뢰도가 낮다:

```
[1] System Prompt       ← 운영자 제어, 최고 신뢰
[2] Developer Messages  ← 코드 내 하드코딩, 높은 신뢰
[3] User Turn           ← 사용자 입력, 낮은 신뢰
[4] Tool Results        ← 외부 세계, 최저 신뢰 (공격자가 제어 가능)
```

**핵심 취약점 패턴**: 낮은 신뢰 계층의 콘텐츠가 높은 신뢰 계층으로 **상승(escalation)** 할 때 발생.

---

## 탐지해야 할 에이전트 특화 취약점 유형 (10가지)

### [A1] 간접 프롬프트 인젝션 (Indirect Prompt Injection)
**정의**: 공격자가 에이전트가 나중에 처리할 외부 콘텐츠(웹 페이지, 파일, 이메일, DB 레코드 등)에 지시문을 심어 에이전트의 행동을 통제.

**탐지 패턴**:
```bash
# 외부 콘텐츠를 LLM에 직접 전달하는 도구 찾기
grep -rn "wrapExternalContent\|wrapWebContent" <path> --include="*.ts" | grep "return"
# → wrapExternalContent 없이 content를 반환하는 도구 = 후보
grep -rn "text:.*\`.*\${" <path> --include="*.ts" | grep -v "wrapExternal\|wrapWeb"
```

**코드에서 확인할 것**:
- 도구가 외부 콘텐츠를 가져와 tool result로 반환하는가?
- 반환 전에 `wrapExternalContent()` 또는 동등한 보호가 적용되는가?
- 동일 에이전트에 위험 도구(`exec`, `file_write`)가 등록되어 있는가?

**위험 신호**: `text: \`...\${rawContent}\`` 패턴, `return { text: externalData }` 패턴

---

### [A2] 저장된 프롬프트 인젝션 (Stored Prompt Injection)
**정의**: 공격자가 오염된 콘텐츠를 DB/메모리/파일에 미리 저장 → 에이전트가 나중에 조회할 때 실행.

**탐지 패턴**:
```bash
# 외부 입력을 저장하는 곳 → 나중에 LLM에 전달되는 곳까지 taint 추적
grep -rn "INSERT INTO\|\.push\|\.set\|\.store" <path> --include="*.ts" | head -30
# 저장된 데이터를 LLM messages에 넣는 곳
grep -rn "memory\.search\|recall\|retrieve\|getHistory\|loadContext" <path> --include="*.ts"
```

**코드에서 확인할 것**:
- 저장 시: LLM 요약/변환 없이 원문이 저장되는가? (`chunkMarkdown()`, 직접 INSERT 등)
- 조회 시: `wrapExternalContent()` 없이 저장된 텍스트가 LLM 컨텍스트에 삽입되는가?
- 저장→조회 사이에 sanitization이 있는가?

---

### [A3] 도구 결과 인젝션 (Tool Result Injection)
**정의**: 에이전트가 사용하는 도구(exec, web_fetch, file_read 등)의 결과가 다음 LLM 호출의 입력이 될 때, 결과에 포함된 인젝션이 실행.

**탐지 패턴**:
```bash
# tool result가 messages 배열에 추가되는 방식
grep -rn "role.*tool\|tool_result\|toolResult\|ToolResultBlock" <path> --include="*.ts"
# tool result를 감싸는 보호 함수 존재 여부
grep -rn "wrapToolResult\|sanitizeToolOutput\|escapeToolContent" <path> --include="*.ts"
```

**코드에서 확인할 것**:
- tool result가 `content: rawOutput` 형태로 그대로 messages에 추가되는가?
- exec/shell 출력이 그대로 다음 LLM 호출에 포함되는가? (재귀적 인젝션 가능)
- web_fetch/file_read 결과에 공격자가 제어 가능한 내용이 포함될 수 있는가?

---

### [A4] 다중 에이전트 신뢰 경계 위반 (Multi-Agent Trust Escalation)
**정의**: 낮은 신뢰의 서브에이전트가 높은 신뢰의 오케스트레이터에게 메시지를 보낼 때, 서브에이전트의 출력이 무조건 신뢰되면 권한 상승 발생.

**탐지 패턴**:
```bash
# 서브에이전트 결과를 오케스트레이터가 처리하는 방식
grep -rn "subagent\|Subagent\|spawn.*agent\|runAgent\|delegateTo" <path> --include="*.ts"
grep -rn "result.*message\|output.*inject\|agentResponse.*prompt" <path> --include="*.ts"
```

**코드에서 확인할 것**:
- 서브에이전트 출력이 오케스트레이터 LLM의 user/system turn에 삽입되는가?
- 삽입 전에 서브에이전트 결과가 살균/검증되는가?
- 서브에이전트에 외부 입력 접근 권한이 있는가?

**위험 시나리오**: 외부 입력 처리 서브에이전트 → 조작된 결과 반환 → 오케스트레이터가 exec 실행

---

### [A5] 지시문 계층 우회 (Instruction Hierarchy Bypass)
**정의**: system prompt의 지시가 user turn이나 tool result에 삽입된 상충 지시에 의해 무력화됨.

**탐지 패턴**:
```bash
# system prompt와 user turn이 조합되는 방식
grep -rn "messages.*system\|systemPrompt\|extraSystemPrompt" <path> --include="*.ts"
grep -rn "prependEvents\|systemLines\|buildReplyPrompt" <path> --include="*.ts"
```

**코드에서 확인할 것**:
- system prompt에 "외부 콘텐츠를 신뢰하지 말라"는 지시가 있는가?
- user turn이나 tool result에서 온 콘텐츠가 `System:` 접두사를 달고 삽입되는가?
- LLM이 두 지시 간 충돌 시 어느 쪽을 우선시하도록 설계됐는가?

---

### [A6] 메모리 오염 (Memory Poisoning)
**정의**: 공격자가 에이전트의 장기/단기 메모리에 오염된 콘텐츠를 주입하여, 이후 세션에서 반복 실행.

**탐지 패턴**:
```bash
# 메모리 쓰기: 외부 입력이 메모리로 저장되는 경로
grep -rn "memory\.add\|memory\.store\|addMemory\|saveMemory\|promoteTo" <path> --include="*.ts"
# 메모리 읽기: 저장된 내용이 LLM에 전달되는 경로
grep -rn "memory\.search\|memory\.get\|loadMemory\|recallMemory" <path> --include="*.ts"
```

**코드에서 확인할 것**:
- 쓰기 경로: 외부 입력이 LLM 변환 없이 원문 저장되는가?
- 읽기 경로: 저장된 내용이 `wrapExternalContent` 없이 LLM에 전달되는가?
- 쓰기 임계값(score, recall count 등)이 실제로 달성 가능한가?

---

### [A7] 도구 연쇄 공격 (Tool Chain Exploitation)
**정의**: 공격자가 하나의 도구를 통해 에이전트가 다른 위험한 도구를 연속 실행하도록 유도.

**탐지 패턴**:
```bash
# 어떤 도구들이 같은 에이전트/프로파일에 등록되어 있는가
grep -rn "profiles.*coding\|tool.*register\|toolCatalog\|allowedTools" <path> --include="*.ts"
# 도구 실행 순서 제어 여부
grep -rn "tool.*sequence\|toolChain\|autoApprove\|askBeforeRun" <path> --include="*.ts"
```

**코드에서 확인할 것**:
- `exec`/`file_write`와 `web_fetch`/`memory_search` 같은 읽기 도구가 동일 세션에 등록되어 있는가?
- 도구 A의 출력이 도구 B의 인수로 직접 전달되는 자동화 패턴이 있는가?
- `ask=off`/`autoApprove=true` 설정이 기본값인가?

---

### [A8] 에이전트 목표 탈취 (Goal Hijacking)
**정의**: 주입된 지시가 에이전트의 원래 목표를 완전히 교체하여, 공격자가 원하는 작업을 대신 수행.

**탐지 패턴**:
```bash
# 에이전트 목표/태스크가 외부 입력에서 오는 경우
grep -rn "goal\|objective\|task.*user\|userGoal" <path> --include="*.ts"
grep -rn "run_task\|taskBody\|agentTask" <path> --include="*.ts"
```

**코드에서 확인할 것**:
- 에이전트의 최초 task/goal이 외부 입력(webhook, API 등)에서 설정되는가?
- task 내용이 LLM user/system turn에 직접 삽입되는가?
- task 내용에 대한 content validation이 있는가?

---

### [A9] 반성/평가자 에이전트 조작 (Critic/Evaluator Manipulation)
**정의**: 다중 에이전트 시스템에서 평가자(critic) 에이전트가 주입된 콘텐츠를 평가할 때, 평가 결과 자체가 오염됨.

**탐지 패턴**:
```bash
# critic/judge/evaluator 패턴
grep -rn "critic\|judge\|evaluate\|review.*agent\|verif.*agent" <path> --include="*.ts" -i
```

**코드에서 확인할 것**:
- 평가자 에이전트가 평가 대상 콘텐츠를 직접 user turn에 받는가?
- 평가 결과가 후속 실행 결정에 자동으로 사용되는가?
- 평가자 에이전트에도 위험 도구가 등록되어 있는가?

---

### [A10] 컨텍스트 창 조작 (Context Window Manipulation)
**정의**: 공격자가 대량의 무해한 콘텐츠를 보내 초기 system prompt를 컨텍스트 창 밖으로 밀어내거나, 특정 패턴으로 초기 지시를 희석.

**탐지 패턴**:
```bash
# 컨텍스트 크기 제한 여부
grep -rn "maxTokens\|contextLimit\|truncate\|trimContext\|maxContext" <path> --include="*.ts"
# 긴 외부 콘텐츠를 무제한 삽입하는 경로
grep -rn "\.join\|concat.*content\|append.*history" <path> --include="*.ts"
```

**코드에서 확인할 것**:
- 외부 콘텐츠 길이에 제한이 없는가?
- 긴 입력이 시스템 지시보다 앞에 삽입되는가?
- 컨텍스트 압축/트런케이션이 system prompt를 잘라낼 수 있는가?

---

## 탐지 절차

### Step 1 — 에이전트 아키텍처 파악

```bash
python3 tools/detect_stack.py <local_path>
```

확인:
- LLM API 호출 위치 (`openai`, `anthropic`, `messages.create`)
- 도구 등록 방식 (`toolCatalog`, `allowedTools`, `tool-catalog.ts`)
- 에이전트 간 통신 패턴 (subagent spawn, message passing)
- 메모리 시스템 존재 여부

### Step 2 — 신뢰 경계 지도 작성

코드를 읽어 다음 질문에 답한다:

```
Q1: 외부 입력(HTTP, 채팅, 파일, 음성 등)이 어디서 들어오는가?
Q2: 그 입력이 LLM messages에 삽입되기 전에 어떤 변환을 거치는가?
Q3: 삽입된 위치는 system turn인가 user turn인가 tool result인가?
Q4: 동일 에이전트 세션에 위험 도구(exec, file_write)가 있는가?
Q5: 인간 승인 게이트(ask=always 등)가 있는가?
```

### Step 3 — 보호 함수 일관성 검사

올바른 보호 패턴이 한 곳에는 적용되고 다른 곳에는 빠진 경우 → 즉시 후보 등록.

```bash
# wrapExternalContent 적용 현황
grep -rn "wrapExternalContent\|wrapWebContent" <path> --include="*.ts"
# 미적용 도구와 적용 도구를 비교
```

```bash
# sanitizeInboundSystemTags 적용 현황
grep -rn "sanitizeInboundSystemTags" <path> --include="*.ts"
# 적용된 경로 vs 미적용 경로 목록화
```

### Step 4 — 기본값(Default) 분석

기본값이 안전한지 확인:

```bash
grep -rn "DEFAULT_ASK\|DEFAULT_SECURITY\|groupPolicy\|toolsAllow\|dmPolicy" <path> --include="*.ts"
grep -rn "'open'\|'off'\|'full'\|'allowlist'" <path> --include="*.ts" | grep -i "default\|=\s*['\"]"
```

위험 기본값 패턴:
- `DEFAULT_ASK = 'off'` → exec 자동 실행
- `groupPolicy = 'open'` → 모든 멤버 접근 허용
- `toolsAllow = undefined` → 모든 도구 허용
- `sandbox = 'auto'` + `sandboxAvailable = false` → 호스트 실행

---

## 출력 형식

```json
{
  "agent_architecture": {
    "llm_calls": ["<file>:<line>"],
    "tool_registry": "<file>:<line>",
    "memory_system": "<file> or null",
    "multi_agent": true/false,
    "trust_layers_identified": ["system_prompt", "user_turn", "tool_result"]
  },
  "findings": [
    {
      "id": "FIND-XXX",
      "vuln_class": "A1|A2|A3|A4|A5|A6|A7|A8|A9|A10",
      "vuln_type": "PROMPT_INJECTION|STORED_INJECTION|TOOL_ABUSE|...",
      "title": "...",
      "trust_escalation": "tool_result → user_turn",
      "source": "<file>:<line> → \"code\"",
      "sink": "<file>:<line> → \"code\"",
      "taint_path": ["step1", "step2"],
      "dangerous_tools_reachable": ["exec", "file_write"],
      "human_gate_present": false,
      "confidence_base": 0.70
    }
  ]
}
```
