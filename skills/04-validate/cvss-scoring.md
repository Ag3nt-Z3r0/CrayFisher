# Skill 04-C: CVSS 3.1 Scoring

## 목적
04-A/04-B를 통과한 유효 취약점에 CVSS 3.1 점수를 계산한다.

## 벡터 선택 가이드

각 취약점에 대해 아래 질문으로 벡터를 결정한다.

### AV (Attack Vector)
- 인터넷/LAN에서 직접 → `N` (Network)
- 동일 로컬 네트워크 필요 → `A` (Adjacent)
- 로컬 실행 필요 → `L` (Local)
- 물리 접근 필요 → `P` (Physical)

### AC (Attack Complexity)
- 특별 조건 없음 → `L` (Low)
- 레이스컨디션, 특정 환경 설정 필요 → `H` (High)

### PR (Privileges Required)
- 인증 불필요 → `N`
- 일반 계정 필요 → `L`
- 관리자 권한 필요 → `H`

### UI (User Interaction)
- 공격자 혼자 실행 → `N`
- 피해자의 행동 필요 (링크 클릭 등) → `R`

### S (Scope)
- 취약한 컴포넌트 범위 내 → `U` (Unchanged)
- 다른 컴포넌트/컨테이너에 영향 → `C` (Changed)

### C/I/A (Confidentiality / Integrity / Availability)
- 영향 없음 → `N`
- 부분 영향 → `L`
- 완전 영향 → `H`

## 취약점 유형별 기본 벡터

| 유형 | 기본 벡터 | 기본 점수 |
|------|---------|---------|
| Command Injection | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 |
| SQL Injection | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L` | 9.4 |
| Insecure Deserialization | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 |
| Prompt Injection | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` | 9.3 |
| SSRF | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` | 9.3 |
| Path Traversal | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` | 8.2 |
| XSS (Stored) | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 |
| CORS Misconfiguration | `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | 5.4 |
| Crypto Weakness (GCM) | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | 7.4 |
| DoS (ReDoS) | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 7.5 |
| Auth Bypass | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 |

## 컨텍스트 조정

- `auth` 또는 `login` 관련 파일 → PR을 `L` (인증된 사용자 환경)
- 로컬 전용 기능 (`local`, `localhost` 접근) → AV를 `L`
- 공격자가 직접 트리거 못하고 관리자 개입 필요 → PR을 `H`

## CVSS 점수 계산 공식

```
ISS = 1 - (1 - CIA_C) × (1 - CIA_I) × (1 - CIA_A)

if S == U:
  Impact = 6.42 × ISS
  PR_w = PR_U
else:
  Impact = 7.52 × (ISS - 0.029) - 3.25 × ((ISS - 0.02)^15)
  PR_w = PR_C

Exploitability = 8.22 × AV × AC × PR_w × UI

if Impact ≤ 0: Score = 0
elif S == U: Score = min(Impact + Exploitability, 10)
else: Score = min(1.08 × (Impact + Exploitability), 10)

[올림 처리: ceil(Score × 10) / 10]
```

계수표:
- AV: N=0.85, A=0.62, L=0.55, P=0.20
- AC: L=0.77, H=0.44
- PR(U): N=0.85, L=0.62, H=0.27 / PR(C): N=0.85, L=0.68, H=0.50
- UI: N=0.85, R=0.62
- CIA: N=0.00, L=0.22, H=0.56

## 출력
```
## CVSS Scores: <저장소명>

| # | 위치 | 유형 | 벡터 | 점수 | 심각도 |
|---|------|------|------|------|--------|
```

심각도 기준: CRITICAL(≥9.0) / HIGH(≥7.0) / MEDIUM(≥4.0) / LOW(≥0.1)
