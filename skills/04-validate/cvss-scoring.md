# Skill 04-C: CVSS 3.1 Scoring

## Purpose
Compute a CVSS 3.1 score for a valid vulnerability that passed 04-A / 04-B.

## Vector selection guide

For each vulnerability, pick the vector using the questions below.

### AV (Attack Vector)
- Directly from the internet/LAN → `N` (Network)
- Requires same local network → `A` (Adjacent)
- Requires local execution → `L` (Local)
- Requires physical access → `P` (Physical)

### AC (Attack Complexity)
- No special conditions → `L` (Low)
- Race condition or specific environment required → `H` (High)

### PR (Privileges Required)
- No auth required → `N`
- Regular account required → `L`
- Admin privileges required → `H`

### UI (User Interaction)
- Attacker triggers it alone → `N`
- Requires victim action (clicking a link, etc.) → `R`

### S (Scope)
- Confined to the vulnerable component → `U` (Unchanged)
- Affects other components/containers → `C` (Changed)

### C/I/A (Confidentiality / Integrity / Availability)
- No impact → `N`
- Partial impact → `L`
- Full impact → `H`

## Default vectors by vulnerability type

| Type | Default vector | Default score |
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
| **RCE chain (host exec)** | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 |
| **LPE chain (scope→admin/host)** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.9 |
| **Sandbox-escape chain** | `AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.0 |

## Chained vulnerability scoring (`vuln_type = CHAIN`)

A chain's vector is **assembled from two different links**, not scored as one
sink:

- **Exploitability metrics — from the ENTRY link** (how the attacker first gets
  in): `AV`, `AC`, `PR`, `UI`. If the entry is an unauthenticated HTTP/webhook/
  ingested-content path → `AV:N`, `PR:N`, `UI:N`. If the chain needs a logged-in
  tier to start → `PR:L`. If any link needs a race (CWE-367) or a non-default
  precondition → `AC:H`.
- **Impact metrics + Scope — from the TERMINAL link** (what the end state does):
  `C/I/A` and `S`. Host code execution / host file overwrite ⇒ `C:H/I:H/A:H`.
  Crossing a sandbox / component / privilege boundary ⇒ `S:C` (this is what
  pushes RCE/LPE chains to ~9.8–10.0).
- **Do not average links.** A chain that *starts* unauth and *ends* in host RCE is
  scored unauth-entry + host-RCE-impact, i.e. critical — even if every individual
  link was only MEDIUM.

Worked example (C2 — workspace write on `sys.path` ⇒ RCE):
entry = unauth upload (`AV:N/PR:N/UI:N`), terminal = host import (`S:C/C:H/I:H/A:H`),
no race (`AC:L`) → `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = **10.0**.

## Context adjustments

- File related to `auth` or `login` → set PR to `L` (authenticated user environment)
- Local-only feature (`local`, `localhost` access) → set AV to `L`
- Attacker cannot trigger directly and an admin must intervene → set PR to `H`

## CVSS score formula

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

[Round up: ceil(Score × 10) / 10]
```

Coefficient table:
- AV: N=0.85, A=0.62, L=0.55, P=0.20
- AC: L=0.77, H=0.44
- PR(U): N=0.85, L=0.62, H=0.27 / PR(C): N=0.85, L=0.68, H=0.50
- UI: N=0.85, R=0.62
- CIA: N=0.00, L=0.22, H=0.56

## Output
```
## CVSS Scores: <repo-name>

| # | Location | Type | Vector | Score | Severity |
|---|------|------|------|------|--------|
```

Severity thresholds: CRITICAL (≥9.0) / HIGH (≥7.0) / MEDIUM (≥4.0) / LOW (≥0.1)
