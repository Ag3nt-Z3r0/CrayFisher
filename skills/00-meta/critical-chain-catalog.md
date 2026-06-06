# Critical Chain Catalog — Primitive Taxonomy & Canonical RCE/LPE Chains

> Data reference for [`../03-taint/exploit-chaining.md`](../03-taint/exploit-chaining.md)
> (Phase 3-C). This file is the *vocabulary and template set*; the procedure
> skill is *how to apply it*. Same split as
> [agent-cwe-priority.md](agent-cwe-priority.md) (data) ↔
> [ai-agent-flows.md](../03-taint/ai-agent-flows.md) (procedure).

## 1. Why chaining exists

Most CVSS-critical agent bugs (RCE, LPE, full account/host takeover) are **not
single source→sink findings**. They are *compositions* of two or more
lower-severity primitives where the **output of one becomes the precondition of
the next**. The OpenClaw Critical-13 confirms this empirically: 9 of 13 are
multi-step `operator.read → operator.admin → host exec` self-escalation
**chains**, 2 are TOCTOU+symlink sandbox-escape chains. A pipeline that only
reports isolated primitives systematically under-rates exactly the bugs that
matter most.

A chain converts moderate findings into a critical one. Example: an
"arbitrary file write, but only inside the workspace" (MEDIUM, often rejected as
low-impact) **+** "the workspace is added to `PYTHONPATH`/`sys.path` at startup"
(a benign-looking config line) **= unauthenticated RCE** (CRITICAL). Neither
link alone is a CVE-grade finding; the chain is.

## 2. Primitive capability vocabulary

A *primitive* is a capability a confirmed finding grants the attacker. Tag every
recon finding with one or more. Each tag has a **precondition** (what the
attacker needs to use it) and a **product** (what it yields, which may be another
primitive's precondition).

| Primitive | What the attacker gains | Typical source finding | CWE |
|---|---|---|---|
| `arbitrary-read` | read any path/host content | path traversal read, SSRF, file_read tool | CWE-22/918 |
| `arbitrary-write` | write attacker bytes to attacker-chosen path | path traversal write, file_write tool | CWE-22 |
| `bounded-write` | write to a *constrained* location (workspace, tmp, fixed dir) | "safe" write tool | CWE-22 |
| `write-to-exec-location` | write to a path that is later executed/sourced | bounded-write + exec-location knowledge | CWE-22+94 |
| `path-control` | influence a filesystem path used by another op | unsanitized tool arg | CWE-22/73 |
| `symlink-plant` | create a symlink the target later follows | write tool w/o O_NOFOLLOW | CWE-59 |
| `env-control` | set/leak a process env var | env passthrough, denylist bypass | CWE-184/526 |
| `ssrf` | make the server issue attacker-chosen requests | fetch on attacker URL/host | CWE-918 |
| `prompt-injection` | inject instructions the LLM will follow | A1/A2/A3/A5/A6 | CWE-1427 |
| `tool-invoke` | cause the agent to call a tool of attacker's choosing | excessive agency + injection | LLM06 |
| `exec-primitive` | run a process/command | shell tool, cmdi sink | CWE-78/77 |
| `scope-read` | read-tier authorization token/session | low-tier pairing/login | CWE-863 |
| `scope-write` | write-tier authorization | mid-tier scope | CWE-863 |
| `scope-admin` | admin/operator authorization | self-escalation endpoint | CWE-863/269 |
| `approval-bypass` | skip a human/approval gate | timeout fallback, strict-eval miss | LLM06 |
| `sandbox-fs-bridge` | write/read across the sandbox↔host FS boundary | shared mount, TOCTOU | CWE-367/59 |
| `deser-sink` | feed bytes to an unsafe deserializer | pickle/yaml.load reachable | CWE-502 |
| `cred-access` | obtain a credential/token/key | arbitrary-read of secret, metadata SSRF | CWE-522 |
| `memory-write` | persist attacker content into agent memory | A6 write path | CWE-1427 |

## 3. Terminal sinks (what makes a chain "critical")

A chain is only worth a critical rating if its **terminal link** reaches one of:

- **Host code execution** — `exec`/`spawn`/`eval`/`import` of attacker-influenced
  content, or write-to-exec-location that is subsequently run.
- **Privilege/scope elevation to admin/host** — attacker ends with `scope-admin`,
  root, or capabilities the trust model never grants their entry tier (LPE).
- **Credential exf/ reuse** — obtains a secret and a path to *use or send* it.
- **Sandbox/host escape** — code or writes that cross the sandbox→host boundary.
- **Irreversible privileged action** — payment, deploy, `git push`, prod data
  destruction, account takeover.

Pure "read of non-secret data" or "DoS" is **not** a critical terminal — those
stay at their own single-finding severity.

## 4. Canonical chain templates

Each template = `entry primitive → … → terminal sink ⇒ impact`. Use as hunting
hypotheses, never as a substitute for per-link evidence.

### C1 — Indirect Prompt Injection → Tool Invoke → Exec  ⇒ RCE *(canonical agent RCE)*
```
prompt-injection (A1/A3, external content/tool result)
  → tool-invoke   (excessive agency: ask=off / autoApprove / no allowlist)
  → exec-primitive (shell/file_write/eval tool in same catalog)
```
Agent analogue: the single most common agent RCE. Maps OWASP **LLM01→LLM06**.
Preconditions to prove: (a) external content lands unwrapped in a turn the model
acts on; (b) a dangerous tool is registered in the *same* session; (c) no human
gate. See A1/A3/A7 in [ai-agent-flows.md](../03-taint/ai-agent-flows.md).

### C2 — Path Traversal Write + Symlink → Write-to-Exec-Location  ⇒ RCE
```
arbitrary-write or bounded-write (CWE-22)
  [+ symlink-plant (CWE-59) to escape a bounded dir]
  → write-to-exec-location
```
Exec locations to look for: shell startup files (see the **sourcing-precision**
note below), cron (`/etc/cron.*`, `crontab`), systemd units, `.git/hooks/*`,
`package.json` `scripts` / `pre`+`postinstall`, `pyproject.toml`/`setup.py`,
`sitecustomize.py` / a dir on `sys.path`/`PYTHONPATH`, `authorized_keys`,
`.npmrc`, Dockerfile/entrypoint, app config that is `eval`'d/imported at boot.

> **Sourcing precision (critical for the edge proof).** A startup file is only an
> exec-location if the process's *actual entrypoint* sources/executes **that
> specific file**. Shell startup is not uniform:
> - **Login shell** (`bash -l`, `bash -lc`, SSH login, container `ENTRYPOINT
>   ["bash","-lc",…]`) reads the first of `~/.bash_profile`, `~/.bash_login`,
>   `~/.profile` — **NOT `~/.bashrc`** (zsh login: `~/.zprofile`).
> - **Interactive non-login shell** reads `~/.bashrc` (zsh: `~/.zshrc`).
> - `~/.bashrc` runs under a login shell only if a profile file explicitly
>   sources it (common on desktops, **absent** in minimal containers).
>
> So a write to `~/.bashrc` is NOT RCE under a `bash -lc` entrypoint; target
> `~/.bash_profile`/`~/.profile` instead. Always read the entrypoint and name the
> file it really sources.

### C3 — Env-Denylist Bypass → Tool Exec  ⇒ RCE
```
env-control (CWE-184 incomplete blocklist: PYTHONWARNINGS, NODE_OPTIONS,
             LD_PRELOAD, GIT_DIR, PIP_INDEX_URL, UV_INDEX_URL, HGRCPATH,
             CARGO_BUILD_RUSTC_WRAPPER, MAKEFLAGS, PERL5OPT, RUBYOPT, …)
  → exec-primitive (host exec env runs a subprocess that honors the var)
```
Use [`../../tools/env_denylist_fuzz.py`](../../tools/env_denylist_fuzz.py) to
enumerate variants. Matches Agent-Zero-DB pattern **D** (bypass variant) + **G3**.

### C4 — Scope Self-Escalation → Approval Bypass → Host Exec  ⇒ LPE *(Critical-13 dominant)*
```
scope-read  (low tier: pairing/inbound/login)
  → scope-write / scope-admin (CWE-863 missing or wrong check on an endpoint)
  → approval-bypass (gate skipped: timeout fallback / strict-eval miss)
  → exec-primitive / node-invoke (host exec or sandbox spawn)
```
Maps to [agent-authorization.md](../04-validate/policies/agent-authorization.md).
9/13 OpenClaw criticals. Build the trust ladder
(§"trust tier collapse" in [agent-zero-db-distill.md](../knowledge/agent-zero-db-distill.md))
and find a missing check on each arrow.

### C5 — Memory Poisoning → Later Tool Invoke  ⇒ Persistent RCE / delayed hijack
```
memory-write (A6, external input persisted unsanitized)
  → [later session] memory-read into prompt → tool-invoke → exec-primitive
```
Time-delayed C1. Must prove a *real retrieval path* reads the entry back
(see AGENT.md `memory-poisoning-no-readback`).

### C6 — Sandbox FS Bridge TOCTOU + Symlink  ⇒ Host RCE / escape
```
sandbox-fs-bridge (shared mount between sandbox container and host)
  + symlink-plant + race (CWE-367 check-then-use)
  → arbitrary-write on host → write-to-exec-location
```
Maps to [sandbox-escape.md](../04-validate/policies/sandbox-escape.md). Requires
the product to *claim* sandboxing (else it is excessive-agency, per AGENT.md
`sandbox-no-claim`).

### C7 — SSRF → Cloud Metadata → Credential Reuse  ⇒ Privilege Escalation
```
ssrf (CWE-918, attacker-controlled host)
  → arbitrary-read of 169.254.169.254 / metadata → cred-access
  → reuse credential against a privileged API → irreversible action
```

### C8 — Deserialization reachable via another primitive  ⇒ RCE
```
arbitrary-write / path-control / tool-arg
  → deser-sink (pickle.loads / yaml.load(unsafe) / unserialize on attacker bytes)
```
Only when the deserializer is genuinely unsafe (see AGENT.md `deser-safe-format`).

## 5. Composition rule (the edge test)

An edge `A → B` is valid **only** when the *product* of A literally satisfies the
*precondition* of B, demonstrated by read code — not by narrative. Examples:

- VALID: A yields `bounded-write` to `~/`; B (`write-to-exec-location`) needs a
  path sourced at login; `~/.bash_profile` is in `~/` and `bash -lc` is the
  entrypoint (proven at `Dockerfile:N`), and a login shell sources
  `~/.bash_profile` (NOT `~/.bashrc` — see C2 sourcing-precision note). Edge holds.
- INVALID: A yields write **only** under `/tmp/workspace/<uuid>/`; B needs a write
  to `~/.bashrc`. No proven path from the bounded dir to `~`. Edge fails →
  chain broken at this link → drop or downgrade to the single-link severity.

## 6. Scoring posture (consumed by judgment-agent / cvss-scoring)

- **Exploitability metrics (AV/AC/PR/UI)** come from the **entry link** — how the
  attacker first reaches the chain.
- **Impact metrics (C/I/A) + Scope** come from the **terminal link** — what the
  end state actually does. RCE/host-escape ⇒ `C:H/I:H/A:H`; crossing a
  sandbox/component boundary ⇒ `S:C`.
- **Chain confidence = min(link confidences)** (weakest link). One unproven link
  collapses the whole chain.
- **AC rises to H** when any link needs a race (CWE-367) or a non-default precondition.

See [cvss-scoring.md](../04-validate/cvss-scoring.md) §"Chained vulnerability
scoring" for default vectors.
