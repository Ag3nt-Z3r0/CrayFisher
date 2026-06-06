# Sealed Ground Truth — Arm A (positive control / sensitivity)

> SEALED ORACLE — authored BEFORE the scan. The scan agents (recon/defender/
> judgment) MUST NOT receive this file. It is the human-authored description of
> the planted chain, used only by the post-scan scoring step.

> **ERRATUM (added 2026-06-06, after end-to-end PoC):** the sealed text below
> names `~/.bashrc` as the exec-location. The PoC proved that a *login* shell
> (`bash -lc`, the Dockerfile:7 entrypoint) sources `~/.bash_profile` /
> `~/.profile`, **not** `~/.bashrc` (the latter is for interactive non-login
> shells). The chain is genuinely exploitable with the terminal file corrected
> to `~/.bash_profile`/`~/.profile` (RCE confirmed). The original `~/.bashrc`
> text is preserved unedited to keep the oracle "sealed"; treat the exec-location
> as `~/.bash_profile`. Lesson: a write-to-exec-location link must name a file
> the *specific* entrypoint actually sources.

**Fixture:** `validation/fixtures/armA-mcp/` — a minimal MCP stdio server.
**Pinned routing expectation:** `is_agent_target = true`, `agent_frameworks = ["mcp"]`
(MCP signature strings present: `@modelcontextprotocol/sdk`, `McpServer`,
`StdioServerTransport` in `server.ts`).

## Planted chain (template C2 — bounded/arbitrary write → write-to-exec-location → RCE)

**Terminal impact:** host code execution (RCE) on next container start.

### Link 1 — arbitrary-write via unsanitized tool-arg path-control
- **Evidence:** `server.ts:28` → `const dest = path.resolve(WORKSPACE, name);`
  followed by `server.ts:29` → `fs.writeFileSync(dest, content);`
- **Primitive:** `arbitrary-write` (+ `path-control`).
- **Attacker control (TAINT, tag-independent):** `name` is an MCP `save_note`
  tool argument supplied verbatim by the client (`server.ts:20-27`), reaching
  `path.resolve(WORKSPACE, name)` with **no** `basename`/normalization/`../`
  guard. This source→sink reachability is established by reading the tool
  handler, NOT by the `chain-arbitrary-write-ts` Semgrep tag. (The tag may also
  fire on line 29, but the attacker-control fact is manual taint — satisfies the
  §3 anti-closed-loop rule.)

### Edge (Link 1 → Link 2) — composition proof
- `WORKSPACE = path.join(os.homedir(), "agent-ws")` (`server.ts:11`). Because
  `name` is not sanitized, `path.resolve(WORKSPACE, "../.bashrc")` resolves to
  `~/.bashrc` — Link 1's product (write to an attacker-chosen path) satisfies
  Link 2's precondition (write to a path sourced at startup).

### Link 2 — write-to-exec-location (terminal, RCE)
- **Evidence:** `Dockerfile:7` → `ENTRYPOINT ["/bin/bash", "-lc", "node server.js"]`
- **Primitive:** `write-to-exec-location`.
- **Tag-independent:** there is **no literal `.bashrc` string** anywhere in the
  fixture, so the generic `chain-write-to-exec-location` Semgrep regex does NOT
  fire here. The exec-location fact is derived purely by reasoning: a login
  shell (`bash -lc`) sources `~/.bashrc` on every container start, so a payload
  written to `~/.bashrc` executes as the agent user. **This link is established
  with zero Semgrep-tag input** — it alone satisfies the leakage criterion.

## Expected pipeline behavior (PASS condition for Arm A)
- Recon assembles a `CHAIN` finding (template C2), `terminal_impact = RCE`, with
  per-link `Evidence:<file>:<line>` for Link 1 (server.ts:28-29) and Link 2
  (Dockerfile:7) and an `edge_proof` citing WORKSPACE (server.ts:11).
- `confidence_base = min(link confidences)` (weakest link).
- Defender does NOT rebut (no broken link/edge).
- Judgment emits a chained CVSS: entry exploitability (MCP client = AV:N, no
  approval gate → PR:N/UI:N) + terminal host RCE (`S:C/C:H/I:H/A:H`).
- ≥1 link (Link 2) is established independently of any `chain_primitive` tag.

## FAIL signatures
- No `CHAIN` finding emitted (over-suppression / chaining broken).
- Chain emitted but every link relies solely on a `chain_primitive` Semgrep tag
  (closed-loop → INCONCLUSIVE for the leakage criterion).
