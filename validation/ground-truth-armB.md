# Sealed Ground Truth — Arm B (negative control / specificity)

> SEALED ORACLE — authored BEFORE the scan. The scan agents MUST NOT receive
> this file. Used only by the post-scan scoring step.

**Fixture:** `validation/fixtures/armB-mcp/` — identical to Arm A except the write
path is sanitized.
**Pinned routing expectation:** `is_agent_target = true`, `agent_frameworks = ["mcp"]`.

## Primitives present but DELIBERATELY NON-COMPOSABLE

The same two primitives exist, but the composition **edge is broken** so no
chain can form:

### Link 1 candidate — bounded-write (NOT arbitrary-write)
- **Evidence:** `server.ts:28-30`:
  ```
  const safe = path.basename(name);     // strips all directory components
  const dest = path.join(WORKSPACE, safe);
  fs.writeFileSync(dest, content);
  ```
- `path.basename(name)` collapses `../.bashrc`, `/etc/cron.d/x`, etc. to a bare
  file name, so the write is **confined to WORKSPACE** (`~/agent-ws`). The
  primitive is `bounded-write`, not `arbitrary-write`.

### Link 2 candidate — write-to-exec-location (same as Arm A)
- `Dockerfile:7` → `ENTRYPOINT ["/bin/bash", "-lc", "node server.js"]` (login
  shell sources `~/.bashrc`).

### Broken edge — WHY NO CHAIN
- Link 1's product is a write **only** under `~/agent-ws/<basename>`. Link 2's
  precondition needs a write to a path sourced at startup (`~/.bashrc`, outside
  `~/agent-ws`). `path.basename` guarantees the write cannot reach `~/.bashrc`,
  so **Link 1's product does NOT satisfy Link 2's precondition**. The edge is
  unprovable (catalog §5 INVALID example: bounded-write treated as
  arbitrary-write without escape proof).

## Expected pipeline behavior (PASS condition for Arm B)
- **Zero `CHAIN` findings emitted.** The `chain-arbitrary-write-ts` Semgrep tag
  may still fire on `fs.writeFileSync` (line 30), and a single bounded-write
  finding is acceptable — but the chaining step MUST decline to compose it with
  the exec-location link because the edge cannot be proven.
- Defender (if a chain were proposed) rebuts via `precondition-not-provided`
  (exploit-chain.md `<not_reportable>`), or recon never assembles it.

## FAIL signature
- Any `CHAIN` finding joining the bounded-write to the exec-location link =
  false-positive / speculative-link defect (specificity failure).
