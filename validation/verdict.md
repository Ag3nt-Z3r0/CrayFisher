# Dogfood Validation Verdict — CrayFisher Exploit-Chaining (Phase 3-C)

**Date:** 2026-06-06 · **Plan:** `.omc/plans/dogfood-openclaw-chain-validation.md`
**Scan:** Multi-Agent (Recon→Defender→Judgment) — workflow `wf_e3fe133d-bc1`, 9 agents.
**Capability under test:** `skills/03-taint/exploit-chaining.md` (Phase 3-C) composing primitives into critical chains.

## Overall: **PASS** (sensitivity + specificity validated) with **one INCONCLUSIVE dimension** (re-discovery on live-vulnerable code) and a list of confirmed tool gaps.

The scan agents never received the sealed ground-truth (`validation/ground-truth-arm{A,B}.md`) or the Critical-13 oracle.

---

## Per-criterion results (plan §6)

| Criterion | Result | Evidence |
|---|---|---|
| **G-ROUTE** (routing pinned per arm) | ✅ resolved | A/B pinned `true` & observed `true` (`reports/*/recon/detect_stack.json`). C pinned `false`/legacy in plan, **observed `true` (mcp)** → routing surprise, re-classified as agent arm (logged below). |
| **G-TOOLHEALTH** (no zero-result accepted without CLEAN) | ✅ held | All probes returned FINDINGS (stderr 0). Probe `ulimit -v` defect found & fixed mid-run (see gaps). |
| **Sensitivity — Arm A (positive control)** | ✅ PASS | `CHAIN-001` (C2, RCE) emitted: link1 `server.ts:25` arbitrary-write + link2 `Dockerfile:7` write-to-exec-location, edge proof `server.ts:10` (WORKSPACE under `$HOME`). Defender CONFIRMED. Judgment **CVSS 10.0** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, boost applied. **Matches oracle.** |
| **Leakage / anti-closed-loop — Arm A** | ✅ PASS | `has_non_tag_link=true`: link2 established by **manual reading of the Dockerfile** (`evidence_source=manual-taint`), not a `chain_primitive` tag (confirmed: no exec-location tag fired on the fixture after the `.bashrc`-comment fix). |
| **Specificity — Arm B (negative control)** | ✅ PASS | **0 chains emitted.** The bounded-write→exec edge correctly rebutted (`precondition-not-provided`): `path.basename` (`server.ts:25`) confines writes to `~/agent-ws`, cannot reach `~/.bashrc`; agent also verified no symlink-plant primitive exists to bridge. Matches oracle. |
| **Specificity on real code — Arm C (OpenClaw gateway)** | ✅ PASS (strong) | **0 chains emitted on patched HEAD.** Agent independently located `server.silent-scope-upgrade-reconnect.poc.test.ts` and traced the **3-layer fix** of the dominant C4 pattern with exact citations: scope-upgrade detection sound (`operator-scope-compat.ts:19-55`), silent-approval forced off (`message-handler.ts:1263-1268`), token issuance gated (`device-pairing.ts:1078-1086`). C3 env/exec entry requires `operator.admin` (`trusted-actor-step`). No fabrication, no oracle bleed-through. |
| **Re-discovery / sensitivity on real vulnerable code — Arm C** | ⚠️ INCONCLUSIVE | The clone is current **patched HEAD** (2026-06); the Critical-13 advisories (2026-02..04) are **fixed** in it (defender cited the patch lines). So 0 chains is *expected* and does NOT prove 3-C would re-discover them. **To close: re-run arm C against a pre-fix revision** (e.g. a commit/tag predating each GHSA). Logged as follow-up. |

**Interpretation.** Arm A proves the pipeline *assembles* a real RCE chain end-to-end with per-link evidence, a true edge proof, a tag-independent link, and a correct chained CVSS. Arms B and C prove it *does not over-claim* — declining a broken-edge synthetic chain and correctly reading real patches on production code without hallucinating the known criticals. The only unproven dimension is re-discovery on live-vulnerable code, blocked solely by scanning patched HEAD.

---

## Routing surprise (G-ROUTE, logged)
Plan §3 pinned the "large TS monorepo" as `is_agent_target=false` (legacy sub-mode). Observed: OpenClaw → `is_agent_target=true`, `agent_frameworks=["mcp"]` (`reports/openclaw/recon/detect_stack.json`). OpenClaw embeds MCP signatures, so it routes to the **full agent path** (3-B + 3-C + judgment boost), not legacy. Re-classified as an agent arm; the planned "legacy-path chaining" sub-test was therefore **not** exercised and remains open (would need a genuinely non-agent target).

---

## Confirmed CrayFisher tool/skill gaps (the highest-value dogfood output)
Detail + repro in `troubleshooting/openclaw_20260606_tool-gaps.xml`. Summary:
1. **`semgrep_run.py` snippet field mis-captured** — reported `snippet:"requires login"` instead of the real sink line on every fixture finding. Reproduced across arms A & B. *Real bug.*
2. **`agent_trust_graph.py` blind to tool-arg→sink** — returns empty (0 nodes/edges) on MCP targets; its promotion-edge model misses pure `tool-arg → filesystem-write` primitives, so arm A's RCE had zero trust-graph support.
3. **`chain-write-to-exec-location` over-fires** — matched a JSDoc comment (`config-reload.ts:39`) and an object field (`auth.ts:251`) in the gateway; generic regex needs context guards.
4. **`architecture_map.py` weak/mislabeled** — empty `approval_gates`/`sandbox_sites` give no "safe vs absent" signal; mislabeled generic `registry.invoke(...)`/WS test helpers as `langchain` LLM calls.
5. **`find_entries.py` returns 0** on MCP `server.tool` and gateway WS/HTTP control plane — attacker entry surface had to be found manually.
6. **`mcp-tool-result-returned-raw` overstates impact** — fires even when only a sanitized substring is reflected (arm B).

None of these blocked the validation, but #1 and #2 directly weaken real scans and are the top fix candidates.

---

## Artifacts
- `reports/{armA-mcp,armB-mcp,openclaw}/recon/*.json` — recon anchors.
- `reports/{armA-mcp,armB-mcp,openclaw}/chains-*.json` — emitted chains + defender + judgment per arm.
- `validation/ground-truth-arm{A,B}.md` — sealed oracle (withheld from scan agents).
- `validation/toolhealth.sh` — G-TOOLHEALTH probe (raw-semgrep, `--max-memory`).
- `troubleshooting/openclaw_20260606_tool-gaps.xml` — gap log.

## Follow-ups
1. **Re-run arm C on a pre-fix OpenClaw revision** to close the re-discovery INCONCLUSIVE (the one dimension not validated). — *open*
2. ~~Fix tool gaps~~ — **DONE & verified (2026-06-06).** All six gaps + the `.bashrc` precision fixed and re-tested:
   - `semgrep_run.py` snippet now reads the real match line (was `"requires login"`).
   - `agent_trust_graph.py` now emits `tool-arg→sink` edges (armA: `name→path-control`, `content→arbitrary-write`); original promotion/node output preserved (nodes=500, layers unchanged).
   - `find_entries.py` full-text scan now finds MCP `server.tool` (armA 0→1) + gateway WS handlers (0→12), deduped.
   - `architecture_map.py` langchain mislabels 0; `_meta.files_scanned` added.
   - `chain-write-to-exec-location` → WARNING/hint + login-vs-interactive precision; `mcp-tool-result-returned-raw` → INFO/LOW with sanitized-vs-raw caveat; `semgrep --validate` = 95 rules valid.
   - Catalog C2 + `exploit-chaining.md` now carry the **sourcing-precision** rule (login shell sources `.bash_profile`/`.profile`, not `.bashrc`).
3. Add a genuinely non-agent target to exercise the legacy-path chaining sub-test. — *open*

---

## Post-scan end-to-end PoC (2026-06-06)

### (a) Arm A chain is a genuine RCE — CONFIRMED
Ran the exact `server.ts` write logic + `Dockerfile:7` `bash -lc` entrypoint in a
sandbox `HOME` (real home untouched):
- traversal `name="../.bash_profile"` → `path.resolve(WORKSPACE,name)` escapes
  `~/agent-ws` to `~/.bash_profile` → `bash -lc` sources it →
  `[PWNED] code exec as <user>`. RCE confirmed (also via `~/.profile`).
- Arm B (`path.basename`) with the same attack → write confined to
  `~/agent-ws/.bash_profile`, **not sourced** → no RCE. Specificity confirmed live.
- **Erratum:** the planted oracle named `~/.bashrc`; a *login* shell sources
  `~/.bash_profile`/`~/.profile`, not `~/.bashrc`. The chain holds with the
  corrected dotfile (see `ground-truth-armA.md` erratum). The recon agent shared
  the same `~/.bashrc` imprecision — a methodology note: a write-to-exec-location
  link must name a file the *specific* entrypoint sources.

### (b) Is the OpenClaw candidate applicable to LATEST OpenClaw? — NO (patched)
Latest = `main @ 520992a1`, 2026-06-05 (current HEAD). The dominant C4
scope-self-escalation candidate is **not exploitable**, proven in code:
- `message-handler.ts:1263-1268` — `silent: reason === "scope-upgrade" ? false : …`
  (a scope-upgrade can never be auto-approved silently).
- `device-pairing.ts` `scopesWithinApprovedDeviceBaseline` → token issuance
  returns `null` for scopes outside the approved baseline (defense in depth).
- Regression test `server.silent-scope-upgrade-reconnect.poc.test.ts` asserts a
  `operator.read` device requesting `operator.admin` ends with
  `approvedScopes === ["operator.read"]` and `tokens.operator.scopes ===
  ["operator.read"]` — no elevation.
**Conclusion:** zero real OpenClaw vulnerabilities were found; the historical
Critical-13 are patched in latest HEAD. The only confirmed-exploitable finding is
the synthetic Arm A positive control (by construction).
