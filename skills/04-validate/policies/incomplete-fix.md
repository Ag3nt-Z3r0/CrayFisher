```xml
<policy type="incomplete-fix">

  <!--
    The five Agent-Zero-DB incomplete-fix patterns, distilled into one
    reportability gate. A finding is reportable only if it ties to one
    of these patterns with concrete evidence from the patch / adjacent
    code, not just intuition that "the fix looked shallow".

    Patterns (see skills/knowledge/agent-zero-db-distill.md):
      A — Re-emergence (same CVE, root cause untouched)
      B — Adjacent miss (sibling function in same module)
      C — Deeper trigger (1st patch blocks surface, earlier layer reachable)
      D — Bypass variant (denylist + new token)
      E — Workspace multi-vector (policy enforced per-channel/plugin/tool)
  -->

  <reportable>
    <condition id="pattern-a-re-emergence">
      The targeted code is the *same file and same function* as a
      previously-patched CVE/GHSA, the bytes around the previous patch
      do not address the root cause, and a new triggering path exists.
      Verify: cite the previous CVE/GHSA id from a code comment, commit
      message, or `tools/incomplete_fix_scan.py` output. Show the new
      triggering path with file:line.
    </condition>
    <condition id="pattern-b-adjacent-miss">
      A previously-patched function has a *sibling function in the same
      file* with the identical defect (same signature shape, same sink,
      missing the same check).
      Verify: locate the original patched function from git blame; find
      the sibling; show why the patch did not apply.
    </condition>
    <condition id="pattern-c-deeper-trigger">
      A previously-patched entry point now blocks the trigger, but an
      *earlier* layer (parser, pre-auth body handler, middleware) reaches
      the same sink without invoking the new check.
      Verify: show the patched check site; show the earlier layer that
      bypasses it; trace a request path that reaches the sink via the
      earlier layer.
    </condition>
    <condition id="pattern-d-bypass-variant">
      A denylist / blocklist style policy is expanded by the previous
      patch, but a new bypass token / variant exists.
      Verify: enumerate the denylist contents at the patch site; cite
      the new token. For env vars use `tools/env_denylist_fuzz.py` /
      `skills/knowledge/openclaw-ghsa-seed.json :
      env_denylist_known_bypass_seeds` as the seed list.
    </condition>
    <condition id="pattern-e-workspace-multi-vector">
      A policy keyword (e.g., `workspace-only`, `allow_outside_workspace
      = false`) appears in multiple file paths with separate enforcement
      bodies; one vector enforces, another does not.
      Verify: grep for the policy keyword; list all enforcement sites;
      show which vector is missing.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="pattern-claimed-without-evidence" reason="speculation">
      The finding asserts "this looks like an incomplete fix" without
      tying to a concrete prior patch / GHSA / commit.
      Verify: confirm no prior advisory or commit reference is present
      in the finding.
    </condition>
    <condition id="single-fix-shallow-but-no-bypass" reason="aesthetic, not exploit">
      The patch looks shallow but no new exploit path is demonstrated.
      Verify: confirm the finding does not include a working
      reproduction.
    </condition>
    <condition id="root-cause-already-addressed" reason="actually complete">
      The previous patch addresses the root cause architecturally
      (centralized check, schema clamp, allowlist replaces denylist),
      and the patterns above do not apply.
      Verify: read the centralized check; confirm it covers every path
      the policy gates.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you cite a concrete prior advisory (CVE / GHSA / commit) that this finding extends?</item>
    <item>Did you match the finding to one of patterns A–E and show the matching evidence?</item>
    <item>Did you reproduce the bypass (or show a code-level path that does)?</item>
    <item>Did you check whether the previous fix was a one-shot or a centralized refactor?</item>
  </verify>

</policy>
```
