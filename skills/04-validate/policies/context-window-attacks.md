```xml
<policy type="context-window-attacks">

  <!--
    A10 — Context window manipulation. External content squeezes out the
    system prompt by sheer length, or by ordering, so the higher-trust
    instructions are evicted from the visible window.
    Maps to CWE-400 + OWASP LLM06.
    Lower priority than direct prompt injection because it requires a
    concrete way to demonstrate eviction, not just "long content".
  -->

  <reportable>
    <condition id="unbounded-external-concatenation">
      Code concatenates an unbounded external string (web fetch result,
      file content, tool output, scraped page) into a prompt without a
      length cap.
      Verify: locate the concatenation site; confirm no `len()` /
      `length` / `slice` / truncate before the concat; confirm the
      source can be arbitrarily large.
    </condition>
    <condition id="system-prompt-evictable-by-window">
      The total prompt length can plausibly exceed the model's effective
      context window such that the leading system prompt is dropped from
      the model's attention (by length-based truncation or by older
      messages being purged from the front).
      Verify: locate the truncation policy (e.g., `messages = messages[-N:]`
      or token-count clamp from the head). Confirm the system message is
      part of the truncated head.
    </condition>
    <condition id="head-truncation-of-system">
      A retention rule like "keep last N messages" applies to the
      messages array without pinning the system message at index 0.
      Verify: read the retention function; confirm system is not
      preserved.
    </condition>
    <condition id="external-tokens-not-counted">
      Token-budget logic counts only user messages but not tool /
      retrieval output, so external content escapes the budget.
      Verify: read the token-count code; confirm which roles it counts.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="system-pinned-and-bounded" reason="system never evicted">
      System message is pinned at position 0 of every LLM call and the
      retention policy never removes it. Plus, the inputs that make up
      the system message are themselves bounded.
      Verify: read the retention function and the system-prompt
      assembly; confirm both invariants.
    </condition>
    <condition id="external-content-clamped" reason="hard length cap">
      External content (RAG chunks, tool output, fetched documents) is
      hard-capped to a per-piece byte budget and per-turn total budget
      that fits well inside the model's window with system prompt.
      Verify: read the clamp; check that overflow drops the content,
      not the system prompt.
    </condition>
    <condition id="no-system-prompt-claim" reason="no trust delta to evict">
      The agent does not rely on a system prompt for security-relevant
      behavior (e.g., a research notebook agent where the user owns the
      whole context).
      Verify: read what the system message contains; confirm it has no
      authorization / safety statements whose eviction would matter.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you locate every place external content lands inside the LLM call's messages?</item>
    <item>Did you read the truncation / retention policy and confirm whether the system message is pinned?</item>
    <item>Did you check whether the token-budget logic accounts for tool output / RAG chunks?</item>
    <item>Did you produce a concrete demonstration that the system message can be evicted (not just a theoretical concern)?</item>
  </verify>

</policy>
```
