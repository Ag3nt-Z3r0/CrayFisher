```xml
<policy type="supply-chain-plugin">

  <!--
    Supply-chain attack on plugin / extension loaders.
    OWASP LLM05 (5.8% of corpus, 27 advisories) + LLM07 (10.2%, 48).
    Maps to CWE-1357 (Reliance on Untrusted Component).
  -->

  <reportable>
    <condition id="plugin-fetched-no-integrity">
      The product fetches a plugin / extension / agent definition from a
      remote source and loads it without verifying signature, hash, or
      pinned version.
      Verify: locate the loader (`fetch`, `requests.get`, `npm install`,
      `pip install`, custom downloader). Confirm no signature / hash /
      lockfile pin check between download and load.
    </condition>
    <condition id="plugin-source-attacker-influenceable">
      The plugin URL / package name / version is selected based on
      attacker-influenceable input (user query, channel payload, an LLM
      response).
      Verify: trace the plugin identifier back to a literal-or-input
      source.
    </condition>
    <condition id="marketplace-fetch-via-mutable-tag">
      Plugin fetch uses a mutable tag (`latest`, `main`, `dev`) instead
      of a content-pinned identifier.
      Verify: read the fetch URL template / config; confirm mutable tag.
    </condition>
    <condition id="dynamic-import-from-disk-write">
      A code path writes a file to disk, then imports / requires / evals
      that file in the same process.
      Verify: trace write site to import site. Confirm same file, no
      integrity check between.
    </condition>
    <condition id="post-install-hook-allowed">
      Plugin format permits a post-install hook that runs arbitrary code
      with the host user's privilege.
      Verify: read the install flow; confirm hooks are honored without
      a sandbox.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="signed-and-verified" reason="signature gate">
      Each plugin is signed; signature is verified by the loader against
      an operator-controlled public key; bad signature blocks load.
      Verify: read the signature-verification call; confirm it raises /
      returns false-y on mismatch and the loader honors the result.
    </condition>
    <condition id="immutable-pin" reason="content-addressable">
      Plugins are pinned by content hash (sha256, ipfs cid, sigstore
      digest) and the loader refuses any other reference shape.
      Verify: read the loader's identifier parser.
    </condition>
    <condition id="sandbox-isolates-plugin" reason="contained execution">
      Plugins run in a separate process / container with no privilege
      to affect host or the agent's own state.
      Verify: read the spawn / IPC code; confirm the boundary.
    </condition>
    <condition id="loader-disabled-by-default" reason="off-by-default">
      The remote-fetch path is disabled by default and requires explicit
      operator opt-in (a non-default flag).
      Verify: read the loader's entry-condition. Confirm the default
      configuration does not exercise the path.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you locate every code path that loads code from outside the repo (HTTP fetch, package install, dynamic import, eval-from-file)?</item>
    <item>Did you check the integrity gate for each path (signature, hash, pin)?</item>
    <item>Did you check whether the plugin source identifier is attacker-influenceable?</item>
    <item>Did you check whether post-install hooks are permitted?</item>
  </verify>

</policy>
```
