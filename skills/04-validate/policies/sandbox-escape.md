```xml
<policy type="sandbox-escape">

  <!--
    Sandbox escape. Two of the 13 Critical advisories in the OpenClaw
    corpus are this pattern (TOCTOU + heartbeat context inheritance).
    Maps to CWE-269 + CWE-367 (TOCTOU) + CWE-59 (Symlink Following).
  -->

  <reportable>
    <condition id="docker-socket-mounted-into-sandbox">
      The sandbox container has `/var/run/docker.sock` (or equivalent
      host control plane) mounted, so the sandbox can spawn / manipulate
      host containers.
      Verify: read `Dockerfile.sandbox*` or compose file. Confirm the
      mount. The control-plane mount means sandbox == host.
    </condition>
    <condition id="fs-bridge-toctou">
      An action checks a path (existence / permission / link) and then
      operates on the same path in a separate syscall, with the sandbox
      having FS access between the check and the use.
      Verify: locate the `stat`/`exists`/`isFile` call paired with the
      `read`/`write`/`exec` call; confirm both use the path (not a stable
      fd); confirm the sandbox can rewrite the path between.
    </condition>
    <condition id="symlink-follow-without-clamp">
      Filesystem code follows symlinks without restricting the resolved
      path to a workspace prefix.
      Verify: read the file-open / read / write site. Confirm
      `O_NOFOLLOW` is absent, or `realpath` is computed but not compared
      against an allowlist prefix.
    </condition>
    <condition id="sandbox-auto-fallback-to-host">
      A `sandbox="auto"` config falls back to host execution when no
      sandbox runtime is available, without telling the operator or
      blocking the action.
      Verify: read the sandbox-selection function; confirm the fallback
      branch executes on host and does not gate behind an explicit
      opt-in.
    </condition>
    <condition id="heartbeat-or-context-inheritance">
      Long-lived background processes (heartbeat, healthcheck, session
      refresh) inherit the host's environment / credentials, and code
      paths reachable from the sandbox can wake or steer them.
      Verify: locate the background process spawn. Confirm what context
      it inherits and what sandbox-side input can reach it.
    </condition>
    <condition id="host-network-or-mount-from-sandbox">
      The sandbox has access to the host network (Docker `host` network
      mode, or shared net namespace) or to a bind-mounted host directory.
      Verify: read sandbox runtime args / container manifest.
    </condition>
  </reportable>

  <not_reportable>
    <condition id="no-sandbox-no-claim" reason="no sandbox is claimed">
      The product makes no claim of sandboxing — tools run directly on
      the host with the user's privilege. The relevant policy here is
      excessive-agency, not sandbox-escape.
      Verify: confirm no sandbox layer exists and the README does not
      claim one.
    </condition>
    <condition id="strong-isolation-runtime" reason="hypervisor isolation">
      Sandbox uses a hypervisor-class isolation runtime (Firecracker,
      gVisor in strict mode, e2b) with no host bind-mounts, no host
      socket, no host network namespace, no shared kernel surface.
      Verify: read the runtime config; cross-check against the runtime's
      documented escape model.
    </condition>
    <condition id="path-resolved-with-fd" reason="syscall-safe">
      File operations use *at family of syscalls with a stable directory
      fd, or use canonical-path-then-compare-prefix-then-open with no
      window for path mutation.
      Verify: read the file-op code; confirm fd-based or atomic resolution.
    </condition>
  </not_reportable>

  <verify>
    <item>Did you find the sandbox runtime declaration and read it (Dockerfile, runtime config, library API)?</item>
    <item>Did you check for host-control-plane mounts (docker.sock, /proc, host network)?</item>
    <item>Did you read every file-access site reachable from inside the sandbox?</item>
    <item>Did you check whether `sandbox="auto"` has a silent host fallback?</item>
  </verify>

</policy>
```
