# Security Policy

## The bridge is a powerful authenticated local control channel

The x64dbg plugin in this project exposes an HTTP bridge that the Python MCP
server talks to. By design it:

- **Binds to loopback only** (`127.0.0.1`), so it is not reachable from other hosts.
- **Rejects non-loopback authorities.** Any supplied `Host` or `Origin` whose
  authority is not loopback is refused, which blocks remote DNS-rebinding and
  browser-based requests from non-loopback origins.
- **Requires a fresh 256-bit bearer token.** The plugin generates it after a
  successful loopback bind and publishes a hidden descriptor under
  `%LOCALAPPDATA%\x64dbgMCP` with a protected DACL for the owner, SYSTEM, and
  Administrators. It rotates when the debugger or HTTP bridge restarts.
- **Binds authentication to identity.** The descriptor records PID, process
  creation time, architecture, port, and immutable bridge instance ID. Python
  verifies all of them against authenticated `Bridge/Hello` protocol v3.
- **Does not leak transport credentials.** Python accepts only a loopback root
  URL, ignores proxy/NETRC environment state, disables redirects, sends the
  token only in `X-MCP-Auth-Token`, and redacts token fields from logs.
- **Guards mutations separately.** Authentication does not replace bridge,
  session, PID/generation, or optional event-sequence compare-and-swap guards.
  A shared route-policy SHA prevents Python/native guard drift.

### What this means for you

- The token blocks blind/browser access and other Windows users that cannot read
  the descriptor. It is **not** a security boundary against a process already
  running as your Windows user: same-user code may read your files, inspect your
  processes, or inject into them.
- A token holder has the bridge's full debugger authority, including raw
  `ExecCommand`, process-memory reads/writes, and execution control. Route/session
  guards prevent stale or accidental mutations; tool profiles only reduce MCP
  discovery. Neither is authorization against a malicious authenticated caller.
- **Do not run the bridge on shared, multi-user, or untrusted machines**, and do
  not run it while untrusted local software is active.
- Analyze malware only inside a disposable VM that you already treat as
  compromised.
- The listening port (default `8888`) may be changed. The descriptor is matched
  to that exact port; changing it is configuration, not a security control.

If you need isolation from analyzed code, use a disposable VM and a dedicated
user boundary. Never place token descriptor contents in issue reports.

## Reporting a vulnerability

Please report anything that could put users at risk **privately** — open a GitHub
security advisory or a private channel to the maintainers rather than a public
issue. Include reproduction steps and the affected commit/version.
