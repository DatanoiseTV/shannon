# Security model

`shannon` is a privileged process that reads plaintext network payloads. Treat it
accordingly. This document describes what it can see, what it cannot see, what
privileges it needs, and how to report vulnerabilities.

## Threat model

`shannon` is **not** a security tool. It is an observability tool that, by virtue
of running with kernel privileges, has access to sensitive data. Its posture is:

- **Trusted operator.** The user running `shannon` is assumed to already have
  privileged access to the host. `shannon` does not bypass access control; it
  requires capabilities equivalent to root.
- **Untrusted traffic.** Every byte read from the kernel is treated as
  adversarial input. Parsers must never panic on malformed data, never
  over-read a buffer, and never recurse without bounds.
- **Leakage is the threat.** The primary risk is `shannon` displaying,
  logging, or exporting data the operator did not intend to expose.

## What `shannon` can see

- Plaintext of every TCP byte sent or received by processes on the host,
  including TLS connections that terminate in a supported userland library
  (`libssl`, `boringssl` via uprobes). This means HTTP request bodies,
  database queries, Redis commands, cookies, bearer tokens, and any other
  data flowing through those libraries.
- 4-tuples (saddr, sport, daddr, dport) of every TCP connection.
- Process context (PID, TGID, comm, cgroup) for each event.
- DNS questions and answers sent via `udp_sendmsg` on port 53.

## What `shannon` cannot see (yet)

- Kernel-terminated TLS (`ktls`) plaintext — we see the ciphertext only.
- TLS done in a runtime not currently hooked (Go's `crypto/tls`, Rust's
  `rustls`, JVM's JSSE, .NET's SChannel). These are planned.
- QUIC. Planned.
- Payload of TCP sent via `splice`/`sendfile` syscalls that never touch
  userland buffers. Mostly irrelevant for L7.
- Anything a process does that does not cross the kernel (e.g. pure
  userland IPC, shared-memory).

## Required privileges

Minimum on kernel ≥ 5.8:

```
CAP_BPF            load / verify BPF programs
CAP_PERFMON        attach kprobes / tracepoints / uprobes
CAP_NET_ADMIN      open perf ring buffers
CAP_SYS_RESOURCE   rlimit adjustments on older kernels (optional ≥ 5.11)
```

On older kernels, `CAP_SYS_ADMIN` subsumes all of the above. `shannon doctor`
reports the exact set required by your kernel.

`shannon` **never** requests capabilities it doesn't need. It drops ambient and
inheritable sets on startup and, where possible, drops effective capabilities
after program load and attach. (This is a defense-in-depth measure; the process
still has file access for TUI/log output.)

## Redaction

The default redaction mode (`--redact auto`) removes:

- HTTP headers: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
  `X-Api-Key`, `X-Auth-Token`, and any header matching `*token*`, `*secret*`,
  `*password*` case-insensitively.
- Query-string parameters matching the same patterns.
- Postgres `PasswordMessage` frames.
- Redis `AUTH` commands.
- MySQL `COM_CHANGE_USER` and auth-handshake packets.

`--redact strict` additionally removes all headers and all bodies, keeping only
the method / verb / status / size / timing.

`--redact off` disables redaction entirely. It is intentionally awkward to
enable — it must be set on the CLI on every invocation; there is no global
`--redact off` config option.

## Reporting a vulnerability

Please report vulnerabilities privately by opening a GitHub Security Advisory.
Do not file a public issue. We aim to acknowledge within 3 business days and
publish a fix within 30 days, coordinating disclosure with the reporter.

Out of scope:
- Reports that require the operator to deliberately disable redaction.
- Reports that require a pre-existing root shell (`shannon` itself already
  requires privileges equivalent to root).
- Denial-of-service via deliberately malformed probes — `shannon` will log the
  malformed frame and skip it; this is by design.

In scope:
- Parser panics / crashes on crafted network payloads.
- Out-of-bounds reads of kernel or userspace memory triggered by payload.
- Redaction escapes (secret material appearing in output despite `--redact auto`
  or `strict`).
- Capability escalation or leak through `shannon`.
