# shannon

> Named after Claude Shannon. Turns a stream of bytes on a wire into meaning you can read.

`shannon` is a zero-instrumentation L7 observability tool for Linux. Drop a single
binary on a host (or a Kubernetes node) and see, in real time, every HTTP, gRPC,
Postgres, Redis, MySQL and DNS request the machine is making — including requests
over TLS, without configuring any keys.

It does this with eBPF: kernel probes on TCP, uprobes on `libssl` (and other TLS
runtimes), and protocol parsers in userspace. No sidecars. No application changes.
No private keys. No kernel modules. ~1% CPU on typical workloads.

## Status

Pre-alpha. Kernel ≥ 5.8 with BTF is required. Tested on Debian 13 / kernel 6.12.
API and event schema are **not** stable.

## Quick start

```bash
# interactive TUI (default)
sudo shannon

# just postgres queries from pid 1234
sudo shannon trace -p 1234 --protocol postgres

# top-like view, sorted by p99
sudo shannon top --sort p99

# pre-flight: is this box supported?
shannon doctor

# record everything to a file (zstd-compressed JSONL)
sudo shannon record -o capture.jsonl.zst --rotate 100M

# play it back later (pipe to jq, feed the TUI, or summarise)
shannon trace  --replay capture.jsonl.zst
shannon analyze capture.jsonl.zst
```

## Install

Binary releases are not yet published. Build from source:

```bash
git clone https://github.com/<owner>/shannon
cd shannon
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo xtask build --release
sudo ./target/release/shannon doctor
```

See [docs/architecture.md](docs/architecture.md) for how it works and
[SECURITY.md](SECURITY.md) for what it can and cannot see.

## What it decodes today

| Protocol          | Status | Notes                                                       |
|-------------------|--------|-------------------------------------------------------------|
| HTTP/1.x          | ✅     | Request/response, headers, bodies                          |
| HTTP/2            | ✅     | HPACK, per-stream framing                                  |
| gRPC              | ✅     | On HTTP/2: method, status; full decode with `--proto`      |
| WebSocket         | ✅     | RFC 6455 frames, follows HTTP/1.1 `Upgrade` handshake      |
| Socket.IO / Engine.IO | ✅ | On WebSocket: event name, namespace, JSON args, ack IDs    |
| Postgres          | ✅     | Startup, Simple / Extended query                           |
| Redis             | ✅     | RESP2 + RESP3                                              |
| MySQL             | ✅     | COM_QUERY, COM_STMT_PREPARE/EXECUTE                        |
| DNS               | ✅     | Questions + answers (udp/53)                               |
| Kafka wire        | ✅     | Produce, Fetch, Metadata, OffsetCommit; API versions 0–12  |
| MongoDB wire      | ✅     | `OP_MSG`, BSON decode                                      |
| TLS — OpenSSL     | ✅     | `SSL_{read,write,read_ex,write_ex}` uprobes on libssl      |
| TLS — BoringSSL   | ✅     | Same symbols as libssl                                     |
| TLS — GnuTLS      | ✅     | `gnutls_record_{send,recv}` uprobes                        |
| TLS — NSS         | ✅     | `PR_Read` / `PR_Write` + `ssl3_SendPlainText` uprobes      |
| TLS — Go          | ✅     | Symbol-scan `/proc/<pid>/exe`; `crypto/tls.(*Conn).{R,W}`  |
| QUIC              | Partial| Packet type + SNI from Initial; encrypted payload deferred |

Each connection carries a protocol state machine that can *upgrade itself*:
HTTP/1.1 → WebSocket (on `101 Switching Protocols`) → Socket.IO (on event
frames), and HTTP/2 → gRPC (on `application/grpc`). Nothing you configure.

Deferred to v0.2: Rust `rustls`, Java JSSE, QUIC payload decryption.

## Privacy

`shannon` sees plaintext payloads. Redaction is **on by default** (`--redact auto`)
and strips `Authorization`, `Cookie`, `Set-Cookie`, and query-string params matching
`*token*|*password*|*secret*|api_key`. Run `shannon trace --redact strict` to strip
all headers and bodies. You opt into visibility with `--redact off`; never the
other way around. See [SECURITY.md](SECURITY.md).

## Use cases

- **Incident response**. "Why is the billing service slow?" → `sudo shannon
  top --sort p99 --group-by endpoint` on the affected node. No redeploy,
  no sidecar, no code change.
- **Debugging microservice calls**. See exact HTTP requests one service is
  making to another, including headers and body, even over TLS, without
  touching either service's code.
- **Tracing production bugs that don't reproduce locally**. Capture real
  traffic with `shannon record -o live.jsonl.zst`, ship the file to a
  dev box, replay with `shannon trace --replay`.
- **Security posture audits**. Which processes talk to which external
  IPs, and what credentials flow? `shannon trace --peer 0.0.0.0/0
  --redact off --protocol http` (use responsibly — see disclaimer).
- **Understanding a black-box binary**. Point shannon at a pid with
  `shannon trace -p $(pidof mysterybin)` and watch it talk.
- **CI / integration tests**. Record a baseline of service calls, then
  assert behavioural invariants in CI.
- **Capacity planning**. `shannon analyze capture.jsonl.zst` gives
  per-endpoint RPS and latency distributions from a representative
  recording.

## Disclaimer

This is **research-grade software**. It installs eBPF programs into the
Linux kernel and reads plaintext bytes from every TCP socket on the host
it runs on.

- **No warranty.** shannon is provided "as is". The authors and
  contributors take no liability for any malfunction, system instability,
  data loss, damage, or loss of business arising from its use.
- **No fitness for any particular purpose** — including production,
  compliance, or legal use — is implied or guaranteed.
- **You are responsible for how you use it.** shannon is a tool; the
  operator decides what to point it at. Using it to observe traffic
  belonging to parties who have not authorised such observation may be
  illegal in your jurisdiction (wiretap, privacy, data-protection laws).
  The authors take no responsibility for misuse, abuse, or use in
  violation of any law, contract, or policy.
- **Privilege boundary.** Running shannon is equivalent to running as
  root — treat it accordingly. Do not deploy without understanding
  [SECURITY.md](SECURITY.md).

Use only on systems you own or have explicit written permission to
observe. Respect the privacy of users whose traffic crosses those
systems.

## License

Licensed under either of [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
