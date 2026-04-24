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

## License

Licensed under either of [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
