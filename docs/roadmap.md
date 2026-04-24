# Roadmap

This document tracks the build-up order. Anything not here is not on the
critical path.

## v0.1 — foundation (the PR series you're reading)

| # | Area | Commit |
|---|------|--------|
| 1 | Project scaffold (licenses, docs, CI) | ✅ |
| 2 | Cargo workspace, toolchains, xtask | ✅ |
| 3 | `shannon-common` shared ABI types | ✅ |
| 4 | Scaffolding of `shannon-ebpf` programs + maps | ⏳ |
| 5 | `shannon` CLI skeleton + `doctor` + `completions` | ✅ |
| 6 | BPF: connection lifecycle (TCP v4 + v6, close) | ⏳ |
| 7 | BPF: tcp_sendmsg / tcp_recvmsg data capture | ⏳ |
| 8 | BPF: `sched_process_exec` for PID→comm/binary | ⏳ |
| 9 | Userspace: aya loader + program attach | ⏳ |
| 10 | Userspace: event decode + filter routing | ⏳ |
| 11 | Userspace: flow reconstruction + buffer mgmt | ⏳ |
| 12 | Parser: HTTP/1.x | ⏳ |
| 13 | Parser: HTTP/2 + HPACK | ⏳ |
| 14 | Parser: gRPC on HTTP/2 | ⏳ |
| 15 | Parser: Postgres wire | ⏳ |
| 16 | Parser: Redis RESP2/3 | ⏳ |
| 17 | Parser: DNS wire | ⏳ |
| 18 | TUI: service-map view | ⏳ |
| 19 | TUI: live-log view | ⏳ |
| 20 | TUI: connections + stats views | ⏳ |
| 21 | `shannon trace` command end-to-end | ⏳ |
| 22 | `shannon top` command | ⏳ |
| 23 | Record / replay / analyze | ⏳ |
| 24 | TLS uprobes — OpenSSL / BoringSSL | ⏳ |
| 25 | TLS uprobes — Go crypto/tls (binary symbol scan) | ⏳ |

## v0.2 features requested after v0.1 kickoff

| Area | Notes |
|------|-------|
| `--pid N --follow-children` | Attach to PID + transitively track fork/clone children via `sched_process_fork`. |
| `shannon target CMD...` | Spawn `CMD`, auto-filter to that tree only. |
| `--dump-files DIR` | Extract file bodies from HTTP multipart / direct uploads / gRPC streams into DIR for later reverse engineering. |
| gRPC proto inference | Infer `.proto` schemas from observed protobuf wire bytes + method names; emit editable `.proto` files. |
| Certificate pinning detection | Capture server cert chain during TLS handshake, compare against system CA trust store, flag pinned / self-signed / unknown-CA chains. |
| Rogue CA detection | Warn when a cert chain roots to a CA not in the system trust store (possible interception). |
| WebRTC signalling | SDP recognition inside HTTP/WS bodies; STUN/TURN packet parsing. |

## v0.2 — protocol breadth

| Area | Notes |
|------|-------|
| Parser: WebSocket | Post-Upgrade state transition from HTTP/1 |
| Parser: Socket.IO / Engine.IO | Layered on WebSocket text frames |
| Parser: MySQL | COM_QUERY + prepared statement flow |
| Parser: MongoDB wire | OP_MSG + BSON |
| Parser: Kafka wire | Produce, Fetch, Metadata, OffsetCommit |
| Parser: Cassandra CQL | Protocol v4 and v5 |
| Parser: Memcached | Text + binary |
| Parser: MQTT 3.1.1 / 5 | |
| Parser: NATS | |
| Parser: AMQP 0-9-1 | |
| Parser: MSSQL TDS | |
| TLS uprobes — GnuTLS | |
| TLS uprobes — NSS | |
| QUIC packet classification + SNI | No payload decryption in v0.2 |

## v0.3 and beyond

- Rust `rustls` uprobes (DWARF-driven symbol discovery)
- JVM JSSE (JVMTI agent approach)
- QUIC payload decryption (via key-material interception)
- Kubernetes-native: node agent + cluster aggregator
- Prometheus / OTLP exporters
- Retention storage (parquet shards)

## Explicit non-goals

- SQLite "wire" — SQLite has no wire protocol; it is embedded.
- Kernel-TLS (`ktls`) plaintext — we see the ciphertext only; the plaintext
  never leaves the kernel on the wire. Approaching this needs a different
  mechanism (e.g. ktls hooks), not listed here yet.
- Full APM / metrics backend — this tool produces observations; downstream
  projects consume them.
