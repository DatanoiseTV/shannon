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
| Body decompression | Decode `Content-Encoding: gzip|br|deflate|zstd` on the fly so `--dump-files` and `trace` show real payloads, not wire-compressed bytes. |
| Memory-leak mode | Separate `shannon memleak -p PID` subcommand hooking malloc/free/calloc/realloc via uprobes on libc, tracking unfreed allocations with stack traces. Orthogonal to network observation. |
| Discovery protocols | mDNS (UDP/5353), SSDP (UDP/1900), DNS-SD, LLMNR (UDP/5355) — passive capture + parse, useful for LAN fingerprinting and ICS/IoT discovery maps. |
| AWS / S3 semantics | Detect S3 + S3-compatible (MinIO, R2, Backblaze B2, Wasabi) request/response pairs on HTTP, surface bucket / key / operation. Also AWS SigV4 detection → caller identity without decrypting payloads. Extended: DynamoDB, SQS, SNS, STS, IAM, Lambda invocation surfaces. |
| LLM / OpenAI-compatible APIs | Recognise OpenAI-shape (`/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`), Anthropic Messages, Google Gemini, Ollama, LM Studio, vLLM, TGI, LiteLLM, Azure OpenAI, AWS Bedrock, local llama.cpp servers. Pull model, token counts, tool calls, streaming SSE deltas. |
| VM / guest traffic | Host-level capture of guest VM traffic: `veth` / tap interface observability, vhost-user for kernel-TLS-terminated KVM, virtio-net probe points, capturing NAT-translated flows via `xt_nat` / conntrack. Per-VM attribution via libvirt domain id → cgroup map. |
| Leaked-credential / API-key scanner | Pattern-match captured plaintext against known credential shapes: AWS (`AKIA…`/`ASIA…`), GitHub (`ghp_…`/`gho_…`), GitLab, Slack `xox[abpr]-…`, Stripe `sk_live_`/`sk_test_`, Twilio, JWT structure, PEM/PKCS8 blocks, SSH private keys, generic `*_TOKEN=`/`*_SECRET=`/`*_API_KEY=` env-style assignments. Alert + auto-redact in output. |
| Codegen assistant | `scripts/shannon-codegen` — feeds a recording through Claude Code with a prepared prompt to synthesise `.proto` or IDL from observed messages, generate C/Go/Rust/Python client/server skeletons that speak the observed protocol, explain unknown binary structures. |
| Industrial / OT protocols | Modbus-TCP (`tcp/502`), DNP3 (`tcp/20000`), IEC 60870-5-104 (`tcp/2404`), BACnet/IP (`udp/47808`), OPC-UA binary (`tcp/4840`), EtherNet/IP + CIP (`tcp/44818`, `udp/2222`), Siemens S7comm (`tcp/102`), PROFINET. Passive parse surfaces device / function-code / register pairs — high value for plant-floor and building-automation observability, usual care re: liability / consent. |
| Container attribution | Kernel probes already see traffic from every container (eBPF is kernel-global). Userspace addition: resolve `cgroup_id` → container name by reading `/sys/fs/cgroup/**/<id>` paths, parsing Docker (`/docker/<hex>`), containerd (`/kubepods*/pod<uid>/<container>`), cri-o, Podman. Add `--container NAME` / `--image GLOB` / `--pod K8S_POD` filters; render `[container/web-1]` in trace output alongside PID. |
| ZeroTier protocol | UDP/9993 (default). Parse the plaintext packet header: 8-byte packet ID, 5-byte destination ZT address, 5-byte source ZT address, flags/hops byte, 1-byte cipher, 8-byte MAC. Surface verb (HELLO, OK, ERROR, WHOIS, MULTICAST_LIKE, MULTICAST_GATHER, FRAME, EXT_FRAME, etc.), src/dst node IDs (10-hex-digit format), and packet size. Payload stays encrypted (Salsa20/Poly1305) without keys — v0.4 integration with planet/moon config for control-plane decode. |

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
