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
| Cross-OS guests (Windows / macOS) | Three layered paths: **(1) host-side**, always available — shannon on the Linux host sees every VM's `tap`/`vnet` NIC traffic regardless of guest OS. Works for plaintext and cleartext DNS immediately; for guest-terminated TLS it's ciphertext only. **(2) guest agent for Linux VMs** — shannon binary runs inside, same capabilities as bare metal. **(3) guest agent for Windows** — port the userspace to use [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows) for the same surface (XDP, cgroup-like hooks), OR ship a separate `shannon-etw-agent` that sources events from Event Tracing for Windows (ETW) providers: Microsoft-Windows-DNS-Client, Microsoft-Windows-WinINet, Microsoft-Windows-Schannel-Events — emits the same NDJSON event format for unified analysis. **macOS**: Endpoint Security framework + DTrace uprobes for userspace symbol interception. |
| Hardware / device-driver tracing | Separate observability domain on the same eBPF foundation. Attach points: **syscalls** — `enter_ioctl`/`exit_ioctl` with fd→path resolution so we name the device (`/dev/sda`, `/dev/ttyUSB0`, `/dev/nvidia0`), `read`/`write`/`pread`/`pwrite` filtered to char/block devs. **USB** — `usb_submit_urb`, `usb_bulk_msg`, `usb_control_msg` (vendor id, product id, endpoint, transfer length). **PCI** — `pci_read_config_*`/`pci_write_config_*` (bus:device.function, register, value). **I²C / SPI** — `i2c_transfer`, `i2c_smbus_xfer`, `spi_sync`. **Block I/O** — tracepoint `block_rq_issue`/`block_rq_complete` (device, sector, size, latency). **IRQ** — tracepoint `irq_handler_entry`/`exit` for latency histograms per IRQ line. New subcommand `shannon hwtrace --device /dev/... [--syscall ioctl]`; emits one record per transaction with process attribution, device identity, op-code, and latency. Useful for: driver dev, kernel debugging, HW testing, understanding what proprietary apps talk to which devices. |
| X.509 cert / private-key dump | Whenever shannon sees a TLS ClientHello / ServerHello / Certificate message or a plaintext PEM block in a captured body, extract and save to `--cert-dir DIR` (default off). In the terminal show only a short summary line (subject CN, SAN count, issuer, NotAfter, fingerprint first 8 hex). Files written as `<fingerprint>.pem` / `<fingerprint>.key`. Privacy-sensitive: private keys go to a separate `--key-dir` with stricter semantics and a scary warning banner on enable. |
| Security-warning rules | Extension of the secrets scanner. Emit high-severity warnings when: (a) default credentials observed (`admin:admin`, `root:root`, `postgres:postgres`, vendor defaults catalogue — Cisco, MikroTik, Ubiquiti, Hikvision, Grafana, etc.), (b) unauthenticated sensitive commands (Redis `CONFIG` without prior AUTH, Memcached `flush_all` on public port), (c) plaintext credentials on a non-loopback socket, (d) outdated TLS versions (<1.2) or weak ciphers observed, (e) PII patterns (credit card numbers, passport, national ID shapes) traversing unencrypted channels. `shannon trace --warn-only` filters to just these. |
| pcap / pcapng output | `shannon record --pcap out.pcapng` writes a **synthesised** pcap alongside the JSONL record. Each captured flow is materialised as synthetic Ethernet → IPv4/v6 → TCP/UDP frames carrying the plaintext payload (observed via uprobes for TLS, kprobes for TCP). Timestamps, direction, src/dst/ports preserved. For TLS flows we also write a parallel encrypted.pcap of the real wire bytes. Output is `pcapng` by default (richer metadata — capture interface, comment option with PID/comm/protocol) with legacy `pcap` selectable via `--pcap-format classic`. Opens cleanly in Wireshark / tshark / zeek. |
| Leaked-credential / API-key scanner | Pattern-match captured plaintext against known credential shapes: AWS (`AKIA…`/`ASIA…`), GitHub (`ghp_…`/`gho_…`), GitLab, Slack `xox[abpr]-…`, Stripe `sk_live_`/`sk_test_`, Twilio, JWT structure, PEM/PKCS8 blocks, SSH private keys, generic `*_TOKEN=`/`*_SECRET=`/`*_API_KEY=` env-style assignments. Alert + auto-redact in output. |
| Codegen assistant | `scripts/shannon-codegen` — feeds a recording through Claude Code with a prepared prompt to synthesise `.proto` or IDL from observed messages, generate C/Go/Rust/Python client/server skeletons that speak the observed protocol, explain unknown binary structures. |
| HTTP/3 + QUIC | Full HTTP/3 parser riding on QUIC streams. QPACK decode. Needs QUIC payload decryption first — either a host-side uprobe on the QUIC library in use (`ngtcp2`, `quiche`, `msquic`, Go's `quic-go`) mirroring our libssl approach, or SSLKEYLOGFILE-driven decryption for user-controlled processes. |
| File reassembly | Fold chunked / `Transfer-Encoding: chunked` / multipart / `Range:` responses back into original files: reconstitute partial content ranges, recombine multipart parts, optionally decompress (`Content-Encoding: gzip|br|deflate|zstd`). Save to `--dump-files DIR/<method>_<host>_<path>_<sha>.<ext>` with auto-extension from Content-Type. |
| IMAP parser | `tcp/143` + `tcp/993` (IMAPS on TLS via libssl). LOGIN/AUTHENTICATE (credential capture + redaction), SELECT, FETCH, SEARCH, EXPUNGE, STATUS, LIST. Extract message UIDs, folder names, envelope metadata. |
| POP3 parser | `tcp/110` + `tcp/995`. USER/PASS (credential capture + redaction), STAT, LIST, RETR, DELE, UIDL, APOP. Extract message counts and sizes. |
| SMTP parser | `tcp/25`/`587`/`465`. EHLO, AUTH (LOGIN/PLAIN/CRAM-MD5 — redact credentials), MAIL FROM, RCPT TO, DATA; decode RFC 5322 headers if `--dump-files` is on. |
| Embedded JS micro-engine for user analyzers | `shannon trace --script filter.js` or `--script-dir scripts/` — load user JS that receives each decoded record and can: filter (`return false` to drop), annotate (`record.tag = 'interesting'`), emit side-effects (write to file, post a webhook, accumulate counters), redact. Backed by [`boa`](https://github.com/boa-dev/boa) for pure-Rust ECMAScript execution. Hot path stays fast because the script is optional; when unused, zero overhead. Globals exposed to script: `record`, `protocol`, `dir`, `pid`, `comm`, plus a small stdlib (`emit`, `warn`, `incr(counter, n)`, `state` persistent map, `fetch_json` for side-channel lookups). |
| TLS 1.3 certificate extraction | Current `--dump-certs` only sees TLS 1.2 Certificate messages (they're plaintext on the wire). TLS 1.3 encrypts the server `Certificate` after ServerHello with handshake traffic keys, so it never hits our TCP parser in the clear. Hook libssl's `SSL_get_peer_cert_chain` / `SSL_get0_verified_chain` as uprobes at the library boundary, same technique as our SSL_read/write. Also handle BoringSSL's equivalent `SSL_get_peer_certificate` and Go's `crypto/tls.(*Conn).ConnectionState().PeerCertificates`. |
| wine / wine64 binary tracing | When the observed process is a Windows PE loaded by wine, the TLS surface is SChannel (Windows DLLs) rather than libssl. Options: (a) observe at wine's own TLS wrappers (uprobes on `secur32.dll!SSL_*` loaded into the wine server process), (b) `shannon target wine program.exe` to spawn-and-attach with correct child-tracking, (c) hook wine's `NtCreateFile` / `NtWriteFile` syscalls for filesystem observability inside the emulated environment. CLI: `shannon trace --wine` auto-detects wineserver and plumbs the uprobes; `shannon target wine foo.exe` spawns via wine with child-tracking on. |
| Protobuf schema brute-force | `shannon proto infer --samples dir/ --threads N --time 60s` multithread search for the most-likely `.proto` schema given a corpus of raw binary messages. Each worker tries a random permutation of (tag → wire-type → name-hint) mappings, decodes the whole corpus under that hypothesis, and scores by (bytes consumed / length of decoded-as-nested-messages / UTF-8 ratio of Len fields). Workers share a Bloom filter of tried permutations and a lock-free leaderboard; main thread prints the current best every N seconds. Termination conditions: time budget exhausted, leaderboard unchanged for M seconds, or all-fields-named hit. Emits: `inferred.proto` with best-fit definitions, plus a confidence table listing alternatives. |
| Industrial / OT protocols | Broad surface — group by domain. Passive parse of function-code / register / object-ID pairs across the lot; usual care re: liability / consent on plant networks. |
|   — Factory / PLC       | Modbus-TCP (`tcp/502`), Modbus-RTU-over-TCP, Siemens S7comm (`tcp/102`), Siemens FETCH/WRITE, Omron FINS (`udp/9600`), Mitsubishi MELSEC MC / SLMP (`tcp/5007`, `tcp/5562`), Allen-Bradley DF1-over-TCP. |
|   — Fieldbus-over-IP    | EtherNet/IP + CIP (`tcp/44818`, `udp/2222`), PROFINET, EtherCAT (L2, captured via AF_PACKET), Powerlink, SERCOS III, CC-Link IE Field / TSN, Foundation Fieldbus HSE. |
|   — SCADA / utility     | DNP3 (`tcp/20000`), IEC 60870-5-104 (`tcp/2404`), IEC 61850 MMS (`tcp/102`), IEC 61850 GOOSE + SV (L2 multicast), ICCP / TASE.2 (`tcp/102`), BSAP, IEEE C37.118 Synchrophasor (`tcp/4712`). |
|   — Building automation | BACnet/IP (`udp/47808`), KNX/IP (`udp/3671`), LonWorks / LonTalk-IP. |
|   — Process industry    | OPC-UA binary (`tcp/4840`), HART-IP (`tcp/udp 5094`). |
|   — Metering / utility  | DLMS/COSEM (`tcp/4059`), M-Bus over IP, IEC 62056. |
| Container attribution | Kernel probes already see traffic from every container (eBPF is kernel-global). Userspace addition: resolve `cgroup_id` → container name by reading `/sys/fs/cgroup/**/<id>` paths, parsing Docker (`/docker/<hex>`), containerd (`/kubepods*/pod<uid>/<container>`), cri-o, Podman. Add `--container NAME` / `--image GLOB` / `--pod K8S_POD` filters; render `[container/web-1]` in trace output alongside PID. |
| ZeroTier protocol | Three layers, none of which need ZT key material: (1) **uprobes on `zerotier-one`**: attach to `Packet::armor`/`dearmor`, `Switch::onRemotePacket`, `Switch::send` — same technique as libssl, sees plaintext on both sides of the Salsa20/Poly1305 boundary. C++ symbols resolved via DWARF demangling at load time. (2) **uprobes on `libzt.so`** for embedded-SDK apps: `zts_bsd_{read,write,sendto,recvfrom}` carry application payloads in the virtual network. (3) **kprobes on `tun_net_xmit`/`tun_do_read`** filtered to interface names matching `zt*` — captures decapsulated Ethernet/IP frames flowing through the ZT TAP, completely independent of ZT's crypto. UDP/9993 header-only parse (verb, node IDs, packet ID) remains a useful cross-reference. |

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
