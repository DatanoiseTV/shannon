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

# service-map: who talks to whom, by protocol
sudo shannon map
sudo shannon map --format dot | dot -Tsvg > map.svg
sudo shannon map --format json > edges.ndjson

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

**50 L7 protocols** span web, databases, messaging, mail, directory,
telephony, SMS / carrier, media-streaming, remote-access,
operational-technology, file-sharing, VPN, AAA / network-management,
and legacy chat.

### Web + APIs

| Protocol | Notes |
|---|---|
| HTTP/1.x | Requests, responses, headers, bodies, chunked + range reassembly |
| HTTP/2 | HPACK, per-stream framing |
| gRPC | On HTTP/2: service, method, status; body decode with `--proto` |
| WebSocket | RFC 6455 frames; follows HTTP/1.1 `101 Upgrade` handshake |
| Socket.IO / Engine.IO | Event name, namespace, JSON args, ack IDs |
| TLS 1.0-1.3 | ClientHello / ServerHello SNI + ALPN + cipher-suite inspection |

### Databases

| Protocol | Notes |
|---|---|
| Postgres | Startup, Simple / Extended query, bind parameters |
| MySQL | COM_QUERY, COM_STMT_PREPARE/EXECUTE |
| MongoDB wire | `OP_MSG`, `OP_QUERY`, BSON decode |
| Redis | RESP2 + RESP3 |
| Cassandra CQL | Opcodes, frame headers, query strings |
| Memcached | ASCII + binary protocols |
| Oracle TNS | CONNECT descriptor, SERVICE_NAME / SID / PROGRAM / USER |
| MS SQL Server TDS | PreLogin / Login7 (user / server / app / db), batch / RPC |

### Messaging + streaming

| Protocol | Notes |
|---|---|
| Kafka wire | Produce / Fetch / Metadata / OffsetCommit, API 0-12 |
| AMQP 0.9.1 (RabbitMQ) | Full class/method table, basic.publish routing-key + exchange |
| MQTT 3.1.1 / 5 | CONNECT / PUBLISH / SUBSCRIBE with topic + QoS |
| NATS | Text protocol: PUB / SUB / MSG / HPUB / HMSG / INFO |
| STUN / TURN | WebRTC signalling, XOR-MAPPED-ADDRESS decode, SOFTWARE |

### Mail + directory

| Protocol | Notes |
|---|---|
| IMAP | Tagged command framing, LOGIN redacted |
| POP3 | USER + PASS (password redacted) |
| SMTP | HELO / EHLO / AUTH (credentials redacted) + MAIL FROM / RCPT TO |
| LDAP | BER: BindRequest (password redacted), SearchRequest with scopes |
| Kerberos v5 | AS-REQ / AS-REP / TGS-REQ / ... with realm + cname + sname |

### Remote access + proxy + telephony

| Protocol | Notes |
|---|---|
| SSH | Banner + software identification |
| RDP | X.224 ConnectionRequest, mstshash= username leak, TLS/CredSSP negotiation |
| Telnet | IAC option negotiation + cleartext text extraction |
| FTP | USER / PASS (redacted) / RETR / STOR / MLSD + reply codes |
| SOCKS4 / SOCKS5 | CONNECT / BIND / UDP-ASSOCIATE with DOMAIN / IPv4 / IPv6 |
| SIP | INVITE / REGISTER / ... with Call-ID + Via + From/To + User-Agent |
| RTSP | DESCRIBE / SETUP / PLAY / TEARDOWN on IP cameras + media servers |
| SMPP | SMS peer-to-peer: bind_* (system_id + redacted password), submit_sm |
| IRC | PASS (redacted) / NICK / USER / JOIN / PRIVMSG / numeric replies |

### Operational-technology (ICS / SCADA / building automation)

| Protocol | Notes |
|---|---|
| Modbus/TCP | Function codes on tcp/502 |
| Siemens S7comm | TPKT + COTP + S7; ROSCTR + function-code decode |
| EtherNet/IP + CIP | ODVA encapsulation (tcp/44818 + 2222); session + command decode |
| DNP3 | IEEE 1815 link-layer framing (tcp/20000) |
| IEC-104 | Telecontrol APDU: I / S / U frames + ASDU TypeID catalogue |
| OPC-UA | IEC 62541-6 §7.1.2 binary framing (tcp/4840) |
| BACnet/IP | BVLC + NPDU + APDU; readProperty / writeProperty / Who-Is / I-Am |

### Infrastructure + auth + management

| Protocol | Notes |
|---|---|
| DNS | Questions + answers over tcp/udp 53 |
| DHCP | Op / transaction / chaddr MAC / options (Host Name, Vendor Class) |
| TFTP | RRQ / WRQ / DATA / ACK / ERROR / OACK with options |
| NTP | Full 48-byte header; stratum / mode / ref_id (GPS, PPS, LOCL) |
| RADIUS | Access-Request / Accept / Reject; User-Name + Called/Calling-Station |
| TACACS+ | AUTHEN / AUTHOR / ACCT; flags incl. UNENCRYPTED warning |
| SNMP v1/v2c | Version + community string + PDU type + first OID |
| Syslog | RFC 3164 + RFC 5424 + RFC 6587 octet-counted framing |
| SSDP | UDP discovery (mDNS-adjacent) |

### File sharing + VPN

| Protocol | Notes |
|---|---|
| SMB2 / SMB3 | TreeConnect share path, Create filename (UCS-2LE), NT_STATUS names |
| NFS / ONC-RPC | Record-marker framing; NFSv3 / MOUNT / PORTMAP / NLM program + procedure decode |
| WireGuard | HandshakeInit / Response / CookieReply / TransportData; ephemeral-key preview |

### TLS runtimes lifted for plaintext

| Runtime | Hook |
|---|---|
| OpenSSL / libssl | `SSL_{read,write,read_ex,write_ex}` uprobes |
| BoringSSL | Same symbols as libssl |
| GnuTLS | `gnutls_record_{send,recv}` uprobes |
| NSS | `PR_Read` / `PR_Write` + `ssl3_SendPlainText` uprobes |
| Go `crypto/tls` | `/proc/<pid>/exe` symbol scan → `crypto/tls.(*Conn).{R,W}` |
| QUIC (partial) | Packet type + SNI from Initial; encrypted payload deferred |

Each connection carries a protocol state machine that can *upgrade itself*:
HTTP/1.1 → WebSocket → Socket.IO (on event frames), HTTP/2 → gRPC
(on `application/grpc`), and any TCP → TLS (on a ClientHello record).
Nothing you configure.

Both transports captured — **TCP** via `tcp_sendmsg` / `tcp_recvmsg`
kprobes and **UDP** via `udp_sendmsg` kprobe (IPv4 + IPv6 — dst
address and port read off `struct sock` with a `msg->msg_name`
fallback for unconnected sockets). UDP receive side is deferred
(needs a kretprobe dance).

Deferred to v0.2: Rust `rustls`, Java JSSE, QUIC payload decryption,
UDP receive path.

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
