# DEMO

A scripted, end-to-end exercise of shannon's main features against a
real Linux box. Every block of output below is verbatim from a fresh
run of `scripts/demo.sh`; the artefacts under
[`docs/demo-output/`](docs/demo-output/) are produced by that same
script and let anyone re-verify without re-running the full pipeline.

## What it covers

| Feature | Where to see it |
|---|---|
| Environment pre-flight | [§1](#1-environment-pre-flight) |
| Recording to a file | [§2](#2-recording-25-s-of-traffic) |
| Aggregate `analyze` | [§3](#3-aggregate-analyze-summary) |
| DNS decode (A / AAAA + answers) | [§4 DNS](#dns) |
| HTTP/1 request + response | [§4 HTTP/1](#http1) |
| TLS handshake (SNI, ALPN, cipher) | [§4 TLS](#tls-handshake) |
| Redis cleartext protocol | [§4 Redis](#redis) |
| MQTT publish/subscribe | [§4 MQTT](#mqtt) |
| **CoAP** (the new parser) | [§4 CoAP](#coap) |
| **SQLite uprobes** (cleartext SQL) | [§4 SQLite](#sqlite-uprobes) |
| Connection-start tracking | [§4 Conn](#connection-start) |

## How to reproduce

```bash
# On a Linux host with a built shannon (cargo xtask build --release).
sudo apt-get install -y \
  redis-server redis-tools mosquitto mosquitto-clients \
  libcoap3-bin sqlite3 curl dnsutils

bash scripts/demo.sh                 # records 25s, writes /tmp/shannon-demo/
```

The script is self-contained: it spins up a local CoAP server so the
client GETs round-trip, drives traffic through every supported client
in three rounds, then replays the capture per protocol.

To verify someone else's run, point `analyze` at the captured
recording shipped in this tree:

```bash
sudo ./target/release/shannon analyze docs/demo-output/capture.jsonl.zst
```

That should reproduce the numbers in [§3](#3-aggregate-analyze-summary)
exactly — the recording contains the same bytes the kernel handed
shannon during this run.

---

## 1. Environment pre-flight

```text
$ sudo shannon doctor
✓  kernel >= 5.8                 running 6.12
✓  kernel BTF                    /sys/kernel/btf/vmlinux present
!  rlimit memlock                8 MiB
     fix: ulimit -l unlimited  # or set LimitMEMLOCK=infinity in the systemd unit
✓  privileges                    running as root
✓  libssl (for TLS)              /lib/x86_64-linux-gnu/libssl.so.3
✓  libsqlite3 (for SQL)          /lib/x86_64-linux-gnu/libsqlite3.so.0
✓  bpffs mount                   /sys/fs/bpf mounted
✓  kprobe targets                found all 5 symbols
```

The `!` is a soft warning — the demo runs with the Debian default 8 MiB
memlock and shannon attaches successfully. Bumping it to `unlimited`
silences the warning.

## 2. Recording 25 s of traffic

```bash
sudo shannon record \
  -o /tmp/shannon-demo/capture.jsonl.zst \
  --max-duration 25s
```

The recorder writes zstd-compressed JSONL by default. After the run:

```text
Capture complete: 31K /tmp/shannon-demo/capture.jsonl.zst
```

## 3. Aggregate `analyze` summary

```text
$ sudo shannon analyze docs/demo-output/capture.jsonl.zst
shannon analyze — 273 lines (0 unparseable)
duration: 291.3s
bytes:    tx=8.3 KiB  rx=22.2 KiB

event kinds:
  tcp_data      206
  conn_start    30
  tls_data      25
  sqlite        12

top processes:
  pid=245306 comm=curl             events=39       tx=2.1 KiB rx=6.4 KiB
  pid=245321 comm=curl             events=37       tx=2.1 KiB rx=6.4 KiB
  pid=245291 comm=curl             events=37       tx=2.1 KiB rx=6.4 KiB
  pid=239149 comm=mosquitto        events=27       tx=12 B rx=108 B
  pid=239235 comm=redis-server     events=14       tx=93 B rx=281 B
  pid=245319 comm=curl             events=10       tx=187 B rx=567 B
  pid=245312 comm=mosquitto_pub    events=8        tx=36 B rx=4 B
  pid=245297 comm=mosquitto_pub    events=8        tx=36 B rx=4 B
  pid=245327 comm=mosquitto_pub    events=8        tx=36 B rx=4 B
  pid=245310 comm=redis-cli        events=7        tx=38 B rx=83 B
  …

top peers:
  104.16.124.96:443                events=50       tx=3.7 KiB rx=10.6 KiB
  104.16.123.96:443                events=26       tx=1.9 KiB rx=5.3 KiB
  8.8.8.8:53                       events=36       tx=783 B rx=1.9 KiB
  34.107.221.82:80                 events=9        tx=297 B rx=648 B
  127.0.0.1:5683                   events=6        tx=87 B rx=477 B
  127.0.0.1:6379                   events=27       tx=372 B rx=102 B
  127.0.0.1:1883                   events=21       tx=108 B rx=12 B
  …
```

`104.16.124.96:443` is `www.cloudflare.com`, `8.8.8.8:53` is Google
DNS, the 127.0.0.1 peers are the local Redis / MQTT / CoAP servers
the script targets. shannon attributes traffic to the originating
process and shows by-peer bandwidth without ever touching the network
stack with iptables / tc.

## 4. Per-protocol replay

The full per-protocol output lives under `docs/demo-output/06-*.txt`.
Reproduce any of these with:

```bash
sudo shannon trace --replay docs/demo-output/capture.jsonl.zst \
  | grep ' dns →'           # or http, tls, redis, mqtt, coap, SQL …
```

### DNS

```text
dns →  dns id=29528 ? A example.com
dns ←  dns id=29528 rcode=NOERROR  example.com -> 104.20.23.154
dns →  dns id=28618 ? A www.iana.org
dns ←  dns id=28618 rcode=NOERROR  www.iana.org -> ianawww.vip.icann.org
dns →  dns id=237 ? A detectportal.firefox.com
dns →  dns id=30184 ? AAAA detectportal.firefox.com
dns ←  dns id=237 rcode=NOERROR  detectportal.firefox.com -> detectportal.prod.mozaws.net
dns ←  dns id=30184 rcode=NOERROR  detectportal.firefox.com -> detectportal.prod.mozaws.net
dns →  dns id=7713 ? A www.cloudflare.com
dns →  dns id=29731 ? AAAA www.cloudflare.com
dns ←  dns id=7713 rcode=NOERROR  www.cloudflare.com -> 104.16.124.96
dns ←  dns id=29731 rcode=NOERROR  www.cloudflare.com -> 2606:4700::6810:7c60
```

Every question is paired with its answer; the rendered RHS resolves
CNAMEs (`detectportal.firefox.com -> detectportal.prod.mozaws.net`)
without a follow-up call.

### HTTP/1

```text
http →  GET /success.txt  0 B
http ←  200 OK  8 B
http →  GET /success.txt  0 B
http ←  200 OK  8 B
http →  GET /success.txt  0 B
http ←  200 OK  8 B
```

Three rounds of `curl http://detectportal.firefox.com/success.txt` —
the response body is exactly 8 bytes (the literal "success\n").

### TLS handshake

```text
tls →  tls ClientHello TLS1.3 sni=www.cloudflare.com alpn=h2,http/1.1 ciphers=30
tls ←  tls ServerHello TLS1.3 cipher=0x1302
tls →  tls ClientHello TLS1.3 sni=www.cloudflare.com alpn=h2,http/1.1 ciphers=30
tls ←  tls ServerHello TLS1.3 cipher=0x1302
tls →  tls ClientHello TLS1.3 sni=www.cloudflare.com alpn=h2,http/1.1 ciphers=30
tls ←  tls ServerHello TLS1.3 cipher=0x1302
```

SNI, advertised ALPN list, cipher count from the ClientHello — and
the server's selected cipher (`0x1302` = `TLS_AES_256_GCM_SHA384`) from
the ServerHello. No interception, no MITM cert: this is the same
metadata Wireshark would show, except shannon attaches it to the
originating PID/comm.

### Redis

```text
redis →  SET "demo:greeting" "hello-from-shannon"
redis ←  ["SET", "demo:greeting", "hello-from-shannon"]
redis →  +OK
redis ←  +OK
redis →  GET "demo:greeting"
redis ←  ["GET", "demo:greeting"]
redis →  "hello-from-shannon"
redis ←  "hello-from-shannon"
redis →  INCR "demo:counter"
redis ←  ["INCR", "demo:counter"]
redis →  (integer) 7
redis ←  (integer) 7
```

Full RESP2 decode — both the command (with arguments) and the
response (`+OK`, bulk strings, integers).

### MQTT

```text
mqtt →  -> CONNECT v4 client_id=
mqtt ←  <- CONNECT v4 client_id=
mqtt →  -> CONNACK session_present=false rc=0
mqtt ←  <- CONNACK session_present=false rc=0
mqtt →  -> PUBLISH topic=demo/topic qos=0
mqtt →  -> DISCONNECT rc=0
mqtt ←  <- PUBLISH topic=demo/topic qos=0
mqtt ←  <- DISCONNECT rc=0
```

Both legs of the broker conversation: the client side (`mosquitto_pub`)
and the broker side (`mosquitto`). Topic, QoS, return codes are all
visible.

### CoAP

```text
coap →  coap CON GET mid=41055 /.well-known/core 0B
coap ←  coap ACK 2.05 Content mid=41055 cf=application/link-format 151B
coap →  coap CON GET mid=43274 /.well-known/core 0B
coap ←  coap ACK 2.05 Content mid=43274 cf=application/link-format 151B
coap →  coap CON GET mid=46766 /.well-known/core 0B
coap ←  coap ACK 2.05 Content mid=46766 cf=application/link-format 151B
```

Type (`CON` confirmable), code (`GET` request, `2.05 Content` success
response), message-id correlation across request/response pairs, the
assembled Uri-Path (`/.well-known/core`), and the Content-Format
(`application/link-format`, IANA media type 40) on the response.

### SQLite (uprobes)

```text
SQL    pid=245293 comm=sqlite3  db=0x56204a3d7aa8  exec: SELECT*FROM"main".sqlite_master ORDER BY rowid
SQL    pid=245293 comm=sqlite3  db=0x56204a3d7aa8  prepare_v2: SELECT*FROM"main".sqlite_master ORDER BY rowid
SQL    pid=245293 comm=sqlite3  db=0x56204a3d7aa8  exec: SELECT*FROM"main".sqlite_master WHERE tbl_name='users' AND type!='trigger' ORDER BY rowid
SQL    pid=245293 comm=sqlite3  db=0x56204a3d7aa8  prepare_v2: SELECT*FROM"main".sqlite_master WHERE tbl_name='users' AND type!='trigger' ORDER BY rowid
…
```

These come from uprobes on `sqlite3_prepare_v2` and `sqlite3_exec` in
`/lib/x86_64-linux-gnu/libsqlite3.so.0` — there is no network leg.
Note the `db=0x…` handle: it stays stable for the lifetime of an
open database, so multiple statements on the same handle correlate.
The visible queries are the catalogue lookups the `sqlite3` CLI runs
internally to validate `WHERE tbl_name = 'users'` against
`sqlite_master`.

### Connection start

```text
CONN   pid=245289 comm=curl       10.243.243.8:48460 -> 34.107.221.82:80
CONN   pid=245291 comm=curl       lab[10.243.243.8]:39518 -> 104.16.124.96:443
CONN   pid=245294 comm=redis-cli  127.0.0.1:54374 -> 127.0.0.1:6379
CONN   pid=245295 comm=redis-cli  127.0.0.1:54384 -> 127.0.0.1:6379
CONN   pid=245296 comm=redis-cli  127.0.0.1:54390 -> 127.0.0.1:6379
CONN   pid=245297 comm=mosquitto_pub  127.0.0.1:39884 -> 127.0.0.1:1883
…
```

shannon's `inet_sock_set_state` tracepoint catches every TCP
established transition, so you see the connection itself before any
payload bytes.

---

## What's NOT in this demo (yet)

- **TLS plaintext via libssl uprobes** — these tests run `curl`, which
  loads libssl dynamically; uprobes are attached but the demo doesn't
  surface the decrypted payload separately. To see it, run
  `sudo shannon trace --comm 'curl*' --redact off` while making an
  HTTPS request — shannon will print the cleartext HTTP/2 frames
  inside the TLS session.
- **gRPC / HTTP/2** — the demo doesn't include an HTTP/2 client; the
  HTTP/2 + gRPC parsers are exercised by the test suite (see
  `cargo test http2`).
- **Service map** — `shannon map` is a live UI and doesn't yet
  replay; run it directly while traffic flows for a who-talks-to-who
  graph.
- **Industrial protocols** (Modbus, S7, DNP3, IEC-104, BACnet, OPC-UA,
  EtherNet/IP) — covered by integration tests; demo stays on
  developer-laptop-friendly clients.
