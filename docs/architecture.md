# Architecture

```
┌────────────────────────── userspace ──────────────────────────┐
│                                                                │
│    ┌──────────┐    ┌────────────┐    ┌──────────────┐          │
│    │   CLI    │───▶│  Loader    │───▶│ Event Router │          │
│    │ (clap)   │    │  (aya)     │    │              │          │
│    └──────────┘    └────────────┘    └──────┬───────┘          │
│                                              │                  │
│                       ┌──────────────────────┼──────────────┐   │
│                       ▼                      ▼              ▼   │
│                ┌────────────┐         ┌────────────┐  ┌──────┐  │
│                │ Flow       │────────▶│ Protocol   │──│ Agg  │  │
│                │ Reconstr.  │         │ Parsers    │  │ +TUI │  │
│                └────────────┘         └────────────┘  └──────┘  │
│                       ▲                                          │
└───────────────────────┼──────────────────────────────────────────┘
                        │  ring buffer                             
┌───────────────────────┼──── kernel (eBPF) ────────────────────┐
│                                                                │
│  ┌────────────┐  ┌──────────────┐  ┌────────────┐  ┌────────┐ │
│  │ Conn. life │  │ tcp_sendmsg  │  │ SSL_read   │  │ udp/53 │ │
│  │ (sockops)  │  │ tcp_recvmsg  │  │ SSL_write  │  │ DNS    │ │
│  └────────────┘  │ (kprobes)    │  │ (uprobes)  │  └────────┘ │
│                  └──────────────┘  └────────────┘              │
│                                                                │
│           ┌── tracepoint: sched_process_exec ──┐               │
│           └── pid → comm → cgroup table ───────┘               │
└────────────────────────────────────────────────────────────────┘
```

## Data path

1. **Kernel probes** fire on every TCP send/recv, SSL read/write, UDP DNS,
   and process exec. Each probe writes a small fixed-size `Event` (see
   [`shannon-common`](../shannon-common)) to a BPF ring buffer.
2. **Userspace loader** opens the ring buffer, fans out to a per-CPU consumer
   that decodes `Event` bytes into strongly typed enums.
3. **Flow reconstructor** keys events by `(pid, tid, src, dst, src_port,
   dst_port)` and buffers contiguous bytes per direction with bounded
   per-connection memory.
4. **Protocol parsers** run on the reconstructed byte stream. Each parser is
   a state machine that emits zero or more L7 records (e.g. one HTTP
   request/response pair) and reports how many bytes it consumed. Parsers
   never own the buffer; they borrow slices.
5. **Aggregator** folds L7 records into a service graph (who called whom,
   with what, how fast, how often).
6. **Exporters** render: TUI (ratatui), NDJSON on stdout, or (planned)
   OTLP/OpenTelemetry traces.

## Why a ring buffer and not perf event array

Linux ≥ 5.8 provides `BPF_MAP_TYPE_RINGBUF` with MPSC semantics, per-CPU
ordering, and significantly lower overhead than perf event arrays. We require
it as a baseline rather than maintaining two code paths.

## Why uprobes on `libssl`, not kernel TLS

Kernel TLS (`ktls`) moves symmetric encryption into the kernel after the
handshake. But userland libraries still do plaintext on their side of the
`SSL_read` / `SSL_write` boundary, so uprobing that function gives us
plaintext regardless of whether symmetric encryption happens in-kernel or
in-userspace. This is the same approach Pixie pioneered.

Go's `crypto/tls` and Rust's `rustls` don't go through `libssl`, so they need
their own uprobes or runtime-specific hooks. Those are on the roadmap.

## Memory budget

Per-connection buffer: 16 KiB per direction, capped. A connection exceeding
the cap drops oldest bytes (ring buffer). At 10k concurrent connections that
is ~320 MiB worst-case; the default ceiling is 100k bytes per connection and
we prune idle flows after 30s without data.

## Verifier notes

All BPF programs compile with `-Copt-level=3` and pass the verifier on
kernel 5.8+. Notes:

- Loops are unrolled (`#[inline(always)]`) or explicitly bounded with
  `#pragma unroll` equivalents.
- Every `bpf_probe_read_user` is preceded by a length mask `len & (BUF_CAP - 1)`
  where `BUF_CAP` is a power of two.
- Per-CPU scratch maps are used for structs larger than 512 bytes.
- No function pointers or indirect calls.
