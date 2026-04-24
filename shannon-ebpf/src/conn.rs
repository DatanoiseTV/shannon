//! Connection-lifecycle probes.
//!
//! Three attachments cooperate to get accurate per-connection attribution:
//!
//! 1. `kprobe:tcp_v4_connect` and `kprobe:tcp_v6_connect` fire in the
//!    originating userspace task's context. Their first argument is the
//!    `struct sock *sk`. We stash `{pid, tgid, comm}` against that pointer
//!    in the `SOCKS` LRU map — this is the only reliable way to know who
//!    opened the connection.
//! 2. `tracepoint:sock:inet_sock_set_state` observes state transitions
//!    system-wide. When a socket moves to `TCP_ESTABLISHED` we emit a
//!    `ConnStart` event enriched with the PID we previously recorded; the
//!    handler itself runs in softirq context where `current` is usually
//!    the per-CPU idle task, so we never trust `bpf_get_current_pid_tgid()`
//!    here.
//! 3. On `TCP_CLOSE` we emit `ConnEnd` and drop the entry from `SOCKS`.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, tracepoint},
    programs::{ProbeContext, TracePointContext},
};

use shannon_common::{ConnEndPayload, ConnStartPayload, EventKind, COMM_LEN, HEADER_SIZE};

use crate::{
    maps::{SockInfo, EVENTS, SOCKS},
    util,
};

// ---------------------------------------------------------------------------
// Tracepoint field offsets — from /sys/kernel/tracing/events/sock/
// inet_sock_set_state/format on a 6.12 kernel. These are stable across
// modern kernels; we deliberately hardcode the offsets rather than drag in
// a BTF-relocated struct descriptor for a 60-byte tracepoint.
// ---------------------------------------------------------------------------

const TP_SKADDR: usize = 8;
const TP_OLDSTATE: usize = 16;
const TP_NEWSTATE: usize = 20;
const TP_SPORT: usize = 24;
const TP_DPORT: usize = 26;
const TP_FAMILY: usize = 28;
const TP_PROTOCOL: usize = 30;
const TP_SADDR4: usize = 32;
const TP_DADDR4: usize = 36;
const TP_SADDR6: usize = 40;
const TP_DADDR6: usize = 56;

const TCP_ESTABLISHED: i32 = 1;
const TCP_CLOSE: i32 = 7;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// ---------------------------------------------------------------------------
// kprobe: tcp_v4_connect / tcp_v6_connect
// ---------------------------------------------------------------------------

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<u64>(0) else {
        return 1;
    };
    stash_pid(sk);
    0
}

#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<u64>(0) else {
        return 1;
    };
    stash_pid(sk);
    0
}

#[inline(always)]
fn stash_pid(sk: u64) {
    if util::is_self() {
        return;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);

    // Merge with any existing entry; `inet_sock_set_state` may have been
    // seen first on some paths and we don't want to wipe its address info.
    let existing = unsafe { SOCKS.get(&sk) }.copied();
    let info = match existing {
        Some(mut i) => {
            i.pid = pid;
            i.tgid = tgid;
            i.comm = comm;
            i
        }
        None => SockInfo {
            sock_id: sk,
            pid,
            tgid,
            sport: 0,
            dport: 0,
            family: 0,
            protocol: 0,
            _pad: [0; 2],
            saddr: [0; 16],
            daddr: [0; 16],
            bytes_sent: 0,
            bytes_recv: 0,
            started_ns: unsafe { bpf_ktime_get_ns() },
            comm,
        },
    };
    let _ = SOCKS.insert(&sk, &info, 0);
}

// ---------------------------------------------------------------------------
// tracepoint: sock:inet_sock_set_state
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_state(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_state(ctx: &TracePointContext) -> Result<(), i64> {
    let oldstate: i32 = unsafe { ctx.read_at(TP_OLDSTATE) }?;
    let newstate: i32 = unsafe { ctx.read_at(TP_NEWSTATE) }?;

    // We only care about the two edges that bracket a real flow.
    if newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE {
        return Ok(());
    }
    if newstate == TCP_CLOSE && oldstate != TCP_ESTABLISHED {
        // Listen-socket teardown or failed connect — not interesting here.
        return Ok(());
    }

    let sk: u64 = unsafe { ctx.read_at(TP_SKADDR) }?;
    // Look up stashed task info *first*: in softirq context current is the
    // idle task, so filtering by current tgid would either leak every
    // connection (filter-by-0 collision) or mis-match. The SOCKS entry
    // carries the real tgid recorded at tcp_*_connect time.
    let pre_info = unsafe { SOCKS.get(&sk) }.copied();
    if let Some(i) = pre_info {
        if util::filtered_out(i.tgid) {
            return Ok(());
        }
    }

    let sport: u16 = unsafe { ctx.read_at(TP_SPORT) }?;
    // dport is stored as raw network-byte-order in the tracepoint. Read as
    // two bytes and compose host-order explicitly — `u16::swap_bytes` on the
    // BPF target is sometimes elided by the optimiser.
    let dport_hi: u8 = unsafe { ctx.read_at(TP_DPORT) }?;
    let dport_lo: u8 = unsafe { ctx.read_at(TP_DPORT + 1) }?;
    let dport = (u16::from(dport_hi) << 8) | u16::from(dport_lo);

    let family: u16 = unsafe { ctx.read_at(TP_FAMILY) }?;
    let protocol_u16: u16 = unsafe { ctx.read_at(TP_PROTOCOL) }?;
    let (saddr, daddr) = read_addrs(ctx, family)?;

    // Look up stashed info from tcp_{v4,v6}_connect. Missing entries happen
    // for accepted inbound connections; userspace flags those rather than
    // showing the softirq `swapper` comm.
    let info_opt = pre_info;
    let (pid, tgid, comm) =
        info_opt.map_or((0u32, 0u32, [0u8; COMM_LEN]), |i| (i.pid, i.tgid, i.comm));

    if newstate == TCP_ESTABLISHED {
        let info = SockInfo {
            sock_id: sk,
            pid,
            tgid,
            sport,
            dport,
            family: (family & 0xFF) as u8,
            protocol: (protocol_u16 & 0xFF) as u8,
            _pad: [0; 2],
            saddr,
            daddr,
            bytes_sent: 0,
            bytes_recv: 0,
            started_ns: unsafe { bpf_ktime_get_ns() },
            comm,
        };
        let _ = SOCKS.insert(&sk, &info, 0);
        emit_conn_start(
            sk,
            (family & 0xFF) as u8,
            (protocol_u16 & 0xFF) as u8,
            sport,
            dport,
            saddr,
            daddr,
            pid,
            tgid,
            comm,
        );
    } else {
        emit_conn_end(sk);
        let _ = SOCKS.remove(&sk);
    }
    Ok(())
}

fn read_addrs(ctx: &TracePointContext, family: u16) -> Result<([u8; 16], [u8; 16]), i64> {
    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    if family == AF_INET {
        let s4: [u8; 4] = unsafe { ctx.read_at(TP_SADDR4) }?;
        let d4: [u8; 4] = unsafe { ctx.read_at(TP_DADDR4) }?;
        s[..4].copy_from_slice(&s4);
        d[..4].copy_from_slice(&d4);
    } else if family == AF_INET6 {
        s = unsafe { ctx.read_at(TP_SADDR6) }?;
        d = unsafe { ctx.read_at(TP_DADDR6) }?;
    }
    Ok((s, d))
}

#[allow(clippy::too_many_arguments)]
fn emit_conn_start(
    sock_id: u64,
    family: u8,
    protocol: u8,
    sport: u16,
    dport: u16,
    saddr: [u8; 16],
    daddr: [u8; 16],
    pid: u32,
    tgid: u32,
    comm: [u8; COMM_LEN],
) {
    let Some(mut entry) = EVENTS.reserve::<Event<ConnStartPayload>>(0) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        let mut header = util::fill_header(EventKind::ConnStart);
        if pid != 0 {
            header.pid = pid;
            header.tgid = tgid;
            header.comm = comm;
        }
        header.total_len = size_of::<Event<ConnStartPayload>>() as u32;
        (*ev).header = header;
        (*ev).payload = ConnStartPayload {
            protocol,
            family,
            _pad: 0,
            sport,
            dport,
            saddr,
            daddr,
            sock_id,
        };
    }
    entry.submit(0);
}

fn emit_conn_end(sock_id: u64) {
    let info = unsafe { SOCKS.get(&sock_id) }.copied();
    let Some(mut entry) = EVENTS.reserve::<Event<ConnEndPayload>>(0) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        let mut header = util::fill_header(EventKind::ConnEnd);
        if let Some(i) = info {
            if i.pid != 0 {
                header.pid = i.pid;
                header.tgid = i.tgid;
                header.comm = i.comm;
            }
        }
        header.total_len = size_of::<Event<ConnEndPayload>>() as u32;
        (*ev).header = header;
        (*ev).payload = ConnEndPayload {
            sock_id,
            bytes_sent: info.map_or(0, |i| i.bytes_sent),
            bytes_recv: info.map_or(0, |i| i.bytes_recv),
            rtt_us: 0,
            _pad: 0,
        };
    }
    entry.submit(0);
}

/// Small generic to keep `emit_conn_*` tidy.
#[repr(C)]
pub struct Event<P: Copy> {
    pub header: shannon_common::EventHeader,
    pub payload: P,
}

// Compile-time check that every event frame begins with a full header.
const _: () = {
    assert!(core::mem::offset_of!(Event<ConnStartPayload>, header) == 0);
    assert!(size_of::<shannon_common::EventHeader>() == HEADER_SIZE);
};
