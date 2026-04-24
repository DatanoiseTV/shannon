//! Connection-lifecycle probe.
//!
//! We attach a single tracepoint — `sock:inet_sock_set_state` — which fires
//! on every TCP state transition system-wide. From the state machine we
//! emit:
//!
//! - `ConnStart` on `* -> TCP_ESTABLISHED`
//! - `ConnEnd`   on `* -> TCP_CLOSE`
//!
//! Other transitions are ignored; they're interesting for forensic tools
//! but noisy for service-level observability.

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};

use shannon_common::{ConnEndPayload, ConnStartPayload, EventKind, HEADER_SIZE};

use crate::{
    maps::{EVENTS, SOCKS, SockInfo},
    util,
};

// ---------------------------------------------------------------------------
// Tracepoint field layout — from /sys/kernel/tracing/events/sock/
// inet_sock_set_state/format on a 6.12 kernel.
//
//   field:unsigned short common_type;         offset:0;  size:2;
//   field:unsigned char common_flags;         offset:2;  size:1;
//   field:unsigned char common_preempt_count; offset:3;  size:1;
//   field:int common_pid;                     offset:4;  size:4;
//
//   field:const void * skaddr;                offset:8;  size:8;
//   field:int oldstate;                       offset:16; size:4;
//   field:int newstate;                       offset:20; size:4;
//   field:__u16 sport;                        offset:24; size:2;
//   field:__u16 dport;                        offset:26; size:2;
//   field:__u16 family;                       offset:28; size:2;
//   field:__u16 protocol;                     offset:30; size:2;
//   field:__u8 saddr[4];                      offset:32; size:4;
//   field:__u8 daddr[4];                      offset:36; size:4;
//   field:__u8 saddr_v6[16];                  offset:40; size:16;
//   field:__u8 daddr_v6[16];                  offset:56; size:16;
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

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_inet_sock_set_state(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_inet_sock_set_state(ctx: &TracePointContext) -> Result<(), i64> {
    let oldstate: i32 = unsafe { ctx.read_at(TP_OLDSTATE) }?;
    let newstate: i32 = unsafe { ctx.read_at(TP_NEWSTATE) }?;

    // We only care about the two edges that bracket a real flow.
    if newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE {
        return Ok(());
    }
    // Filter out CLOSE transitions that weren't from a LIVE state; those are
    // listener-socket teardowns we don't care about.
    if newstate == TCP_CLOSE && oldstate != TCP_ESTABLISHED {
        return Ok(());
    }

    if util::is_self() || util::filtered_out_by_pid() {
        return Ok(());
    }

    let skaddr: u64 = unsafe { ctx.read_at(TP_SKADDR) }?;
    // The kernel stores `sport` in host byte order (`sk->sk_num`) and `dport`
    // in network byte order (`sk->sk_dport`). We forward both raw — userspace
    // does the `u16::from_be` so the BPF bytecode stays minimal.
    let sport: u16 = unsafe { ctx.read_at(TP_SPORT) }?;
    let dport: u16 = unsafe { ctx.read_at(TP_DPORT) }?;
    let family: u16 = unsafe { ctx.read_at(TP_FAMILY) }?;
    let protocol_u16: u16 = unsafe { ctx.read_at(TP_PROTOCOL) }?;

    let (saddr, daddr) = read_addrs(ctx, family)?;

    if newstate == TCP_ESTABLISHED {
        emit_conn_start(
            skaddr,
            (family & 0xFF) as u8,
            (protocol_u16 & 0xFF) as u8,
            sport,
            dport,
            saddr,
            daddr,
        );
    } else {
        emit_conn_end(skaddr);
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

fn emit_conn_start(
    sock_id: u64,
    family: u8,
    protocol: u8,
    sport: u16,
    dport: u16,
    saddr: [u8; 16],
    daddr: [u8; 16],
) {
    // Remember the socket so later data events can attribute bytes to it.
    let info = SockInfo {
        sock_id,
        pid: 0,
        tgid: 0,
        sport,
        dport,
        family,
        protocol,
        _pad: [0; 2],
        saddr,
        daddr,
        bytes_sent: 0,
        bytes_recv: 0,
        started_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
    };
    let _ = SOCKS.insert(&sock_id, &info, 0);

    let Some(mut entry) = EVENTS.reserve::<Event<ConnStartPayload>>(0) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        let mut header = util::fill_header(EventKind::ConnStart);
        header.total_len = core::mem::size_of::<Event<ConnStartPayload>>() as u32;
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
    let _ = SOCKS.remove(&sock_id);

    let Some(mut entry) = EVENTS.reserve::<Event<ConnEndPayload>>(0) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        let mut header = util::fill_header(EventKind::ConnEnd);
        header.total_len = core::mem::size_of::<Event<ConnEndPayload>>() as u32;
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

/// Small generic to keep `emit_conn_start` / `emit_conn_end` tidy.
#[repr(C)]
pub struct Event<P: Copy> {
    pub header: shannon_common::EventHeader,
    pub payload: P,
}

// Compile-time check that our event frames always start with a full header.
const _: () = {
    assert!(core::mem::offset_of!(Event<ConnStartPayload>, header) == 0);
    assert!(core::mem::size_of::<shannon_common::EventHeader>() == HEADER_SIZE);
};
