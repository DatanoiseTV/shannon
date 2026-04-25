//! TCP payload capture probes.
//!
//! We kprobe `tcp_sendmsg` and `tcp_recvmsg` to forward the plaintext bytes
//! that cross the socket boundary in userland. For receive we need
//! `kretprobe` (data is only populated when the syscall returns), so we
//! stash the call's arguments in a `CALLS` map keyed by PID/TGID at entry
//! and read them out at exit.
//!
//! ## msghdr / iov_iter layout
//!
//! The kernel passes data to `tcp_sendmsg` and `tcp_recvmsg` via `struct
//! msghdr`. Reading the iovec out of that struct requires walking:
//!
//! ```text
//!   msghdr + 16 → iov_iter
//!     iov_iter + 16 → iovec *  (const struct iovec *__iov)
//!       iovec + 0  → void __user *iov_base
//!       iovec + 8  → size_t iov_len
//! ```
//!
//! Offsets match x86_64 Linux 6.12. Portability across kernels would use
//! BTF CO-RE; for now we document the version we target and verify in
//! `shannon doctor`.

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_user_buf,
    },
    macros::{kprobe, kretprobe, map},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};

use shannon_common::{EventKind, TcpDataHeader};

use crate::{
    conn::Event,
    maps::{EVENTS, SCRATCH, SOCKS},
    util,
};

/// Temporary map: (pid_tgid) → call arguments recorded at kprobe entry so
/// the kretprobe can reconstruct the call. At entry we walk the iov_iter
/// once and stash `iov_base` directly — by return time the iter has
/// advanced, but the user buffer at `iov_base` is now populated.
#[repr(C)]
#[derive(Copy, Clone)]
struct PendingRecv {
    sk: u64,
    iov_base: u64,
    iov_cap: u64,
}

#[map]
static PENDING_RECV: HashMap<u64, PendingRecv> =
    HashMap::with_max_entries(16_384, aya_ebpf::bindings::BPF_F_NO_PREALLOC);

// Offsets derived from x86_64 Linux 6.12 BTF. If a target kernel changes
// these we'd see verifier failures or garbage data; both are loud.
//
//   struct msghdr { ...; struct iov_iter msg_iter; ... }
//     msg_iter at offset 16
//
//   struct iov_iter {
//     u8 iter_type;        // 0
//     u8 flags[3];         // 1..=3
//     size_t iov_offset;   // 8
//     union {
//       struct iovec __ubuf_iovec;        // ITER_UBUF variant
//       struct { const struct iovec *__iov; size_t count; };  // ITER_IOVEC
//     };                                  // offset 16..=31
//     ...
//   }
const MSGHDR_IOV_ITER_OFF: usize = 16;
const IOV_ITER_TYPE_OFF: usize = 0;
const IOV_ITER_UNION_OFF: usize = 16;
const IOVEC_BASE_OFF: usize = 0;
const IOVEC_LEN_OFF: usize = 8;

// Linux iter_type discriminant values (include/linux/uio.h).
const ITER_UBUF: u8 = 0;
const ITER_IOVEC: u8 = 1;

/// Bytes of payload we forward per event. Must be a power of two ≤
/// [`TCP_DATA_CAP`] so the mask in `bpf_probe_read_user_buf` stays cheap.
const CAP: usize = 4096;

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<u64>(0) else {
        return 1;
    };
    let Some(msg) = ctx.arg::<u64>(1) else {
        return 1;
    };
    let Some(size) = ctx.arg::<usize>(2) else {
        return 1;
    };
    let (iov_base, iov_cap) = resolve_iovec(msg).unwrap_or((0, 0));
    if iov_base != 0 {
        let captured = (iov_cap as usize).min(size).min(CAP) as u32;
        emit_tcp_data_from_buf(sk, iov_base, captured, size as u32, Direction::Tx);
    }
    0
}

#[kprobe]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<u64>(0) else {
        return 1;
    };
    let Some(msg) = ctx.arg::<u64>(1) else {
        return 1;
    };

    // Walk the iov_iter now so we capture the buffer address the caller
    // prepared — by kretprobe time the iter has advanced past it.
    let (iov_base, iov_cap) = resolve_iovec(msg).unwrap_or((0, 0));
    if iov_base == 0 {
        return 0;
    }

    let pt = bpf_get_current_pid_tgid();
    let _ = PENDING_RECV.insert(
        &pt,
        &PendingRecv {
            sk,
            iov_base,
            iov_cap,
        },
        0,
    );
    0
}

#[kretprobe]
pub fn tcp_recvmsg_ret(ctx: RetProbeContext) -> u32 {
    let pt = bpf_get_current_pid_tgid();
    let Some(pending) = (unsafe { PENDING_RECV.get(&pt) }).copied() else {
        return 0;
    };
    let _ = PENDING_RECV.remove(&pt);

    // ret < 0 is -errno; 0 is "peer closed". Nothing to capture either way.
    let ret: i32 = ctx.ret().unwrap_or(-1);
    if ret <= 0 {
        return 0;
    }
    let captured = (ret as usize).min(pending.iov_cap as usize).min(CAP) as u32;
    emit_tcp_data_from_buf(
        pending.sk,
        pending.iov_base,
        captured,
        ret as u32,
        Direction::Rx,
    );
    0
}

#[derive(Copy, Clone)]
pub enum Direction {
    Tx = 0,
    Rx = 1,
}

fn emit_tcp_data_from_buf(sk: u64, user_buf: u64, captured: u32, total_bytes: u32, dir: Direction) {
    if util::is_self() || util::filtered_out_by_pid() {
        return;
    }
    let info = unsafe { SOCKS.get(&sk) }
        .copied()
        .unwrap_or(crate::maps::SockInfo {
            sock_id: sk,
            pid: 0,
            tgid: 0,
            sport: 0,
            dport: 0,
            family: 0,
            protocol: 0,
            _pad: [0; 2],
            saddr: [0; 16],
            daddr: [0; 16],
            bytes_sent: 0,
            bytes_recv: 0,
            started_ns: 0,
            comm: [0; 16],
        });

    let Some(scratch_ptr) = SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: per-CPU slot, valid for the duration of this program.
    let scratch = unsafe { &mut *scratch_ptr };

    let n = (captured as usize).min(CAP);
    let captured_len = if n > 0 {
        match unsafe { bpf_probe_read_user_buf(user_buf as *const u8, &mut scratch.bytes[..n]) } {
            Ok(()) => n as u32,
            Err(_) => 0,
        }
    } else {
        0
    };

    // Total event size = EventHeader + TcpDataHeader + captured payload.
    let total_len = size_of::<shannon_common::EventHeader>()
        + size_of::<TcpDataHeader>()
        + captured_len as usize;

    // Reserve a full fixed-size slot in the ring; we'll overwrite the
    // unused tail with zeros. Fixed size keeps the verifier happy and the
    // overhead is acceptable at CAP = 4 KiB.
    let Some(mut entry) = EVENTS.reserve::<Event<TcpDataFrame>>(0) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        let mut header = util::fill_header(EventKind::TcpData);
        if info.pid != 0 {
            header.pid = info.pid;
            header.tgid = info.tgid;
            header.comm = info.comm;
        }
        header.total_len = total_len as u32;
        (*ev).header = header;
        (*ev).payload.body = TcpDataHeader {
            protocol: info.protocol,
            direction: dir as u8,
            family: info.family,
            _pad: 0,
            sport: info.sport,
            dport: info.dport,
            saddr: info.saddr,
            daddr: info.daddr,
            sock_id: sk,
            total_bytes,
            captured_len,
        };
        // Copy captured bytes into the frame's data field. Use the
        // bpf_probe_read_kernel helper rather than core::ptr::copy_*
        // — the latter lowers to a manual byte loop on bpf-target,
        // which 5.15's verifier walks symbolically and rejects with
        // "instruction limit exceeded". The helper is one-shot and
        // doesn't get unrolled.
        let dst = (*ev).payload.data.as_mut_ptr();
        let src = scratch.bytes.as_ptr();
        let n = (captured_len as usize).min(CAP);
        let dst_slice = core::slice::from_raw_parts_mut(dst, n);
        let _ = bpf_probe_read_kernel_buf(src, dst_slice);
    }
    entry.submit(0);
}

/// Fixed-size payload for `tcp_sendmsg` / `tcp_recvmsg` events. Kept
/// `#[repr(C)]` so it matches on both sides without any `bytemuck`
/// gymnastics. Size stays constant even when `captured_len < CAP`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpDataFrame {
    pub body: TcpDataHeader,
    pub data: [u8; CAP],
}

/// Resolve (iov_base, iov_capacity) from a kernel msghdr pointer,
/// handling both ITER_UBUF and ITER_IOVEC iov_iter variants.
/// `pub` so the UDP path in [`crate::udp`] can reuse it — the layout
/// is the same between `tcp_sendmsg` and `udp_sendmsg`.
pub fn resolve_iovec(msg: u64) -> Result<(u64, u64), i64> {
    let iov_iter = msg + MSGHDR_IOV_ITER_OFF as u64;
    let iter_type: u8 =
        unsafe { bpf_probe_read_kernel((iov_iter + IOV_ITER_TYPE_OFF as u64) as *const u8) }?;

    match iter_type {
        ITER_UBUF => {
            let base: u64 = unsafe {
                bpf_probe_read_kernel((iov_iter + IOV_ITER_UNION_OFF as u64) as *const u64)
            }?;
            let len: u64 = unsafe {
                bpf_probe_read_kernel(
                    (iov_iter + IOV_ITER_UNION_OFF as u64 + IOVEC_LEN_OFF as u64) as *const u64,
                )
            }?;
            Ok((base, len))
        }
        ITER_IOVEC => {
            let iov_ptr: u64 = unsafe {
                bpf_probe_read_kernel((iov_iter + IOV_ITER_UNION_OFF as u64) as *const u64)
            }?;
            if iov_ptr == 0 {
                return Ok((0, 0));
            }
            let base: u64 =
                unsafe { bpf_probe_read_kernel((iov_ptr + IOVEC_BASE_OFF as u64) as *const u64) }?;
            let len: u64 =
                unsafe { bpf_probe_read_kernel((iov_ptr + IOVEC_LEN_OFF as u64) as *const u64) }?;
            Ok((base, len))
        }
        // Kernel-internal producers; not relevant for L7 plaintext.
        _ => Ok((0, 0)),
    }
}
