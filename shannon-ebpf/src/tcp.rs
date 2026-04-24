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
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user_buf},
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

/// Temporary map: (pid_tgid) → (sk, msghdr) recorded at kprobe entry so
/// the kretprobe can reconstruct the call. Scoped per-thread so concurrent
/// tcp_recvmsg calls on different CPUs don't collide.
#[repr(C)]
#[derive(Copy, Clone)]
struct PendingRecv {
    sk: u64,
    msg: u64,
}

#[map]
static PENDING_RECV: HashMap<u64, PendingRecv> =
    HashMap::with_max_entries(16_384, aya_ebpf::bindings::BPF_F_NO_PREALLOC);

// Offsets derived from x86_64 Linux 6.12 headers. If a target kernel
// changes these we'd see verifier failures or garbage data; both are loud.
const MSGHDR_IOV_ITER_OFF: usize = 16;
const IOV_ITER_IOV_OFF: usize = 16;
const IOVEC_BASE_OFF: usize = 0;
const IOVEC_LEN_OFF: usize = 8;

/// Bytes of payload we forward per event. Must be a power of two ≤
/// [`TCP_DATA_CAP`] so the mask in `bpf_probe_read_user_buf` stays cheap.
const CAP: usize = 4096;

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<u64>(0) else { return 1 };
    let Some(msg) = ctx.arg::<u64>(1) else { return 1 };
    let Some(size) = ctx.arg::<usize>(2) else { return 1 };
    emit_tcp_data(sk, msg, size as u32, Direction::Tx);
    0
}

#[kprobe]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<u64>(0) else { return 1 };
    let Some(msg) = ctx.arg::<u64>(1) else { return 1 };
    let pt = bpf_get_current_pid_tgid();
    let _ = PENDING_RECV.insert(&pt, &PendingRecv { sk, msg }, 0);
    0
}

#[kretprobe]
pub fn tcp_recvmsg_ret(ctx: RetProbeContext) -> u32 {
    let pt = bpf_get_current_pid_tgid();
    let Some(pending) = (unsafe { PENDING_RECV.get(&pt) }).copied() else { return 0 };
    let _ = PENDING_RECV.remove(&pt);

    // Return value < 0 is an error; non-positive means no bytes available.
    let ret: i32 = ctx.ret().unwrap_or(-1);
    if ret <= 0 {
        return 0;
    }
    emit_tcp_data(pending.sk, pending.msg, ret as u32, Direction::Rx);
    0
}

#[derive(Copy, Clone)]
enum Direction {
    Tx = 0,
    Rx = 1,
}

fn emit_tcp_data(sk: u64, msg: u64, total_bytes: u32, dir: Direction) {
    if util::is_self() || util::filtered_out_by_pid() {
        return;
    }
    // Look up sock metadata. Missing is OK — we still emit, just with
    // a zeroed 4-tuple so userspace knows we saw traffic on an
    // unattributed socket (e.g. inbound/accepted before we attached).
    let info = unsafe { SOCKS.get(&sk) }.copied().unwrap_or(crate::maps::SockInfo {
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

    let Some(scratch_ptr) = SCRATCH.get_ptr_mut(0) else { return };
    // SAFETY: per-CPU map slot valid for this program's lifetime.
    let scratch = unsafe { &mut *scratch_ptr };

    // Try to read payload — if it fails we still emit a zero-length
    // event so the CLI can show "X bytes sent" even without content.
    let captured_len = read_first_iovec(msg, &mut scratch.bytes).unwrap_or(0);

    // Total event size = EventHeader + TcpDataHeader + captured payload.
    let total_len = size_of::<shannon_common::EventHeader>()
        + size_of::<TcpDataHeader>()
        + captured_len as usize;

    // Reserve a full fixed-size slot in the ring; we'll overwrite the
    // unused tail with zeros. Fixed size keeps the verifier happy and the
    // overhead is acceptable at CAP = 4 KiB.
    let Some(mut entry) = EVENTS.reserve::<Event<TcpDataFrame>>(0) else { return };
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
        // Copy captured bytes into the frame's data field.
        let dst = (*ev).payload.data.as_mut_ptr();
        let src = scratch.bytes.as_ptr();
        let n = (captured_len as usize).min(CAP);
        core::ptr::copy_nonoverlapping(src, dst, n);
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

fn read_first_iovec(msg: u64, dst: &mut [u8]) -> Result<u32, i64> {
    // iov_iter base.
    let iov_iter = msg + MSGHDR_IOV_ITER_OFF as u64;

    // Union field in `iov_iter`: the iovec pointer, at offset 16.
    let iov_ptr: u64 = unsafe {
        bpf_probe_read_kernel((iov_iter + IOV_ITER_IOV_OFF as u64) as *const u64)
    }?;
    if iov_ptr == 0 {
        return Ok(0);
    }

    let iov_base: u64 =
        unsafe { bpf_probe_read_kernel((iov_ptr + IOVEC_BASE_OFF as u64) as *const u64) }?;
    let iov_len: u64 =
        unsafe { bpf_probe_read_kernel((iov_ptr + IOVEC_LEN_OFF as u64) as *const u64) }?;
    if iov_base == 0 || iov_len == 0 {
        return Ok(0);
    }

    // Clamp to CAP. We don't mask — a 4KiB cap is a power of two, so the
    // verifier can bound-check via the `.min(CAP)`.
    let n = (iov_len as usize).min(CAP);
    if n == 0 {
        return Ok(0);
    }
    unsafe {
        bpf_probe_read_user_buf(iov_base as *const u8, &mut dst[..n])?;
    }
    Ok(n as u32)
}
