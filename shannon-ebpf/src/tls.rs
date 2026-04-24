//! TLS plaintext capture via library uprobes.
//!
//! We attach uprobes to the boundary functions of userland TLS libraries:
//! their `*_write` call receives plaintext that the library is *about to*
//! encrypt, their `*_read` call returns plaintext the library has *just*
//! decrypted. By riding those boundaries we see TLS traffic in the clear
//! without ever touching keys or intercepting certificates.
//!
//! This module implements the OpenSSL / BoringSSL path (both export the
//! same symbols — `SSL_read`, `SSL_write`, plus the `_ex` variants used
//! when the buffer may exceed `INT_MAX`). GnuTLS, NSS and Go are handled
//! in their own symbol sets by the userspace loader, which attaches the
//! appropriate uprobe to the appropriate binary.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_buf},
    macros::{map, uprobe, uretprobe},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};

use shannon_common::{EventHeader, EventKind, TlsDataHeader, TlsLib};

use crate::{
    maps::{EVENTS, SCRATCH},
    util,
};

/// Payload cap per TLS event — same as the TCP path for consistency.
const CAP: usize = 4096;

/// Per-thread bookkeeping of in-flight `SSL_read` / `SSL_read_ex` calls.
#[repr(C)]
#[derive(Copy, Clone)]
struct PendingRead {
    ssl: u64,
    buf: u64,
    /// Pointer to the `size_t *readbytes` out-parameter (only for the `_ex`
    /// variants; zero otherwise).
    readbytes_out: u64,
    lib: u8,
    _pad: [u8; 7],
}

#[map]
static PENDING_SSL: HashMap<u64, PendingRead> =
    HashMap::with_max_entries(16_384, aya_ebpf::bindings::BPF_F_NO_PREALLOC);

// ---------------------------------------------------------------------------
// OpenSSL / BoringSSL: SSL_write(SSL*, const void *buf, int num)
// ---------------------------------------------------------------------------

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    let Some(ssl) = ctx.arg::<u64>(0) else { return 1 };
    let Some(buf) = ctx.arg::<u64>(1) else { return 1 };
    let Some(num) = ctx.arg::<i32>(2) else { return 1 };
    if num <= 0 {
        return 0;
    }
    emit_tls_data(ssl, buf, num as u32, num as u32, Direction::Tx, TlsLib::OpenSsl);
    0
}

// int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)
#[uprobe]
pub fn ssl_write_ex(ctx: ProbeContext) -> u32 {
    let Some(ssl) = ctx.arg::<u64>(0) else { return 1 };
    let Some(buf) = ctx.arg::<u64>(1) else { return 1 };
    let Some(num) = ctx.arg::<u64>(2) else { return 1 };
    if num == 0 {
        return 0;
    }
    let n = (num as usize).min(CAP) as u32;
    emit_tls_data(ssl, buf, n, num as u32, Direction::Tx, TlsLib::OpenSsl);
    0
}

// ---------------------------------------------------------------------------
// OpenSSL / BoringSSL: SSL_read(SSL*, void *buf, int num)
// ---------------------------------------------------------------------------

#[uprobe]
pub fn ssl_read(ctx: ProbeContext) -> u32 {
    let Some(ssl) = ctx.arg::<u64>(0) else { return 1 };
    let Some(buf) = ctx.arg::<u64>(1) else { return 1 };
    let pt = bpf_get_current_pid_tgid();
    let _ = PENDING_SSL.insert(
        &pt,
        &PendingRead {
            ssl,
            buf,
            readbytes_out: 0,
            lib: TlsLib::OpenSsl as u8,
            _pad: [0; 7],
        },
        0,
    );
    0
}

#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) -> u32 {
    finish_read(&ctx, /* via_ex = */ false)
}

// int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *readbytes)
#[uprobe]
pub fn ssl_read_ex(ctx: ProbeContext) -> u32 {
    let Some(ssl) = ctx.arg::<u64>(0) else { return 1 };
    let Some(buf) = ctx.arg::<u64>(1) else { return 1 };
    let Some(readbytes_out) = ctx.arg::<u64>(3) else { return 1 };
    let pt = bpf_get_current_pid_tgid();
    let _ = PENDING_SSL.insert(
        &pt,
        &PendingRead {
            ssl,
            buf,
            readbytes_out,
            lib: TlsLib::OpenSsl as u8,
            _pad: [0; 7],
        },
        0,
    );
    0
}

#[uretprobe]
pub fn ssl_read_ex_ret(ctx: RetProbeContext) -> u32 {
    finish_read(&ctx, /* via_ex = */ true)
}

fn finish_read(ctx: &RetProbeContext, via_ex: bool) -> u32 {
    let pt = bpf_get_current_pid_tgid();
    let Some(pending) = (unsafe { PENDING_SSL.get(&pt) }).copied() else { return 0 };
    let _ = PENDING_SSL.remove(&pt);

    let ret: i32 = ctx.ret().unwrap_or(-1);
    let bytes: u32 = if via_ex {
        // `SSL_read_ex` returns 1 on success; the byte count is in `*readbytes`.
        if ret != 1 || pending.readbytes_out == 0 {
            return 0;
        }
        match unsafe {
            aya_ebpf::helpers::bpf_probe_read_user::<u64>(pending.readbytes_out as *const u64)
        } {
            Ok(v) => (v as usize).min(CAP) as u32,
            Err(_) => 0,
        }
    } else {
        // `SSL_read` returns bytes (>0) or ≤0 on error / close.
        if ret <= 0 {
            return 0;
        }
        ret as u32
    };
    if bytes == 0 {
        return 0;
    }
    let lib = TlsLib::from_u8(pending.lib).unwrap_or(TlsLib::OpenSsl);
    emit_tls_data(pending.ssl, pending.buf, bytes, bytes, Direction::Rx, lib);
    0
}

// ---------------------------------------------------------------------------
// Event assembly
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
enum Direction {
    Tx = 0,
    Rx = 1,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TlsFrame {
    header: EventHeader,
    body: TlsDataHeader,
    data: [u8; CAP],
}

#[inline(always)]
fn emit_tls_data(
    ssl: u64,
    buf: u64,
    captured: u32,
    total: u32,
    dir: Direction,
    lib: TlsLib,
) {
    if util::is_self() || util::filtered_out_by_pid() {
        return;
    }
    let Some(scratch_ptr) = SCRATCH.get_ptr_mut(0) else { return };
    // SAFETY: per-CPU slot, valid for the duration of this program.
    let scratch = unsafe { &mut *scratch_ptr };

    let n = (captured as usize).min(CAP);
    let captured_len: u32 = if n > 0 {
        match unsafe { bpf_probe_read_user_buf(buf as *const u8, &mut scratch.bytes[..n]) } {
            Ok(()) => n as u32,
            Err(_) => 0,
        }
    } else {
        0
    };

    let total_len =
        size_of::<EventHeader>() + size_of::<TlsDataHeader>() + captured_len as usize;

    let Some(mut entry) = EVENTS.reserve::<TlsFrame>(0) else { return };
    unsafe {
        let ev = entry.as_mut_ptr();
        let mut header = util::fill_header(EventKind::TlsData);
        header.total_len = total_len as u32;
        (*ev).header = header;
        (*ev).body = TlsDataHeader {
            tls_lib: lib as u8,
            direction: dir as u8,
            _pad: 0,
            conn_id: ssl,
            socket_fd: -1,
            total_bytes: total,
            captured_len,
            _pad2: 0,
        };
        let dst = (*ev).data.as_mut_ptr();
        let src = scratch.bytes.as_ptr();
        let copy_n = (captured_len as usize).min(CAP);
        core::ptr::copy_nonoverlapping(src, dst, copy_n);
    }
    entry.submit(0);
}
