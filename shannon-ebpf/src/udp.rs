//! UDP payload capture.
//!
//! `udp_sendmsg` has the same signature as `tcp_sendmsg`
//! (`sk`, `msg`, `len`), so we reuse [`crate::tcp::resolve_iovec`]
//! to get the user buffer. What's new is that UDP sockets aren't
//! tracked in the `SOCKS` LRU (there's no `tcp_v4_connect` /
//! `inet_sock_set_state` equivalent for UDP that we probe), so we
//! read the destination address + port directly off `struct sock`
//! every call.
//!
//! ## Receive side
//!
//! For `udp_recvmsg` the user buffer is filled on return, so a
//! clean implementation needs a `kretprobe` (same dance as TCP).
//! v1 ships the TX path only — that's enough to light up:
//!
//!   - DNS / mDNS / SSDP / LLMNR queries
//!   - NTP client requests
//!   - DHCP DISCOVER / REQUEST
//!   - TFTP RRQ / WRQ
//!   - Kerberos AS-REQ / TGS-REQ over UDP
//!   - Syslog emitters (legacy udp/514)
//!   - BACnet / SNMP polls
//!   - STUN client binding, WireGuard handshake init
//!
//! …across roughly half the shipped parsers that are currently
//! idle waiting for a UDP data path.
//!
//! ## struct sock layout (x86_64 Linux 6.12)
//!
//! ```text
//!   offset 0   skc_daddr         __be32  (dest IPv4, network order)
//!   offset 4   skc_rcv_saddr     __be32  (local IPv4)
//!   offset 8   skc_hash          u32
//!   offset 12  skc_dport         __be16  (dest port, network order)
//!   offset 14  skc_num           u16     (local port, host order)
//!   offset 16  skc_family        u16
//! ```
//!
//! For unconnected UDP these fields read as zero; we fall back to
//! walking `msg->msg_name` (a `sockaddr_in*`) when that happens.
//!
//! ## struct msghdr
//!
//! ```text
//!   offset 0   msg_name     void *     (sockaddr)
//!   offset 8   msg_namelen  int
//! ```

use aya_ebpf::{
    helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_buf, bpf_probe_read_user_buf},
    macros::kprobe,
    programs::ProbeContext,
};

use shannon_common::{EventKind, TcpDataHeader};

use crate::conn::Event;
use crate::maps::{EVENTS, SCRATCH};
use crate::tcp::{resolve_iovec, Direction, TcpDataFrame};
use crate::util;

// struct sock / sock_common — x86_64, Linux 6.12,
// CONFIG_NET_NS=y, CONFIG_IPV6=y. Offsets derived from kernel
// headers; if a target kernel has a different config the v6 reads
// return zeros / EFAULT and we skip emission rather than emit
// garbage. Same approach as the tcp probes.
const SK_DADDR: usize = 0;       // __be32 IPv4 daddr
const SK_SADDR: usize = 4;       // __be32 IPv4 saddr
const SK_DPORT: usize = 12;      // __be16 dport (shared between v4 + v6)
const SK_SPORT: usize = 14;      // u16    local port (host order)
const SK_FAMILY: usize = 16;
const SK_V6_DADDR: usize = 56;   // struct in6_addr (16 bytes)
const SK_V6_SADDR: usize = 72;   // struct in6_addr (16 bytes)

// struct msghdr
const MSGHDR_NAME_OFF: usize = 0;
const MSGHDR_NAMELEN_OFF: usize = 8;

// struct sockaddr_in
const SOCKADDR_IN_PORT: usize = 2;
const SOCKADDR_IN_ADDR: usize = 4;

// struct sockaddr_in6
const SOCKADDR_IN6_PORT: usize = 2;
const SOCKADDR_IN6_ADDR: usize = 8; // skip u16 family + u16 port + u32 flowinfo

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_UDP: u8 = 17;

const CAP: usize = 4096;

#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<u64>(0) else { return 1 };
    let Some(msg) = ctx.arg::<u64>(1) else { return 1 };
    let Some(size) = ctx.arg::<usize>(2) else { return 1 };
    if util::is_self() || util::filtered_out_by_pid() {
        return 0;
    }
    let (iov_base, iov_cap) = resolve_iovec(msg).unwrap_or((0, 0));
    if iov_base == 0 {
        return 0;
    }
    let captured = (iov_cap as usize).min(size).min(CAP) as u32;
    emit_udp_data(sk, msg, iov_base, captured, size as u32, Direction::Tx);
    0
}

#[inline(always)]
fn emit_udp_data(
    sk: u64,
    msg: u64,
    user_buf: u64,
    captured: u32,
    total_bytes: u32,
    dir: Direction,
) {
    // Pull dst fields from the sock. Unconnected UDP will have
    // skc_dport == 0, in which case we fall back to msg_name.
    let family: u16 = unsafe { bpf_probe_read_kernel((sk + SK_FAMILY as u64) as *const u16) }
        .unwrap_or(0);
    if family != AF_INET && family != AF_INET6 {
        return;
    }

    // Ports are in the same position regardless of family.
    let dport_be: u16 =
        unsafe { bpf_probe_read_kernel((sk + SK_DPORT as u64) as *const u16) }.unwrap_or(0);
    let sport_host: u16 =
        unsafe { bpf_probe_read_kernel((sk + SK_SPORT as u64) as *const u16) }.unwrap_or(0);

    let mut saddr16 = [0u8; 16];
    let mut daddr16 = [0u8; 16];
    let mut dport_final = dport_be;

    if family == AF_INET {
        let saddr_be: u32 =
            unsafe { bpf_probe_read_kernel((sk + SK_SADDR as u64) as *const u32) }.unwrap_or(0);
        let daddr_be: u32 =
            unsafe { bpf_probe_read_kernel((sk + SK_DADDR as u64) as *const u32) }.unwrap_or(0);
        saddr16[..4].copy_from_slice(&saddr_be.to_ne_bytes());
        daddr16[..4].copy_from_slice(&daddr_be.to_ne_bytes());

        if dport_final == 0 {
            // Unconnected send — dst is in msg->msg_name (sockaddr_in).
            let (pr, ad) = read_msg_name_v4(msg);
            dport_final = pr;
            if ad != 0 {
                daddr16 = [0u8; 16];
                daddr16[..4].copy_from_slice(&ad.to_ne_bytes());
            }
        }
    } else {
        // AF_INET6
        let mut v6_s = [0u8; 16];
        let mut v6_d = [0u8; 16];
        let _ =
            unsafe { bpf_probe_read_kernel_buf((sk + SK_V6_SADDR as u64) as *const u8, &mut v6_s) };
        let _ =
            unsafe { bpf_probe_read_kernel_buf((sk + SK_V6_DADDR as u64) as *const u8, &mut v6_d) };
        saddr16 = v6_s;
        daddr16 = v6_d;

        if dport_final == 0 {
            let (pr, ad) = read_msg_name_v6(msg);
            dport_final = pr;
            if let Some(a) = ad {
                daddr16 = a;
            }
        }
    }

    if dport_final == 0 {
        return;
    }
    // Userspace applies `.swap_bytes()` on h.dport uniformly. We read
    // the raw __be16 from `struct sock`, so the value we just got is
    // already the wire-endian representation of the port as a LE u16.
    // Emitting it unchanged lets userspace's swap produce the correct
    // host-order display value.
    let dport_wire = dport_final;
    let sport = sport_host;

    let Some(scratch_ptr) = SCRATCH.get_ptr_mut(0) else {
        return;
    };
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

    let total_len = size_of::<shannon_common::EventHeader>()
        + size_of::<TcpDataHeader>()
        + captured_len as usize;

    let Some(mut entry) = EVENTS.reserve::<Event<TcpDataFrame>>(0) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        let mut header = util::fill_header(EventKind::TcpData);
        header.total_len = total_len as u32;
        (*ev).header = header;
        (*ev).payload.body = TcpDataHeader {
            protocol: IPPROTO_UDP,
            direction: dir as u8,
            family: (family & 0xff) as u8,
            _pad: 0,
            sport,
            dport: dport_wire,
            saddr: saddr16,
            daddr: daddr16,
            sock_id: sk,
            total_bytes,
            captured_len,
        };
        let dst = (*ev).payload.data.as_mut_ptr();
        let src = scratch.bytes.as_ptr();
        let n = (captured_len as usize).min(CAP);
        core::ptr::copy_nonoverlapping(src, dst, n);
    }
    entry.submit(0);
}

#[inline(always)]
fn read_msg_name_v4(msg: u64) -> (u16, u32) {
    let name_ptr: u64 =
        unsafe { bpf_probe_read_kernel((msg + MSGHDR_NAME_OFF as u64) as *const u64) }.unwrap_or(0);
    let name_len: i32 =
        unsafe { bpf_probe_read_kernel((msg + MSGHDR_NAMELEN_OFF as u64) as *const i32) }
            .unwrap_or(0);
    if name_ptr == 0 || (name_len as usize) < 8 {
        return (0, 0);
    }
    let sa_family: u16 =
        unsafe { bpf_probe_read_kernel(name_ptr as *const u16) }.unwrap_or(0);
    if sa_family != AF_INET {
        return (0, 0);
    }
    let port: u16 = unsafe {
        bpf_probe_read_kernel((name_ptr + SOCKADDR_IN_PORT as u64) as *const u16)
    }
    .unwrap_or(0);
    let addr: u32 = unsafe {
        bpf_probe_read_kernel((name_ptr + SOCKADDR_IN_ADDR as u64) as *const u32)
    }
    .unwrap_or(0);
    (port, addr)
}

#[inline(always)]
fn read_msg_name_v6(msg: u64) -> (u16, Option<[u8; 16]>) {
    let name_ptr: u64 =
        unsafe { bpf_probe_read_kernel((msg + MSGHDR_NAME_OFF as u64) as *const u64) }.unwrap_or(0);
    let name_len: i32 =
        unsafe { bpf_probe_read_kernel((msg + MSGHDR_NAMELEN_OFF as u64) as *const i32) }
            .unwrap_or(0);
    if name_ptr == 0 || (name_len as usize) < 24 {
        return (0, None);
    }
    let sa_family: u16 =
        unsafe { bpf_probe_read_kernel(name_ptr as *const u16) }.unwrap_or(0);
    if sa_family != AF_INET6 {
        return (0, None);
    }
    let port: u16 = unsafe {
        bpf_probe_read_kernel((name_ptr + SOCKADDR_IN6_PORT as u64) as *const u16)
    }
    .unwrap_or(0);
    let mut addr = [0u8; 16];
    let r = unsafe {
        bpf_probe_read_kernel_buf(
            (name_ptr + SOCKADDR_IN6_ADDR as u64) as *const u8,
            &mut addr,
        )
    };
    if r.is_err() {
        return (port, None);
    }
    (port, Some(addr))
}
