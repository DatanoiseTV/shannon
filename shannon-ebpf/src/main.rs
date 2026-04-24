//! shannon kernel-side eBPF programs.
//!
//! This binary crate compiles to `bpfel-unknown-none`. Each submodule owns
//! one probe family (connection lifecycle, TCP data, TLS uprobes, DNS).
//! The userspace loader attaches them by name at runtime.
//!
//! ## Verifier discipline
//!
//! - No recursion, no function pointers, no dynamic dispatch.
//! - Every `bpf_probe_read_user` buffer length is masked with a
//!   power-of-two mask so the verifier can prove bounds.
//! - Events bigger than the BPF stack (512 bytes) are staged in a per-CPU
//!   scratch array map, not on the stack.
//! - All maps are declared up front with fixed capacities.
//!
//! The current commit carries only the *scaffold* — maps, shared types,
//! and a single placeholder program that attaches to prove the tooling
//! works end-to-end. Actual probes land in follow-up commits in the order
//! documented in `docs/roadmap.md`.

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]
#![allow(non_upper_case_globals)]
#![warn(clippy::pedantic)]

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    macros::{kprobe, map},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
};

use shannon_common::{
    ABI_VERSION, ConnEndPayload, ConnStartPayload, DnsHeader, EventHeader, ProcExecHeader,
    ProcExitPayload, TcpDataHeader, TlsDataHeader,
};

/// Main event ring buffer. 16 MiB absorbs short bursts on a loaded box.
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Per-CPU scratch slot for staging events that exceed the BPF stack.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScratchEvent {
    pub header: EventHeader,
    pub body: [u8; 16 * 1024 + 128],
}

#[map]
pub static SCRATCH: PerCpuArray<ScratchEvent> = PerCpuArray::with_max_entries(1, 0);

/// Map of active socket pointers → flow metadata.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockInfo {
    pub sock_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u8,
    pub protocol: u8,
    pub _pad: [u8; 2],
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

#[map]
pub static SOCKS: LruHashMap<u64, SockInfo> = LruHashMap::with_max_entries(65_536, 0);

/// Filter: if non-empty, only events whose `tgid` is present here are emitted.
#[map]
pub static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(4096, BPF_F_NO_PREALLOC);

/// Filter: when populated, only emit events whose cgroup id is in here.
#[map]
pub static CGROUP_FILTER: HashMap<u64, u8> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

/// The PID of shannon itself, so we can skip our own traffic by default.
#[map]
pub static SELF_PID: HashMap<u32, u8> = HashMap::with_max_entries(1, BPF_F_NO_PREALLOC);

/// Placeholder probe — attached to `do_nothing_symbol` by the loader just so
/// we exercise the load+attach path before any real probe is landed.
#[kprobe]
pub fn shannon_placeholder(_ctx: ProbeContext) -> u32 {
    // Keep the maps alive so the verifier doesn't drop them.
    let _ = EVENTS.reserve::<[u8; 0]>(0);
    0
}

// Force layout checks so a careless refactor of `shannon-common` fails fast.
#[allow(dead_code)]
const _ASSERT_ABI: u8 = ABI_VERSION;
#[allow(dead_code)]
const _SIZES: [usize; 8] = [
    core::mem::size_of::<EventHeader>(),
    core::mem::size_of::<ConnStartPayload>(),
    core::mem::size_of::<ConnEndPayload>(),
    core::mem::size_of::<TcpDataHeader>(),
    core::mem::size_of::<TlsDataHeader>(),
    core::mem::size_of::<DnsHeader>(),
    core::mem::size_of::<ProcExecHeader>(),
    core::mem::size_of::<ProcExitPayload>(),
];

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
