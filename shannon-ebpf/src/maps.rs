//! Shared maps used across all shannon BPF programs.
//!
//! Declared in one place so every program sees the same instances. Userspace
//! opens them by name via aya's `Ebpf::map()` / `map_mut()`.

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    macros::map,
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
};

use shannon_common::{EventHeader, TCP_DATA_CAP};

/// Main event ring buffer. 16 MiB absorbs short bursts on a loaded box.
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Per-CPU scratch slot for staging events that exceed the 512-byte BPF
/// stack. Size covers any single event type.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScratchBuf {
    pub bytes: [u8; core::mem::size_of::<EventHeader>() + 256 + TCP_DATA_CAP],
}

#[map]
pub static SCRATCH: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(1, 0);

/// Live socket table.
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
    pub started_ns: u64,
    /// `task_struct.comm` captured at the `tcp_*_connect` kprobe — the
    /// `inet_sock_set_state` tracepoint runs in softirq and cannot get it.
    pub comm: [u8; 16],
}

#[map]
pub static SOCKS: LruHashMap<u64, SockInfo> = LruHashMap::with_max_entries(65_536, 0);

/// PID allow-list. When userspace populates at least one entry, only events
/// from those `tgid`s are emitted.
#[map]
pub static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(4096, BPF_F_NO_PREALLOC);

/// Cgroup-id allow-list.
#[map]
pub static CGROUP_FILTER: HashMap<u64, u8> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

/// Single-entry map holding shannon's own PID so we can skip its traffic by
/// default.
#[map]
pub static SELF_PID: HashMap<u32, u8> = HashMap::with_max_entries(1, BPF_F_NO_PREALLOC);

/// Self-observability counters. Per-CPU u64 array indexed by the
/// `STAT_*` constants in `shannon_common`. Userspace sums across CPUs
/// and exposes the result as Prometheus counters.
#[map]
pub static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(shannon_common::STAT_SLOTS, 0);

/// Bump a per-CPU stat slot by one. The aya helper returns `None` only
/// when the index is out of range; we silently ignore so a counter
/// miscount can never crash the BPF program.
#[inline(always)]
pub fn bump_stat(idx: u32) {
    if let Some(slot) = STATS.get_ptr_mut(idx) {
        unsafe { *slot += 1 };
    }
}
