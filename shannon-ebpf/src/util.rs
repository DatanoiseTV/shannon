//! Helpers shared by multiple probes.

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
};

use shannon_common::{ABI_VERSION, COMM_LEN, EventHeader, EventKind};

use crate::maps::{PID_FILTER, SELF_PID};

/// Populate a fresh [`EventHeader`] with the caller's context. `total_len`
/// should be set by the caller after appending the payload.
#[inline(always)]
pub fn fill_header(kind: EventKind) -> EventHeader {
    // `bpf_get_current_pid_tgid()` returns `tgid << 32 | pid`. aya exposes
    // it as a single u64; we split by convention.
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);

    EventHeader {
        version: ABI_VERSION,
        kind: kind as u8,
        _pad: 0,
        total_len: 0,
        cpu: unsafe { aya_ebpf::helpers::bpf_get_smp_processor_id() },
        ts_ns: unsafe { bpf_ktime_get_ns() },
        pid,
        tgid,
        uid,
        gid,
        cgroup_id: unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() },
        netns_cookie: 0,
        comm,
    }
}

/// Returns `true` when the current PID should be dropped because it matches
/// shannon's own `tgid` and the operator hasn't asked to include self.
#[inline(always)]
pub fn is_self() -> bool {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    unsafe { SELF_PID.get(&tgid).is_some() }
}

/// Returns `true` when the PID_FILTER is non-empty and the current tgid is
/// not in it (i.e. we should drop this event).
#[inline(always)]
pub fn filtered_out_by_pid() -> bool {
    // Peek at entry 0 of the filter map as a probe: if any entry exists,
    // the filter is active and we require the current tgid to be present.
    //
    // We can't cheaply count entries from BPF, so we adopt a conservative
    // rule: if a well-known "sentinel" key is present (written by userspace
    // when the filter is enabled), we require membership.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    unsafe {
        // Sentinel key `0` indicates "filter active". Userspace sets this
        // when any --pid argument is passed; clears it otherwise.
        if PID_FILTER.get(&0u32).is_some() {
            PID_FILTER.get(&tgid).is_none()
        } else {
            false
        }
    }
}
