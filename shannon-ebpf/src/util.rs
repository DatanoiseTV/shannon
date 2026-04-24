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

/// Sentinel key in [`PID_FILTER`] indicating the filter is active. We use
/// `u32::MAX` rather than `0` because `0` is a legal PID (swapper / softirq
/// context), so using `0` as the sentinel collides with kernel-context
/// traffic observed via tracepoints.
const FILTER_SENTINEL: u32 = u32::MAX;

/// Returns `true` when the PID_FILTER is active and the given tgid is not
/// in it.
#[inline(always)]
pub fn filtered_out(tgid: u32) -> bool {
    unsafe {
        if PID_FILTER.get(&FILTER_SENTINEL).is_some() {
            PID_FILTER.get(&tgid).is_none()
        } else {
            false
        }
    }
}

/// Legacy wrapper for paths that *do* run in user context (kprobes in the
/// caller's task), where `bpf_get_current_pid_tgid` gives the right answer.
#[inline(always)]
pub fn filtered_out_by_pid() -> bool {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    filtered_out(tgid)
}
