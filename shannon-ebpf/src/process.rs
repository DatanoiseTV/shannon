//! Process-tree tracking.
//!
//! `tracepoint:sched:sched_process_fork` fires every time a task forks. If
//! the parent is in our PID allow-list, we copy the child in too — that's
//! the `--follow-children` feature.

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use crate::maps::PID_FILTER;

// /sys/kernel/tracing/events/sched/sched_process_fork/format
//  common_*                         0..8
//  char parent_comm[16]             8
//  pid_t parent_pid                 24
//  char child_comm[16]              28
//  pid_t child_pid                  44
const TP_PARENT_PID_OFF: usize = 24;
const TP_CHILD_PID_OFF: usize = 44;

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_fork(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let parent_pid: u32 = unsafe { ctx.read_at(TP_PARENT_PID_OFF) }?;
    let child_pid: u32 = unsafe { ctx.read_at(TP_CHILD_PID_OFF) }?;
    // Only propagate when the filter is active (sentinel key 0 present)
    // AND the parent is a member. Otherwise we'd blanket-admit every
    // fork on the box.
    let active = unsafe { PID_FILTER.get(&0u32) }.is_some();
    if !active {
        return Ok(());
    }
    if unsafe { PID_FILTER.get(&parent_pid) }.is_some() {
        let _ = PID_FILTER.insert(&child_pid, &1u8, 0);
    }
    Ok(())
}
