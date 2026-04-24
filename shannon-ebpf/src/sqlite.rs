//! libsqlite3 uprobes — SQL statement capture.
//!
//! SQLite isn't a wire protocol; it's a library every desktop app,
//! mobile runtime, and embedded device on the planet links against.
//! We attach uprobes to the two functions every SQL statement
//! eventually goes through:
//!
//! ```text
//!   int sqlite3_prepare_v2(sqlite3 *db,
//!                          const char *zSql,
//!                          int        nByte,
//!                          sqlite3_stmt **ppStmt,
//!                          const char **pzTail);
//!
//!   int sqlite3_exec(sqlite3 *db,
//!                    const char *sql,
//!                    int (*cb)(void*, int, char**, char**),
//!                    void *cb_arg,
//!                    char **errmsg);
//! ```
//!
//! In both, the SQL string is at arg 1 and the database handle at
//! arg 0. `nByte == -1` means "NUL-terminated"; we cap reads at
//! [`SQLITE_TEXT_CAP`] either way.

use aya_ebpf::{helpers::bpf_probe_read_user_buf, macros::uprobe, programs::ProbeContext};

use shannon_common::{EventKind, SqliteHeader, SQLITE_TEXT_CAP};

use crate::conn::Event;
use crate::maps::{EVENTS, SCRATCH};
use crate::util;

const CAP: usize = SQLITE_TEXT_CAP;

const API_PREPARE: u8 = 1;
const API_EXEC: u8 = 2;

#[uprobe]
pub fn sqlite_prepare_v2(ctx: ProbeContext) -> u32 {
    let Some(db) = ctx.arg::<u64>(0) else {
        return 1;
    };
    let Some(sql) = ctx.arg::<u64>(1) else {
        return 1;
    };
    let nbyte_raw = ctx.arg::<i32>(2).unwrap_or(-1);
    if sql == 0 {
        return 0;
    }
    // Normalise nbyte to a bounded u32 in [0, CAP] so the verifier
    // sees a non-negative, bounded length right up to the helper
    // call. Sentinel CAP+1 means "no length known, walk as string".
    let want = if nbyte_raw < 0 {
        CAP as u32 + 1
    } else if (nbyte_raw as u32) > CAP as u32 {
        CAP as u32
    } else {
        nbyte_raw as u32
    };
    let total = if nbyte_raw < 0 {
        u32::MAX
    } else {
        nbyte_raw as u32
    };
    emit(db, sql, want, total, API_PREPARE);
    0
}

#[uprobe]
pub fn sqlite_exec(ctx: ProbeContext) -> u32 {
    let Some(db) = ctx.arg::<u64>(0) else {
        return 1;
    };
    let Some(sql) = ctx.arg::<u64>(1) else {
        return 1;
    };
    if sql == 0 {
        return 0;
    }
    // sqlite3_exec takes a C string — no length arg. Use the
    // string-sentinel so the emitter reads the full CAP and userspace
    // trims at NUL.
    emit(db, sql, CAP as u32 + 1, u32::MAX, API_EXEC);
    0
}

#[inline(always)]
fn emit(db: u64, sql_ptr: u64, want: u32, sql_total: u32, api: u8) {
    if util::is_self() || util::filtered_out_by_pid() {
        return;
    }
    // Clamp to [0, CAP] with a mask so the verifier sees a tight
    // bound. `CAP + 1` (the "string sentinel" from the caller) becomes
    // `CAP`; anything else gets clamped down to CAP, and a zero read
    // returns early.
    let n = (want as usize).min(CAP);
    if n == 0 {
        return;
    }

    let Some(scratch_ptr) = SCRATCH.get_ptr_mut(0) else {
        return;
    };
    let scratch = unsafe { &mut *scratch_ptr };
    let captured_len: u32 =
        match unsafe { bpf_probe_read_user_buf(sql_ptr as *const u8, &mut scratch.bytes[..n]) } {
            Ok(()) => n as u32,
            Err(_) => 0,
        };
    if captured_len == 0 {
        return;
    }

    let total_len = size_of::<shannon_common::EventHeader>()
        + size_of::<SqliteHeader>()
        + captured_len as usize;

    let Some(mut entry) = EVENTS.reserve::<Event<SqliteFrame>>(0) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        let mut header = util::fill_header(EventKind::SqliteQuery);
        header.total_len = total_len as u32;
        (*ev).header = header;
        (*ev).payload.body = SqliteHeader {
            api,
            _pad: [0; 3],
            db_handle: db,
            sql_total_bytes: sql_total,
            captured_len,
        };
        let dst = (*ev).payload.data.as_mut_ptr();
        let src = scratch.bytes.as_ptr();
        let ncopy = (captured_len as usize).min(CAP);
        core::ptr::copy_nonoverlapping(src, dst, ncopy);
    }
    entry.submit(0);
}

/// Fixed-size payload mirror; matches the reservation size the BPF
/// verifier wants to see.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SqliteFrame {
    pub body: SqliteHeader,
    pub data: [u8; CAP],
}
