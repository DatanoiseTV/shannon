//! shannon kernel-side eBPF programs.
//!
//! This binary crate compiles to `bpfel-unknown-none`. Each submodule owns
//! one probe family. The userspace loader attaches them by program name
//! at runtime.
//!
//! ## Verifier discipline
//!
//! - No recursion, no function pointers, no dynamic dispatch.
//! - Every `bpf_probe_read_user` buffer length is masked with a
//!   power-of-two mask so the verifier can prove bounds.
//! - Events bigger than the BPF stack (512 bytes) are staged in a per-CPU
//!   scratch array map, not on the stack.
//! - All maps are declared up front with fixed capacities.

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

pub mod conn;
pub mod maps;
pub mod process;
pub mod sqlite;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod util;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Re-export program entry points so aya can find them by name. aya attaches
// BPF programs by their `#[<program_type>]`-annotated function symbol, but
// `#[used]` via re-export keeps the compiler from eliding them.
pub use conn::{inet_sock_set_state, tcp_v4_connect, tcp_v6_connect};
pub use process::sched_process_fork;
pub use tcp::{tcp_recvmsg, tcp_recvmsg_ret, tcp_sendmsg};
pub use sqlite::{sqlite_exec, sqlite_prepare_v2};
pub use udp::{udp_recvmsg, udp_recvmsg_ret, udp_sendmsg};
pub use tls::{
    ssl_read, ssl_read_ex, ssl_read_ex_ret, ssl_read_ret, ssl_write, ssl_write_ex,
};
