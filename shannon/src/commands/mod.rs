//! Command implementations. Each subcommand's entry point is a `run` function
//! that takes `&Cli` and its own `Args` struct.

pub mod analyze;
pub mod ask;
pub mod proto_infer;
pub mod record;
pub mod top;
pub mod trace;
pub mod watch;
