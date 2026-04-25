//! Library facade — exposes the protocol parsers + the event types they
//! emit so external consumers (fuzz harnesses, integration tests,
//! downstream analysis tools) can call them without going through the
//! `shannon` binary.
//!
//! The binary crate (`src/main.rs`) is the operator-facing surface and
//! has its own copy of these modules; this library only exists to make
//! the parsers reusable. Both compile against the same source files —
//! adding a parser in `parsers/` automatically makes it visible here
//! and to the binary's `use crate::parsers::…` paths.

#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
// The bin keeps these modules `pub(crate)` so the workspace's
// `missing_debug_implementations` doesn't fire. Re-exposing them as
// `pub` for external fuzz / test consumption flips that on for ~80
// parser types we don't care about deriving Debug for. Silence here.
#![allow(missing_debug_implementations)]
#![allow(unreachable_pub)]

pub mod events;
pub mod parsers;
