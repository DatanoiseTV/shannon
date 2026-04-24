//! `shannon watch` — interactive TUI. Composed of a loader that streams
//! events from the kernel, a flow reconstructor, a set of protocol parsers,
//! and a ratatui UI rendering four views over the same aggregated state.
//!
//! This module is the entry point; the heavy lifting lives in
//! [`crate::runtime`] (loader + event loop) and [`crate::tui`] (views).

use crate::cli::{Cli, WatchArgs};

pub fn run(_cli: &Cli, _args: WatchArgs) -> anyhow::Result<()> {
    // Runtime::spawn(cli, args).block_until_exit()
    anyhow::bail!("`shannon watch` runtime is wired up in a subsequent commit; see docs/roadmap.md")
}
