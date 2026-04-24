//! `shannon top` — live aggregate summary.

use crate::cli::{Cli, TopArgs};

pub fn run(_cli: &Cli, _args: TopArgs) -> anyhow::Result<()> {
    anyhow::bail!("`shannon top` runtime is wired up in a subsequent commit; see docs/roadmap.md")
}
