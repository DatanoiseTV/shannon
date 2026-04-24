//! `shannon analyze` — summary statistics over a recording.

use crate::cli::{Cli, AnalyzeArgs};

pub fn run(_cli: &Cli, _args: AnalyzeArgs) -> anyhow::Result<()> {
    anyhow::bail!("`shannon analyze` runtime is wired up in a subsequent commit; see docs/roadmap.md")
}
