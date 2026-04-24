//! `shannon record` — headless recorder to disk.

use crate::cli::{Cli, RecordArgs};

pub fn run(_cli: &Cli, _args: RecordArgs) -> anyhow::Result<()> {
    anyhow::bail!("`shannon record` runtime is wired up in a subsequent commit; see docs/roadmap.md")
}
