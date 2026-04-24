//! `shannon trace` — stream decoded events to stdout in pretty, ndjson, or
//! console form.

use crate::cli::{Cli, TraceArgs};

pub fn run(_cli: &Cli, _args: TraceArgs) -> anyhow::Result<()> {
    anyhow::bail!("`shannon trace` runtime is wired up in a subsequent commit; see docs/roadmap.md")
}
