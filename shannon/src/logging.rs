//! `tracing` setup. Verbosity comes from the `-v` flags; everything else is
//! cranked down to warn by default so a quiet terminal is a quiet shannon.

use std::fs::OpenOptions;
use std::path::Path;

use anyhow::{Context, Result};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialise the global tracing subscriber.
///
/// - `verbose`: `0` warn, `1` info, `2` debug, `3+` trace.
/// - `quiet`: overrides verbose; only errors.
/// - `log_file`: when `Some`, additionally emits structured JSON to that file.
pub fn init(verbose: u8, quiet: bool, log_file: Option<&Path>) -> Result<()> {
    let level = if quiet {
        "shannon=error"
    } else {
        match verbose {
            0 => "shannon=warn",
            1 => "shannon=info",
            2 => "shannon=debug",
            _ => "shannon=trace,aya=debug",
        }
    };
    let filter = EnvFilter::try_from_env("SHANNON_LOG").unwrap_or_else(|_| EnvFilter::new(level));

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_ansi(atty::is(atty::Stream::Stderr));

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer);

    if let Some(path) = log_file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening log file {}", path.display()))?;
        let json_layer = fmt::layer()
            .json()
            .with_writer(file)
            .with_current_span(true);
        registry
            .with(json_layer)
            .try_init()
            .context("installing tracing subscriber")?;
    } else {
        registry
            .try_init()
            .context("installing tracing subscriber")?;
    }
    Ok(())
}

// atty is tiny and the tracing_subscriber feature we need for tty-detection is
// optional; inline a 1-line helper rather than pulling another crate.
mod atty {
    pub enum Stream {
        Stderr,
    }
    pub fn is(stream: Stream) -> bool {
        use std::io::IsTerminal;
        match stream {
            Stream::Stderr => std::io::stderr().is_terminal(),
        }
    }
}
