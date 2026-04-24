//! shannon — zero-instrumentation L7 observability via eBPF.
//!
//! The binary crate is deliberately thin: it wires clap to a set of command
//! handlers. All real logic lives in sibling modules.

#![forbid(unsafe_op_in_unsafe_fn)]
// Binary-crate conveniences: these let wiring go in incrementally without
// fighting the default lint set while modules are still being connected up.
#![allow(dead_code)]

mod api_catalog;
mod ask_tools;
mod aws;
mod cert_dump;
mod cli;
mod commands;
mod config;
mod containers;
mod dns_cache;
mod doctor;
mod events;
mod file_dump;
mod flow;
mod llm;
mod llm_client;
mod logging;
mod parsers;
mod pcap;
mod proto;
mod proto_infer;
mod runtime;
mod secrets;
mod warnings;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

/// Main entry. Returns a process exit code:
///
/// - `0` success
/// - `1` any other error
/// - `2` usage error (emitted by clap on parse failure)
/// - `64` config error
/// - `77` missing privileges
/// - `78` kernel / BTF unsupported
fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(err) = logging::init(cli.verbose, cli.quiet, cli.log_file.as_deref()) {
        eprintln!("shannon: failed to initialise logging: {err:#}");
        return ExitCode::from(1);
    }

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Print the full cause chain — `{:#}` on `anyhow::Error` walks it.
            eprintln!("shannon: error: {err:#}");
            for (i, cause) in err.chain().enumerate().skip(1) {
                eprintln!("  caused by ({i}): {cause}");
            }
            tracing::debug!(error = ?err, "error detail");
            let code = err.downcast_ref::<AppError>().map_or(1u8, AppError::exit_code);
            ExitCode::from(code)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let command = cli.command.clone().unwrap_or(Command::Watch(cli::WatchArgs::default()));
    match command {
        Command::Watch(args) => commands::watch::run(&cli, args),
        Command::Trace(args) => commands::trace::run(&cli, args),
        Command::Top(args) => commands::top::run(&cli, args),
        Command::Map(args) => commands::map::run(&cli, args),
        Command::Record(args) => commands::record::run(&cli, args),
        Command::Analyze(args) => commands::analyze::run(&cli, args),
        Command::Ask(args) => commands::ask::run(&cli, args),
        Command::ProtoInfer(args) => commands::proto_infer::run(&cli, args),
        Command::Doctor => doctor::run(&cli),
        Command::Completions(args) => cli::print_completions(args.shell),
        Command::Version => {
            println!("shannon {}", env!("CARGO_PKG_VERSION"));
            println!("commit {}", option_env!("SHANNON_GIT_SHA").unwrap_or("unknown"));
            println!("abi-version {}", shannon_common::ABI_VERSION);
            Ok(())
        }
    }
}

/// Errors whose variants map directly to documented exit codes.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    MissingPrivileges(String),
    #[error("{0}")]
    Unsupported(String),
}

impl AppError {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) => 64,
            Self::MissingPrivileges(_) => 77,
            Self::Unsupported(_) => 78,
        }
    }
}
