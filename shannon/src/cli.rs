//! Command-line interface definition.
//!
//! Every flag, every default, every conflict is declared here so the CLI
//! contract is legible in one file. Commands defer all behaviour to
//! [`crate::commands`] modules.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

/// Top-level shannon CLI.
///
/// When invoked with no subcommand, `shannon` launches the interactive TUI
/// (`shannon watch`). This is the primary path — everything else is either a
/// non-interactive slice of the same data (`trace`, `top`) or an operational
/// helper (`doctor`, `record`, `analyze`, `completions`).
#[derive(Parser, Clone, Debug)]
#[command(
    name = "shannon",
    version,
    about = "Zero-instrumentation L7 observability via eBPF",
    long_about = None,
    disable_help_subcommand = true,
    arg_required_else_help = false,
    propagate_version = true,
)]
pub struct Cli {
    /// Increase verbosity. `-v` info, `-vv` debug, `-vvv` trace.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-error output.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Write structured logs (JSON) to this file.
    #[arg(long, global = true, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Disable ANSI colours.
    #[arg(long, global = true, env = "NO_COLOR")]
    pub no_color: bool,

    /// Override the config file (default: `$XDG_CONFIG_HOME/shannon/config.toml`).
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Forward BPF-side `bpf_printk` messages to the log file (debug-only).
    #[arg(long, global = true, hide = true)]
    pub bpf_log: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Top-level commands.
#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    /// Launch the interactive TUI (default when no subcommand is given).
    Watch(WatchArgs),
    /// Stream decoded events to stdout.
    Trace(TraceArgs),
    /// Live aggregate summary (rps / p50 / p99 / errors).
    Top(TopArgs),
    /// Record events to disk for later analysis.
    Record(RecordArgs),
    /// Summarise a recording.
    Analyze(AnalyzeArgs),
    /// Diagnose environment (kernel, BTF, privileges, libssl).
    Doctor,
    /// Generate shell completions.
    Completions(CompletionsArgs),
    /// Print version and build info.
    Version,
}

// ---------------------------------------------------------------------------
// Shared filter flags
// ---------------------------------------------------------------------------

/// Filters that can be applied to `trace`, `watch`, and `top`.
///
/// Semantics: different keys are AND-combined; repeated values within one key
/// are OR-combined (e.g. `-p 1 -p 2 --protocol http` = `(pid==1 OR pid==2)
/// AND protocol==http`).
#[derive(Args, Clone, Debug, Default)]
pub struct FilterArgs {
    /// Restrict to these PIDs (thread group ids). Repeatable.
    #[arg(short, long = "pid", value_name = "PID", num_args = 1.., action = clap::ArgAction::Append)]
    pub pid: Vec<u32>,

    /// Restrict by process name glob (e.g. `nginx*`). Repeatable.
    #[arg(long = "comm", value_name = "GLOB", num_args = 1.., action = clap::ArgAction::Append)]
    pub comm: Vec<String>,

    /// Restrict to a Kubernetes pod by name.
    #[arg(long = "pod", value_name = "NAME")]
    pub pod: Option<String>,

    /// Restrict to a cgroup v2 path.
    #[arg(long = "cgroup", value_name = "PATH")]
    pub cgroup: Option<PathBuf>,

    /// Protocols to match. Repeatable.
    #[arg(long = "protocol", value_name = "PROTO", num_args = 1..)]
    pub protocol: Vec<ProtocolFilter>,

    /// Destination ports or ranges, e.g. `443` or `8000-8999`. Repeatable.
    #[arg(long = "port", value_name = "N|RANGE", num_args = 1.., action = clap::ArgAction::Append)]
    pub port: Vec<String>,

    /// Peer IP or CIDR (v4 or v6). Repeatable.
    #[arg(long = "peer", value_name = "CIDR", num_args = 1.., action = clap::ArgAction::Append)]
    pub peer: Vec<String>,

    /// Minimum message size in bytes; events below this are skipped.
    #[arg(long = "min-bytes", value_name = "N")]
    pub min_bytes: Option<u32>,

    /// Restrict by direction.
    #[arg(long = "direction", value_enum, default_value_t = DirectionFilter::Both)]
    pub direction: DirectionFilter,

    /// Include shannon's own traffic in the output. Off by default.
    #[arg(long = "include-self", default_value_t = false)]
    pub include_self: bool,

    /// With `--pid`: also match processes that fork from a matched
    /// process (transitively). Implemented via a `sched_process_fork`
    /// tracepoint that copies parents into children at fork time.
    #[arg(long = "follow-children", default_value_t = false)]
    pub follow_children: bool,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Hash)]
#[value(rename_all = "lower")]
pub enum ProtocolFilter {
    Http,
    Http2,
    Grpc,
    Websocket,
    SocketIo,
    Postgres,
    Redis,
    Mysql,
    Mongodb,
    Cassandra,
    Memcached,
    Kafka,
    Amqp,
    Mqtt,
    Nats,
    Mssql,
    Dns,
    Tls,
    Tcp,
    Udp,
    Quic,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub enum DirectionFilter {
    Tx,
    Rx,
    #[default]
    Both,
}

// ---------------------------------------------------------------------------
// Command-specific argument structs
// ---------------------------------------------------------------------------

#[derive(Args, Clone, Debug, Default)]
pub struct WatchArgs {
    /// Refresh interval for live panels.
    #[arg(long, default_value = "200ms", value_parser = parse_duration)]
    pub refresh: Duration,

    /// Initial view.
    #[arg(long, value_enum, default_value_t = WatchView::Map)]
    pub view: WatchView,

    /// Theme.
    #[arg(long, value_enum, default_value_t = Theme::Auto)]
    pub theme: Theme,

    /// Mirror-save every decoded event to this file while the TUI runs.
    /// Same format rules as `shannon record`.
    #[arg(long = "save", value_name = "PATH")]
    pub save: Option<PathBuf>,

    #[command(flatten)]
    pub filter: FilterArgs,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub enum WatchView {
    #[default]
    Map,
    Log,
    Connections,
    Stats,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub enum Theme {
    #[default]
    Auto,
    Dark,
    Light,
    HighContrast,
}

#[derive(Args, Clone, Debug, Default)]
pub struct TraceArgs {
    /// Output format. Auto-detects based on whether stdout is a tty.
    #[arg(short, long, value_enum)]
    pub output: Option<OutputFormat>,

    /// Hide message bodies.
    #[arg(long)]
    pub no_body: bool,

    /// Redaction level.
    #[arg(long, value_enum, default_value_t = RedactMode::Auto)]
    pub redact: RedactMode,

    /// Truncate bodies larger than this number of bytes.
    #[arg(long, value_name = "BYTES", default_value_t = 4096)]
    pub max_body: u32,

    /// Keep streaming after the initial buffer is drained. Default true for tty.
    #[arg(long)]
    pub follow: bool,

    /// Stop after N events.
    #[arg(short = 'c', long, value_name = "N")]
    pub count: Option<u64>,

    /// Only events newer than this duration.
    #[arg(long, value_parser = parse_duration)]
    pub since: Option<Duration>,

    /// Also save the stream to this file (same format as `shannon record`).
    #[arg(long = "save", value_name = "PATH")]
    pub save: Option<PathBuf>,

    /// Read events from this file instead of the kernel.
    #[arg(long = "replay", value_name = "PATH")]
    pub replay: Option<PathBuf>,

    /// Emit a per-endpoint latency histogram when the command exits.
    #[arg(long)]
    pub latency_hist: bool,

    /// Build a running API catalog (URL templates, params, schemas) and
    /// save to this JSON file on exit. Combine with `--openapi` to also
    /// emit an OpenAPI 3.0 spec.
    #[arg(long = "catalog", value_name = "PATH")]
    pub catalog_file: Option<PathBuf>,

    /// Export the API catalog as OpenAPI 3.0 YAML at this path on exit.
    #[arg(long = "openapi", value_name = "PATH")]
    pub openapi_file: Option<PathBuf>,

    /// Scan every decoded payload for leaked credentials / API keys.
    /// Matches print as inline warnings; secrets themselves are redacted.
    #[arg(long = "scan-secrets")]
    pub scan_secrets: bool,

    /// Dump parsed HTTP response bodies into this directory, decompressing
    /// `Content-Encoding: gzip|deflate|zstd` on the way. File names include
    /// a timestamp, method, host, path slug, and short content hash.
    #[arg(long = "dump-files", value_name = "DIR")]
    pub dump_files_dir: Option<PathBuf>,

    #[command(flatten)]
    pub filter: FilterArgs,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
#[value(rename_all = "lower")]
pub enum OutputFormat {
    Pretty,
    Ndjson,
    Jsonl,
    Console,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub enum RedactMode {
    #[default]
    Auto,
    Strict,
    Off,
}

#[derive(Args, Clone, Debug, Default)]
pub struct TopArgs {
    /// Refresh interval.
    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    pub interval: Duration,

    /// Sort key.
    #[arg(long, value_enum, default_value_t = TopSort::Rps)]
    pub sort: TopSort,

    /// Group events by this dimension.
    #[arg(long = "group-by", value_enum, default_value_t = TopGroupBy::Service)]
    pub group_by: TopGroupBy,

    /// Depth of the top-N per group.
    #[arg(long, default_value_t = 20)]
    pub depth: u32,

    #[command(flatten)]
    pub filter: FilterArgs,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub enum TopSort {
    #[default]
    Rps,
    P50,
    P99,
    Bytes,
    Errors,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub enum TopGroupBy {
    #[default]
    Service,
    Endpoint,
    Pid,
    Pod,
    Peer,
}

#[derive(Args, Clone, Debug, Default)]
pub struct RecordArgs {
    /// Output file. Use `-` for stdout.
    #[arg(short, long, value_name = "PATH")]
    pub output: PathBuf,

    /// File format.
    #[arg(long, value_enum, default_value_t = RecordFormat::Jsonl)]
    pub format: RecordFormat,

    /// Compression.
    #[arg(long, value_enum, default_value_t = RecordCompression::Zstd)]
    pub compress: RecordCompression,

    /// Rotate the output file after it reaches this size (e.g. 100M, 1G).
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    pub rotate: Option<u64>,

    /// Stop recording after this duration.
    #[arg(long = "max-duration", value_parser = parse_duration)]
    pub max_duration: Option<Duration>,

    /// Stop recording after this many bytes written (post-compression).
    #[arg(long = "max-size", value_parser = parse_size)]
    pub max_size: Option<u64>,

    /// Also record raw payload bytes (large — default off).
    #[arg(long)]
    pub raw: bool,

    #[command(flatten)]
    pub filter: FilterArgs,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub enum RecordFormat {
    #[default]
    Jsonl,
    Cbor,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub enum RecordCompression {
    #[default]
    Zstd,
    Gz,
    None,
}

#[derive(Args, Clone, Debug, Default)]
pub struct AnalyzeArgs {
    /// Input file (produced by `shannon record` or `shannon trace --save`).
    pub input: PathBuf,

    /// Emit the aggregated summary as JSON.
    #[arg(long)]
    pub json: bool,

    /// How many top endpoints / peers to show.
    #[arg(long, default_value_t = 20)]
    pub depth: u32,
}

#[derive(Args, Clone, Debug)]
pub struct CompletionsArgs {
    /// Target shell.
    #[arg(value_enum)]
    pub shell: Shell,
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| format!("invalid duration '{s}': {e}"))
}

/// Parse a size literal like `10`, `10k`, `100M`, `1.5G`. Base-1024.
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".into());
    }
    let (num, suffix) = s
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit() && *c != '.')
        .map_or((s, ""), |(i, _)| (&s[..i], &s[i..]));
    let value: f64 = num.parse().map_err(|e| format!("invalid size number '{num}': {e}"))?;
    let mul = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => 1024.0f64.powi(4),
        other => return Err(format!("unknown size suffix '{other}'")),
    };
    Ok((value * mul) as u64)
}

/// Emit shell completions to stdout.
pub fn print_completions(shell: Shell) -> anyhow::Result<()> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_literals() {
        assert_eq!(parse_size("10").unwrap(), 10);
        assert_eq!(parse_size("1k").unwrap(), 1024);
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("100M").unwrap(), 100 * 1024 * 1024);
        assert_eq!(parse_size("1.5G").unwrap(), ((1.5 * 1024.0 * 1024.0 * 1024.0) as u64));
        assert!(parse_size("10X").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn parse_duration_literals() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn cli_parses_default_invocation() {
        let cli = Cli::try_parse_from(["shannon"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_trace_with_filters() {
        let cli = Cli::try_parse_from([
            "shannon", "trace", "-p", "100", "-p", "200", "--protocol", "http", "postgres",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Trace(args)) => {
                assert_eq!(args.filter.pid, vec![100, 200]);
                assert!(args.filter.protocol.contains(&ProtocolFilter::Http));
                assert!(args.filter.protocol.contains(&ProtocolFilter::Postgres));
            }
            _ => panic!("expected Trace"),
        }
    }
}
