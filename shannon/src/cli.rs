//! Command-line interface definition.
//!
//! Every flag, every default, every conflict is declared here so the CLI
//! contract is legible in one file. Commands defer all behaviour to
//! [`crate::commands`] modules.

use std::path::{Path, PathBuf};
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

    /// Serve Prometheus metrics (`/metrics`) on this address. Default
    /// off; passing e.g. `127.0.0.1:9750` exposes shannon's BPF-side
    /// counters (events emitted, ringbuffer drops, filter drops).
    #[arg(long, global = true, value_name = "ADDR")]
    pub metrics_listen: Option<std::net::SocketAddr>,

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
    /// Service-map view — live graph of who talks to whom.
    Map(MapArgs),
    /// Record events to disk for later analysis.
    Record(RecordArgs),
    /// Summarise a recording.
    Analyze(AnalyzeArgs),
    /// Ask a question about observed traffic via a local LLM with tool-use.
    Ask(AskArgs),
    /// Infer a `.proto` schema from a directory of raw protobuf messages.
    ProtoInfer(ProtoInferArgs),
    /// Diagnose environment (kernel, BTF, privileges, libssl).
    Doctor,
    /// Generate shell completions.
    Completions(CompletionsArgs),
    /// Generate `man` pages — one .1 per subcommand — into the given directory.
    Manpages(ManpagesArgs),
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

    /// Additional binaries to attach libssl / libsqlite3 uprobes to.
    /// Covers statically-linked SQLite or OpenSSL (Go apps bundling
    /// their own TLS, custom Rust binaries, appliance firmware in a
    /// single ELF). Symbol probes are best-effort: missing symbols
    /// skip without aborting the attach. Repeatable.
    #[arg(long = "attach-bin", value_name = "PATH", num_args = 1.., action = clap::ArgAction::Append)]
    pub attach_bin: Vec<PathBuf>,
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

    /// Also write synthesised IP/TCP frames (plaintext payloads) to this
    /// pcap file. Opens in Wireshark / tshark / Zeek directly — linktype
    /// is `LINKTYPE_RAW` (raw IP). For TLS-over-libssl flows the pcap
    /// holds the plaintext from the uprobe boundary, not the wire bytes.
    #[arg(long = "pcap", value_name = "FILE")]
    pub pcap_file: Option<PathBuf>,

    /// Extract X.509 certificates from observed TLS handshakes and save
    /// them in this directory as `<sha256-prefix>.der` plus a `.txt`
    /// summary with subject CN, issuer CN, SAN count, validity window,
    /// and full SHA-256 fingerprint.
    #[arg(long = "dump-certs", value_name = "DIR")]
    pub dump_certs_dir: Option<PathBuf>,

    /// Certificate pinning allowlist directory. Every `.der` file in
    /// this directory has its SHA-256 computed and added to the
    /// trusted set; any cert observed on the wire whose fingerprint
    /// isn't in the set gets flagged `⚠ cert-anomaly not in pinning
    /// allowlist`. Typically the same directory populated by a prior
    /// `--dump-certs` run — dump, review, trust, then pin.
    #[arg(long = "cert-pin", value_name = "DIR")]
    pub cert_pin_dir: Option<PathBuf>,

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

#[derive(Args, Clone, Debug, Default)]
pub struct MapArgs {
    /// Redraw interval.
    #[arg(long, default_value = "2s", value_parser = parse_duration)]
    pub interval: Duration,

    /// Maximum rows in table mode.
    #[arg(long, default_value_t = 40)]
    pub depth: u32,

    /// Output format.
    #[arg(long, value_enum, default_value_t = MapFormat::Table)]
    pub format: MapFormat,

    #[command(flatten)]
    pub filter: FilterArgs,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub enum MapFormat {
    #[default]
    Table,
    /// ratatui-driven interactive view: scroll, sort, quit. Same edge
    /// data as `table`, just paginated and key-driven.
    Tui,
    Json,
    Dot,
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

#[derive(Args, Clone, Debug, Default)]
pub struct ProtoInferArgs {
    /// Directory of raw protobuf message files (one per sample).
    #[arg(long, value_name = "DIR")]
    pub samples: PathBuf,

    /// Write the generated .proto here. Defaults to stdout.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Worker threads. 0 = number of logical CPUs.
    #[arg(long, default_value_t = 0)]
    pub threads: usize,

    /// Stop inference after this wall-clock duration.
    #[arg(long, value_parser = parse_duration)]
    pub time: Option<Duration>,

    /// Name of the top-level message in the generated .proto.
    #[arg(long, default_value = "Inferred")]
    pub message: String,
}

#[derive(Args, Clone, Debug, Default)]
pub struct AskArgs {
    /// Free-form question. Run against a loaded catalog via an
    /// OpenAI-compatible LLM server (Ollama / LM Studio / vLLM / ...).
    pub question: String,

    /// Saved catalog file produced by `shannon trace --catalog FILE`.
    #[arg(long, value_name = "PATH")]
    pub catalog: Option<PathBuf>,

    /// Events JSONL file (produced by `shannon record`). Enables the
    /// `search_events` tool.
    #[arg(long, value_name = "PATH")]
    pub events: Option<PathBuf>,

    /// Endpoint shortcut (`ollama`, `lmstudio`) or a full base URL.
    /// Default: `ollama` (http://localhost:11434/v1).
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Model name to request. For Ollama this must be a pulled model
    /// (e.g. `llama3.2`); for LM Studio the currently-loaded model.
    #[arg(long, default_value = "llama3.2")]
    pub model: String,

    /// Bearer token for non-local providers (OpenAI, Azure).
    #[arg(long, env = "SHANNON_ASK_API_KEY")]
    pub api_key: Option<String>,

    /// Start an interactive REPL; the positional `question` is ignored
    /// and each line typed at the `shannon>` prompt is sent as a new
    /// turn. Conversation history carries across turns.
    #[arg(long, short = 'i')]
    pub interactive: bool,
}

#[derive(Args, Clone, Debug)]
pub struct CompletionsArgs {
    /// Target shell.
    #[arg(value_enum)]
    pub shell: Shell,
}

#[derive(Args, Clone, Debug)]
pub struct ManpagesArgs {
    /// Output directory. Created if missing. One `shannon-<sub>.1` file
    /// per subcommand plus the top-level `shannon.1`.
    #[arg(value_name = "OUT_DIR")]
    pub out_dir: PathBuf,
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
    let value: f64 = num
        .parse()
        .map_err(|e| format!("invalid size number '{num}': {e}"))?;
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

/// Walk the clap command tree and write one roff manpage per subcommand
/// into `out_dir`. The top-level binary becomes `shannon.1`; each
/// subcommand becomes `shannon-<sub>.1`. Writes are stable so the
/// output is committable / diffable.
pub fn generate_manpages(out_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    use anyhow::Context;
    use clap::CommandFactory;
    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let cmd = Cli::command();
    let mut written = Vec::new();
    write_one(&cmd, "shannon", out_dir, &mut written)?;
    for sub in cmd.get_subcommands() {
        let leaf = sub.get_name().to_string();
        let stem = format!("shannon-{leaf}");
        // The subcommand is rendered as a top-level command for the
        // purpose of the manpage so flags / args show up properly.
        let owned = sub.clone().name(stem.clone()).bin_name(stem.clone());
        write_one(&owned, &stem, out_dir, &mut written)?;
    }
    written.sort();
    Ok(written)
}

fn write_one(
    cmd: &clap::Command,
    stem: &str,
    out_dir: &Path,
    written: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let path = out_dir.join(format!("{stem}.1"));
    let mut buf: Vec<u8> = Vec::new();
    clap_mangen::Man::new(cmd.clone())
        .render(&mut buf)
        .with_context(|| format!("rendering manpage for {stem}"))?;
    std::fs::write(&path, &buf).with_context(|| format!("writing {}", path.display()))?;
    written.push(path);
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
        assert_eq!(
            parse_size("1.5G").unwrap(),
            ((1.5 * 1024.0 * 1024.0 * 1024.0) as u64)
        );
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
            "shannon",
            "trace",
            "-p",
            "100",
            "-p",
            "200",
            "--protocol",
            "http",
            "postgres",
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
