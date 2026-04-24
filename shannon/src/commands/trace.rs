//! `shannon trace` — stream decoded events to stdout.
//!
//! For v0.1 the output format is a line-oriented human-readable rendering:
//!
//!   `HH:MM:SS.mmm CONN  pid=NNN comm=foo  192.168.1.2:9000 -> 1.1.1.1:443`
//!   `HH:MM:SS.mmm TCP→  pid=NNN comm=foo  ...:52 B 'GET / HTTP/1.1'`
//!
//! It's machine-parseable by `awk`/`cut` for quick shell hacks; the richer
//! structured output (ndjson) is wired up alongside the protocol parsers
//! in the next commit batch.

use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tokio::signal;

use crate::cli::{Cli, TraceArgs};
use crate::events::{DecodedEvent, Direction};
use crate::runtime::Runtime;

pub fn run(_cli: &Cli, _args: TraceArgs) -> Result<()> {
    // Tokio with a shared runtime; the ring-buffer reader uses its own
    // OS thread because aya's ringbuf is sync.
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move { run_async().await })
}

async fn run_async() -> Result<()> {
    let mut runtime = Runtime::start()?;
    let mut out = std::io::stdout().lock();
    let color = std::io::stdout().is_terminal();

    eprintln!("shannon: attached. press ctrl-c to stop.");
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            maybe = runtime.events_rx.recv() => match maybe {
                Some(ev) => render_event(&mut out, &ev, color)?,
                None => break,
            }
        }
    }
    Ok(())
}

fn render_event(out: &mut impl Write, ev: &DecodedEvent, _color: bool) -> std::io::Result<()> {
    match ev {
        DecodedEvent::ConnStart(ctx, c) => writeln!(
            out,
            "{}  CONN   pid={} comm={:<15}  {}:{} -> {}:{}",
            wall_clock(),
            ctx.tgid,
            truncate(&ctx.comm, 15),
            fmt_ip(&c.src.0),
            c.src.1,
            fmt_ip(&c.dst.0),
            c.dst.1,
        ),
        DecodedEvent::ConnEnd(ctx, c) => writeln!(
            out,
            "{}  END    pid={} comm={:<15}  sock={:x}  sent={} recv={}  rtt={}us",
            wall_clock(),
            ctx.tgid,
            truncate(&ctx.comm, 15),
            c.sock_id,
            c.bytes_sent,
            c.bytes_recv,
            c.rtt_us,
        ),
        DecodedEvent::TcpData(ctx, d) => writeln!(
            out,
            "{}  TCP{}  pid={} comm={:<15}  {}:{} {} {}:{}  {} B",
            wall_clock(),
            arrow(d.direction),
            ctx.tgid,
            truncate(&ctx.comm, 15),
            fmt_ip(&d.src.0),
            d.src.1,
            dir_arrow(d.direction),
            fmt_ip(&d.dst.0),
            d.dst.1,
            d.total_bytes,
        ),
        DecodedEvent::TlsData(ctx, d) => writeln!(
            out,
            "{}  TLS{}  pid={} comm={:<15}  lib={}  conn={:x}  {} B",
            wall_clock(),
            arrow(d.direction),
            ctx.tgid,
            truncate(&ctx.comm, 15),
            d.tls_lib.label(),
            d.conn_id,
            d.total_bytes,
        ),
        DecodedEvent::Dns(ctx, d) => writeln!(
            out,
            "{}  DNS{}  pid={} comm={:<15}  {}:{} {} {}:{}",
            wall_clock(),
            arrow(d.direction),
            ctx.tgid,
            truncate(&ctx.comm, 15),
            fmt_ip(&d.src.0),
            d.src.1,
            dir_arrow(d.direction),
            fmt_ip(&d.dst.0),
            d.dst.1,
        ),
    }
}

fn fmt_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                format!("[{v6}]")
            }
        }
    }
}

fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n { s } else { &s[..n] }
}

fn arrow(d: Direction) -> &'static str {
    match d {
        Direction::Tx => "→",
        Direction::Rx => "←",
    }
}

fn dir_arrow(d: Direction) -> &'static str {
    match d {
        Direction::Tx => "->",
        Direction::Rx => "<-",
    }
}

fn wall_clock() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}.{millis:03}")
}
