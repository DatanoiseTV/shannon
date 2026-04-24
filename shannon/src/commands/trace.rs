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
use crate::flow::{FlowKey, FlowTable};
use crate::parsers::ParsedRecord;
use crate::runtime::{FilterSetup, Runtime};

pub fn run(_cli: &Cli, args: TraceArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move { run_async(args).await })
}

async fn run_async(args: TraceArgs) -> Result<()> {
    let filter = FilterSetup {
        pids: args.filter.pid.clone(),
        follow_children: args.filter.follow_children,
    };
    let mut runtime = Runtime::start_with(&filter)?;
    let mut out = std::io::stdout().lock();
    let color = std::io::stdout().is_terminal();
    let mut flows = FlowTable::default();

    if !filter.pids.is_empty() {
        eprintln!(
            "shannon: attached, filter: pids={:?}{}",
            filter.pids,
            if filter.follow_children { " (+children)" } else { "" }
        );
    } else {
        eprintln!("shannon: attached. press ctrl-c to stop.");
    }
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            maybe = runtime.events_rx.recv() => match maybe {
                Some(ev) => handle_event(&mut out, &mut flows, &ev, color)?,
                None => break,
            }
        }
    }
    Ok(())
}

fn handle_event(
    out: &mut impl Write,
    flows: &mut FlowTable,
    ev: &DecodedEvent,
    color: bool,
) -> std::io::Result<()> {
    render_event(out, ev, color)?;

    // Feed data events into the per-flow parser and emit any records
    // that fall out. End events clean up flow state.
    match ev {
        DecodedEvent::TcpData(ctx, d) => {
            let key = FlowKey::Tcp { pid: ctx.tgid, sock_id: d.sock_id };
            let records = flows.feed(key, d.direction, &d.data);
            for r in records {
                render_record(out, ev, &r)?;
            }
        }
        DecodedEvent::TlsData(ctx, d) => {
            let key = FlowKey::Tls { pid: ctx.tgid, conn_id: d.conn_id };
            let records = flows.feed(key, d.direction, &d.data);
            for r in records {
                render_record(out, ev, &r)?;
            }
        }
        DecodedEvent::ConnEnd(ctx, c) => {
            flows.forget(&FlowKey::Tcp { pid: ctx.tgid, sock_id: c.sock_id });
        }
        DecodedEvent::ConnStart(_, _) | DecodedEvent::Dns(_, _) => {}
    }
    Ok(())
}

fn render_record(
    out: &mut impl Write,
    source: &DecodedEvent,
    r: &ParsedRecord,
) -> std::io::Result<()> {
    let via = match source {
        DecodedEvent::TcpData(_, _) => "http",
        DecodedEvent::TlsData(_, _) => "https",
        _ => "http",
    };
    match r.kind {
        crate::parsers::http1::RecordKind::Request => writeln!(
            out,
            "{}  {} → {} {}  {} B",
            wall_clock(),
            via,
            r.method.as_deref().unwrap_or("?"),
            r.path.as_deref().unwrap_or("/"),
            r.total_body_bytes,
        ),
        crate::parsers::http1::RecordKind::Response => writeln!(
            out,
            "{}  {} ← {} {}  {} B",
            wall_clock(),
            via,
            r.status.unwrap_or(0),
            r.reason.as_deref().unwrap_or(""),
            r.total_body_bytes,
        ),
    }
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
            "{}  TCP{}  pid={} comm={:<15}  {}:{} {} {}:{}  {} B{}",
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
            preview(&d.data),
        ),
        DecodedEvent::TlsData(ctx, d) => writeln!(
            out,
            "{}  TLS{}  pid={} comm={:<15}  lib={}  {} B{}",
            wall_clock(),
            arrow(d.direction),
            ctx.tgid,
            truncate(&ctx.comm, 15),
            d.tls_lib.label(),
            d.total_bytes,
            preview(&d.data),
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

/// Preview the first few printable bytes of a payload — useful for
/// eyeballing HTTP on a TCP event without a parser wired up.
fn preview(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let n = data.len().min(64);
    let mut s = String::with_capacity(n + 6);
    s.push_str("  '");
    for &b in &data[..n] {
        if b.is_ascii_graphic() || b == b' ' {
            s.push(b as char);
        } else if b == b'\r' {
            s.push_str("\\r");
        } else if b == b'\n' {
            s.push_str("\\n");
        } else if b == b'\t' {
            s.push_str("\\t");
        } else {
            s.push('.');
        }
    }
    if data.len() > n {
        s.push_str("…");
    }
    s.push('\'');
    s
}

fn wall_clock() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}.{millis:03}")
}
