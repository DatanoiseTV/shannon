//! `shannon top` — live aggregate summary.
//!
//! Like `htop` but for service calls. Feeds every observed HTTP/1 and
//! HTTP/2 record through the API catalog (same aggregator that powers
//! `trace --catalog`), then redraws a sorted table every `--interval`.
//!
//! Output is tty-aware: on an interactive terminal we use ANSI clear-
//! screen for a stable view; when piped to a file we print each
//! snapshot followed by a form feed so readers can split.

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::signal;

use crate::api_catalog::{ApiCatalog, EndpointSummary, Http1Fact, Http2Fact};
use crate::cli::{Cli, TopArgs, TopGroupBy, TopSort};
use crate::events::DecodedEvent;
use crate::flow::{AnyRecord, FlowKey, FlowTable};
use crate::parsers::http1::RecordKind as Http1Kind;
use crate::runtime::{FilterSetup, Runtime};

pub fn run(_cli: &Cli, args: TopArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move { run_async(args).await })
}

async fn run_async(args: TopArgs) -> Result<()> {
    let filter = FilterSetup {
        pids: args.filter.pid.clone(),
        follow_children: args.filter.follow_children,
        attach_bins: args.filter.attach_bin.clone(),
    };
    let mut runtime = Runtime::start_with(&filter)?;
    let mut flows = FlowTable::default();
    let catalog = Arc::new(ApiCatalog::new());
    let tty = std::io::stdout().is_terminal();

    let started = Instant::now();
    let interval = args.interval;
    let mut last_tick = Instant::now();

    let mut out = std::io::stdout().lock();
    render_snapshot(&mut out, &catalog, &args, tty, started.elapsed())?;
    loop {
        let rx_deadline = tokio::time::sleep(interval.saturating_sub(last_tick.elapsed()));
        tokio::pin!(rx_deadline);
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = &mut rx_deadline => {
                render_snapshot(&mut out, &catalog, &args, tty, started.elapsed())?;
                last_tick = Instant::now();
            }
            maybe = runtime.events_rx.recv() => match maybe {
                Some(ev) => absorb(&mut flows, &catalog, &ev),
                None => break,
            }
        }
    }
    Ok(())
}

fn absorb(flows: &mut FlowTable, catalog: &ApiCatalog, ev: &DecodedEvent) {
    match ev {
        DecodedEvent::TcpData(ctx, d) => {
            let key = FlowKey::Tcp { pid: ctx.tgid, sock_id: d.sock_id };
            flows.hint_port(key.clone(), d.dst.1);
            let peer = format!("{}:{}", d.dst.0, d.dst.1);
            for r in flows.feed(key, d.direction, &d.data) {
                feed_record(catalog, &r, &peer);
            }
        }
        DecodedEvent::TlsData(ctx, d) => {
            let key = FlowKey::Tls { pid: ctx.tgid, conn_id: d.conn_id };
            let peer = format!("tls:{:x}", d.conn_id);
            for r in flows.feed(key, d.direction, &d.data) {
                feed_record(catalog, &r, &peer);
            }
        }
        DecodedEvent::ConnEnd(ctx, c) => {
            flows.forget(&FlowKey::Tcp { pid: ctx.tgid, sock_id: c.sock_id });
        }
        _ => {}
    }
}

fn feed_record(cat: &ApiCatalog, r: &AnyRecord, peer: &str) {
    match r {
        AnyRecord::Http1(hr) => {
            let req = match hr.kind {
                Http1Kind::Request => Http1Fact {
                    method: hr.method.clone().unwrap_or_default(),
                    path: hr.path.clone().unwrap_or_default(),
                    headers: hr.headers.clone(),
                    body: hr.body.clone(),
                    status: None,
                },
                Http1Kind::Response => Http1Fact {
                    method: String::new(),
                    path: String::new(),
                    headers: hr.headers.clone(),
                    body: hr.body.clone(),
                    status: hr.status,
                },
            };
            cat.record_http1(&req, None, peer);
        }
        AnyRecord::Http2(h2) => {
            let fact = Http2Fact {
                stream_id: h2.stream_id,
                method: h2.method.clone(),
                path: h2.path.clone(),
                authority: h2.authority.clone(),
                content_type: h2.content_type.clone(),
                status: h2.status,
                headers: h2.headers.clone(),
                grpc_service: h2.grpc.as_ref().map(|g| g.service.clone()),
                grpc_method: h2.grpc.as_ref().map(|g| g.method.clone()),
                grpc_status: h2.grpc.as_ref().and_then(|g| g.grpc_status),
                body: h2.data.clone(),
                end_stream: h2.end_stream,
            };
            cat.record_http2(&fact, peer);
        }
        _ => {}
    }
}

fn render_snapshot(
    out: &mut impl Write,
    cat: &ApiCatalog,
    args: &TopArgs,
    tty: bool,
    uptime: Duration,
) -> std::io::Result<()> {
    let mut snap: Vec<EndpointSummary> = cat.snapshot();
    sort_snapshot(&mut snap, args.sort.clone());
    snap.truncate(args.depth as usize);

    // Regroup per --group-by — we ignore anything not matching the group,
    // and coalesce endpoints with the same group into one row.
    let rows = regroup(&snap, args.group_by.clone());

    if tty {
        // ANSI clear + home.
        write!(out, "\x1b[2J\x1b[H")?;
    }
    writeln!(
        out,
        "shannon top   uptime {}s   endpoints {}   sort={:?}   group-by={:?}",
        uptime.as_secs(),
        cat.len(),
        args.sort,
        args.group_by,
    )?;
    writeln!(
        out,
        "{:<50} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "endpoint", "calls", "p50", "p99", "tx", "rx",
    )?;
    writeln!(out, "{}", "─".repeat(104))?;
    for row in rows {
        writeln!(
            out,
            "{:<50} {:>10} {:>10} {:>10} {:>10} {:>10}",
            truncate(&row.key, 50),
            row.calls,
            row.p50.map_or("-".into(), |v| format!("{v:.0}ms")),
            row.p99.map_or("-".into(), |v| format!("{v:.0}ms")),
            humanise(row.tx_bytes),
            humanise(row.rx_bytes),
        )?;
    }
    if !tty {
        writeln!(out, "\x0c")?; // form feed between snapshots
    }
    out.flush()?;
    Ok(())
}

struct Row {
    key: String,
    calls: u64,
    p50: Option<f64>,
    p99: Option<f64>,
    tx_bytes: u64,
    rx_bytes: u64,
}

fn regroup(snap: &[EndpointSummary], group_by: TopGroupBy) -> Vec<Row> {
    use std::collections::BTreeMap;
    let mut acc: BTreeMap<String, Row> = BTreeMap::new();
    for e in snap {
        let key = match group_by {
            TopGroupBy::Service => {
                e.host.clone().unwrap_or_else(|| e.template.split('/').next().unwrap_or("").to_string())
            }
            TopGroupBy::Endpoint => e.key.clone(),
            TopGroupBy::Pid => "-".to_string(),
            TopGroupBy::Pod => "-".to_string(),
            TopGroupBy::Peer => e.host.clone().unwrap_or_else(|| "-".to_string()),
        };
        let row = acc.entry(key.clone()).or_insert(Row {
            key,
            calls: 0,
            p50: None,
            p99: None,
            tx_bytes: 0,
            rx_bytes: 0,
        });
        row.calls += e.call_count;
        row.p50 = merge_opt(row.p50, e.latency_ms_p50, f64::max);
        row.p99 = merge_opt(row.p99, e.latency_ms_p99, f64::max);
        row.tx_bytes += e.avg_request_bytes * e.call_count;
        row.rx_bytes += e.avg_response_bytes * e.call_count;
    }
    let mut out: Vec<Row> = acc.into_values().collect();
    out.sort_by(|a, b| b.calls.cmp(&a.calls));
    out
}

fn merge_opt(a: Option<f64>, b: Option<f64>, f: fn(f64, f64) -> f64) -> Option<f64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(f(x, y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        _ => None,
    }
}

fn sort_snapshot(snap: &mut [EndpointSummary], by: TopSort) {
    match by {
        TopSort::Rps | TopSort::Bytes => {
            snap.sort_by(|a, b| b.call_count.cmp(&a.call_count));
        }
        TopSort::P50 => {
            snap.sort_by(|a, b| {
                b.latency_ms_p50.unwrap_or(0.0)
                    .partial_cmp(&a.latency_ms_p50.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        TopSort::P99 => {
            snap.sort_by(|a, b| {
                b.latency_ms_p99.unwrap_or(0.0)
                    .partial_cmp(&a.latency_ms_p99.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        TopSort::Errors => {
            snap.sort_by(|a, b| {
                let ea = err_count(a);
                let eb = err_count(b);
                eb.cmp(&ea)
            });
        }
    }
}

fn err_count(e: &EndpointSummary) -> u64 {
    e.status_counts
        .iter()
        .filter(|(c, _)| *c >= 400)
        .map(|(_, n)| *n)
        .sum()
}

fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n { s } else { &s[..n] }
}

fn humanise(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
