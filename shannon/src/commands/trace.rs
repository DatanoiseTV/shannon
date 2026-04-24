//! `shannon trace` — stream decoded events to stdout.

use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tokio::signal;

use crate::api_catalog::{ApiCatalog, Http1Fact, Http2Fact};
use crate::cli::{Cli, TraceArgs};
use crate::dns_cache::DnsCache;
use crate::events::{DecodedEvent, Direction};
use crate::file_dump::FileDumper;
use crate::flow::{AnyRecord, FlowKey, FlowTable};
use crate::parsers::http1::RecordKind as Http1Kind;
use crate::runtime::{FilterSetup, Runtime};
use crate::secrets;

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
    let dns = DnsCache::new();

    // API catalog only if explicitly requested.
    let catalog: Option<Arc<ApiCatalog>> = args.catalog_file.as_ref().map(|p| {
        Arc::new(ApiCatalog::load(p).unwrap_or_else(|err| {
            tracing::warn!(%err, "couldn't load existing catalog; starting empty");
            ApiCatalog::new()
        }))
    });

    // File dumper — write HTTP response bodies to disk on the fly.
    let mut dumper = match args.dump_files_dir.as_ref() {
        Some(p) => Some(FileDumper::open(p)?),
        None => None,
    };

    banner(&args, &filter);
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            maybe = runtime.events_rx.recv() => match maybe {
                Some(ev) => handle_event(
                    &mut out, &mut flows, &dns, catalog.as_deref(), dumper.as_mut(), &args, &ev, color,
                )?,
                None => break,
            }
        }
    }
    if let Some(d) = dumper.as_ref() {
        eprintln!("shannon: dumped {} file(s)", d.count());
    }

    if let (Some(cat), Some(path)) = (catalog.as_ref(), args.catalog_file.as_ref()) {
        if let Err(err) = cat.save(path) {
            tracing::error!(%err, path = %path.display(), "saving catalog");
        } else {
            eprintln!("shannon: catalog saved ({} endpoints) to {}", cat.len(), path.display());
        }
    }
    if let (Some(cat), Some(path)) = (catalog.as_ref(), args.openapi_file.as_ref()) {
        if let Err(err) = cat.export_openapi(path, "shannon observed") {
            tracing::error!(%err, path = %path.display(), "exporting openapi");
        } else {
            eprintln!("shannon: openapi exported to {}", path.display());
        }
    }
    Ok(())
}

fn banner(args: &TraceArgs, filter: &FilterSetup) {
    let mut tags: Vec<String> = Vec::new();
    if !filter.pids.is_empty() {
        tags.push(format!("pids={:?}", filter.pids));
    }
    if filter.follow_children {
        tags.push("+children".into());
    }
    if args.scan_secrets {
        tags.push("secrets-scan".into());
    }
    if args.catalog_file.is_some() {
        tags.push("catalog".into());
    }
    if args.openapi_file.is_some() {
        tags.push("openapi".into());
    }
    let suffix = if tags.is_empty() { String::new() } else { format!(" ({})", tags.join(", ")) };
    eprintln!("shannon: attached{suffix}. press ctrl-c to stop.");
}

#[allow(clippy::too_many_arguments)]
fn handle_event(
    out: &mut impl Write,
    flows: &mut FlowTable,
    dns: &DnsCache,
    catalog: Option<&ApiCatalog>,
    dumper: Option<&mut FileDumper>,
    args: &TraceArgs,
    ev: &DecodedEvent,
    color: bool,
) -> std::io::Result<()> {
    render_event(out, dns, ev, color)?;

    match ev {
        DecodedEvent::TcpData(ctx, d) => {
            if args.scan_secrets {
                scan_and_warn(out, "tcp", ctx.tgid, &ctx.comm, &d.data)?;
            }
            let key = FlowKey::Tcp { pid: ctx.tgid, sock_id: d.sock_id };
            flows.hint_port(key.clone(), d.dst.1);
            let peer = format!("{}:{}", d.dst.0, d.dst.1);
            let records = flows.feed(key, d.direction, &d.data);
            dispatch_records(out, d.direction, &peer, &records, catalog, dumper)?;
        }
        DecodedEvent::TlsData(ctx, d) => {
            if args.scan_secrets {
                scan_and_warn(out, "tls", ctx.tgid, &ctx.comm, &d.data)?;
            }
            let key = FlowKey::Tls { pid: ctx.tgid, conn_id: d.conn_id };
            let peer = format!("tls:{:x}", d.conn_id);
            let records = flows.feed(key, d.direction, &d.data);
            dispatch_records(out, d.direction, &peer, &records, catalog, dumper)?;
        }
        DecodedEvent::ConnEnd(ctx, c) => {
            flows.forget(&FlowKey::Tcp { pid: ctx.tgid, sock_id: c.sock_id });
        }
        DecodedEvent::ConnStart(_, _) | DecodedEvent::Dns(_, _) => {}
    }
    Ok(())
}

fn dispatch_records(
    out: &mut impl Write,
    dir: Direction,
    peer: &str,
    records: &[AnyRecord],
    catalog: Option<&ApiCatalog>,
    mut dumper: Option<&mut FileDumper>,
) -> std::io::Result<()> {
    for r in records {
        render_record(out, dir, r)?;
        if let Some(cat) = catalog {
            feed_catalog(cat, r, peer);
        }
        if let Some(d) = dumper.as_deref_mut() {
            if let AnyRecord::Http1(hr) = r {
                if let Some(path) = d.write_http1(
                    hr,
                    hr.method.as_deref(),
                    hr.path.as_deref(),
                    hr.headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                        .map(|(_, v)| v.as_str()),
                ) {
                    writeln!(out, "{}  📥 dumped {}", wall_clock(), path.display())?;
                }
            }
        }
    }
    Ok(())
}

fn scan_and_warn(
    out: &mut impl Write,
    layer: &str,
    pid: u32,
    comm: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    for f in secrets::scan(bytes) {
        writeln!(
            out,
            "{}  ⚠ SECRET [{}] {} pid={} comm={:<15} sample={}",
            wall_clock(),
            layer,
            f.kind_label,
            pid,
            truncate(comm, 15),
            f.sample,
        )?;
    }
    Ok(())
}

fn feed_catalog(cat: &ApiCatalog, r: &AnyRecord, peer: &str) {
    match r {
        AnyRecord::Http1(hr) => {
            let path = hr.path.clone().unwrap_or_default();
            let method = hr.method.clone().unwrap_or_default();
            let req = match hr.kind {
                Http1Kind::Request => Http1Fact {
                    method,
                    path,
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

fn render_record(out: &mut impl Write, dir: Direction, r: &AnyRecord) -> std::io::Result<()> {
    writeln!(
        out,
        "{}  {} {}  {}",
        wall_clock(),
        r.protocol(),
        arrow(dir),
        r.display_line()
    )
}

fn render_event(
    out: &mut impl Write,
    dns: &DnsCache,
    ev: &DecodedEvent,
    _color: bool,
) -> std::io::Result<()> {
    match ev {
        DecodedEvent::ConnStart(ctx, c) => writeln!(
            out,
            "{}  CONN   pid={} comm={:<15}  {} -> {}",
            wall_clock(),
            ctx.tgid,
            truncate(&ctx.comm, 15),
            fmt_endpoint(dns, &c.src.0, c.src.1),
            fmt_endpoint(dns, &c.dst.0, c.dst.1),
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
            "{}  TCP{}  pid={} comm={:<15}  {} {} {}  {} B{}",
            wall_clock(),
            arrow(d.direction),
            ctx.tgid,
            truncate(&ctx.comm, 15),
            fmt_endpoint(dns, &d.src.0, d.src.1),
            dir_arrow(d.direction),
            fmt_endpoint(dns, &d.dst.0, d.dst.1),
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
            "{}  DNS{}  pid={} comm={:<15}  {} {} {}",
            wall_clock(),
            arrow(d.direction),
            ctx.tgid,
            truncate(&ctx.comm, 15),
            fmt_endpoint(dns, &d.src.0, d.src.1),
            dir_arrow(d.direction),
            fmt_endpoint(dns, &d.dst.0, d.dst.1),
        ),
    }
}

fn fmt_endpoint(dns: &DnsCache, ip: &IpAddr, port: u16) -> String {
    let base = fmt_ip(ip);
    match dns.lookup(*ip) {
        Some(name) if !name.is_empty() && name.as_str() != base => {
            format!("{name}[{base}]:{port}")
        }
        _ => format!("{base}:{port}"),
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
        s.push('…');
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
