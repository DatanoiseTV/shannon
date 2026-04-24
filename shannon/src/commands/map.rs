//! `shannon map` — service-map aggregator.
//!
//! Watches live traffic and renders a running map of who talks to
//! whom over what protocol: one row per (process, peer, protocol)
//! edge, with call count, byte counters, and a best-guess peer
//! label drawn from SNI / HTTP Host / DNS PTR. Output modes:
//!
//!   - `table` (default): redraws an ANSI-cleared table every
//!     `--interval`, sorted by recent activity.
//!   - `tui`: ratatui-driven interactive view with scrollable rows,
//!     sort toggles, and quit on `q` / `Ctrl+C`.
//!   - `dot`: emits a Graphviz DOT graph on every tick, suitable
//!     for piping through `dot -Tsvg`.
//!   - `json`: newline-delimited JSON edges for scripting.
//!
//! The command is the first user-facing feature that uses *every*
//! L7 parser: TLS lands SNI, HTTP1/2 lands Host+authority, DNS
//! lands PTR/A names — all of which get merged into the peer label
//! shown in the graph.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self as cterm_event, Event as CEvent, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction as LayoutDirection, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Terminal,
};
use tokio::signal;

use crate::cli::{Cli, MapArgs, MapFormat};
use crate::dns_cache::DnsCache;
use crate::events::{DecodedEvent, Direction};
use crate::flow::{AnyRecord, FlowKey, FlowTable};
use crate::runtime::{FilterSetup, Runtime};

pub fn run(_cli: &Cli, args: MapArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move { run_async(args).await })
}

async fn run_async(args: MapArgs) -> Result<()> {
    let filter = FilterSetup {
        pids: args.filter.pid.clone(),
        follow_children: args.filter.follow_children,
        attach_bins: args.filter.attach_bin.clone(),
    };
    let mut runtime = Runtime::start_with(&filter)?;
    let flows = FlowTable::default();
    let dns = DnsCache::new();
    let map = ServiceMap::default();

    match args.format {
        MapFormat::Tui => run_tui(&args, runtime, flows, dns, map).await,
        _ => run_periodic(&args, &mut runtime, flows, dns, map).await,
    }
}

/// Periodic-redraw path — the `table`, `json`, `dot` formats all
/// share this loop; they differ only in the writer invoked by
/// [`render`].
async fn run_periodic(
    args: &MapArgs,
    runtime: &mut Runtime,
    mut flows: FlowTable,
    dns: DnsCache,
    mut map: ServiceMap,
) -> Result<()> {
    let tty = io::stdout().is_terminal() && matches!(args.format, MapFormat::Table);
    let mut out = io::stdout().lock();

    let interval = args.interval;
    let mut last_tick = Instant::now();
    render(&mut out, &map, args, tty)?;

    loop {
        let deadline = tokio::time::sleep(interval.saturating_sub(last_tick.elapsed()));
        tokio::pin!(deadline);
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = &mut deadline => {
                render(&mut out, &map, args, tty)?;
                last_tick = Instant::now();
            }
            maybe = runtime.events_rx.recv() => match maybe {
                Some(ev) => absorb(&mut map, &mut flows, &dns, &ev),
                None => break,
            }
        }
    }
    render(&mut out, &map, args, tty)?;
    Ok(())
}

fn absorb(map: &mut ServiceMap, flows: &mut FlowTable, dns: &DnsCache, ev: &DecodedEvent) {
    match ev {
        DecodedEvent::ConnStart(ctx, c) => {
            map.connect_hint(ctx.tgid, ctx.comm.clone(), c.dst.0, c.dst.1, dns);
        }
        DecodedEvent::TcpData(ctx, d) => {
            let key = FlowKey::Tcp {
                pid: ctx.tgid,
                sock_id: d.sock_id,
            };
            flows.hint_port(key.clone(), d.dst.1);
            let edge_key = EdgeKey {
                pid: ctx.tgid,
                peer_addr: d.dst.0,
                peer_port: d.dst.1,
            };
            let comm = ctx.comm.clone();
            let bytes_tx = if matches!(d.direction, Direction::Tx) {
                d.total_bytes as u64
            } else {
                0
            };
            let bytes_rx = if matches!(d.direction, Direction::Rx) {
                d.total_bytes as u64
            } else {
                0
            };
            map.touch(
                edge_key.clone(),
                comm.clone(),
                None,
                bytes_tx,
                bytes_rx,
                dns,
            );
            for r in flows.feed(key, d.direction, &d.data) {
                let (proto, label) = classify(&r);
                map.record(edge_key.clone(), comm.clone(), proto, label);
            }
        }
        DecodedEvent::TlsData(_ctx, _d) => {
            // TLS flow lands in a different FlowKey; parsers still emit
            // records, but we don't currently have dest-addr here. Skip
            // for v1 — the TcpData pass on the underlying socket will
            // have already created the edge.
        }
        DecodedEvent::ConnEnd(ctx, c) => {
            // Don't delete — we want end-of-session byte counters
            // reflected in the edge. Just annotate last-seen.
            map.end_hint(ctx.tgid, c.sock_id);
        }
        DecodedEvent::Dns(_, _) | DecodedEvent::Sqlite(_, _) => {}
    }
}

fn classify(r: &AnyRecord) -> (&'static str, Option<String>) {
    // Peer-label hint per record kind.
    match r {
        AnyRecord::Http1(h) => {
            let host = h.headers.iter().find_map(|(k, v)| {
                if k.eq_ignore_ascii_case("host") {
                    Some(v.clone())
                } else {
                    None
                }
            });
            ("http", host)
        }
        AnyRecord::Http2(h) => ("h2", h.authority.clone()),
        AnyRecord::Tls(t) => ("tls", t.sni.clone()),
        AnyRecord::Postgres(_) => ("pg", None),
        AnyRecord::Mysql(_) => ("mysql", None),
        AnyRecord::Redis(_) => ("redis", None),
        AnyRecord::Mongodb(_) => ("mongo", None),
        AnyRecord::Kafka(_) => ("kafka", None),
        AnyRecord::Cassandra(_) => ("cql", None),
        AnyRecord::Memcached(_) => ("memcached", None),
        AnyRecord::Mqtt(_) => ("mqtt", None),
        AnyRecord::Nats(_) => ("nats", None),
        AnyRecord::WebSocket(_) => ("ws", None),
        AnyRecord::Pop3(_) => ("pop3", None),
        AnyRecord::Smtp(_) => ("smtp", None),
        AnyRecord::Imap(_) => ("imap", None),
        AnyRecord::Modbus(_) => ("modbus", None),
        AnyRecord::Ldap(_) => ("ldap", None),
        AnyRecord::OpcUa(_) => ("opcua", None),
        AnyRecord::Iec104(_) => ("iec104", None),
        AnyRecord::Ssh(_) => ("ssh", None),
        AnyRecord::Dnp3(_) => ("dnp3", None),
        AnyRecord::S7(_) => ("s7", None),
        AnyRecord::Enip(_) => ("enip", None),
        AnyRecord::Bacnet(_) => ("bacnet", None),
        AnyRecord::Stun(_) => ("stun", None),
        AnyRecord::Ftp(_) => ("ftp", None),
        AnyRecord::Sip(_) => ("sip", None),
        AnyRecord::Rdp(_) => ("rdp", None),
        AnyRecord::Socks(_) => ("socks", None),
        AnyRecord::Telnet(_) => ("telnet", None),
        AnyRecord::Ntp(_) => ("ntp", None),
        AnyRecord::Radius(_) => ("radius", None),
        AnyRecord::Syslog(_) => ("syslog", None),
        AnyRecord::Amqp(_) => ("amqp", None),
        AnyRecord::Kerberos(k) => ("krb5", k.realm.clone()),
        AnyRecord::Oracle(o) => ("oracle", o.service_name.clone().or_else(|| o.sid.clone())),
        AnyRecord::Mssql(m) => (
            "mssql",
            m.database.clone().or_else(|| m.server_name.clone()),
        ),
        AnyRecord::Dhcp(d) => ("dhcp", d.hostname.clone()),
        AnyRecord::Tftp(_) => ("tftp", None),
        AnyRecord::Tacacs(_) => ("tacacs+", None),
        AnyRecord::Snmp(s) => ("snmp", s.community.clone()),
        AnyRecord::Smb(s) => ("smb", s.share_path.clone()),
        AnyRecord::WireGuard(_) => ("wg", None),
        AnyRecord::Irc(_) => ("irc", None),
        AnyRecord::Nfs(_) => ("nfs", None),
        AnyRecord::Rtsp(r) => (
            "rtsp",
            match &r.kind {
                crate::parsers::rtsp::RtspKind::Request { uri, .. } => Some(uri.clone()),
                _ => None,
            },
        ),
        AnyRecord::Smpp(s) => ("smpp", s.system_id.clone()),
        AnyRecord::Dns(d) => (
            if d.multicast { "mdns" } else { "dns" },
            d.questions.first().map(|q| q.name.clone()),
        ),
        AnyRecord::Quic(q) => ("quic", q.tls.as_ref().and_then(|t| t.sni.clone())),
        AnyRecord::Coap(c) => (
            "coap",
            if c.uri_path.is_empty() {
                None
            } else {
                Some(format!("/{}", c.uri_path))
            },
        ),
    }
}

#[derive(Default)]
struct ServiceMap {
    edges: BTreeMap<EdgeKey, Edge>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeKey {
    pid: u32,
    peer_addr: IpAddr,
    peer_port: u16,
}

struct Edge {
    comm: String,
    protocol: &'static str,
    peer_label: Option<String>,
    calls: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    first_seen: Instant,
    last_seen: Instant,
}

impl ServiceMap {
    fn connect_hint(&mut self, pid: u32, comm: String, addr: IpAddr, port: u16, dns: &DnsCache) {
        let key = EdgeKey {
            pid,
            peer_addr: addr,
            peer_port: port,
        };
        let now = Instant::now();
        let e = self.edges.entry(key).or_insert_with(|| Edge {
            comm: comm.clone(),
            protocol: "-",
            peer_label: dns.lookup(addr).map(|s| s.to_string()),
            calls: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            first_seen: now,
            last_seen: now,
        });
        e.comm = comm;
        e.last_seen = now;
    }

    fn touch(
        &mut self,
        key: EdgeKey,
        comm: String,
        proto: Option<&'static str>,
        tx: u64,
        rx: u64,
        dns: &DnsCache,
    ) {
        let now = Instant::now();
        let e = self.edges.entry(key.clone()).or_insert_with(|| Edge {
            comm: comm.clone(),
            protocol: "-",
            peer_label: dns.lookup(key.peer_addr).map(|s| s.to_string()),
            calls: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            first_seen: now,
            last_seen: now,
        });
        e.comm = comm;
        if let Some(p) = proto {
            e.protocol = p;
        }
        e.tx_bytes += tx;
        e.rx_bytes += rx;
        e.last_seen = now;
    }

    fn record(&mut self, key: EdgeKey, comm: String, proto: &'static str, label: Option<String>) {
        let now = Instant::now();
        let e = self.edges.entry(key).or_insert_with(|| Edge {
            comm: comm.clone(),
            protocol: proto,
            peer_label: label.clone(),
            calls: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            first_seen: now,
            last_seen: now,
        });
        e.comm = comm;
        e.protocol = proto;
        if e.peer_label.is_none() {
            e.peer_label = label;
        }
        e.calls += 1;
        e.last_seen = now;
    }

    fn end_hint(&mut self, _pid: u32, _sock_id: u64) {
        // Placeholder — we could tie sock_id back to an edge key for a
        // precise "connection closed" annotation. Byte totals are
        // already captured via TcpData events.
    }
}

fn render(out: &mut impl Write, map: &ServiceMap, args: &MapArgs, tty: bool) -> io::Result<()> {
    match args.format {
        MapFormat::Table => render_table(out, map, args.depth, tty),
        MapFormat::Json => render_json(out, map),
        MapFormat::Dot => render_dot(out, map),
        // Tui owns its own loop (see `run_tui`) so it never hits
        // this periodic-render path.
        MapFormat::Tui => Ok(()),
    }
}

fn render_table(out: &mut impl Write, map: &ServiceMap, depth: u32, tty: bool) -> io::Result<()> {
    if tty {
        write!(out, "\x1b[2J\x1b[H")?;
    }
    writeln!(out, "shannon map   edges={}", map.edges.len(),)?;
    writeln!(
        out,
        "{:>7} {:<16} {:<8} {:<38} {:>6} {:>10} {:>10} {:>8}",
        "pid", "comm", "proto", "peer", "calls", "tx", "rx", "age",
    )?;
    writeln!(out, "{}", "─".repeat(107))?;
    let mut rows: Vec<(&EdgeKey, &Edge)> = map.edges.iter().collect();
    rows.sort_by(|a, b| b.1.last_seen.cmp(&a.1.last_seen));
    let now = Instant::now();
    for (key, edge) in rows.iter().take(depth as usize) {
        let peer = match edge.peer_label.as_deref() {
            Some(s) => format!("{s} [{}:{}]", key.peer_addr, key.peer_port),
            None => format!("{}:{}", key.peer_addr, key.peer_port),
        };
        let age = now.saturating_duration_since(edge.last_seen);
        writeln!(
            out,
            "{:>7} {:<16} {:<8} {:<38} {:>6} {:>10} {:>10} {:>8}",
            key.pid,
            truncate(&edge.comm, 16),
            edge.protocol,
            truncate(&peer, 38),
            edge.calls,
            humanise(edge.tx_bytes),
            humanise(edge.rx_bytes),
            format_age(age),
        )?;
    }
    if !tty {
        writeln!(out, "\x0c")?;
    }
    out.flush()
}

fn render_json(out: &mut impl Write, map: &ServiceMap) -> io::Result<()> {
    for (key, edge) in &map.edges {
        writeln!(
            out,
            r#"{{"pid":{},"comm":{},"protocol":"{}","peer_addr":"{}","peer_port":{},"peer_label":{},"calls":{},"tx":{},"rx":{}}}"#,
            key.pid,
            json_str(&edge.comm),
            edge.protocol,
            key.peer_addr,
            key.peer_port,
            match &edge.peer_label {
                Some(s) => json_str(s),
                None => "null".to_string(),
            },
            edge.calls,
            edge.tx_bytes,
            edge.rx_bytes,
        )?;
    }
    out.flush()
}

fn render_dot(out: &mut impl Write, map: &ServiceMap) -> io::Result<()> {
    writeln!(out, "digraph shannon {{")?;
    writeln!(out, "  rankdir=LR;")?;
    writeln!(out, "  node [shape=box, fontname=\"Menlo\"];")?;
    let mut procs = std::collections::BTreeSet::new();
    let mut peers = std::collections::BTreeSet::new();
    for (key, edge) in &map.edges {
        procs.insert((key.pid, edge.comm.clone()));
        let peer = match &edge.peer_label {
            Some(s) => s.clone(),
            None => format!("{}:{}", key.peer_addr, key.peer_port),
        };
        peers.insert(peer);
    }
    for (pid, comm) in &procs {
        writeln!(out, "  \"p{pid}\" [label=\"{comm}\\npid {pid}\"];")?;
    }
    for peer in &peers {
        writeln!(
            out,
            "  \"q_{}\" [label=\"{peer}\", style=dashed];",
            hash32(peer)
        )?;
    }
    for (key, edge) in &map.edges {
        let peer = match &edge.peer_label {
            Some(s) => s.clone(),
            None => format!("{}:{}", key.peer_addr, key.peer_port),
        };
        writeln!(
            out,
            "  \"p{}\" -> \"q_{}\" [label=\"{} {}c tx={} rx={}\"];",
            key.pid,
            hash32(&peer),
            edge.protocol,
            edge.calls,
            humanise(edge.tx_bytes),
            humanise(edge.rx_bytes),
        )?;
    }
    writeln!(out, "}}")?;
    out.flush()
}

fn hash32(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in s.as_bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn humanise(n: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n}")
    } else {
        format!("{v:.1}{}", UNITS[u])
    }
}

fn format_age(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else {
        format!("{}h", s / 3600)
    }
}

// ---------------------------------------------------------------------------
// TUI mode
// ---------------------------------------------------------------------------

/// Interactive ratatui loop. Scroll rows with ↑/↓ / PgUp / PgDn,
/// cycle the sort column with `s`, toggle ascending/descending with
/// `r`, quit with `q` / `Esc` / `Ctrl+C`.
async fn run_tui(
    args: &MapArgs,
    mut runtime: Runtime,
    mut flows: FlowTable,
    dns: DnsCache,
    mut map: ServiceMap,
) -> Result<()> {
    let mut terminal = setup_tui_terminal()?;
    let mut ui = TuiState::new(args.depth as usize);

    let tick = args.interval.min(Duration::from_millis(500));
    let mut last_draw = Instant::now();

    let res = loop {
        // Draw only every `tick` so a firehose of events doesn't
        // starve the UI.
        if last_draw.elapsed() >= tick {
            terminal.draw(|f| draw_tui(f, &map, &ui))?;
            last_draw = Instant::now();
        }

        // Drain input without blocking — one quit key is enough to
        // exit.
        while cterm_event::poll(Duration::from_millis(0))? {
            if let CEvent::Key(k) = cterm_event::read()? {
                match handle_tui_key(&mut ui, k, map.edges.len()) {
                    KeyResult::Quit => {
                        break_outer(&mut terminal, &map, &ui)?;
                        return Ok(());
                    }
                    KeyResult::Continue => {}
                }
            }
        }

        let deadline = tokio::time::sleep(tick);
        tokio::pin!(deadline);
        tokio::select! {
            _ = signal::ctrl_c() => break Ok::<_, anyhow::Error>(()),
            _ = &mut deadline => {}
            maybe = runtime.events_rx.recv() => match maybe {
                Some(ev) => absorb(&mut map, &mut flows, &dns, &ev),
                None => break Ok(()),
            }
        }
    };

    restore_tui_terminal(&mut terminal)?;
    res
}

fn break_outer(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    _map: &ServiceMap,
    _ui: &TuiState,
) -> Result<()> {
    restore_tui_terminal(terminal)
}

fn setup_tui_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_tui_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    Ok(())
}

enum KeyResult {
    Continue,
    Quit,
}

fn handle_tui_key(ui: &mut TuiState, k: KeyEvent, row_count: usize) -> KeyResult {
    match (k.code, k.modifiers) {
        (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => KeyResult::Quit,
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => KeyResult::Quit,
        (KeyCode::Char('s'), _) => {
            ui.sort = ui.sort.next();
            KeyResult::Continue
        }
        (KeyCode::Char('r'), _) => {
            ui.desc = !ui.desc;
            KeyResult::Continue
        }
        (KeyCode::Up, _) => {
            let cur = ui.table_state.selected().unwrap_or(0);
            ui.table_state.select(Some(cur.saturating_sub(1)));
            KeyResult::Continue
        }
        (KeyCode::Down, _) => {
            let cur = ui.table_state.selected().unwrap_or(0);
            let next = (cur + 1).min(row_count.saturating_sub(1));
            ui.table_state.select(Some(next));
            KeyResult::Continue
        }
        (KeyCode::PageUp, _) => {
            let cur = ui.table_state.selected().unwrap_or(0);
            ui.table_state.select(Some(cur.saturating_sub(10)));
            KeyResult::Continue
        }
        (KeyCode::PageDown, _) => {
            let cur = ui.table_state.selected().unwrap_or(0);
            let next = (cur + 10).min(row_count.saturating_sub(1));
            ui.table_state.select(Some(next));
            KeyResult::Continue
        }
        _ => KeyResult::Continue,
    }
}

struct TuiState {
    table_state: TableState,
    sort: TuiSort,
    desc: bool,
    /// Upper bound on visible rows (from `--depth`).
    depth: usize,
}

impl TuiState {
    fn new(depth: usize) -> Self {
        let mut st = TableState::default();
        st.select(Some(0));
        Self {
            table_state: st,
            sort: TuiSort::LastSeen,
            desc: true,
            depth,
        }
    }
}

#[derive(Clone, Copy)]
enum TuiSort {
    LastSeen,
    Calls,
    Bytes,
    Proto,
    Peer,
}

impl TuiSort {
    const fn next(self) -> Self {
        match self {
            Self::LastSeen => Self::Calls,
            Self::Calls => Self::Bytes,
            Self::Bytes => Self::Proto,
            Self::Proto => Self::Peer,
            Self::Peer => Self::LastSeen,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::LastSeen => "last-seen",
            Self::Calls => "calls",
            Self::Bytes => "bytes",
            Self::Proto => "proto",
            Self::Peer => "peer",
        }
    }
}

fn draw_tui(f: &mut ratatui::Frame<'_>, map: &ServiceMap, ui: &TuiState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    // Header.
    let by_proto = protocol_histogram(map);
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "shannon map",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("   edges={}   sort={} {}   ",
                map.edges.len(),
                ui.sort.label(),
                if ui.desc { "↓" } else { "↑" },
            )),
            Span::raw(by_proto),
        ]),
        Line::from(Span::styled(
            " pid     comm             proto    peer                                     calls       tx         rx     age",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(Block::default().borders(Borders::BOTTOM));

    f.render_widget(header, chunks[0]);

    // Table body.
    let mut rows: Vec<(&EdgeKey, &Edge)> = map.edges.iter().collect();
    sort_rows(&mut rows, ui.sort, ui.desc);
    let rows = rows.into_iter().take(ui.depth).collect::<Vec<_>>();
    let now = Instant::now();
    let table_rows: Vec<Row<'_>> = rows
        .iter()
        .map(|(key, edge)| {
            let peer = match edge.peer_label.as_deref() {
                Some(s) => format!("{s} [{}:{}]", key.peer_addr, key.peer_port),
                None => format!("{}:{}", key.peer_addr, key.peer_port),
            };
            let age = now.saturating_duration_since(edge.last_seen);
            Row::new(vec![
                Cell::from(format!("{:>7}", key.pid)),
                Cell::from(truncate(&edge.comm, 16)),
                Cell::from(edge.protocol).style(proto_colour(edge.protocol)),
                Cell::from(truncate(&peer, 40)),
                Cell::from(format!("{:>6}", edge.calls)),
                Cell::from(format!("{:>10}", humanise(edge.tx_bytes))),
                Cell::from(format!("{:>10}", humanise(edge.rx_bytes))),
                Cell::from(format!("{:>6}", format_age(age))),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(8),
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Length(40),
        Constraint::Length(7),
        Constraint::Length(11),
        Constraint::Length(11),
        Constraint::Length(7),
    ];
    let table = Table::new(table_rows, widths).row_highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    // Render with a mutable state clone since we can't borrow ui
    // mutably through &ui.
    let mut local_state = ui.table_state.clone();
    f.render_stateful_widget(table, chunks[1], &mut local_state);

    // Footer.
    let footer = Paragraph::new(Span::styled(
        " q quit · s cycle sort · r reverse · ↑/↓ select · PgUp/PgDn jump 10",
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(footer, chunks[2]);
}

fn protocol_histogram(map: &ServiceMap) -> String {
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for (_, edge) in &map.edges {
        *counts.entry(edge.protocol).or_default() += edge.calls.max(1);
    }
    counts
        .into_iter()
        .map(|(p, n)| format!("{p}={n}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn sort_rows(rows: &mut Vec<(&EdgeKey, &Edge)>, sort: TuiSort, desc: bool) {
    match sort {
        TuiSort::LastSeen => rows.sort_by(|a, b| b.1.last_seen.cmp(&a.1.last_seen)),
        TuiSort::Calls => rows.sort_by(|a, b| b.1.calls.cmp(&a.1.calls)),
        TuiSort::Bytes => {
            rows.sort_by(|a, b| (b.1.tx_bytes + b.1.rx_bytes).cmp(&(a.1.tx_bytes + a.1.rx_bytes)))
        }
        TuiSort::Proto => rows.sort_by(|a, b| a.1.protocol.cmp(b.1.protocol)),
        TuiSort::Peer => rows.sort_by(|a, b| {
            a.1.peer_label
                .as_deref()
                .unwrap_or("")
                .cmp(b.1.peer_label.as_deref().unwrap_or(""))
        }),
    }
    if !desc && matches!(sort, TuiSort::LastSeen | TuiSort::Calls | TuiSort::Bytes) {
        rows.reverse();
    }
}

fn proto_colour(p: &str) -> Style {
    let c = match p {
        "http" | "h2" => Color::Green,
        "tls" => Color::Magenta,
        "dns" | "mdns" => Color::Cyan,
        "pg" | "mysql" | "mongo" | "redis" | "oracle" | "mssql" | "cql" | "memcached" => {
            Color::Yellow
        }
        "kafka" | "nats" | "mqtt" | "amqp" | "stun" | "sip" | "rtsp" | "smpp" => Color::Blue,
        "ssh" | "ftp" | "rdp" | "socks" | "telnet" | "irc" => Color::Red,
        "modbus" | "s7" | "enip" | "dnp3" | "iec104" | "opcua" | "bacnet" => Color::LightYellow,
        "ntp" | "radius" | "tacacs+" | "snmp" | "dhcp" | "tftp" | "syslog" | "krb5" | "ldap" => {
            Color::LightBlue
        }
        "smb" | "nfs" | "wg" => Color::LightMagenta,
        _ => Color::White,
    };
    Style::default().fg(c)
}
