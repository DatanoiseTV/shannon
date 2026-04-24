//! `shannon watch` — interactive TUI.
//!
//! Live view of decoded events streaming from the kernel. Single pane for
//! v0.1: a header with global counters (events/sec, protocol breakdown,
//! active flows), a middle scrolling log of decoded records with
//! per-protocol colour coding, and a footer hint line. Quit with `q` or
//! `Ctrl+C`; `space` to pause auto-scroll, `c` to clear the log.
//!
//! Harnesses the same runtime + flow dispatcher as `shannon trace`, so
//! every protocol that parses under `trace` also flows through here.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self as cterm_event, Event as CEvent, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction as LayoutDirection, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

use crate::cli::{Cli, WatchArgs};
use crate::events::{DecodedEvent, Direction};
use crate::flow::{AnyRecord, FlowKey, FlowTable};
use crate::runtime::{FilterSetup, Runtime};

const LOG_CAP: usize = 2048;
const HEADER_TICK: Duration = Duration::from_millis(250);

pub fn run(_cli: &Cli, args: WatchArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move { run_async(args).await })
}

async fn run_async(args: WatchArgs) -> Result<()> {
    let filter = FilterSetup {
        pids: args.filter.pid.clone(),
        follow_children: args.filter.follow_children,
    };
    let mut runtime = Runtime::start_with(&filter)?;
    let mut flows = FlowTable::default();
    let mut state = AppState::new();

    let mut terminal = setup_terminal()?;
    let res = event_loop(&mut terminal, &mut runtime, &mut flows, &mut state).await;
    restore_terminal()?;
    res
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    runtime: &mut Runtime,
    flows: &mut FlowTable,
    state: &mut AppState,
) -> Result<()> {
    let mut last_tick = Instant::now();
    loop {
        // Render.
        terminal.draw(|f| draw(f, state))?;

        // Poll kernel events with a short timeout so the UI stays
        // responsive even when the network is idle.
        let timeout = HEADER_TICK.saturating_sub(last_tick.elapsed());
        let rx_deadline = tokio::time::sleep(timeout);
        tokio::pin!(rx_deadline);

        tokio::select! {
            _ = &mut rx_deadline => {}
            maybe = runtime.events_rx.recv() => {
                if let Some(ev) = maybe {
                    state.absorb(&ev, flows);
                } else {
                    break;
                }
            }
        }

        // Drain input without blocking.
        while cterm_event::poll(Duration::from_millis(0))? {
            match cterm_event::read()? {
                CEvent::Key(k) => {
                    if !handle_key(state, k) {
                        return Ok(());
                    }
                }
                CEvent::Resize(_, _) => {}
                _ => {}
            }
        }

        if last_tick.elapsed() >= HEADER_TICK {
            state.tick();
            last_tick = Instant::now();
        }
    }
    Ok(())
}

fn handle_key(state: &mut AppState, k: KeyEvent) -> bool {
    match (k.code, k.modifiers) {
        (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => return false,
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => return false,
        (KeyCode::Char(' '), _) => state.paused = !state.paused,
        (KeyCode::Char('c'), _) => {
            state.log.clear();
            state.list_state.select(None);
        }
        (KeyCode::Up, _) => {
            let next = state.list_state.selected().map_or(0, |i| i.saturating_sub(1));
            state.list_state.select(Some(next));
        }
        (KeyCode::Down, _) => {
            let n = state.log.len();
            let next = state
                .list_state
                .selected()
                .map_or(0, |i| (i + 1).min(n.saturating_sub(1)));
            state.list_state.select(Some(next));
        }
        _ => {}
    }
    true
}

struct AppState {
    started: Instant,
    log: Vec<LogLine>,
    list_state: ListState,
    total_events: u64,
    last_tick_events: u64,
    events_per_sec: f64,
    protocol_counts: HashMap<&'static str, u64>,
    active_flows: usize,
    paused: bool,
    tick_count: u64,
}

struct LogLine {
    proto: &'static str,
    dir_arrow: &'static str,
    text: String,
}

impl AppState {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            log: Vec::with_capacity(LOG_CAP),
            list_state: ListState::default(),
            total_events: 0,
            last_tick_events: 0,
            events_per_sec: 0.0,
            protocol_counts: HashMap::new(),
            active_flows: 0,
            paused: false,
            tick_count: 0,
        }
    }

    fn absorb(&mut self, ev: &DecodedEvent, flows: &mut FlowTable) {
        self.total_events += 1;
        let (entry, proto_tag) = classify(ev);
        if let Some(p) = proto_tag {
            *self.protocol_counts.entry(p).or_default() += 1;
        }
        if let Some(line) = entry {
            if !self.paused {
                self.push_log(line);
            }
        }

        // Feed data events into flow/parsers and append any records.
        match ev {
            DecodedEvent::TcpData(ctx, d) => {
                let key = FlowKey::Tcp { pid: ctx.tgid, sock_id: d.sock_id };
                flows.hint_port(key.clone(), d.dst.1);
                for r in flows.feed(key, d.direction, &d.data) {
                    if !self.paused {
                        self.push_log(from_any_record(&r, d.direction));
                    }
                    *self.protocol_counts.entry(r.protocol()).or_default() += 1;
                }
            }
            DecodedEvent::TlsData(ctx, d) => {
                let key = FlowKey::Tls { pid: ctx.tgid, conn_id: d.conn_id };
                for r in flows.feed(key, d.direction, &d.data) {
                    if !self.paused {
                        self.push_log(from_any_record(&r, d.direction));
                    }
                    *self.protocol_counts.entry(r.protocol()).or_default() += 1;
                }
            }
            DecodedEvent::ConnEnd(ctx, c) => {
                flows.forget(&FlowKey::Tcp { pid: ctx.tgid, sock_id: c.sock_id });
            }
            _ => {}
        }
        self.active_flows = flows.len();
    }

    fn push_log(&mut self, line: LogLine) {
        if self.log.len() >= LOG_CAP {
            self.log.remove(0);
        }
        self.log.push(line);
    }

    fn tick(&mut self) {
        self.tick_count += 1;
        let delta = self.total_events - self.last_tick_events;
        self.events_per_sec = (delta as f64) / (HEADER_TICK.as_secs_f64());
        self.last_tick_events = self.total_events;
    }
}

fn classify(ev: &DecodedEvent) -> (Option<LogLine>, Option<&'static str>) {
    match ev {
        DecodedEvent::ConnStart(ctx, c) => (
            Some(LogLine {
                proto: "conn",
                dir_arrow: "→",
                text: format!(
                    "pid={} comm={}  {}:{} -> {}:{}",
                    ctx.tgid, trunc(&ctx.comm, 15),
                    c.src.0, c.src.1, c.dst.0, c.dst.1,
                ),
            }),
            Some("conn"),
        ),
        DecodedEvent::ConnEnd(ctx, c) => (
            Some(LogLine {
                proto: "end ",
                dir_arrow: "×",
                text: format!(
                    "pid={} comm={}  sent={} recv={} rtt={}us",
                    ctx.tgid, trunc(&ctx.comm, 15), c.bytes_sent, c.bytes_recv, c.rtt_us
                ),
            }),
            Some("end"),
        ),
        DecodedEvent::Dns(ctx, d) => (
            Some(LogLine {
                proto: "dns ",
                dir_arrow: arrow(d.direction),
                text: format!(
                    "pid={} comm={}  {}:{} {} {}:{}",
                    ctx.tgid, trunc(&ctx.comm, 15),
                    d.src.0, d.src.1, dir_arrow(d.direction),
                    d.dst.0, d.dst.1,
                ),
            }),
            Some("dns"),
        ),
        DecodedEvent::TcpData(_, _) | DecodedEvent::TlsData(_, _) => (None, None),
    }
}

fn from_any_record(r: &AnyRecord, dir: Direction) -> LogLine {
    LogLine { proto: r.protocol(), dir_arrow: arrow(dir), text: r.display_line() }
}

fn draw(f: &mut ratatui::Frame<'_>, state: &AppState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    // Header.
    let uptime = state.started.elapsed();
    let mut header_spans = vec![
        Span::styled("shannon", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::raw(format!("up {}s   ", uptime.as_secs())),
        Span::raw(format!("events {}   ", state.total_events)),
        Span::raw(format!("{:.0}/s   ", state.events_per_sec)),
        Span::raw(format!("flows {}   ", state.active_flows)),
    ];
    let mut protos: Vec<_> = state.protocol_counts.iter().collect();
    protos.sort_by(|a, b| b.1.cmp(a.1));
    for (i, (k, v)) in protos.iter().take(6).enumerate() {
        if i > 0 {
            header_spans.push(Span::raw(" "));
        }
        header_spans.push(Span::styled(
            format!("{k}:{v}"),
            Style::default().fg(protocol_color(k)),
        ));
    }
    if state.paused {
        header_spans.push(Span::raw("   "));
        header_spans.push(Span::styled(
            "PAUSED",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    let header = Paragraph::new(Line::from(header_spans)).block(
        Block::default().borders(Borders::ALL).title(Span::styled(
            " shannon watch ",
            Style::default().fg(Color::Cyan),
        )),
    );
    f.render_widget(header, chunks[0]);

    // Log: render tail that fits the viewport.
    let viewport_lines = chunks[1].height.saturating_sub(2) as usize;
    let start = state.log.len().saturating_sub(viewport_lines.max(1));
    let items: Vec<ListItem<'_>> = state.log[start..]
        .iter()
        .map(|l| {
            let spans = vec![
                Span::styled(
                    format!("{:>6}", l.proto),
                    Style::default().fg(protocol_color(l.proto)),
                ),
                Span::raw(" "),
                Span::styled(l.dir_arrow, Style::default().fg(Color::DarkGray)),
                Span::raw(" "),
                Span::raw(l.text.clone()),
            ];
            ListItem::new(Line::from(spans))
        })
        .collect();
    let list = List::new(items).block(
        Block::default().borders(Borders::ALL).title(Span::styled(
            " live ",
            Style::default().fg(Color::Cyan),
        )),
    );
    // We don't use ListState selection for rendering in v0.1, but keep
    // the hook live so ↑/↓ can attach to highlight selection later.
    let mut list_state = state.list_state.clone();
    f.render_stateful_widget(list, chunks[1], &mut list_state);

    // Footer.
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("space", Style::default().fg(Color::Yellow)),
        Span::raw(" pause  "),
        Span::styled("c", Style::default().fg(Color::Yellow)),
        Span::raw(" clear"),
    ]));
    f.render_widget(footer, chunks[2]);
}

fn protocol_color(proto: &str) -> Color {
    match proto {
        "http" => Color::Green,
        "h2" => Color::LightGreen,
        "pg" => Color::Cyan,
        "mysql" => Color::Cyan,
        "redis" => Color::Red,
        "mongo" => Color::LightCyan,
        "kafka" => Color::Magenta,
        "cql" => Color::Yellow,
        "mc" => Color::LightRed,
        "mqtt" => Color::LightMagenta,
        "nats" => Color::LightBlue,
        "ws" => Color::Green,
        "pop3" => Color::Yellow,
        "smtp" => Color::Yellow,
        "imap" => Color::Yellow,
        "dns" => Color::Blue,
        "conn" => Color::DarkGray,
        "end" => Color::DarkGray,
        _ => Color::Gray,
    }
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

fn trunc(s: &str, n: usize) -> &str {
    if s.len() <= n { s } else { &s[..n] }
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn restore_terminal() -> Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}
