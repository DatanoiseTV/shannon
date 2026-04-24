//! `shannon analyze` — summary statistics over a JSONL recording.
//!
//! Reads a recording produced by `shannon record -o FILE` (plain JSONL,
//! or zstd / gzip compressed — sniffed from magic bytes), streams the
//! events once through an aggregator, and prints:
//!
//! - event-kind histogram (conn_start / conn_end / tcp_data / tls_data / dns)
//! - top N processes by event count
//! - top N peers (host:port) by bytes transferred
//! - bytes in / out totals
//! - recording duration (first → last ts_wall_ms)
//!
//! With `--json` the same summary is emitted as machine-readable JSON.
//!
//! Holds everything in memory; bounded by `--depth` per category.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::{AnalyzeArgs, Cli};

pub fn run(_cli: &Cli, args: AnalyzeArgs) -> Result<()> {
    let reader = open_maybe_compressed(&args.input)?;
    let mut agg = Aggregator::default();
    let mut total_lines = 0u64;
    let mut parse_errors = 0u64;
    for line in BufReader::new(reader).lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => return Err(e).context("reading input"),
        };
        if line.is_empty() {
            continue;
        }
        total_lines += 1;
        match serde_json::from_str::<EventRow>(&line) {
            Ok(row) => agg.absorb(&row),
            Err(_) => parse_errors += 1,
        }
    }
    let report = agg.into_report(args.depth as usize);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
        );
    } else {
        render(&report, total_lines, parse_errors);
    }
    Ok(())
}

fn open_maybe_compressed(path: &Path) -> Result<Box<dyn Read + Send>> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    use std::io::{Read as _, Seek as _, SeekFrom};
    let n = f.read(&mut magic)?;
    f.seek(SeekFrom::Start(0))?;
    if n >= 4 && magic[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        Ok(Box::new(zstd::stream::Decoder::new(f)?) as Box<dyn Read + Send>)
    } else if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        Ok(Box::new(flate2::read::GzDecoder::new(f)) as Box<dyn Read + Send>)
    } else {
        Ok(Box::new(f) as Box<dyn Read + Send>)
    }
}

#[derive(Deserialize)]
struct EventRow {
    ts_wall_ms: Option<u64>,
    kind: String,
    pid: u32,
    tgid: u32,
    comm: String,
    #[serde(default)]
    src: Option<String>,
    #[serde(default)]
    dst: Option<String>,
    #[serde(default)]
    total_bytes: Option<u64>,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    bytes_sent: Option<u64>,
    #[serde(default)]
    bytes_recv: Option<u64>,
}

#[derive(Default)]
struct Aggregator {
    kind_counts: HashMap<String, u64>,
    per_pid: HashMap<(u32, String), PidAgg>,
    per_peer: HashMap<String, PeerAgg>,
    total_tx_bytes: u64,
    total_rx_bytes: u64,
    first_ms: Option<u64>,
    last_ms: Option<u64>,
}

#[derive(Default)]
struct PidAgg {
    events: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Default)]
struct PeerAgg {
    events: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

impl Aggregator {
    fn absorb(&mut self, row: &EventRow) {
        *self.kind_counts.entry(row.kind.clone()).or_default() += 1;

        if let Some(ts) = row.ts_wall_ms {
            self.first_ms = Some(self.first_ms.map_or(ts, |v| v.min(ts)));
            self.last_ms = Some(self.last_ms.map_or(ts, |v| v.max(ts)));
        }

        let pid_key = (row.tgid, row.comm.clone());
        let pid_slot = self.per_pid.entry(pid_key).or_default();
        pid_slot.events += 1;

        let bytes = row.total_bytes.unwrap_or(0);
        match row.direction.as_deref() {
            Some("tx") => {
                self.total_tx_bytes += bytes;
                pid_slot.tx_bytes += bytes;
            }
            Some("rx") => {
                self.total_rx_bytes += bytes;
                pid_slot.rx_bytes += bytes;
            }
            _ => {}
        }

        // conn_end carries lifetime counts.
        if row.kind == "conn_end" {
            self.total_tx_bytes += row.bytes_sent.unwrap_or(0);
            self.total_rx_bytes += row.bytes_recv.unwrap_or(0);
        }

        if let Some(peer) = row.dst.as_ref() {
            let slot = self.per_peer.entry(peer.clone()).or_default();
            slot.events += 1;
            match row.direction.as_deref() {
                Some("tx") => slot.tx_bytes += bytes,
                Some("rx") => slot.rx_bytes += bytes,
                _ => {}
            }
        }
    }

    fn into_report(self, depth: usize) -> Report {
        let mut kinds: Vec<(String, u64)> = self.kind_counts.into_iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(&a.1));

        let mut pids: Vec<_> = self
            .per_pid
            .into_iter()
            .map(|((tgid, comm), v)| TopPid {
                tgid,
                comm,
                events: v.events,
                tx_bytes: v.tx_bytes,
                rx_bytes: v.rx_bytes,
            })
            .collect();
        pids.sort_by(|a, b| b.events.cmp(&a.events));
        pids.truncate(depth);

        let mut peers: Vec<_> = self
            .per_peer
            .into_iter()
            .map(|(peer, v)| TopPeer {
                peer,
                events: v.events,
                tx_bytes: v.tx_bytes,
                rx_bytes: v.rx_bytes,
            })
            .collect();
        peers.sort_by(|a, b| (b.tx_bytes + b.rx_bytes).cmp(&(a.tx_bytes + a.rx_bytes)));
        peers.truncate(depth);

        let duration_ms = match (self.first_ms, self.last_ms) {
            (Some(a), Some(b)) if b >= a => b - a,
            _ => 0,
        };

        Report {
            kinds,
            top_pids: pids,
            top_peers: peers,
            total_tx_bytes: self.total_tx_bytes,
            total_rx_bytes: self.total_rx_bytes,
            duration_ms,
        }
    }
}

#[derive(Serialize)]
struct Report {
    kinds: Vec<(String, u64)>,
    top_pids: Vec<TopPid>,
    top_peers: Vec<TopPeer>,
    total_tx_bytes: u64,
    total_rx_bytes: u64,
    duration_ms: u64,
}

#[derive(Serialize)]
struct TopPid {
    tgid: u32,
    comm: String,
    events: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Serialize)]
struct TopPeer {
    peer: String,
    events: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

fn render(r: &Report, total_lines: u64, parse_errors: u64) {
    let mut out = std::io::stdout().lock();
    use std::io::Write as _;
    let _ = writeln!(
        out,
        "shannon analyze — {} lines ({} unparseable)",
        total_lines, parse_errors
    );
    let _ = writeln!(out, "duration: {:.1}s", (r.duration_ms as f64) / 1000.0);
    let _ = writeln!(
        out,
        "bytes:    tx={}  rx={}",
        humanise_bytes(r.total_tx_bytes),
        humanise_bytes(r.total_rx_bytes),
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "event kinds:");
    for (k, n) in &r.kinds {
        let _ = writeln!(out, "  {k:<12}  {n}");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "top processes:");
    for p in &r.top_pids {
        let _ = writeln!(
            out,
            "  pid={:<6} comm={:<16} events={:<8} tx={} rx={}",
            p.tgid,
            truncate(&p.comm, 16),
            p.events,
            humanise_bytes(p.tx_bytes),
            humanise_bytes(p.rx_bytes),
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "top peers:");
    for p in &r.top_peers {
        let _ = writeln!(
            out,
            "  {:<40} events={:<8} tx={} rx={}",
            truncate(&p.peer, 40),
            p.events,
            humanise_bytes(p.tx_bytes),
            humanise_bytes(p.rx_bytes),
        );
    }
}

fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
        &s[..n]
    }
}

fn humanise_bytes(n: u64) -> String {
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
