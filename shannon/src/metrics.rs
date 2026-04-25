//! Self-observability — Prometheus exporter for shannon's BPF-side
//! counters.
//!
//! Reads the `STATS` per-CPU array from the loaded BPF object on each
//! HTTP request, sums across CPUs, and emits Prometheus text format.
//! Counters cover what an operator needs to trust the tool in
//! production: events emitted vs dropped (ringbuffer full / OOM /
//! filtered).
//!
//! Deliberately no Prometheus client crate — the text format is small,
//! the request volume is low (Prom scrape ≤ 1 Hz), and pulling in
//! `prometheus` would more than double the compiled binary size.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::{maps::PerCpuArray, Ebpf};
use parking_lot::Mutex;
use shannon_common::{stat_label, STAT_SLOTS};

/// Snapshot of the BPF-side counters. Cheap to clone; passed to the
/// HTTP handler so the listener thread doesn't have to hold the BPF
/// lock for the duration of the response.
#[derive(Default, Clone, Debug)]
pub struct StatsSnapshot {
    pub values: Vec<(String, u64)>,
}

/// Pollable read-only handle over the BPF `STATS` map. Constructed on
/// the loader thread (which owns the `Ebpf` instance) and passed via
/// `Arc<Mutex<>>` to the metrics listener.
pub struct StatsReader {
    inner: PerCpuArray<aya::maps::MapData, u64>,
}

impl StatsReader {
    pub fn from_bpf(bpf: &mut Ebpf) -> Result<Self> {
        let map = bpf
            .take_map("STATS")
            .context("STATS map missing from BPF object")?;
        let inner = PerCpuArray::<_, u64>::try_from(map).context("STATS map type mismatch")?;
        Ok(Self { inner })
    }

    pub fn snapshot(&self) -> Result<StatsSnapshot> {
        let mut values = Vec::with_capacity(STAT_SLOTS as usize);
        for idx in 0..STAT_SLOTS {
            let per_cpu = self
                .inner
                .get(&idx, 0)
                .with_context(|| format!("reading STATS slot {idx}"))?;
            let total: u64 = per_cpu.iter().sum();
            values.push((stat_label(idx).to_string(), total));
        }
        Ok(StatsSnapshot { values })
    }
}

impl StatsSnapshot {
    /// Render in the Prometheus text exposition format. Stable enough
    /// for an `expfmt` parser to consume; we don't bother with HELP /
    /// TYPE lines beyond the bare minimum.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(256);
        for (name, value) in &self.values {
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" counter\n");
            out.push_str(name);
            out.push(' ');
            out.push_str(&value.to_string());
            out.push('\n');
        }
        out
    }
}

/// Spawn a background thread that serves `/metrics` on `addr`. Returns
/// once the listener is bound; the thread runs for the process
/// lifetime. Intentionally minimal — one connection at a time, no TLS,
/// no auth. Bind to `127.0.0.1:9750` by default; expose externally via
/// reverse proxy if you need that.
pub fn serve(reader: Arc<Mutex<StatsReader>>, addr: SocketAddr) -> Result<()> {
    let listener =
        TcpListener::bind(addr).with_context(|| format!("binding metrics listener to {addr}"))?;
    listener
        .set_nonblocking(false)
        .context("setting metrics listener blocking")?;

    std::thread::Builder::new()
        .name("shannon-metrics".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                if let Err(e) = handle(stream, &reader) {
                    tracing::debug!(%e, "metrics request");
                }
            }
        })
        .context("spawn metrics listener thread")?;

    tracing::info!(%addr, "metrics listener started");
    Ok(())
}

fn handle(mut stream: TcpStream, reader: &Mutex<StatsReader>) -> Result<()> {
    // Read just the request line + first headers — we only inspect the
    // path. 1 KiB is overkill for `GET /metrics HTTP/1.1`.
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).context("reading request")?;
    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();

    let body = if path == "/metrics" {
        let snap = reader.lock().snapshot()?;
        snap.render()
    } else if path == "/" {
        String::from("shannon metrics exporter\n\nendpoints:\n  /metrics  Prometheus text format\n")
    } else {
        return write_status(&mut stream, 404, "not found", "");
    };

    write_status(&mut stream, 200, "OK", &body)
}

fn write_status(stream: &mut TcpStream, code: u16, reason: &str, body: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; version=0.0.4\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .context("writing response")?;
    Ok(())
}
