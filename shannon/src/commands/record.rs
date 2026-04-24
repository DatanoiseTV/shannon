//! `shannon record` — headless recorder to disk.
//!
//! Streams every decoded event to a file in newline-delimited JSON. The
//! output is optionally compressed (zstd by default, gzip, or none) and
//! rotated on size. Matches the same `--pid` / `--follow-children`
//! filters as `shannon trace`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::signal;

use crate::cli::{Cli, RecordArgs, RecordCompression, RecordFormat};
use crate::events::{DecodedEvent, Direction};
use crate::runtime::{FilterSetup, Runtime};

pub fn run(_cli: &Cli, args: RecordArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move { run_async(args).await })
}

async fn run_async(args: RecordArgs) -> Result<()> {
    let filter = FilterSetup {
        pids: args.filter.pid.clone(),
        follow_children: args.filter.follow_children,
        attach_bins: args.filter.attach_bin.clone(),
    };
    let mut runtime = Runtime::start_with(&filter)?;

    let mut writer = Writer::open(&args)?;
    let started = Instant::now();
    let mut count = 0u64;
    let mut bytes = 0u64;

    eprintln!(
        "shannon: recording to {}{}",
        args.output.display(),
        match args.compress {
            RecordCompression::Zstd => " (zstd)",
            RecordCompression::Gz => " (gzip)",
            RecordCompression::None => "",
        }
    );

    // Listen for SIGTERM as well as SIGINT so `kill` on the record
    // process flushes the writer cleanly instead of corrupting the
    // last zstd frame.
    use tokio::signal::unix::{signal as unix_signal, SignalKind};
    let mut sigterm = unix_signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            maybe = runtime.events_rx.recv() => match maybe {
                Some(ev) => {
                    let line = serialise(&ev);
                    let n = writer.write_line(&line, &args)?;
                    count += 1;
                    bytes += n as u64;
                    if let Some(max) = args.max_size {
                        if bytes >= max { break; }
                    }
                    if let Some(dur) = args.max_duration {
                        if started.elapsed() >= dur { break; }
                    }
                }
                None => break,
            }
        }
    }
    writer.finish()?;
    eprintln!(
        "shannon: recorded {count} events in {}",
        humantime::format_duration(started.elapsed())
    );
    Ok(())
}

enum Sink {
    Plain(BufWriter<File>),
    Zstd(zstd::stream::write::AutoFinishEncoder<'static, BufWriter<File>>),
    Gz(flate2::write::GzEncoder<BufWriter<File>>),
}

impl Sink {
    fn new(path: &Path, compression: RecordCompression) -> Result<Self> {
        let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
        let w = BufWriter::with_capacity(64 * 1024, f);
        Ok(match compression {
            RecordCompression::None => Self::Plain(w),
            RecordCompression::Zstd => Self::Zstd(
                zstd::stream::write::Encoder::new(w, 3)
                    .context("init zstd")?
                    .auto_finish(),
            ),
            RecordCompression::Gz => Self::Gz(flate2::write::GzEncoder::new(
                w,
                flate2::Compression::default(),
            )),
        })
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(w) => w.write_all(buf),
            Self::Zstd(w) => w.write_all(buf),
            Self::Gz(w) => w.write_all(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(w) => w.flush(),
            Self::Zstd(w) => w.flush(),
            Self::Gz(w) => w.flush(),
        }
    }
}

struct Writer {
    base_path: PathBuf,
    rotation_suffix: u32,
    current_bytes: u64,
    sink: Sink,
}

impl Writer {
    fn open(args: &RecordArgs) -> Result<Self> {
        let path = args.output.clone();
        if !matches!(args.format, RecordFormat::Jsonl) {
            anyhow::bail!(
                "record format {:?} not yet implemented; use jsonl",
                args.format
            );
        }
        let sink = Sink::new(&path, args.compress.clone())?;
        Ok(Self {
            base_path: path,
            rotation_suffix: 0,
            current_bytes: 0,
            sink,
        })
    }

    fn write_line(&mut self, line: &[u8], args: &RecordArgs) -> Result<usize> {
        self.sink.write_all(line)?;
        self.sink.write_all(b"\n")?;
        let n = line.len() + 1;
        self.current_bytes += n as u64;
        if let Some(cap) = args.rotate {
            if self.current_bytes >= cap {
                self.rotate(args)?;
            }
        }
        Ok(n)
    }

    fn rotate(&mut self, args: &RecordArgs) -> Result<()> {
        self.sink.flush()?;
        self.rotation_suffix += 1;
        let stem = self
            .base_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let ext = self
            .base_path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        let parent = self.base_path.parent().unwrap_or(Path::new("."));
        let rotated = parent.join(format!("{stem}.{:03}{ext}", self.rotation_suffix));
        self.sink = Sink::new(&rotated, args.compress.clone())?;
        self.current_bytes = 0;
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        self.sink.flush()?;
        Ok(())
    }
}

#[derive(Serialize)]
struct JsonEvent<'a> {
    ts_ns: u64,
    ts_wall_ms: u128,
    kind: &'static str,
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    cgroup_id: u64,
    comm: &'a str,
    cpu: u32,
    #[serde(flatten)]
    body: JsonBody,
}

#[derive(Serialize)]
#[serde(untagged)]
enum JsonBody {
    Conn {
        direction: &'static str,
        sock_id: u64,
        protocol: u8,
        src: String,
        dst: String,
    },
    ConnEnd {
        sock_id: u64,
        bytes_sent: u64,
        bytes_recv: u64,
        rtt_us: u32,
    },
    TcpData {
        sock_id: u64,
        direction: &'static str,
        protocol: u8,
        src: String,
        dst: String,
        total_bytes: u32,
        data_b64: String,
    },
    TlsData {
        conn_id: u64,
        direction: &'static str,
        tls_lib: &'static str,
        socket_fd: i32,
        total_bytes: u32,
        data_b64: String,
    },
    Dns {
        direction: &'static str,
        src: String,
        dst: String,
        data_b64: String,
    },
    Sqlite {
        api: &'static str,
        db_handle: u64,
        sql_total_bytes: Option<u32>,
        sql: String,
    },
}

fn serialise(ev: &DecodedEvent) -> Vec<u8> {
    let wall_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    match ev {
        DecodedEvent::ConnStart(ctx, c) => serde_json::to_vec(&JsonEvent {
            ts_ns: ctx.ts_ns,
            ts_wall_ms: wall_ms,
            kind: "conn_start",
            pid: ctx.pid,
            tgid: ctx.tgid,
            uid: ctx.uid,
            gid: ctx.gid,
            cgroup_id: ctx.cgroup_id,
            comm: &ctx.comm,
            cpu: ctx.cpu,
            body: JsonBody::Conn {
                direction: "tx",
                sock_id: c.sock_id,
                protocol: c.protocol as u8,
                src: fmt_sockaddr(&c.src.0, c.src.1),
                dst: fmt_sockaddr(&c.dst.0, c.dst.1),
            },
        }),
        DecodedEvent::ConnEnd(ctx, c) => serde_json::to_vec(&JsonEvent {
            ts_ns: ctx.ts_ns,
            ts_wall_ms: wall_ms,
            kind: "conn_end",
            pid: ctx.pid,
            tgid: ctx.tgid,
            uid: ctx.uid,
            gid: ctx.gid,
            cgroup_id: ctx.cgroup_id,
            comm: &ctx.comm,
            cpu: ctx.cpu,
            body: JsonBody::ConnEnd {
                sock_id: c.sock_id,
                bytes_sent: c.bytes_sent,
                bytes_recv: c.bytes_recv,
                rtt_us: c.rtt_us,
            },
        }),
        DecodedEvent::TcpData(ctx, d) => serde_json::to_vec(&JsonEvent {
            ts_ns: ctx.ts_ns,
            ts_wall_ms: wall_ms,
            kind: "tcp_data",
            pid: ctx.pid,
            tgid: ctx.tgid,
            uid: ctx.uid,
            gid: ctx.gid,
            cgroup_id: ctx.cgroup_id,
            comm: &ctx.comm,
            cpu: ctx.cpu,
            body: JsonBody::TcpData {
                sock_id: d.sock_id,
                direction: dir_label(d.direction),
                protocol: d.protocol as u8,
                src: fmt_sockaddr(&d.src.0, d.src.1),
                dst: fmt_sockaddr(&d.dst.0, d.dst.1),
                total_bytes: d.total_bytes,
                data_b64: base64_encode(&d.data),
            },
        }),
        DecodedEvent::TlsData(ctx, d) => serde_json::to_vec(&JsonEvent {
            ts_ns: ctx.ts_ns,
            ts_wall_ms: wall_ms,
            kind: "tls_data",
            pid: ctx.pid,
            tgid: ctx.tgid,
            uid: ctx.uid,
            gid: ctx.gid,
            cgroup_id: ctx.cgroup_id,
            comm: &ctx.comm,
            cpu: ctx.cpu,
            body: JsonBody::TlsData {
                conn_id: d.conn_id,
                direction: dir_label(d.direction),
                tls_lib: d.tls_lib.label(),
                socket_fd: d.socket_fd,
                total_bytes: d.total_bytes,
                data_b64: base64_encode(&d.data),
            },
        }),
        DecodedEvent::Dns(ctx, d) => serde_json::to_vec(&JsonEvent {
            ts_ns: ctx.ts_ns,
            ts_wall_ms: wall_ms,
            kind: "dns",
            pid: ctx.pid,
            tgid: ctx.tgid,
            uid: ctx.uid,
            gid: ctx.gid,
            cgroup_id: ctx.cgroup_id,
            comm: &ctx.comm,
            cpu: ctx.cpu,
            body: JsonBody::Dns {
                direction: dir_label(d.direction),
                src: fmt_sockaddr(&d.src.0, d.src.1),
                dst: fmt_sockaddr(&d.dst.0, d.dst.1),
                data_b64: base64_encode(&d.data),
            },
        }),
        DecodedEvent::Sqlite(ctx, s) => serde_json::to_vec(&JsonEvent {
            ts_ns: ctx.ts_ns,
            ts_wall_ms: wall_ms,
            kind: "sqlite",
            pid: ctx.pid,
            tgid: ctx.tgid,
            uid: ctx.uid,
            gid: ctx.gid,
            cgroup_id: ctx.cgroup_id,
            comm: &ctx.comm,
            cpu: ctx.cpu,
            body: JsonBody::Sqlite {
                api: s.api.label(),
                db_handle: s.db_handle,
                sql_total_bytes: s.sql_total_bytes,
                sql: s.sql.clone(),
            },
        }),
    }
    .unwrap_or_default()
}

fn fmt_sockaddr(ip: &IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                format!("{v4}:{port}")
            } else {
                format!("[{v6}]:{port}")
            }
        }
    }
}

const fn dir_label(d: Direction) -> &'static str {
    match d {
        Direction::Tx => "tx",
        Direction::Rx => "rx",
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let chunks = bytes.chunks_exact(3);
    let tail = chunks.remainder();
    for chunk in chunks {
        let n = u32::from_be_bytes([0, chunk[0], chunk[1], chunk[2]]);
        out.push(A[((n >> 18) & 0x3f) as usize] as char);
        out.push(A[((n >> 12) & 0x3f) as usize] as char);
        out.push(A[((n >> 6) & 0x3f) as usize] as char);
        out.push(A[(n & 0x3f) as usize] as char);
    }
    match tail.len() {
        0 => {}
        1 => {
            let n = u32::from(tail[0]) << 16;
            out.push(A[((n >> 18) & 0x3f) as usize] as char);
            out.push(A[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(tail[0]) << 16) | (u32::from(tail[1]) << 8);
            out.push(A[((n >> 18) & 0x3f) as usize] as char);
            out.push(A[((n >> 12) & 0x3f) as usize] as char);
            out.push(A[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
