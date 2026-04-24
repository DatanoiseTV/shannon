//! JSONL → `DecodedEvent` reader for the `shannon trace --replay`
//! and `shannon analyze` paths.
//!
//! `shannon record` writes one JSON object per line, optionally
//! zstd / gzip-compressed. This module is the inverse: open the
//! file, feed each line to the same `handle_event` pipeline that
//! processes live kernel events. No BPF attach, no privileges
//! required.
//!
//! Only the event kinds shannon currently emits are decoded; lines
//! that don't deserialise (forward-compat fields shannon doesn't
//! recognise yet) are returned as `Err` so the caller can choose
//! to skip-and-continue rather than abort the replay.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::events::{
    ConnEndInfo, ConnInfo, Context4, DecodedEvent, Direction, DnsInfo, SqliteApi, SqliteInfo,
    TcpDataInfo, TlsDataInfo,
};

use shannon_common::{L4Protocol, TlsLib};

/// Iterator over decoded events from a recording file. Transparently
/// handles `.zst` / `.gz` / plain `.jsonl` based on extension.
pub struct ReplayReader {
    inner: Box<dyn BufRead + Send>,
}

impl ReplayReader {
    pub fn open(path: &Path) -> Result<Self> {
        let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let reader: Box<dyn BufRead + Send> = match ext.as_str() {
            "zst" | "zstd" => {
                let dec = zstd::Decoder::new(f).context("opening zstd decoder")?;
                Box::new(BufReader::new(dec))
            }
            "gz" | "gzip" => {
                let dec = flate2::read::GzDecoder::new(f);
                Box::new(BufReader::new(dec))
            }
            _ => Box::new(BufReader::new(f)),
        };
        Ok(Self { inner: reader })
    }
}

impl Iterator for ReplayReader {
    type Item = Result<DecodedEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        loop {
            line.clear();
            match self.inner.read_line(&mut line) {
                Ok(0) => return None,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    return Some(decode_line(trimmed));
                }
                Err(e) => return Some(Err(e.into())),
            }
        }
    }
}

fn decode_line(line: &str) -> Result<DecodedEvent> {
    let raw: RawEvent = serde_json::from_str(line)
        .with_context(|| format!("parsing {}", line.chars().take(200).collect::<String>()))?;
    let ctx = Context4 {
        ts_ns: raw.ts_ns,
        pid: raw.pid,
        tgid: raw.tgid,
        uid: raw.uid,
        gid: raw.gid,
        cgroup_id: raw.cgroup_id,
        comm: raw.comm,
        cpu: raw.cpu,
    };
    match raw.kind.as_str() {
        "conn_start" => {
            let (sport, src_ip) = split_sockaddr(&raw.src.context("conn_start.src")?)?;
            let (dport, dst_ip) = split_sockaddr(&raw.dst.context("conn_start.dst")?)?;
            Ok(DecodedEvent::ConnStart(
                ctx,
                ConnInfo {
                    sock_id: raw.sock_id.unwrap_or(0),
                    protocol: protocol_of(raw.protocol.unwrap_or(6)),
                    src: (src_ip, sport),
                    dst: (dst_ip, dport),
                },
            ))
        }
        "conn_end" => Ok(DecodedEvent::ConnEnd(
            ctx,
            ConnEndInfo {
                sock_id: raw.sock_id.unwrap_or(0),
                bytes_sent: raw.bytes_sent.unwrap_or(0),
                bytes_recv: raw.bytes_recv.unwrap_or(0),
                rtt_us: raw.rtt_us.unwrap_or(0),
            },
        )),
        "tcp_data" => {
            let dir = direction_of(raw.direction.as_deref().unwrap_or("tx"));
            let (sport, src_ip) = split_sockaddr(&raw.src.context("tcp_data.src")?)?;
            let (dport, dst_ip) = split_sockaddr(&raw.dst.context("tcp_data.dst")?)?;
            let data = base64_decode(&raw.data_b64.unwrap_or_default());
            Ok(DecodedEvent::TcpData(
                ctx,
                TcpDataInfo {
                    sock_id: raw.sock_id.unwrap_or(0),
                    protocol: protocol_of(raw.protocol.unwrap_or(6)),
                    direction: dir,
                    src: (src_ip, sport),
                    dst: (dst_ip, dport),
                    total_bytes: raw.total_bytes.unwrap_or(0),
                    data,
                },
            ))
        }
        "tls_data" => {
            let dir = direction_of(raw.direction.as_deref().unwrap_or("tx"));
            let lib = match raw.tls_lib.as_deref().unwrap_or("openssl") {
                "openssl" => TlsLib::OpenSsl,
                "boringssl" => TlsLib::BoringSsl,
                "gnutls" => TlsLib::GnuTls,
                "nss" => TlsLib::Nss,
                "go" | "go_crypto_tls" => TlsLib::GoCryptoTls,
                other => bail!("unknown tls_lib {other}"),
            };
            let data = base64_decode(&raw.data_b64.unwrap_or_default());
            Ok(DecodedEvent::TlsData(
                ctx,
                TlsDataInfo {
                    tls_lib: lib,
                    direction: dir,
                    conn_id: raw.conn_id.unwrap_or(0),
                    socket_fd: raw.socket_fd.unwrap_or(-1),
                    total_bytes: raw.total_bytes.unwrap_or(0),
                    data,
                },
            ))
        }
        "dns" => {
            let dir = direction_of(raw.direction.as_deref().unwrap_or("tx"));
            let (sport, src_ip) = split_sockaddr(&raw.src.context("dns.src")?)?;
            let (dport, dst_ip) = split_sockaddr(&raw.dst.context("dns.dst")?)?;
            let data = base64_decode(&raw.data_b64.unwrap_or_default());
            Ok(DecodedEvent::Dns(
                ctx,
                DnsInfo {
                    direction: dir,
                    src: (src_ip, sport),
                    dst: (dst_ip, dport),
                    data,
                },
            ))
        }
        "sqlite" => {
            let api = match raw.api.as_deref().unwrap_or("prepare_v2") {
                "prepare_v2" => SqliteApi::PrepareV2,
                "exec" => SqliteApi::Exec,
                other => bail!("unknown sqlite api {other}"),
            };
            Ok(DecodedEvent::Sqlite(
                ctx,
                SqliteInfo {
                    api,
                    db_handle: raw.db_handle.unwrap_or(0),
                    sql_total_bytes: raw.sql_total_bytes,
                    sql: raw.sql.unwrap_or_default(),
                },
            ))
        }
        other => bail!("unknown event kind {other}"),
    }
}

#[derive(Deserialize, Debug)]
struct RawEvent {
    ts_ns: u64,
    #[serde(default)]
    _ts_wall_ms: Option<u128>,
    kind: String,
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    cgroup_id: u64,
    comm: String,
    cpu: u32,

    // body fields, all optional and dispatched on `kind`.
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    sock_id: Option<u64>,
    #[serde(default)]
    protocol: Option<u8>,
    #[serde(default)]
    src: Option<String>,
    #[serde(default)]
    dst: Option<String>,
    #[serde(default)]
    bytes_sent: Option<u64>,
    #[serde(default)]
    bytes_recv: Option<u64>,
    #[serde(default)]
    rtt_us: Option<u32>,
    #[serde(default)]
    total_bytes: Option<u32>,
    #[serde(default)]
    data_b64: Option<String>,
    #[serde(default)]
    conn_id: Option<u64>,
    #[serde(default)]
    socket_fd: Option<i32>,
    #[serde(default)]
    tls_lib: Option<String>,
    #[serde(default)]
    api: Option<String>,
    #[serde(default)]
    db_handle: Option<u64>,
    #[serde(default)]
    sql_total_bytes: Option<u32>,
    #[serde(default)]
    sql: Option<String>,
}

fn split_sockaddr(s: &str) -> Result<(u16, IpAddr)> {
    // record.rs writes either "<v4>:<port>" or "[<v6>]:<port>".
    if let Some(rest) = s.strip_prefix('[') {
        let (ip_s, port_s) = rest
            .split_once("]:")
            .with_context(|| format!("malformed v6 sockaddr {s}"))?;
        let ip: IpAddr = ip_s.parse().with_context(|| format!("ip {ip_s}"))?;
        let port: u16 = port_s.parse().with_context(|| format!("port {port_s}"))?;
        return Ok((port, ip));
    }
    let (ip_s, port_s) = s
        .rsplit_once(':')
        .with_context(|| format!("malformed sockaddr {s}"))?;
    let ip: IpAddr = ip_s.parse().with_context(|| format!("ip {ip_s}"))?;
    let port: u16 = port_s.parse().with_context(|| format!("port {port_s}"))?;
    Ok((port, ip))
}

fn protocol_of(p: u8) -> L4Protocol {
    L4Protocol::from_u8(p).unwrap_or(L4Protocol::Tcp)
}

fn direction_of(s: &str) -> Direction {
    match s {
        "rx" => Direction::Rx,
        _ => Direction::Tx,
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.chars() {
        let v: u32 = match c {
            'A'..='Z' => c as u32 - b'A' as u32,
            'a'..='z' => c as u32 - b'a' as u32 + 26,
            '0'..='9' => c as u32 - b'0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            _ => continue,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_data_line() {
        let line = r#"{"ts_ns":1,"ts_wall_ms":2,"kind":"tcp_data","pid":3,"tgid":4,"uid":0,"gid":0,"cgroup_id":0,"comm":"x","cpu":0,"sock_id":7,"direction":"tx","protocol":6,"src":"10.0.0.1:1","dst":"10.0.0.2:2","total_bytes":4,"data_b64":"aGVsbG8="}"#;
        let ev = decode_line(line).expect("ok");
        match ev {
            DecodedEvent::TcpData(ctx, d) => {
                assert_eq!(ctx.tgid, 4);
                assert_eq!(d.dst.1, 2);
                assert_eq!(d.data, b"hello");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_sqlite_line() {
        let line = r#"{"ts_ns":1,"ts_wall_ms":2,"kind":"sqlite","pid":3,"tgid":4,"uid":0,"gid":0,"cgroup_id":0,"comm":"sqlite3","cpu":0,"api":"exec","db_handle":12345,"sql_total_bytes":null,"sql":"SELECT 1"}"#;
        let ev = decode_line(line).expect("ok");
        match ev {
            DecodedEvent::Sqlite(_ctx, s) => {
                assert_eq!(s.api, SqliteApi::Exec);
                assert_eq!(s.sql, "SELECT 1");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ipv6_sockaddr_round_trip() {
        let (p, ip) = split_sockaddr("[2001:db8::1]:443").unwrap();
        assert_eq!(p, 443);
        assert!(matches!(ip, IpAddr::V6(_)));
    }
}
