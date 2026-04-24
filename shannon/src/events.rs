//! Userspace event decoding.
//!
//! Reads bytes coming out of the BPF ring buffer and produces strongly-typed
//! enums. The BPF side lays out structures with `#[repr(C)]`; we read them
//! back with well-aligned pointer casts and explicit length checks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context, Result};

use shannon_common::{
    validate, ConnEndPayload, ConnStartPayload, DnsHeader, EventKind, L4Protocol, SqliteHeader,
    TcpDataHeader, TlsDataHeader, TlsLib, HEADER_SIZE,
};

/// A decoded event ready for consumption by the router / TUI / exporter.
#[derive(Debug, Clone)]
pub enum DecodedEvent {
    ConnStart(Context4, ConnInfo),
    ConnEnd(Context4, ConnEndInfo),
    TcpData(Context4, TcpDataInfo),
    TlsData(Context4, TlsDataInfo),
    Dns(Context4, DnsInfo),
    Sqlite(Context4, SqliteInfo),
}

#[derive(Debug, Clone)]
pub struct SqliteInfo {
    pub api: SqliteApi,
    pub db_handle: u64,
    /// Length of the original SQL string passed to the API call;
    /// `None` when sqlite3_*'s `nByte` was -1 (NUL-terminated).
    pub sql_total_bytes: Option<u32>,
    pub sql: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteApi {
    PrepareV2,
    Exec,
}

impl SqliteApi {
    pub const fn label(self) -> &'static str {
        match self {
            Self::PrepareV2 => "prepare_v2",
            Self::Exec => "exec",
        }
    }
}

/// Per-event common metadata: who did it, when, where (PID/comm/cgroup).
#[derive(Debug, Clone)]
pub struct Context4 {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub comm: String,
    pub cpu: u32,
}

#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub sock_id: u64,
    pub protocol: L4Protocol,
    pub src: (IpAddr, u16),
    pub dst: (IpAddr, u16),
}

#[derive(Debug, Clone)]
pub struct ConnEndInfo {
    pub sock_id: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub rtt_us: u32,
}

#[derive(Debug, Clone)]
pub struct TcpDataInfo {
    pub sock_id: u64,
    pub protocol: L4Protocol,
    pub direction: Direction,
    pub src: (IpAddr, u16),
    pub dst: (IpAddr, u16),
    pub total_bytes: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TlsDataInfo {
    pub tls_lib: TlsLib,
    pub direction: Direction,
    pub conn_id: u64,
    pub socket_fd: i32,
    pub total_bytes: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub direction: Direction,
    pub src: (IpAddr, u16),
    pub dst: (IpAddr, u16),
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Tx,
    Rx,
}

impl From<u8> for Direction {
    fn from(v: u8) -> Self {
        if v == 0 {
            Self::Tx
        } else {
            Self::Rx
        }
    }
}

/// Parse one frame from the ring buffer.
pub fn decode(bytes: &[u8]) -> Result<DecodedEvent> {
    let header = validate(bytes).map_err(|e| anyhow::anyhow!(e))?;
    let kind = EventKind::from_u8(header.kind)
        .with_context(|| format!("unknown event kind {}", header.kind))?;
    let payload = &bytes[HEADER_SIZE..header.total_len as usize];
    let ctx = Context4 {
        ts_ns: header.ts_ns,
        pid: header.pid,
        tgid: header.tgid,
        uid: header.uid,
        gid: header.gid,
        cgroup_id: header.cgroup_id,
        comm: String::from_utf8_lossy(header.comm_bytes()).into_owned(),
        cpu: header.cpu,
    };
    match kind {
        EventKind::ConnStart => {
            let p = read_struct::<ConnStartPayload>(payload)?;
            let family = p.family;
            // Empirically: on Linux 6.12 the `sock:inet_sock_set_state`
            // tracepoint stores `dport` raw (network byte order, as held in
            // `sk->sk_dport`). aya reads two bytes as a LE u16, so the
            // value is the big-endian port with its octets little-endian-
            // interpreted. `swap_bytes` unambiguously flips them back.
            let dport = p.dport.swap_bytes();
            Ok(DecodedEvent::ConnStart(
                ctx,
                ConnInfo {
                    sock_id: p.sock_id,
                    protocol: L4Protocol::from_u8(p.protocol)
                        .with_context(|| format!("unknown protocol {}", p.protocol))?,
                    src: (ip_from_raw(family, &p.saddr)?, p.sport),
                    dst: (ip_from_raw(family, &p.daddr)?, dport),
                },
            ))
        }
        EventKind::ConnEnd => {
            let p = read_struct::<ConnEndPayload>(payload)?;
            Ok(DecodedEvent::ConnEnd(
                ctx,
                ConnEndInfo {
                    sock_id: p.sock_id,
                    bytes_sent: p.bytes_sent,
                    bytes_recv: p.bytes_recv,
                    rtt_us: p.rtt_us,
                },
            ))
        }
        EventKind::TcpData => {
            let h = read_struct::<TcpDataHeader>(payload)?;
            let data_start = size_of::<TcpDataHeader>();
            let data_end = data_start + h.captured_len as usize;
            if payload.len() < data_end {
                bail!("tcp data payload truncated");
            }
            // sport is host-order (from sk->sk_num); dport is
            // network-order (from sk->sk_dport) — propagated from the
            // SockInfo stashed at connect-time.
            let dport = h.dport.swap_bytes();
            Ok(DecodedEvent::TcpData(
                ctx,
                TcpDataInfo {
                    sock_id: h.sock_id,
                    protocol: L4Protocol::from_u8(h.protocol)
                        .with_context(|| format!("unknown protocol {}", h.protocol))?,
                    direction: Direction::from(h.direction),
                    src: (ip_from_raw(h.family, &h.saddr)?, h.sport),
                    dst: (ip_from_raw(h.family, &h.daddr)?, dport),
                    total_bytes: h.total_bytes,
                    data: payload[data_start..data_end].to_vec(),
                },
            ))
        }
        EventKind::TlsData => {
            let h = read_struct::<TlsDataHeader>(payload)?;
            let data_start = size_of::<TlsDataHeader>();
            let data_end = data_start + h.captured_len as usize;
            if payload.len() < data_end {
                bail!("tls data payload truncated");
            }
            let tls_lib = TlsLib::from_u8(h.tls_lib)
                .with_context(|| format!("unknown tls_lib {}", h.tls_lib))?;
            Ok(DecodedEvent::TlsData(
                ctx,
                TlsDataInfo {
                    tls_lib,
                    direction: Direction::from(h.direction),
                    conn_id: h.conn_id,
                    socket_fd: h.socket_fd,
                    total_bytes: h.total_bytes,
                    data: payload[data_start..data_end].to_vec(),
                },
            ))
        }
        EventKind::DnsMsg => {
            let h = read_struct::<DnsHeader>(payload)?;
            let data_start = size_of::<DnsHeader>();
            let data_end = data_start + h.captured_len as usize;
            if payload.len() < data_end {
                bail!("dns payload truncated");
            }
            Ok(DecodedEvent::Dns(
                ctx,
                DnsInfo {
                    direction: Direction::from(h.direction),
                    src: (ip_from_raw(h.family, &h.saddr)?, h.sport),
                    dst: (ip_from_raw(h.family, &h.daddr)?, h.dport),
                    data: payload[data_start..data_end].to_vec(),
                },
            ))
        }
        EventKind::SqliteQuery => {
            let h = read_struct::<SqliteHeader>(payload)?;
            let data_start = size_of::<SqliteHeader>();
            let data_end = data_start + h.captured_len as usize;
            if payload.len() < data_end {
                bail!("sqlite payload truncated");
            }
            let api = match h.api {
                1 => SqliteApi::PrepareV2,
                2 => SqliteApi::Exec,
                other => bail!("unknown sqlite api {other}"),
            };
            // sqlite3_exec reads a NUL-terminated string; we may have
            // captured trailing bytes past the NUL — trim here so
            // downstream consumers see clean SQL.
            let raw = &payload[data_start..data_end];
            let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let sql = String::from_utf8_lossy(&raw[..nul]).into_owned();
            Ok(DecodedEvent::Sqlite(
                ctx,
                SqliteInfo {
                    api,
                    db_handle: h.db_handle,
                    sql_total_bytes: if h.sql_total_bytes == u32::MAX {
                        None
                    } else {
                        Some(h.sql_total_bytes)
                    },
                    sql,
                },
            ))
        }
        EventKind::ProcExec | EventKind::ProcExit | EventKind::KernelLog => {
            // Not surfaced to consumers at this layer; tracked elsewhere.
            bail!("event kind {kind:?} not yet surfaced by decoder");
        }
    }
}

fn read_struct<T: Copy>(bytes: &[u8]) -> Result<T> {
    if bytes.len() < size_of::<T>() {
        bail!(
            "struct {} truncated: have {} need {}",
            std::any::type_name::<T>(),
            bytes.len(),
            size_of::<T>()
        );
    }
    // SAFETY: caller ensures `bytes` holds a valid `T`; `T: Copy` implies
    // no `Drop`, and we align-copy to avoid aliasing rules.
    let mut out = core::mem::MaybeUninit::<T>::uninit();
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            out.as_mut_ptr().cast::<u8>(),
            size_of::<T>(),
        );
        Ok(out.assume_init())
    }
}

fn ip_from_raw(family: u8, raw: &[u8; 16]) -> Result<IpAddr> {
    match family {
        2 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&raw[..4]);
            Ok(IpAddr::V4(Ipv4Addr::from(b)))
        }
        10 => Ok(IpAddr::V6(Ipv6Addr::from(*raw))),
        other => bail!("unknown address family {other}"),
    }
}
