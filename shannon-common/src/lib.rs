//! Types shared between the `shannon` userspace binary and the `shannon-ebpf`
//! kernel programs.
//!
//! This crate is the stable wire ABI between two sides of a ring buffer. It is
//! deliberately `no_std`, allocation-free, and contains only plain-data types
//! with known layouts.
//!
//! ## Layout stability
//!
//! Every event begins with an [`EventHeader`]. Consumers should read the header
//! first, check [`EventHeader::version`], then interpret the payload based on
//! [`EventHeader::kind`]. The header size is fixed at [`HEADER_SIZE`] bytes and
//! will not shrink across minor versions; new fields may be appended if the
//! version is bumped.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::missing_safety_doc)]
// `pub _pad: ...` fields are intentional FFI struct padding for stable
// layout shared with the BPF side. Workspace-wide allow-list covers the
// rest; this one is specific to a `no_std` library that exposes raw
// repr(C) types.
#![allow(clippy::pub_underscore_fields)]
#![allow(clippy::too_long_first_doc_paragraph)]

/// ABI version. Bumped on any breaking layout change.
pub const ABI_VERSION: u8 = 1;

/// Fixed header size. Placed up front so the userspace side can demultiplex
/// events without first matching on [`EventKind`]. Checked at compile time
/// against `size_of::<EventHeader>()` below.
pub const HEADER_SIZE: usize = 72;

/// Maximum bytes of a TCP payload we forward from the kernel per event.
/// Chosen as a balance between ring-buffer bandwidth and parser fidelity —
/// 16 KiB is enough to see most HTTP headers and typical DB queries in one
/// shot; larger payloads are chunked across multiple events.
pub const TCP_DATA_CAP: usize = 16 * 1024;

/// Maximum bytes of a TLS plaintext payload we forward per event.
pub const TLS_DATA_CAP: usize = 16 * 1024;

/// Maximum bytes of a DNS datagram we forward per event.
pub const DNS_DATA_CAP: usize = 512;

/// `TASK_COMM_LEN` from the kernel — the length of `task_struct::comm`.
pub const COMM_LEN: usize = 16;

/// Maximum bytes of an exec filename we forward.
pub const FILENAME_CAP: usize = 256;

// --- Self-observability counters --------------------------------------------
//
// Slot indices into the `STATS` PerCpuArray. Both the BPF programs and
// the userspace exporter index by these constants — keep them in sync
// or the metric labels lie. Append at the end; never renumber.

pub const STAT_EVENTS_EMITTED: u32 = 0;
pub const STAT_EVENTS_DROPPED_RINGBUF: u32 = 1;
pub const STAT_EVENTS_DROPPED_FILTER: u32 = 2;
pub const STAT_EVENTS_DROPPED_OOM: u32 = 3;

/// Number of entries in the STATS map. Bump when adding a slot above.
pub const STAT_SLOTS: u32 = 4;

/// Human-readable label for a stat slot, used as the Prometheus
/// counter `name` attribute. Returns "unknown" for indices outside
/// the table so a future BPF version that bumps STAT_SLOTS without
/// rebuilding userspace doesn't crash the exporter.
#[must_use]
pub const fn stat_label(idx: u32) -> &'static str {
    match idx {
        STAT_EVENTS_EMITTED => "shannon_events_emitted_total",
        STAT_EVENTS_DROPPED_RINGBUF => "shannon_events_dropped_ringbuf_total",
        STAT_EVENTS_DROPPED_FILTER => "shannon_events_dropped_filter_total",
        STAT_EVENTS_DROPPED_OOM => "shannon_events_dropped_oom_total",
        _ => "shannon_unknown_total",
    }
}

/// Maximum bytes of an argv vector we forward.
pub const ARGV_CAP: usize = 2048;

// --- EventKind ---------------------------------------------------------------

/// The kind of event carried by an [`EventHeader`].
///
/// Using `u8` keeps the discriminant stable regardless of repr quirks on the
/// BPF side. The ordering and numeric values are **part of the ABI** — never
/// renumber, only append.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A new TCP (or UDP) flow is observed.
    ConnStart = 1,
    /// A TCP flow ended.
    ConnEnd = 2,
    /// Bytes transferred over a socket (plaintext wire bytes).
    TcpData = 3,
    /// Plaintext bytes intercepted via a TLS library uprobe.
    TlsData = 4,
    /// A DNS datagram (query or response).
    DnsMsg = 5,
    /// A process started via `execve`.
    ProcExec = 6,
    /// A process exited.
    ProcExit = 7,
    /// A SQL statement observed via libsqlite3 uprobe
    /// (`sqlite3_prepare_v2` / `sqlite3_exec`). Plaintext SQL text
    /// follows the fixed header.
    SqliteQuery = 8,
    /// Free-form diagnostic from the BPF side (debug builds only).
    KernelLog = 127,
}

impl EventKind {
    /// Convert a raw byte into an `EventKind`. Returns `None` for unknown
    /// values so forward-compatible consumers can skip events from a newer
    /// ABI they don't understand.
    #[inline]
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::ConnStart),
            2 => Some(Self::ConnEnd),
            3 => Some(Self::TcpData),
            4 => Some(Self::TlsData),
            8 => Some(Self::SqliteQuery),
            5 => Some(Self::DnsMsg),
            6 => Some(Self::ProcExec),
            7 => Some(Self::ProcExit),
            127 => Some(Self::KernelLog),
            _ => None,
        }
    }
}

// --- Direction / Family ------------------------------------------------------

/// Direction of a data event from the observed process's perspective.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outbound (tx, send, write, produce).
    Egress = 0,
    /// Inbound (rx, recv, read, consume).
    Ingress = 1,
}

impl Direction {
    #[inline]
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Egress),
            1 => Some(Self::Ingress),
            _ => None,
        }
    }
}

/// Socket address family. Values match `AF_INET` and `AF_INET6` from
/// `<sys/socket.h>`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrFamily {
    /// `AF_INET`
    V4 = 2,
    /// `AF_INET6`
    V6 = 10,
}

impl AddrFamily {
    #[inline]
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            2 => Some(Self::V4),
            10 => Some(Self::V6),
            _ => None,
        }
    }
}

/// Transport-layer protocol, IANA-assigned values. Only TCP and UDP are
/// observed today; QUIC rides on UDP.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Protocol {
    Tcp = 6,
    Udp = 17,
}

impl L4Protocol {
    #[inline]
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }
}

/// Identifies which TLS runtime produced a [`TlsDataPayload`]. This lets the
/// userspace side render the right symbol (OpenSSL vs Go, etc.) and pick the
/// right heuristics if any.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsLib {
    OpenSsl = 1,
    BoringSsl = 2,
    GnuTls = 3,
    Nss = 4,
    GoCryptoTls = 5,
}

impl TlsLib {
    #[inline]
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::OpenSsl),
            2 => Some(Self::BoringSsl),
            3 => Some(Self::GnuTls),
            4 => Some(Self::Nss),
            5 => Some(Self::GoCryptoTls),
            _ => None,
        }
    }

    /// Human-readable label, stable for inclusion in telemetry.
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OpenSsl => "openssl",
            Self::BoringSsl => "boringssl",
            Self::GnuTls => "gnutls",
            Self::Nss => "nss",
            Self::GoCryptoTls => "go",
        }
    }
}

// --- Header ------------------------------------------------------------------

/// Fixed-size prefix present on every event. Consumers read this first to
/// learn the kind, total length, and process context of what follows.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EventHeader {
    /// ABI version; see [`ABI_VERSION`].
    pub version: u8,
    /// One of [`EventKind`].
    pub kind: u8,
    /// Reserved, always zero.
    pub _pad: u16,
    /// Total byte length of this event including the header.
    pub total_len: u32,
    /// Originating CPU id.
    pub cpu: u32,
    /// Monotonic nanoseconds since boot (`bpf_ktime_get_ns`).
    pub ts_ns: u64,
    /// Kernel thread id (`current->pid`).
    pub pid: u32,
    /// Thread group id, i.e. "PID" in userspace parlance (`current->tgid`).
    pub tgid: u32,
    /// Real user id.
    pub uid: u32,
    /// Real group id.
    pub gid: u32,
    /// cgroup v2 id; zero if unknown.
    pub cgroup_id: u64,
    /// Network namespace cookie; zero if unknown.
    pub netns_cookie: u64,
    /// `task_struct.comm` — NUL-padded.
    pub comm: [u8; COMM_LEN],
}

#[allow(unused_qualifications)]
const _HEADER_SIZE_CHECK: [(); HEADER_SIZE] = [(); size_of::<EventHeader>()];

impl EventHeader {
    /// Return the `comm` field as a byte slice trimmed of trailing NUL bytes.
    #[inline]
    #[must_use]
    pub fn comm_bytes(&self) -> &[u8] {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
        &self.comm[..end]
    }
}

// --- Payload: connection lifecycle ------------------------------------------

/// `EventKind::ConnStart` payload — fired when a TCP connection becomes
/// `ESTABLISHED` or a UDP socket first sends/receives.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnStartPayload {
    pub protocol: u8,
    pub family: u8,
    pub _pad: u16,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sock_id: u64,
}

/// `EventKind::ConnEnd` payload.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnEndPayload {
    pub sock_id: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub rtt_us: u32,
    pub _pad: u32,
}

// --- Payload: TCP data ------------------------------------------------------

/// Fixed portion of a [`EventKind::TcpData`] payload. Followed by
/// `captured_len` bytes of data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpDataHeader {
    pub protocol: u8,
    pub direction: u8,
    pub family: u8,
    pub _pad: u8,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sock_id: u64,
    /// Total byte count in the underlying call, which may exceed what we
    /// captured when the payload is larger than `TCP_DATA_CAP`.
    pub total_bytes: u32,
    /// Bytes of data that follow this header.
    pub captured_len: u32,
}

// --- Payload: TLS data ------------------------------------------------------

/// Fixed portion of a [`EventKind::TlsData`] payload. Followed by
/// `captured_len` bytes of plaintext.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsDataHeader {
    pub tls_lib: u8,
    pub direction: u8,
    pub _pad: u16,
    /// Opaque connection identifier — for OpenSSL/BoringSSL this is the
    /// `SSL*` pointer, for Go the `*crypto/tls.Conn`, etc. Stable for the
    /// lifetime of one TLS connection on one process.
    pub conn_id: u64,
    /// Underlying socket fd if known at the uprobe site; -1 otherwise.
    pub socket_fd: i32,
    pub total_bytes: u32,
    pub captured_len: u32,
    pub _pad2: u32,
}

// --- Payload: SQLite query --------------------------------------------------

/// Fixed portion of a [`EventKind::SqliteQuery`] payload. Followed by
/// `captured_len` UTF-8 bytes of SQL text (truncated at
/// [`SQLITE_TEXT_CAP`]).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SqliteHeader {
    /// 1 = sqlite3_prepare_v2, 2 = sqlite3_exec.
    pub api: u8,
    pub _pad: [u8; 3],
    /// Opaque sqlite3* pointer — stable for the lifetime of one open
    /// database handle on one process.
    pub db_handle: u64,
    /// SQL text length the call originally passed (may be -1 for
    /// "unknown / NUL-terminated"). When -1 this lands as `u32::MAX`.
    pub sql_total_bytes: u32,
    pub captured_len: u32,
}

/// Maximum SQL text we capture per event.
// Kept at 1 KiB to stay well inside the verifier's complexity budget
// for uprobe programs; SQL statements longer than this are truncated.
pub const SQLITE_TEXT_CAP: usize = 1024;

// --- Payload: DNS -----------------------------------------------------------

/// Fixed portion of a [`EventKind::DnsMsg`] payload. Followed by
/// `captured_len` bytes of raw DNS wire format.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DnsHeader {
    pub direction: u8,
    pub family: u8,
    pub _pad: u16,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub total_bytes: u16,
    pub captured_len: u16,
}

// --- Payload: process exec / exit -------------------------------------------

/// Fixed portion of a [`EventKind::ProcExec`] payload. Followed by
/// `filename_len` bytes of the exec'd path, then `argv_len` bytes of the
/// raw argv (NUL-separated).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcExecHeader {
    pub filename_len: u16,
    pub argv_len: u16,
    pub parent_tgid: u32,
}

/// `EventKind::ProcExit` payload.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcExitPayload {
    pub exit_code: i32,
    pub _pad: u32,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

// --- Safety / validation helpers --------------------------------------------

/// Returns `Ok(())` if `buf` begins with a valid [`EventHeader`] and is at
/// least as long as `EventHeader::total_len` says.
///
/// # Errors
///
/// - [`ParseError::Short`] if `buf` is smaller than [`HEADER_SIZE`].
/// - [`ParseError::UnknownVersion`] if the header ABI version differs.
/// - [`ParseError::Truncated`] if the claimed `total_len` exceeds `buf.len()`.
pub fn validate(buf: &[u8]) -> Result<&EventHeader, ParseError> {
    if buf.len() < HEADER_SIZE {
        return Err(ParseError::Short);
    }
    // SAFETY: we just checked the length and `EventHeader` is `#[repr(C)]`
    // with no uninhabited variants, no references, and no pointers.
    let header = unsafe { &*(buf.as_ptr().cast::<EventHeader>()) };
    if header.version != ABI_VERSION {
        return Err(ParseError::UnknownVersion(header.version));
    }
    if (header.total_len as usize) > buf.len() {
        return Err(ParseError::Truncated);
    }
    if (header.total_len as usize) < HEADER_SIZE {
        return Err(ParseError::Truncated);
    }
    Ok(header)
}

/// Errors returned from [`validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer smaller than the header.
    Short,
    /// Event announced a length larger than the buffer.
    Truncated,
    /// ABI version mismatch; the inner byte is what was seen.
    UnknownVersion(u8),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Short => f.write_str("event buffer shorter than header"),
            Self::Truncated => f.write_str("event announced length exceeds buffer"),
            Self::UnknownVersion(v) => write!(f, "unknown ABI version: {v}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_stable_size() {
        assert_eq!(size_of::<EventHeader>(), HEADER_SIZE);
    }

    #[test]
    fn short_buffer_rejected() {
        let buf = [0u8; HEADER_SIZE - 1];
        assert!(matches!(validate(&buf), Err(ParseError::Short)));
    }

    #[test]
    fn roundtrip_event_kinds() {
        for k in [
            EventKind::ConnStart,
            EventKind::ConnEnd,
            EventKind::TcpData,
            EventKind::TlsData,
            EventKind::DnsMsg,
            EventKind::ProcExec,
            EventKind::ProcExit,
            EventKind::KernelLog,
        ] {
            assert_eq!(EventKind::from_u8(k as u8), Some(k));
        }
    }
}
