//! Apache Cassandra / `ScyllaDB` CQL binary protocol parser (v4 and v5).
//!
//! One [`CassandraParser`] instance is owned per (connection, direction)
//! by [`crate::flow`]. It consumes a rolling byte buffer and emits
//! structured [`CqlRecord`] values, one per wire frame.
//!
//! Wire framing:
//!
//! 1. **v4 frame (9 bytes header + body)**: `version (1) | flags (1) |
//!    stream (i16 BE) | opcode (1) | body_length (u32 BE)`. The high bit
//!    of `version` signals direction: `0x04` is a request, `0x84` is a
//!    response. For v5 the high bit works the same way and the byte is
//!    `0x05` / `0x85`.
//! 2. The body is up to `body_length` bytes; if flags bit `0x01` is set
//!    the body is compressed (LZ4 or Snappy). We never decompress — we
//!    surface `compressed = true` and summarise `"<opcode> (compressed)"`.
//! 3. v5 adds an optional outer **envelope layer** carrying CRC-protected
//!    segments of one or more CQL frames. We recognise the version byte
//!    and classify the opcode; for envelope-wrapped or compressed v5
//!    traffic the body summary is best-effort (spec says consumers can
//!    fall back to the header-only view).
//!
//! Body payload formats we decode:
//!
//! - `STARTUP` (`0x01`): string map `{ "CQL_VERSION": "...", optional
//!   "COMPRESSION": "snappy" | "lz4" }`.
//! - `QUERY` (`0x07`): `[long string]` + `[short] consistency` + flags.
//! - `PREPARE` (`0x09`): `[long string]`.
//! - `EXECUTE` (`0x0A`): `[short bytes] prepared_id` + `[short]
//!   consistency` + flags.
//! - `BATCH` (`0x0D`): `type(1) | count(short) | (kind(1) | stmt | params)*
//!   | consistency(short) | flags(1)`.
//! - `ERROR` (`0x00`): `[int] code | [string] message`.
//! - `AUTH_RESPONSE` (`0x0F`): `[bytes] token` — we never surface the
//!   bytes; the body is treated as redacted credentials.
//!
//! Bounded-memory rules:
//!
//! - query text capped at 8 KiB,
//! - summary capped at 512 chars,
//! - prepared-id capped at 128 bytes,
//! - keyspace name capped at 256 chars,
//! - any `body_length` > 256 MiB flips the parser into permanent bypass.
//!
//! The parser never panics: malformed bodies short-circuit to a
//! header-only record and advance past the frame; version bytes outside
//! `{0x04, 0x84, 0x05, 0x85}` bypass the stream.

use std::collections::HashMap;

use crate::events::Direction;

/// Header size for v4 and v5 CQL frames.
const HEADER_LEN: usize = 9;
/// Max plausible body length (256 MiB). Anything bigger = framing error.
const MAX_BODY_LEN: u32 = 256 * 1024 * 1024;
/// Max captured query text.
const MAX_QUERY_BYTES: usize = 8 * 1024;
/// Max captured summary.
const MAX_SUMMARY: usize = 512;
/// Max captured prepared-statement id.
const MAX_PREPARED_ID: usize = 128;
/// Max captured keyspace name (from `USE <ks>`).
const MAX_KEYSPACE: usize = 256;

/// Flag bit: body is compressed (LZ4 / Snappy).
const FLAG_COMPRESSION: u8 = 0x01;
/// Flag bit: tracing is requested / enabled on this frame.
const FLAG_TRACING: u8 = 0x02;

/// Stateful CQL parser. One per (connection, direction).
#[derive(Debug)]
pub struct CassandraParser {
    state: State,
    /// Remember query-text -> prepared-id mappings so `EXECUTE` frames
    /// can resolve the id back to a human-readable statement. Keys are
    /// the raw id bytes in hex; values are the query string.
    prepared: HashMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Normal tagged-frame mode.
    Framed,
    /// Unrecoverable — emit `Skip` for all incoming bytes.
    Bypass,
}

impl Default for CassandraParser {
    fn default() -> Self {
        Self {
            state: State::Framed,
            prepared: HashMap::new(),
        }
    }
}

/// Result of one parse step. Mirrors the shape of the other parsers'
/// `*ParserOutput` types but carries [`CqlRecord`].
#[derive(Debug)]
pub enum CqlParserOutput {
    /// Buffer too short; caller must feed more bytes.
    Need,
    /// A full CQL frame was decoded; caller must drop `consumed`
    /// bytes from the front of the buffer.
    Record {
        record: Box<CqlRecord>,
        consumed: usize,
    },
    /// Bytes are not recognisable as CQL; caller drops `n` bytes and
    /// tries again (or stays in bypass forever).
    Skip(usize),
}

/// Known CQL opcodes. Unknown values become [`CqlOpcode::Unknown`] so
/// the parser never loses a frame on a new spec revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CqlOpcode {
    Error,
    Startup,
    Ready,
    Authenticate,
    Options,
    Supported,
    Query,
    Result,
    Prepare,
    Execute,
    Register,
    Event,
    Batch,
    AuthChallenge,
    AuthResponse,
    AuthSuccess,
    Unknown(u8),
}

impl CqlOpcode {
    const fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::Error,
            0x01 => Self::Startup,
            0x02 => Self::Ready,
            0x03 => Self::Authenticate,
            0x05 => Self::Options,
            0x06 => Self::Supported,
            0x07 => Self::Query,
            0x08 => Self::Result,
            0x09 => Self::Prepare,
            0x0A => Self::Execute,
            0x0B => Self::Register,
            0x0C => Self::Event,
            0x0D => Self::Batch,
            0x0E => Self::AuthChallenge,
            0x0F => Self::AuthResponse,
            0x10 => Self::AuthSuccess,
            other => Self::Unknown(other),
        }
    }

    const fn as_tag(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Startup => "STARTUP",
            Self::Ready => "READY",
            Self::Authenticate => "AUTHENTICATE",
            Self::Options => "OPTIONS",
            Self::Supported => "SUPPORTED",
            Self::Query => "QUERY",
            Self::Result => "RESULT",
            Self::Prepare => "PREPARE",
            Self::Execute => "EXECUTE",
            Self::Register => "REGISTER",
            Self::Event => "EVENT",
            Self::Batch => "BATCH",
            Self::AuthChallenge => "AUTH_CHALLENGE",
            Self::AuthResponse => "AUTH_RESPONSE",
            Self::AuthSuccess => "AUTH_SUCCESS",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

/// One decoded CQL frame.
#[derive(Clone, Debug)]
pub struct CqlRecord {
    /// Protocol version (4 or 5), after stripping the request/response
    /// direction bit.
    pub version: u8,
    /// True when the direction bit was set (`0x84` / `0x85`).
    pub is_response: bool,
    /// Raw flags byte (`0x01` compression, `0x02` tracing, …).
    pub flags: u8,
    /// Stream id. Signed 16-bit in v3+.
    pub stream: i16,
    /// Decoded opcode.
    pub opcode: CqlOpcode,
    /// Short human line suitable for logs.
    pub summary: String,
    /// Populated for `QUERY` / `PREPARE` / `EXECUTE` (post prepared-id
    /// resolution).
    pub query: Option<String>,
    /// Populated when a `USE <ks>` query was observed.
    pub keyspace: Option<String>,
    /// Consistency level on `QUERY` / `EXECUTE` / `BATCH`.
    pub consistency: Option<u16>,
    /// Error code on `ERROR` (opcode 0x00).
    pub error_code: Option<u32>,
    /// Error message on `ERROR`.
    pub error_message: Option<String>,
    /// Declared body length from the frame header.
    pub payload_len: u32,
    /// Frame carries a compressed body (flag `0x01`).
    pub compressed: bool,
    /// Frame carries / requests tracing (flag `0x02`).
    pub tracing: bool,
}

impl CqlRecord {
    /// Short one-line rendering for log surfaces.
    #[must_use]
    pub fn display_line(&self) -> String {
        let tag = self.opcode.as_tag();
        let direction = if self.is_response { "<-" } else { "->" };
        let mut out = String::with_capacity(64);
        out.push_str(direction);
        out.push(' ');
        out.push_str(tag);
        if self.compressed {
            out.push_str(" (compressed)");
            return truncate_owned(out, MAX_SUMMARY);
        }
        if let Some(q) = &self.query {
            out.push(' ');
            out.push('\'');
            out.push_str(q);
            out.push('\'');
        }
        if let Some(ks) = &self.keyspace {
            out.push_str(" USE=");
            out.push_str(ks);
        }
        if let Some(cl) = self.consistency {
            out.push_str(" CL=");
            out.push_str(consistency_name(cl));
        }
        if let Some(code) = self.error_code {
            use std::fmt::Write as _;
            let _ = write!(out, " code=0x{code:04X}");
            if let Some(msg) = &self.error_message {
                out.push(' ');
                out.push('\'');
                out.push_str(msg);
                out.push('\'');
            }
        }
        truncate_owned(out, MAX_SUMMARY)
    }
}

impl CassandraParser {
    /// Parse one frame from the head of `buf`.
    pub fn parse(&mut self, buf: &[u8], _dir: Direction) -> CqlParserOutput {
        if matches!(self.state, State::Bypass) {
            return CqlParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER_LEN {
            return CqlParserOutput::Need;
        }

        let version_byte = buf[0];
        let (version, is_response) = match version_byte {
            0x04 => (4u8, false),
            0x84 => (4u8, true),
            0x05 => (5u8, false),
            0x85 => (5u8, true),
            _ => {
                self.state = State::Bypass;
                return CqlParserOutput::Skip(buf.len());
            }
        };

        let flags = buf[1];
        let stream = i16::from_be_bytes([buf[2], buf[3]]);
        let opcode_byte = buf[4];
        let body_len = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);

        if body_len > MAX_BODY_LEN {
            self.state = State::Bypass;
            return CqlParserOutput::Skip(buf.len());
        }

        let total = HEADER_LEN.saturating_add(body_len as usize);
        if buf.len() < total {
            return CqlParserOutput::Need;
        }

        let body = &buf[HEADER_LEN..total];
        let opcode = CqlOpcode::from_u8(opcode_byte);
        let compressed = flags & FLAG_COMPRESSION != 0;
        let tracing = flags & FLAG_TRACING != 0;

        let mut rec = CqlRecord {
            version,
            is_response,
            flags,
            stream,
            opcode,
            summary: String::new(),
            query: None,
            keyspace: None,
            consistency: None,
            error_code: None,
            error_message: None,
            payload_len: body_len,
            compressed,
            tracing,
        };

        if compressed {
            rec.summary = truncate_owned(format!("{} (compressed)", opcode.as_tag()), MAX_SUMMARY);
        } else {
            self.decode_body(&mut rec, body);
            if rec.summary.is_empty() {
                rec.summary = default_summary(&rec);
            }
        }

        CqlParserOutput::Record {
            record: Box::new(rec),
            consumed: total,
        }
    }

    fn decode_body(&self, rec: &mut CqlRecord, body: &[u8]) {
        match rec.opcode {
            CqlOpcode::Startup => decode_startup(rec, body),
            CqlOpcode::Query => decode_query(rec, body),
            CqlOpcode::Prepare => decode_prepare(rec, body),
            CqlOpcode::Execute => self.decode_execute(rec, body),
            CqlOpcode::Batch => decode_batch(rec, body),
            CqlOpcode::Error => decode_error(rec, body),
            CqlOpcode::AuthResponse => {
                // Auth payload is credentials material — do not surface.
                rec.summary = "AUTH_RESPONSE (redacted)".to_string();
            }
            _ => {}
        }
    }

    fn decode_execute(&self, rec: &mut CqlRecord, body: &[u8]) {
        let mut cur = Cursor::new(body);
        let Some(id) = cur.read_short_bytes() else {
            return;
        };
        if !id.is_empty() && id.len() <= MAX_PREPARED_ID {
            let key = hex_encode(id);
            if let Some(text) = self.prepared.get(&key) {
                rec.query = Some(text.clone());
            } else {
                rec.query = Some(format!("<prepared {key}>"));
            }
        }
        // v5 additionally has `[short bytes] result_metadata_id` before
        // the query parameters. We best-effort probe for it: if the
        // first consistency read does not look valid, retry after a
        // second `[short bytes]`.
        let save = cur.pos;
        if let Some(cl) = cur.read_short() {
            if is_plausible_consistency(cl) {
                rec.consistency = Some(cl);
                return;
            }
        }
        cur.pos = save;
        if rec.version >= 5 && cur.read_short_bytes().is_some() {
            if let Some(cl) = cur.read_short() {
                if is_plausible_consistency(cl) {
                    rec.consistency = Some(cl);
                }
            }
        }
    }
}

// -- opcode-specific decoders -------------------------------------------

fn decode_startup(rec: &mut CqlRecord, body: &[u8]) {
    let mut cur = Cursor::new(body);
    let Some(n) = cur.read_short() else { return };
    let mut cql_version: Option<String> = None;
    let mut compression: Option<String> = None;
    for _ in 0..n {
        let Some(k) = cur.read_string() else { return };
        let Some(v) = cur.read_string() else { return };
        match k.as_str() {
            "CQL_VERSION" => cql_version = Some(v),
            "COMPRESSION" => compression = Some(v),
            _ => {}
        }
    }
    let mut s = String::from("STARTUP");
    if let Some(v) = &cql_version {
        s.push_str(" CQL_VERSION=");
        s.push_str(v);
    }
    if let Some(c) = &compression {
        s.push_str(" COMPRESSION=");
        s.push_str(c);
    }
    rec.summary = truncate_owned(s, MAX_SUMMARY);
}

fn decode_query(rec: &mut CqlRecord, body: &[u8]) {
    let mut cur = Cursor::new(body);
    let Some(q) = cur.read_long_string() else {
        return;
    };
    let trimmed = truncate_str(&q, MAX_QUERY_BYTES).to_string();
    // USE <ks> capture.
    if let Some(ks) = parse_use_keyspace(&trimmed) {
        rec.keyspace = Some(truncate_str(&ks, MAX_KEYSPACE).to_string());
    }
    rec.query = Some(trimmed);
    if let Some(cl) = cur.read_short() {
        rec.consistency = Some(cl);
    }
}

fn decode_prepare(rec: &mut CqlRecord, body: &[u8]) {
    let mut cur = Cursor::new(body);
    let Some(q) = cur.read_long_string() else {
        return;
    };
    rec.query = Some(truncate_str(&q, MAX_QUERY_BYTES).to_string());
}

fn decode_batch(rec: &mut CqlRecord, body: &[u8]) {
    let mut cur = Cursor::new(body);
    let Some(batch_type) = cur.read_u8() else {
        return;
    };
    let Some(n) = cur.read_short() else { return };
    let tag = match batch_type {
        0 => "LOGGED",
        1 => "UNLOGGED",
        2 => "COUNTER",
        _ => "BATCH",
    };
    let mut logged_any = false;
    let mut unlogged_any = false;
    let mut total = 0u32;
    for _ in 0..n {
        let Some(kind) = cur.read_u8() else { break };
        total += 1;
        match kind {
            0 => {
                logged_any = true;
                if cur.read_long_string().is_none() {
                    break;
                }
            }
            1 => {
                unlogged_any = true;
                if cur.read_short_bytes().is_none() {
                    break;
                }
            }
            _ => break,
        }
        // Skip per-statement parameter values: [short n_vals] ([value])*
        let Some(m) = cur.read_short() else { break };
        let mut bad = false;
        for _ in 0..m {
            if cur.read_value().is_none() {
                bad = true;
                break;
            }
        }
        if bad {
            break;
        }
    }
    if let Some(cl) = cur.read_short() {
        rec.consistency = Some(cl);
    }
    let _ = (logged_any, unlogged_any);
    rec.summary = truncate_owned(format!("BATCH {tag} stmts={total}"), MAX_SUMMARY);
}

fn decode_error(rec: &mut CqlRecord, body: &[u8]) {
    let mut cur = Cursor::new(body);
    let Some(code) = cur.read_int() else { return };
    rec.error_code = Some(code);
    if let Some(msg) = cur.read_string() {
        rec.error_message = Some(truncate_str(&msg, MAX_SUMMARY).to_string());
    }
}

// -- helpers ------------------------------------------------------------

fn default_summary(rec: &CqlRecord) -> String {
    let mut s = String::from(rec.opcode.as_tag());
    if let Some(q) = &rec.query {
        s.push(' ');
        s.push('\'');
        s.push_str(q);
        s.push('\'');
    }
    if let Some(cl) = rec.consistency {
        s.push_str(" CL=");
        s.push_str(consistency_name(cl));
    }
    truncate_owned(s, MAX_SUMMARY)
}

const fn consistency_name(v: u16) -> &'static str {
    match v {
        0 => "ANY",
        1 => "ONE",
        2 => "TWO",
        3 => "THREE",
        4 => "QUORUM",
        5 => "ALL",
        6 => "LOCAL_QUORUM",
        7 => "EACH_QUORUM",
        8 => "SERIAL",
        9 => "LOCAL_SERIAL",
        10 => "LOCAL_ONE",
        _ => "UNKNOWN",
    }
}

const fn is_plausible_consistency(v: u16) -> bool {
    v <= 10
}

fn parse_use_keyspace(q: &str) -> Option<String> {
    let t = q.trim_start();
    if t.len() < 4 {
        return None;
    }
    let (head, rest) = t.split_at(4);
    if !head.eq_ignore_ascii_case("USE ") {
        return None;
    }
    let mut name = rest.trim().trim_end_matches(';').trim().to_string();
    if name.starts_with('"') && name.ends_with('"') && name.len() >= 2 {
        name = name[1..name.len() - 1].to_string();
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    // Find the last char boundary at or below `max`.
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn truncate_owned(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// -- cursor -------------------------------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    fn read_u8(&mut self) -> Option<u8> {
        let s = self.take(1)?;
        Some(s[0])
    }

    fn read_short(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }

    fn read_int(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_signed_int(&mut self) -> Option<i32> {
        let s = self.take(4)?;
        Some(i32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// `[string]` = `[short]` length + UTF-8.
    fn read_string(&mut self) -> Option<String> {
        let n = self.read_short()? as usize;
        let s = self.take(n)?;
        Some(String::from_utf8_lossy(s).into_owned())
    }

    /// `[long string]` = `[int]` length + UTF-8.
    fn read_long_string(&mut self) -> Option<String> {
        let n = self.read_int()? as usize;
        let s = self.take(n)?;
        Some(String::from_utf8_lossy(s).into_owned())
    }

    /// `[short bytes]` = `[short]` length + raw bytes.
    fn read_short_bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.read_short()? as usize;
        self.take(n)
    }

    /// `[value]` = `[int]` length + bytes. `-1` = null, `-2` = not set.
    fn read_value(&mut self) -> Option<()> {
        let n = self.read_signed_int()?;
        if n < 0 {
            return Some(());
        }
        #[allow(clippy::cast_sign_loss)]
        let n = n as usize;
        self.take(n).map(|_| ())
    }
}

// -- tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(version: u8, flags: u8, stream: i16, opcode: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.push(version);
        out.push(flags);
        out.extend_from_slice(&stream.to_be_bytes());
        out.push(opcode);
        #[allow(clippy::cast_possible_truncation)]
        let bl = body.len() as u32;
        out.extend_from_slice(&bl.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn expect_record(out: CqlParserOutput) -> (CqlRecord, usize) {
        match out {
            CqlParserOutput::Record { record, consumed } => (*record, consumed),
            CqlParserOutput::Need => panic!("expected Record, got Need"),
            CqlParserOutput::Skip(n) => panic!("expected Record, got Skip({n})"),
        }
    }

    #[test]
    fn startup_request_parses() {
        let mut body = Vec::new();
        // string map { "CQL_VERSION": "3.4.5" }
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&(11u16).to_be_bytes());
        body.extend_from_slice(b"CQL_VERSION");
        body.extend_from_slice(&(5u16).to_be_bytes());
        body.extend_from_slice(b"3.4.5");

        let buf = frame(0x04, 0, 1, 0x01, &body);
        let mut p = CassandraParser::default();
        let (rec, consumed) = expect_record(p.parse(&buf, Direction::Tx));
        assert_eq!(consumed, buf.len());
        assert_eq!(rec.version, 4);
        assert!(!rec.is_response);
        assert_eq!(rec.opcode, CqlOpcode::Startup);
        assert!(rec.summary.contains("CQL_VERSION=3.4.5"));
    }

    #[test]
    fn query_with_consistency() {
        let sql = b"SELECT * FROM ks.t";
        let mut body = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        let len = sql.len() as u32;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(sql);
        body.extend_from_slice(&1u16.to_be_bytes()); // ONE
        body.push(0); // flags

        let buf = frame(0x04, 0, 7, 0x07, &body);
        let mut p = CassandraParser::default();
        let (rec, _) = expect_record(p.parse(&buf, Direction::Tx));
        assert_eq!(rec.opcode, CqlOpcode::Query);
        assert_eq!(rec.query.as_deref(), Some("SELECT * FROM ks.t"));
        assert_eq!(rec.consistency, Some(1));
        let line = rec.display_line();
        assert!(line.contains("CL=ONE"), "got: {line}");
    }

    #[test]
    fn use_query_populates_keyspace() {
        let sql = b"USE myks;";
        let mut body = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        let len = sql.len() as u32;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(sql);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.push(0);

        let buf = frame(0x04, 0, 3, 0x07, &body);
        let mut p = CassandraParser::default();
        let (rec, _) = expect_record(p.parse(&buf, Direction::Tx));
        assert_eq!(rec.keyspace.as_deref(), Some("myks"));
    }

    #[test]
    fn prepare_and_execute_pair() {
        // PREPARE
        let sql = b"INSERT INTO t (a) VALUES (?)";
        let mut body = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        let len = sql.len() as u32;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(sql);
        let buf = frame(0x04, 0, 9, 0x09, &body);
        let mut p = CassandraParser::default();
        let (rec, _) = expect_record(p.parse(&buf, Direction::Tx));
        assert_eq!(rec.opcode, CqlOpcode::Prepare);
        assert_eq!(rec.query.as_deref(), Some("INSERT INTO t (a) VALUES (?)"));

        // EXECUTE with id "deadbeef"
        let id = [0xde, 0xad, 0xbe, 0xef];
        let mut body = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        let idlen = id.len() as u16;
        body.extend_from_slice(&idlen.to_be_bytes());
        body.extend_from_slice(&id);
        body.extend_from_slice(&4u16.to_be_bytes()); // QUORUM
        body.push(0);
        let buf = frame(0x04, 0, 10, 0x0A, &body);
        let (rec, _) = expect_record(p.parse(&buf, Direction::Tx));
        assert_eq!(rec.opcode, CqlOpcode::Execute);
        assert_eq!(rec.consistency, Some(4));
        // We didn't pre-register the id, so parser surfaces a placeholder.
        assert!(rec
            .query
            .as_deref()
            .is_some_and(|q| q.starts_with("<prepared ")));
    }

    #[test]
    fn error_with_code_and_message() {
        let msg = b"Unauthorized";
        let mut body = Vec::new();
        body.extend_from_slice(&0x2200u32.to_be_bytes());
        #[allow(clippy::cast_possible_truncation)]
        let mlen = msg.len() as u16;
        body.extend_from_slice(&mlen.to_be_bytes());
        body.extend_from_slice(msg);
        let buf = frame(0x84, 0, 1, 0x00, &body);
        let mut p = CassandraParser::default();
        let (rec, _) = expect_record(p.parse(&buf, Direction::Rx));
        assert_eq!(rec.opcode, CqlOpcode::Error);
        assert_eq!(rec.error_code, Some(0x2200));
        assert_eq!(rec.error_message.as_deref(), Some("Unauthorized"));
        assert!(rec.is_response);
    }

    #[test]
    fn auth_response_body_is_redacted() {
        let body = b"\x00\x00\x00\x0csuper-secret";
        let buf = frame(0x04, 0, 5, 0x0F, body);
        let mut p = CassandraParser::default();
        let (rec, _) = expect_record(p.parse(&buf, Direction::Tx));
        assert_eq!(rec.opcode, CqlOpcode::AuthResponse);
        assert!(rec.summary.contains("redacted"));
        assert!(rec.query.is_none());
        assert!(!rec.summary.contains("secret"));
    }

    #[test]
    fn compressed_flag_sets_summary_tag() {
        let body = b"\x00\x00\x00\x00"; // opaque compressed bytes
        let buf = frame(0x04, FLAG_COMPRESSION, 2, 0x07, body);
        let mut p = CassandraParser::default();
        let (rec, _) = expect_record(p.parse(&buf, Direction::Tx));
        assert!(rec.compressed);
        assert!(rec.summary.contains("compressed"), "got: {}", rec.summary);
    }

    #[test]
    fn truncated_header_returns_need() {
        let mut p = CassandraParser::default();
        let short = [0x04u8, 0, 0, 0];
        matches!(p.parse(&short, Direction::Tx), CqlParserOutput::Need);
    }

    #[test]
    fn absurd_body_length_skips_and_bypasses() {
        let mut hdr = Vec::new();
        hdr.push(0x04);
        hdr.push(0);
        hdr.extend_from_slice(&0i16.to_be_bytes());
        hdr.push(0x07);
        hdr.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut p = CassandraParser::default();
        match p.parse(&hdr, Direction::Tx) {
            CqlParserOutput::Skip(n) => assert_eq!(n, hdr.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
        // Subsequent calls stay in bypass.
        match p.parse(b"abcd", Direction::Tx) {
            CqlParserOutput::Skip(n) => assert_eq!(n, 4),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn unknown_version_byte_bypasses() {
        let buf = [0x09u8, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut p = CassandraParser::default();
        match p.parse(&buf, Direction::Tx) {
            CqlParserOutput::Skip(n) => assert_eq!(n, buf.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn v5_version_is_recognised() {
        // Minimal OPTIONS frame (no body).
        let buf = frame(0x05, 0, 0, 0x05, &[]);
        let mut p = CassandraParser::default();
        let (rec, _) = expect_record(p.parse(&buf, Direction::Tx));
        assert_eq!(rec.version, 5);
        assert_eq!(rec.opcode, CqlOpcode::Options);
    }

    #[test]
    fn batch_summary_counts_statements() {
        // LOGGED batch with two simple queries and no params.
        let mut body = Vec::new();
        body.push(0u8); // LOGGED
        body.extend_from_slice(&2u16.to_be_bytes());
        for q in &[
            b"INSERT INTO t (a) VALUES (1)".as_ref(),
            b"INSERT INTO t (a) VALUES (2)".as_ref(),
        ] {
            body.push(0u8); // kind = query
            #[allow(clippy::cast_possible_truncation)]
            let l = q.len() as u32;
            body.extend_from_slice(&l.to_be_bytes());
            body.extend_from_slice(q);
            body.extend_from_slice(&0u16.to_be_bytes()); // n_vals = 0
        }
        body.extend_from_slice(&4u16.to_be_bytes()); // QUORUM
        body.push(0); // flags
        let buf = frame(0x04, 0, 11, 0x0D, &body);
        let mut p = CassandraParser::default();
        let (rec, _) = expect_record(p.parse(&buf, Direction::Tx));
        assert_eq!(rec.opcode, CqlOpcode::Batch);
        assert_eq!(rec.consistency, Some(4));
        assert!(rec.summary.contains("stmts=2"), "got: {}", rec.summary);
    }
}
