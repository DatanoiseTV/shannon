//! `PostgreSQL` wire protocol v3 parser.
//!
//! Decodes the protocol spoken by every `PostgreSQL` server since 7.4.
//! One [`PostgresParser`] instance is owned per (connection, direction)
//! by [`crate::flow`]. It consumes a rolling byte buffer and emits
//! structured [`PgRecord`] values, one per wire message.
//!
//! Framing rules we implement:
//!
//! 1. Post-startup, every message is a 1-byte tag followed by a big-endian
//!    4-byte length (counting the length field itself but NOT the tag),
//!    followed by the payload.
//! 2. The first client message has no tag. It's either an `SSLRequest`
//!    (length=8, magic protocol `0x04d2162f` / 80877103) or a
//!    `StartupMessage` (length + protocol version + null-delimited
//!    key/value pairs).
//! 3. If the client sent `SSLRequest`, the server replies with a single
//!    untagged byte: `'S'` for accept, `'N'` for reject. We handle that
//!    specially because it does not fit the normal framing.
//! 4. `PasswordMessage` (`'p'`) contents are redacted by design — we
//!    emit a record but never expose the bytes.
//!
//! The parser is deliberately tolerant: unknown tags fall through to
//! [`PgRecord::Other`], and bytes that cannot match either the startup
//! shape or a known tag switch the parser into permanent bypass.

use crate::events::Direction;

/// Max bytes of SQL text we keep per record.
const MAX_SQL_BYTES: usize = 8 * 1024;
/// Max fields in an `ErrorResponse` / `NoticeResponse`.
const MAX_FIELDS: usize = 256;
/// Protocol version sentinel used by `SSLRequest` (80877103 in decimal).
const SSL_REQUEST_CODE: u32 = 0x04d2_162f;
/// Protocol version sentinel used by `GSSENCRequest` (80877104).
const GSSENC_REQUEST_CODE: u32 = 0x04d2_1630;
/// Protocol version sentinel used by `CancelRequest` (80877102).
const CANCEL_REQUEST_CODE: u32 = 0x04d2_162e;
/// Ceiling on a plausible Postgres message length (1 GiB). Anything
/// bigger is almost certainly a framing error / not Postgres.
const MAX_MESSAGE_LEN: u32 = 1 << 30;

/// Stateful `PostgreSQL` parser. One per (connection, direction).
#[derive(Debug)]
pub struct PostgresParser {
    state: State,
    /// True if the client has sent `SSLRequest` and we're waiting on the
    /// single-byte `'S'` / `'N'` reply on the server side.
    awaiting_ssl_reply: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Pre-startup. Expect either `SSLRequest` or `StartupMessage` on Tx,
    /// or a single byte SSL reply on Rx if we saw `SSLRequest`.
    Startup,
    /// Normal tagged-message mode.
    Tagged,
    /// Unrecoverable — emit `Skip` for all incoming bytes.
    Bypass,
}

impl Default for PostgresParser {
    fn default() -> Self {
        Self {
            state: State::Startup,
            awaiting_ssl_reply: false,
        }
    }
}

/// Result of one parse step. Matches the shape of
/// [`crate::parsers::http1::ParserOutput`] but carries Postgres records.
#[derive(Debug)]
pub enum PgParserOutput {
    /// Buffer too short; caller must feed more bytes.
    Need,
    /// A full wire message was decoded; caller must drop `consumed`
    /// bytes from the front of the buffer.
    Record { record: PgRecord, consumed: usize },
    /// Bytes are not recognisable; caller drops `n` bytes and tries
    /// again (or stays in bypass forever).
    Skip(usize),
}

/// One decoded Postgres wire message.
#[derive(Clone, Debug)]
pub enum PgRecord {
    /// Untagged `StartupMessage` before any tagged traffic.
    Startup {
        protocol: u32,
        params: Vec<(String, String)>,
    },
    /// Untagged `SSLRequest` (length=8, magic protocol `0x04d2162f`).
    SslRequest,
    /// Untagged single-byte SSL negotiation reply: `'S'` = accept,
    /// `'N'` = reject.
    SslResponse(u8),
    /// `'p'` `PasswordMessage` — content is never retained.
    PasswordMessage,
    /// `'Q'` simple query.
    Query { text: String },
    /// `'P'` Parse (extended query prepare).
    Parse {
        name: String,
        text: String,
        param_count: u16,
    },
    /// `'B'` Bind.
    Bind {
        portal: String,
        statement: String,
        param_count: u16,
    },
    /// `'E'` Execute (client side). `max_rows == 0` means unlimited.
    Execute { portal: String, max_rows: u32 },
    /// `'D'` Describe (client side). `kind` is `'S'` for statement or
    /// `'P'` for portal.
    Describe { kind: u8, name: String },
    /// `'C'` `CommandComplete` (server side) OR Close (client side). We
    /// only surface this for the `CommandComplete` case; Close is routed
    /// to [`PgRecord::Other`] to keep the enum unambiguous.
    CommandComplete { tag: String },
    /// `'E'` `ErrorResponse` (server side). Fields are (type byte, value).
    ErrorResponse { fields: Vec<(u8, String)> },
    /// `'N'` `NoticeResponse` (server side).
    NoticeResponse { fields: Vec<(u8, String)> },
    /// `'Z'` `ReadyForQuery`. Status is `'I'` idle, `'T'` in tx, `'E'`
    /// in failed tx.
    ReadyForQuery { status: u8 },
    /// `'T'` `RowDescription`.
    RowDescription { columns: Vec<String> },
    /// `'D'` `DataRow` (server side).
    DataRow { column_count: u16 },
    /// `'R'` Authentication request. `kind` is the sub-type code.
    Authentication { kind: u32 },
    /// `'X'` Terminate.
    Terminate,
    /// Unknown / uninterpreted tag. Always carries the raw length so a
    /// trace reader can still see framing.
    Other { tag: u8, len: u32 },
}

impl PgRecord {
    /// Concise single-line human rendering.
    #[must_use]
    pub fn display_line(&self) -> String {
        match self {
            Self::Startup { protocol, params } => {
                let major = protocol >> 16;
                let minor = protocol & 0xffff;
                let user = params
                    .iter()
                    .find(|(k, _)| k == "user")
                    .map_or("?", |(_, v)| v.as_str());
                let db = params
                    .iter()
                    .find(|(k, _)| k == "database")
                    .map_or(user, |(_, v)| v.as_str());
                format!("STARTUP v{major}.{minor} user={user} db={db}")
            }
            Self::SslRequest => "SSLRequest".to_string(),
            Self::SslResponse(b) => format!("SSLResponse {}", *b as char),
            Self::PasswordMessage => "PasswordMessage <redacted>".to_string(),
            Self::Query { text } => format!("Q: {text}"),
            Self::Parse {
                name,
                text,
                param_count,
            } => {
                format!("PARSE {name}({param_count}): {text}")
            }
            Self::Bind {
                portal,
                statement,
                param_count,
            } => {
                format!("BIND portal={portal} stmt={statement} params={param_count}")
            }
            Self::Execute { portal, max_rows } => {
                format!("EXECUTE portal={portal} max_rows={max_rows}")
            }
            Self::Describe { kind, name } => {
                format!("DESCRIBE {}:{name}", *kind as char)
            }
            Self::CommandComplete { tag } => format!("COMPLETE {tag}"),
            Self::ErrorResponse { fields } => format!("ERROR {}", summarise_fields(fields)),
            Self::NoticeResponse { fields } => {
                format!("NOTICE {}", summarise_fields(fields))
            }
            Self::ReadyForQuery { status } => {
                format!("ReadyForQuery {}", *status as char)
            }
            Self::RowDescription { columns } => {
                format!("RowDescription [{}]", columns.join(","))
            }
            Self::DataRow { column_count } => format!("DataRow cols={column_count}"),
            Self::Authentication { kind } => format!("Authentication {kind}"),
            Self::Terminate => "Terminate".to_string(),
            Self::Other { tag, len } => {
                format!("Other tag={} len={len}", *tag as char)
            }
        }
    }
}

fn summarise_fields(fields: &[(u8, String)]) -> String {
    let mut parts = Vec::new();
    for (k, v) in fields {
        match k {
            b'S' => parts.push(format!("severity={v}")),
            b'C' => parts.push(format!("code={v}")),
            b'M' => parts.push(format!("msg={v}")),
            b'H' => parts.push(format!("hint={v}")),
            _ => {}
        }
    }
    parts.join(" ")
}

impl PostgresParser {
    /// Decode one message from the front of `buf`.
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> PgParserOutput {
        match self.state {
            State::Bypass => PgParserOutput::Skip(buf.len()),
            State::Startup => self.parse_startup(buf, dir),
            State::Tagged => self.parse_tagged(buf, dir),
        }
    }

    fn parse_startup(&mut self, buf: &[u8], dir: Direction) -> PgParserOutput {
        // Server side during startup: either we're awaiting the single-byte
        // SSL reply, or the server has jumped straight into tagged messages
        // (e.g. AuthenticationOK) after a plaintext startup.
        if matches!(dir, Direction::Rx) {
            if self.awaiting_ssl_reply {
                if buf.is_empty() {
                    return PgParserOutput::Need;
                }
                let b = buf[0];
                if b == b'S' || b == b'N' {
                    self.awaiting_ssl_reply = false;
                    // After SSL accept, traffic will be encrypted — we
                    // cannot parse it, so bypass. After reject, the client
                    // either disconnects or retries in plaintext; stay in
                    // Startup so we can still decode that.
                    if b == b'S' {
                        self.state = State::Bypass;
                    }
                    return PgParserOutput::Record {
                        record: PgRecord::SslResponse(b),
                        consumed: 1,
                    };
                }
                // Not 'S' / 'N' — treat as a normal tagged message and
                // fall through. The server is allowed to send an
                // ErrorResponse here.
                self.awaiting_ssl_reply = false;
            }
            // Server side in startup with no pending SSL reply: jump into
            // tagged mode.
            self.state = State::Tagged;
            return self.parse_tagged(buf, dir);
        }

        // Client side, untagged startup message.
        if buf.len() < 8 {
            return PgParserOutput::Need;
        }
        let len = read_u32(&buf[0..4]);
        // Sanity: the length includes itself (4) plus at minimum the
        // protocol code (4), so a valid untagged message is >= 8 bytes.
        if !(8..=MAX_MESSAGE_LEN).contains(&len) {
            self.state = State::Bypass;
            return PgParserOutput::Skip(buf.len());
        }
        let len_usize = len as usize;
        if buf.len() < len_usize {
            return PgParserOutput::Need;
        }
        let code = read_u32(&buf[4..8]);
        match code {
            SSL_REQUEST_CODE => {
                if len != 8 {
                    self.state = State::Bypass;
                    return PgParserOutput::Skip(buf.len());
                }
                self.awaiting_ssl_reply = true;
                PgParserOutput::Record {
                    record: PgRecord::SslRequest,
                    consumed: 8,
                }
            }
            GSSENC_REQUEST_CODE | CANCEL_REQUEST_CODE => {
                // We don't have dedicated variants for these; surface as
                // Other so the trace is still useful, and after Cancel the
                // connection typically closes anyway.
                PgParserOutput::Record {
                    record: PgRecord::Other { tag: 0, len },
                    consumed: len_usize,
                }
            }
            _ => {
                // Require a plausible v3 protocol (major == 3). Reject
                // anything else to avoid decoding random binary as startup.
                let major = code >> 16;
                if major != 3 {
                    self.state = State::Bypass;
                    return PgParserOutput::Skip(buf.len());
                }
                let params = parse_startup_params(&buf[8..len_usize]);
                self.state = State::Tagged;
                PgParserOutput::Record {
                    record: PgRecord::Startup {
                        protocol: code,
                        params,
                    },
                    consumed: len_usize,
                }
            }
        }
    }

    fn parse_tagged(&mut self, buf: &[u8], dir: Direction) -> PgParserOutput {
        if buf.len() < 5 {
            return PgParserOutput::Need;
        }
        let tag = buf[0];
        // Sanity check: Postgres tags are always printable ASCII letters.
        if !tag.is_ascii_alphabetic() {
            self.state = State::Bypass;
            return PgParserOutput::Skip(buf.len());
        }
        let len = read_u32(&buf[1..5]);
        // len counts the 4-byte length field itself but not the tag.
        if !(4..=MAX_MESSAGE_LEN).contains(&len) {
            self.state = State::Bypass;
            return PgParserOutput::Skip(buf.len());
        }
        let total = 1usize + len as usize;
        if buf.len() < total {
            return PgParserOutput::Need;
        }
        let payload = &buf[5..total];
        let record = decode_tagged(tag, payload, dir, len);
        PgParserOutput::Record {
            record,
            consumed: total,
        }
    }
}

/// Parse the `(name, value)` pairs of a `StartupMessage` payload. The
/// block is a sequence of null-terminated C-strings, terminated by a
/// final empty name (i.e. a trailing zero byte). We are tolerant of
/// slightly malformed payloads: any remainder after the last complete
/// pair is silently ignored.
fn parse_startup_params(mut body: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    while !body.is_empty() && body[0] != 0 {
        let Some((name, rest)) = take_cstring(body) else {
            break;
        };
        let Some((value, rest2)) = take_cstring(rest) else {
            break;
        };
        out.push((name, value));
        body = rest2;
        if out.len() >= MAX_FIELDS {
            break;
        }
    }
    out
}

/// Decode a tagged message payload. Direction is used to disambiguate
/// tags that mean different things depending on who sent them (e.g.
/// `'D'` is Describe from the client and `DataRow` from the server;
/// `'E'` is Execute from the client and `ErrorResponse` from the
/// server; `'C'` is Close from the client and `CommandComplete` from
/// the server).
fn decode_tagged(tag: u8, payload: &[u8], dir: Direction, len: u32) -> PgRecord {
    let is_client = matches!(dir, Direction::Tx);
    match tag {
        b'Q' => PgRecord::Query {
            text: take_cstring_truncated(payload),
        },
        b'P' => decode_parse(payload),
        b'B' => decode_bind(payload),
        b'p' => PgRecord::PasswordMessage,
        b'X' => PgRecord::Terminate,
        b'E' if is_client => decode_execute(payload),
        b'E' => PgRecord::ErrorResponse {
            fields: decode_error_fields(payload),
        },
        b'N' if !is_client => {
            // 'N' server side is NoticeResponse. (It is also SSL reject,
            // but that's handled in the startup path.)
            PgRecord::NoticeResponse {
                fields: decode_error_fields(payload),
            }
        }
        b'D' if is_client => decode_describe(payload),
        b'D' => {
            let column_count = if payload.len() >= 2 {
                read_u16(&payload[0..2])
            } else {
                0
            };
            PgRecord::DataRow { column_count }
        }
        b'C' if is_client => {
            // Close message: kind byte + C-string. Surface as Other so we
            // don't confuse it with CommandComplete.
            PgRecord::Other { tag, len }
        }
        b'C' => PgRecord::CommandComplete {
            tag: take_cstring_truncated(payload),
        },
        b'Z' => {
            let status = payload.first().copied().unwrap_or(b'?');
            PgRecord::ReadyForQuery { status }
        }
        b'T' => PgRecord::RowDescription {
            columns: decode_row_description(payload),
        },
        b'R' => {
            let kind = if payload.len() >= 4 {
                read_u32(&payload[0..4])
            } else {
                0
            };
            PgRecord::Authentication { kind }
        }
        _ => PgRecord::Other { tag, len },
    }
}

fn decode_parse(payload: &[u8]) -> PgRecord {
    let (name, rest) = take_cstring(payload).unwrap_or_else(|| (String::new(), payload));
    let (text, rest2) = take_cstring(rest).unwrap_or_else(|| (String::new(), rest));
    let param_count = if rest2.len() >= 2 {
        read_u16(&rest2[0..2])
    } else {
        0
    };
    PgRecord::Parse {
        name,
        text: truncate_sql(text),
        param_count,
    }
}

fn decode_bind(payload: &[u8]) -> PgRecord {
    let (portal, rest) = take_cstring(payload).unwrap_or_else(|| (String::new(), payload));
    let (statement, rest2) = take_cstring(rest).unwrap_or_else(|| (String::new(), rest));
    // Followed by int16 format-code count + format codes, then int16
    // param count + params. We only need the param count.
    if rest2.len() < 2 {
        return PgRecord::Bind {
            portal,
            statement,
            param_count: 0,
        };
    }
    let fmt_count = read_u16(&rest2[0..2]) as usize;
    let after_fmt_offset = 2 + fmt_count.saturating_mul(2);
    if rest2.len() < after_fmt_offset + 2 {
        return PgRecord::Bind {
            portal,
            statement,
            param_count: 0,
        };
    }
    let param_count = read_u16(&rest2[after_fmt_offset..after_fmt_offset + 2]);
    PgRecord::Bind {
        portal,
        statement,
        param_count,
    }
}

fn decode_execute(payload: &[u8]) -> PgRecord {
    let (portal, rest) = take_cstring(payload).unwrap_or_else(|| (String::new(), payload));
    let max_rows = if rest.len() >= 4 {
        read_u32(&rest[0..4])
    } else {
        0
    };
    PgRecord::Execute { portal, max_rows }
}

fn decode_describe(payload: &[u8]) -> PgRecord {
    let kind = payload.first().copied().unwrap_or(0);
    let rest = payload.get(1..).unwrap_or(&[]);
    let (name, _) = take_cstring(rest).unwrap_or_else(|| (String::new(), rest));
    PgRecord::Describe { kind, name }
}

fn decode_error_fields(mut payload: &[u8]) -> Vec<(u8, String)> {
    let mut out = Vec::new();
    while let Some((&field_type, rest)) = payload.split_first() {
        if field_type == 0 {
            break;
        }
        let Some((value, rest2)) = take_cstring(rest) else {
            break;
        };
        out.push((field_type, value));
        payload = rest2;
        if out.len() >= MAX_FIELDS {
            break;
        }
    }
    out
}

fn decode_row_description(payload: &[u8]) -> Vec<String> {
    if payload.len() < 2 {
        return Vec::new();
    }
    let count = read_u16(&payload[0..2]) as usize;
    let cap = count.min(MAX_FIELDS);
    let mut out = Vec::with_capacity(cap);
    let mut cursor = &payload[2..];
    for _ in 0..cap {
        let Some((name, rest)) = take_cstring(cursor) else {
            break;
        };
        out.push(name);
        // Each field is followed by 18 bytes of metadata:
        // int32 table oid, int16 column attnum, int32 type oid,
        // int16 type size, int32 type modifier, int16 format code.
        if rest.len() < 18 {
            break;
        }
        cursor = &rest[18..];
    }
    out
}

fn take_cstring(buf: &[u8]) -> Option<(String, &[u8])> {
    let nul = memchr::memchr(0, buf)?;
    let s = String::from_utf8_lossy(&buf[..nul]).into_owned();
    Some((s, &buf[nul + 1..]))
}

/// Variant of [`take_cstring`] that tolerates a missing terminator: if
/// there's no NUL, take the whole buffer. Used for messages whose only
/// content is a single C-string (Q, C server side).
fn take_cstring_truncated(buf: &[u8]) -> String {
    let nul = memchr::memchr(0, buf).unwrap_or(buf.len());
    let mut s = String::from_utf8_lossy(&buf[..nul]).into_owned();
    s = truncate_sql(s);
    s
}

fn truncate_sql(mut s: String) -> String {
    if s.len() > MAX_SQL_BYTES {
        // Find a char boundary at or below the limit so we never split a
        // UTF-8 scalar in half.
        let mut cut = MAX_SQL_BYTES;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("...[truncated]");
    }
    s
}

fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn read_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[cfg(test)]
mod tests {
    use super::{Direction, PgParserOutput, PgRecord, PostgresParser, State, SSL_REQUEST_CODE};

    /// The v3.0 protocol major.minor encoded as `3 << 16`.
    const PROTOCOL_V3: u32 = 0x0003_0000;

    /// Build a tagged message: tag + len(including len itself) + payload.
    fn framed(tag: u8, payload: &[u8]) -> Vec<u8> {
        let len = (4 + payload.len()) as u32;
        let mut v = Vec::with_capacity(1 + payload.len() + 4);
        v.push(tag);
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// Parser pre-advanced to the tagged-message phase. Equivalent to
    /// observing a startup message first; avoids clippy's
    /// `field_reassign_with_default` grumble.
    fn tagged_parser() -> PostgresParser {
        PostgresParser {
            state: State::Tagged,
            awaiting_ssl_reply: false,
        }
    }

    #[test]
    fn startup_with_params() {
        let mut p = PostgresParser::default();
        let mut body = Vec::new();
        body.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
        body.extend_from_slice(b"user\0alice\0database\0prod\0application_name\0psql\0\0");
        let total_len = (4 + body.len()) as u32;
        let mut full = Vec::with_capacity(4 + body.len());
        full.extend_from_slice(&total_len.to_be_bytes());
        full.extend_from_slice(&body);
        match p.parse(&full, Direction::Tx) {
            PgParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, full.len());
                if let PgRecord::Startup { protocol, params } = record {
                    assert_eq!(protocol, PROTOCOL_V3);
                    assert!(params.iter().any(|(k, v)| k == "user" && v == "alice"));
                    assert!(params.iter().any(|(k, v)| k == "database" && v == "prod"));
                    assert!(params
                        .iter()
                        .any(|(k, v)| k == "application_name" && v == "psql"));
                } else {
                    panic!("expected Startup, got {record:?}");
                }
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn simple_query_q() {
        let mut p = tagged_parser();
        let sql = b"SELECT 1;\0";
        let msg = framed(b'Q', sql);
        match p.parse(&msg, Direction::Tx) {
            PgParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, msg.len());
                match record {
                    PgRecord::Query { text } => assert_eq!(text, "SELECT 1;"),
                    other => panic!("expected Query, got {other:?}"),
                }
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn ready_for_query_idle() {
        let mut p = tagged_parser();
        let msg = framed(b'Z', b"I");
        match p.parse(&msg, Direction::Rx) {
            PgParserOutput::Record {
                record: PgRecord::ReadyForQuery { status },
                consumed,
            } => {
                assert_eq!(status, b'I');
                assert_eq!(consumed, msg.len());
            }
            _ => panic!("expected ReadyForQuery"),
        }
    }

    #[test]
    fn error_response_fields() {
        let mut p = tagged_parser();
        let mut payload = Vec::new();
        payload.extend_from_slice(b"SERROR\0");
        payload.extend_from_slice(b"C42601\0");
        payload.extend_from_slice(b"Msyntax error at or near \"FROM\"\0");
        payload.push(0);
        let msg = framed(b'E', &payload);
        match p.parse(&msg, Direction::Rx) {
            PgParserOutput::Record {
                record: PgRecord::ErrorResponse { fields },
                ..
            } => {
                assert!(fields.iter().any(|(k, v)| *k == b'S' && v == "ERROR"));
                assert!(fields.iter().any(|(k, v)| *k == b'C' && v == "42601"));
                assert!(fields
                    .iter()
                    .any(|(k, v)| *k == b'M' && v.contains("syntax")));
            }
            _ => panic!("expected ErrorResponse"),
        }
    }

    #[test]
    fn parse_bind_execute_triplet() {
        let mut p = tagged_parser();

        // Parse: name=stmt1, text=SELECT $1, 1 param.
        let mut parse_payload = Vec::new();
        parse_payload.extend_from_slice(b"stmt1\0");
        parse_payload.extend_from_slice(b"SELECT $1\0");
        parse_payload.extend_from_slice(&1u16.to_be_bytes());
        parse_payload.extend_from_slice(&25u32.to_be_bytes()); // text oid
        let parse_msg = framed(b'P', &parse_payload);

        // Bind: portal="", statement=stmt1, 0 format codes, 1 param,
        // param len + bytes, 0 result format codes.
        let mut bind_payload = Vec::new();
        bind_payload.extend_from_slice(b"\0"); // portal
        bind_payload.extend_from_slice(b"stmt1\0");
        bind_payload.extend_from_slice(&0u16.to_be_bytes()); // fmt count
        bind_payload.extend_from_slice(&1u16.to_be_bytes()); // param count
        bind_payload.extend_from_slice(&3u32.to_be_bytes());
        bind_payload.extend_from_slice(b"foo");
        bind_payload.extend_from_slice(&0u16.to_be_bytes());
        let bind_msg = framed(b'B', &bind_payload);

        // Execute: portal="", max_rows=0.
        let mut exec_payload = Vec::new();
        exec_payload.extend_from_slice(b"\0");
        exec_payload.extend_from_slice(&0u32.to_be_bytes());
        let exec_msg = framed(b'E', &exec_payload);

        let mut combined = Vec::new();
        combined.extend_from_slice(&parse_msg);
        combined.extend_from_slice(&bind_msg);
        combined.extend_from_slice(&exec_msg);

        // First record: Parse.
        let out = p.parse(&combined, Direction::Tx);
        let consumed = match out {
            PgParserOutput::Record {
                record:
                    PgRecord::Parse {
                        name,
                        text,
                        param_count,
                    },
                consumed,
            } => {
                assert_eq!(name, "stmt1");
                assert_eq!(text, "SELECT $1");
                assert_eq!(param_count, 1);
                consumed
            }
            _ => panic!("expected Parse"),
        };

        // Second: Bind.
        let out = p.parse(&combined[consumed..], Direction::Tx);
        let consumed2 = match out {
            PgParserOutput::Record {
                record:
                    PgRecord::Bind {
                        portal,
                        statement,
                        param_count,
                    },
                consumed,
            } => {
                assert_eq!(portal, "");
                assert_eq!(statement, "stmt1");
                assert_eq!(param_count, 1);
                consumed
            }
            _ => panic!("expected Bind"),
        };

        // Third: Execute.
        let out = p.parse(&combined[consumed + consumed2..], Direction::Tx);
        match out {
            PgParserOutput::Record {
                record: PgRecord::Execute { portal, max_rows },
                ..
            } => {
                assert_eq!(portal, "");
                assert_eq!(max_rows, 0);
            }
            _ => panic!("expected Execute"),
        }
    }

    #[test]
    fn password_message_is_redacted() {
        let mut p = tagged_parser();
        let secret = b"hunter2\0";
        let msg = framed(b'p', secret);
        match p.parse(&msg, Direction::Tx) {
            PgParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, msg.len());
                match record {
                    PgRecord::PasswordMessage => {}
                    other => panic!("expected PasswordMessage, got {other:?}"),
                }
                // Belt-and-braces: the debug rendering must NOT contain
                // the secret.
                let rendered = format!("{record:?}");
                assert!(!rendered.contains("hunter2"));
                let line = record.display_line();
                assert!(!line.contains("hunter2"));
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn malformed_length_triggers_skip_not_panic() {
        let mut p = tagged_parser();
        // tag='Q' followed by length 0xFFFFFFFF and no body.
        let mut msg = vec![b'Q'];
        msg.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        match p.parse(&msg, Direction::Tx) {
            PgParserOutput::Skip(n) => {
                assert_eq!(n, msg.len());
            }
            _ => panic!("expected Skip"),
        }
        // Follow-up bytes also skipped (bypass state).
        match p.parse(b"anything", Direction::Tx) {
            PgParserOutput::Skip(n) => assert_eq!(n, 8),
            _ => panic!("expected Skip"),
        }
    }

    #[test]
    fn ssl_request_then_accept() {
        let mut p = PostgresParser::default();
        // SSLRequest: length=8, code=0x04d2162f.
        let mut msg = 8u32.to_be_bytes().to_vec();
        msg.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
        match p.parse(&msg, Direction::Tx) {
            PgParserOutput::Record {
                record: PgRecord::SslRequest,
                consumed,
            } => assert_eq!(consumed, 8),
            _ => panic!("expected SslRequest"),
        }
        // Server sends 'S'.
        match p.parse(b"S", Direction::Rx) {
            PgParserOutput::Record {
                record: PgRecord::SslResponse(b'S'),
                consumed: 1,
            } => {}
            _ => panic!("expected SslResponse 'S'"),
        }
        // After accept we go into Bypass — further bytes become Skip.
        match p.parse(b"\x16\x03", Direction::Rx) {
            PgParserOutput::Skip(2) => {}
            _ => panic!("expected Skip post-SSL"),
        }
    }

    #[test]
    fn partial_frame_returns_need() {
        let mut p = tagged_parser();
        let full = framed(b'Q', b"SELECT 1;\0");
        for split in 1..full.len() {
            let mut q = tagged_parser();
            match q.parse(&full[..split], Direction::Tx) {
                PgParserOutput::Need => {}
                PgParserOutput::Record { .. } => panic!("too eager at split={split}"),
                PgParserOutput::Skip(_) => panic!("unexpected skip at split={split}"),
            }
        }
        match p.parse(&full, Direction::Tx) {
            PgParserOutput::Record { .. } => {}
            _ => panic!("expected Record on full buffer"),
        }
    }

    #[test]
    fn non_postgres_garbage_bypasses() {
        let mut p = tagged_parser();
        // Tag byte 0x00 is not an ASCII letter — bypass.
        let junk = [0u8, 0, 0, 0, 4];
        match p.parse(&junk, Direction::Tx) {
            PgParserOutput::Skip(_) => {}
            _ => panic!("expected Skip"),
        }
    }
}
