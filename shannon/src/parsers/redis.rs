//! Redis RESP2 + RESP3 parser.
//!
//! Implements the Redis serialization protocol as documented at
//! <https://redis.io/docs/latest/develop/reference/protocol-spec/>, covering
//! both RESP2 (the classic protocol) and RESP3 (introduced in Redis 6).
//!
//! Each parser instance decodes one direction of one connection. On the
//! client-to-server (Tx) side, input is generally an array of bulk strings
//! — the first element is the command name; the remainder are arguments.
//! We also accept the legacy "inline" command form (still supported by
//! `redis-server`) where commands are just whitespace-separated tokens
//! terminated by CRLF.
//!
//! Bounds: bulk strings are truncated to 4 KiB, arrays/maps are capped at
//! 4096 elements per top-level value, and nesting depth is capped at 32.
//! Anything weirder than that is treated as a parse failure and the
//! surrounding buffer is skipped — we never panic on malformed input and
//! we never allocate unboundedly.
//!
//! Secrets handling: `AUTH` command arguments are dropped entirely from
//! the emitted record; for `HELLO` we detect the optional `AUTH
//! <user> <pass>` suffix and redact the password.

use crate::events::Direction;

/// Depth cap for nested aggregates.
const MAX_DEPTH: usize = 32;
/// Element cap for any one aggregate (arrays, maps, sets, push).
const MAX_TOP_ELEMENTS: usize = 4096;
/// Truncation cap for bulk / verbatim string bodies.
const MAX_BULK_BYTES: usize = 4096;
/// Sanity cap on declared bulk/verbatim length.
const MAX_DECLARED_LEN: usize = 512 * 1024 * 1024;

/// Parser state machine. One instance per (connection, direction).
#[derive(Debug, Default)]
pub struct RedisParser {
    bypass: bool,
}

/// Result of one parse step. Mirrors [`crate::parsers::http1::ParserOutput`].
#[derive(Debug)]
pub enum RedisParserOutput {
    Need,
    Record {
        record: RedisRecord,
        consumed: usize,
    },
    Skip(usize),
}

/// A single decoded RESP top-level value, classified for convenient
/// logging. Client-to-server arrays of bulk strings land in
/// [`RedisRecord::Command`]; everything else is a response-shaped value.
#[derive(Clone, Debug)]
pub enum RedisRecord {
    /// Client-side command: first bulk string of the array, uppercased,
    /// plus the remaining arguments. `args` is empty for redacted
    /// commands (e.g. `AUTH`).
    Command {
        name: String,
        args: Vec<RespValue>,
    },
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),
    Array(Vec<RespValue>),
    Null,
    Boolean(bool),
    Double(f64),
    BigNumber(String),
    VerbatimString {
        format: String,
        content: String,
    },
    Map(Vec<(RespValue, RespValue)>),
    Set(Vec<RespValue>),
    Push(Vec<RespValue>),
    /// Inline, whitespace-separated command form.
    Inline {
        tokens: Vec<String>,
    },
}

/// Any RESP value, nested inside another value.
#[derive(Clone, Debug)]
pub enum RespValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),
    Array(Option<Vec<Self>>),
    Null,
    Boolean(bool),
    Double(f64),
    BigNumber(String),
    VerbatimString { format: String, content: String },
    Map(Vec<(Self, Self)>),
    Set(Vec<Self>),
}

impl RedisRecord {
    /// Render a single-line, human-readable form. Intended for trace
    /// output, not for wire reconstruction.
    #[must_use]
    pub fn display_line(&self) -> String {
        match self {
            Self::Command { name, args } => {
                let mut s = name.clone();
                for a in args {
                    s.push(' ');
                    s.push_str(&resp_display(a));
                }
                s
            }
            Self::SimpleString(v) => format!("+{v}"),
            Self::Error(v) => format!("-{v}"),
            Self::Integer(v) => format!("(integer) {v}"),
            Self::BulkString(None) => "(nil)".to_string(),
            Self::BulkString(Some(b)) => format!("\"{}\"", bytes_display(b)),
            Self::Array(items) => fmt_list("[", "]", items),
            Self::Null => "(null)".to_string(),
            Self::Boolean(b) => if *b { "(true)" } else { "(false)" }.to_string(),
            Self::Double(d) => format!("(double) {d}"),
            Self::BigNumber(v) => format!("(big) {v}"),
            Self::VerbatimString { format, content } => format!("({format}) {content}"),
            Self::Map(entries) => fmt_map(entries),
            Self::Set(items) => fmt_list("#{", "}", items),
            Self::Push(items) => fmt_list(">[", "]", items),
            Self::Inline { tokens } => tokens.join(" "),
        }
    }
}

fn fmt_list(open: &str, close: &str, items: &[RespValue]) -> String {
    let mut s = String::from(open);
    for (i, v) in items.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&resp_display(v));
    }
    s.push_str(close);
    s
}

fn fmt_map(entries: &[(RespValue, RespValue)]) -> String {
    let mut s = String::from("{");
    for (i, (k, v)) in entries.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&resp_display(k));
        s.push_str(": ");
        s.push_str(&resp_display(v));
    }
    s.push('}');
    s
}

fn resp_display(v: &RespValue) -> String {
    match v {
        RespValue::Error(s) => format!("-{s}"),
        RespValue::Integer(i) => i.to_string(),
        RespValue::BulkString(None) | RespValue::Array(None) => "(nil)".to_string(),
        RespValue::BulkString(Some(b)) => format!("\"{}\"", bytes_display(b)),
        RespValue::Array(Some(items)) => fmt_list("[", "]", items),
        RespValue::Null => "(null)".to_string(),
        RespValue::Boolean(b) => if *b { "true" } else { "false" }.to_string(),
        RespValue::Double(d) => d.to_string(),
        RespValue::SimpleString(s) | RespValue::BigNumber(s) => s.clone(),
        RespValue::VerbatimString { format, content } => format!("({format}) {content}"),
        RespValue::Map(entries) => fmt_map(entries),
        RespValue::Set(items) => fmt_list("#{", "}", items),
    }
}

fn bytes_display(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(b.len());
    for &byte in b {
        if (0x20..0x7f).contains(&byte) && byte != b'"' && byte != b'\\' {
            out.push(byte as char);
        } else {
            // Writing into a String is infallible; silence the Result.
            let _ = write!(out, "\\x{byte:02x}");
        }
    }
    out
}

/// Outcome of a nested RESP decode step. `consumed` is always measured
/// against the full type-byte-inclusive input slice.
enum DecodeResult {
    Ok { value: RespValue, consumed: usize },
    Need,
    Bypass,
}

impl RedisParser {
    /// Parse one RESP value out of `buf`. On the Tx side, a top-level
    /// array of bulk strings becomes a [`RedisRecord::Command`]; an
    /// inline (non-type-byte) line becomes a [`RedisRecord::Inline`].
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> RedisParserOutput {
        if self.bypass {
            return RedisParserOutput::Skip(buf.len());
        }
        if buf.is_empty() {
            return RedisParserOutput::Need;
        }

        let first = buf[0];
        if !is_type_byte(first) {
            return match dir {
                Direction::Tx => self.parse_inline(buf),
                Direction::Rx => {
                    self.bypass = true;
                    RedisParserOutput::Skip(buf.len())
                }
            };
        }

        // Top-level decode. Use `decode_top` which preserves the Push tag.
        match decode_top(buf, 0) {
            DecodeResult::Need => RedisParserOutput::Need,
            DecodeResult::Bypass => {
                self.bypass = true;
                RedisParserOutput::Skip(buf.len())
            }
            DecodeResult::Ok { value, consumed } => {
                let record = classify(value, dir, buf[0] == b'>');
                RedisParserOutput::Record { record, consumed }
            }
        }
    }

    fn parse_inline(&mut self, buf: &[u8]) -> RedisParserOutput {
        let Some(line_end) = find_crlf(buf) else {
            if buf.len() > MAX_BULK_BYTES {
                self.bypass = true;
                return RedisParserOutput::Skip(buf.len());
            }
            return RedisParserOutput::Need;
        };
        let Ok(line) = std::str::from_utf8(&buf[..line_end]) else {
            self.bypass = true;
            return RedisParserOutput::Skip(buf.len());
        };
        if !is_plausible_inline(line) {
            self.bypass = true;
            return RedisParserOutput::Skip(buf.len());
        }
        let tokens: Vec<String> = line.split_ascii_whitespace().map(str::to_string).collect();
        if tokens.is_empty() {
            return RedisParserOutput::Skip(line_end + 2);
        }
        let name = tokens[0].to_ascii_uppercase();
        let args: Vec<RespValue> = tokens[1..]
            .iter()
            .map(|t| RespValue::BulkString(Some(t.as_bytes().to_vec())))
            .collect();
        let (name, args) = redact(&name, args);
        RedisParserOutput::Record {
            record: RedisRecord::Command { name, args },
            consumed: line_end + 2,
        }
    }
}

const fn is_type_byte(b: u8) -> bool {
    matches!(
        b,
        b'+' | b'-' | b':' | b'$' | b'*' | b'_' | b'#' | b',' | b'(' | b'=' | b'%' | b'~' | b'>'
    )
}

fn is_plausible_inline(line: &str) -> bool {
    if line.is_empty() {
        return true;
    }
    let first_token = line.split_ascii_whitespace().next().unwrap_or("");
    if first_token.is_empty() {
        return true;
    }
    first_token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// Top-level decode that treats `>` as an Array (since `RespValue` has
/// no Push variant); the parse caller remembers the tag and classifies
/// accordingly.
fn decode_top(buf: &[u8], depth: usize) -> DecodeResult {
    decode(buf, depth)
}

/// Fully decode one RESP value starting with its type byte at `buf[0]`.
fn decode(buf: &[u8], depth: usize) -> DecodeResult {
    if depth >= MAX_DEPTH {
        return DecodeResult::Bypass;
    }
    if buf.is_empty() {
        return DecodeResult::Need;
    }
    let tag = buf[0];
    let rest = &buf[1..];
    match tag {
        b'+' => match read_line(rest) {
            LineResult::Need => DecodeResult::Need,
            LineResult::Bad => DecodeResult::Bypass,
            LineResult::Ok(s, c) => ok(RespValue::SimpleString(s), c + 1),
        },
        b'-' => match read_line(rest) {
            LineResult::Need => DecodeResult::Need,
            LineResult::Bad => DecodeResult::Bypass,
            LineResult::Ok(s, c) => ok(RespValue::Error(s), c + 1),
        },
        b':' => match read_line(rest) {
            LineResult::Need => DecodeResult::Need,
            LineResult::Bad => DecodeResult::Bypass,
            LineResult::Ok(s, c) => s
                .parse::<i64>()
                .map_or(DecodeResult::Bypass, |n| ok(RespValue::Integer(n), c + 1)),
        },
        b'$' => decode_bulk(rest),
        b'*' | b'>' => decode_array_like(rest, depth, |items| RespValue::Array(Some(items))),
        b'~' => decode_array_like(rest, depth, RespValue::Set),
        b'_' => match read_line(rest) {
            LineResult::Need => DecodeResult::Need,
            LineResult::Bad => DecodeResult::Bypass,
            LineResult::Ok(s, c) => {
                if s.is_empty() {
                    ok(RespValue::Null, c + 1)
                } else {
                    DecodeResult::Bypass
                }
            }
        },
        b'#' => match read_line(rest) {
            LineResult::Need => DecodeResult::Need,
            LineResult::Bad => DecodeResult::Bypass,
            LineResult::Ok(s, c) => match s.as_str() {
                "t" => ok(RespValue::Boolean(true), c + 1),
                "f" => ok(RespValue::Boolean(false), c + 1),
                _ => DecodeResult::Bypass,
            },
        },
        b',' => match read_line(rest) {
            LineResult::Need => DecodeResult::Need,
            LineResult::Bad => DecodeResult::Bypass,
            LineResult::Ok(s, c) => {
                let parsed = match s.as_str() {
                    "inf" | "+inf" => Ok(f64::INFINITY),
                    "-inf" => Ok(f64::NEG_INFINITY),
                    "nan" | "+nan" | "-nan" => Ok(f64::NAN),
                    _ => s.parse::<f64>(),
                };
                parsed.map_or(DecodeResult::Bypass, |d| ok(RespValue::Double(d), c + 1))
            }
        },
        b'(' => match read_line(rest) {
            LineResult::Need => DecodeResult::Need,
            LineResult::Bad => DecodeResult::Bypass,
            LineResult::Ok(s, c) => {
                if is_bignum(&s) {
                    ok(RespValue::BigNumber(s), c + 1)
                } else {
                    DecodeResult::Bypass
                }
            }
        },
        b'=' => decode_verbatim(rest),
        b'%' => decode_map(rest, depth),
        _ => DecodeResult::Bypass,
    }
}

#[inline]
const fn ok(value: RespValue, consumed: usize) -> DecodeResult {
    DecodeResult::Ok { value, consumed }
}

fn is_bignum(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let rest = if matches!(bytes[0], b'+' | b'-') {
        &bytes[1..]
    } else {
        bytes
    };
    !rest.is_empty() && rest.iter().all(u8::is_ascii_digit)
}

fn decode_bulk(rest: &[u8]) -> DecodeResult {
    let (len_str, header_len) = match read_line(rest) {
        LineResult::Need => return DecodeResult::Need,
        LineResult::Bad => return DecodeResult::Bypass,
        LineResult::Ok(s, c) => (s, c),
    };
    let Ok(n) = len_str.parse::<i64>() else {
        return DecodeResult::Bypass;
    };
    if n == -1 {
        return ok(RespValue::BulkString(None), header_len + 1);
    }
    if n < 0 {
        return DecodeResult::Bypass;
    }
    let Ok(n_usize) = usize::try_from(n) else {
        return DecodeResult::Bypass;
    };
    if n_usize > MAX_DECLARED_LEN {
        return DecodeResult::Bypass;
    }
    if rest.len() < header_len + n_usize + 2 {
        return DecodeResult::Need;
    }
    let body = &rest[header_len..header_len + n_usize];
    if rest[header_len + n_usize] != b'\r' || rest[header_len + n_usize + 1] != b'\n' {
        return DecodeResult::Bypass;
    }
    let keep = body.len().min(MAX_BULK_BYTES);
    ok(
        RespValue::BulkString(Some(body[..keep].to_vec())),
        header_len + n_usize + 2 + 1,
    )
}

fn decode_verbatim(rest: &[u8]) -> DecodeResult {
    let (len_str, header_len) = match read_line(rest) {
        LineResult::Need => return DecodeResult::Need,
        LineResult::Bad => return DecodeResult::Bypass,
        LineResult::Ok(s, c) => (s, c),
    };
    let Ok(n) = len_str.parse::<i64>() else {
        return DecodeResult::Bypass;
    };
    if n < 4 {
        return DecodeResult::Bypass;
    }
    let Ok(n_usize) = usize::try_from(n) else {
        return DecodeResult::Bypass;
    };
    if n_usize > MAX_DECLARED_LEN {
        return DecodeResult::Bypass;
    }
    if rest.len() < header_len + n_usize + 2 {
        return DecodeResult::Need;
    }
    let body = &rest[header_len..header_len + n_usize];
    if rest[header_len + n_usize] != b'\r' || rest[header_len + n_usize + 1] != b'\n' {
        return DecodeResult::Bypass;
    }
    if body[3] != b':' {
        return DecodeResult::Bypass;
    }
    let Ok(format) = std::str::from_utf8(&body[..3]) else {
        return DecodeResult::Bypass;
    };
    let content_raw = &body[4..];
    let keep = content_raw.len().min(MAX_BULK_BYTES);
    let content = String::from_utf8_lossy(&content_raw[..keep]).into_owned();
    ok(
        RespValue::VerbatimString {
            format: format.to_string(),
            content,
        },
        header_len + n_usize + 2 + 1,
    )
}

fn decode_array_like<F>(rest: &[u8], depth: usize, ctor: F) -> DecodeResult
where
    F: FnOnce(Vec<RespValue>) -> RespValue,
{
    let (len_str, header_len) = match read_line(rest) {
        LineResult::Need => return DecodeResult::Need,
        LineResult::Bad => return DecodeResult::Bypass,
        LineResult::Ok(s, c) => (s, c),
    };
    let Ok(n) = len_str.parse::<i64>() else {
        return DecodeResult::Bypass;
    };
    if n == -1 {
        // Null array (RESP2).
        return ok(RespValue::Array(None), header_len + 1);
    }
    if n < 0 {
        return DecodeResult::Bypass;
    }
    let Ok(n_usize) = usize::try_from(n) else {
        return DecodeResult::Bypass;
    };
    if n_usize > MAX_TOP_ELEMENTS {
        return DecodeResult::Bypass;
    }
    let mut items = Vec::with_capacity(n_usize.min(16));
    let mut cursor = header_len;
    for _ in 0..n_usize {
        match decode(&rest[cursor..], depth + 1) {
            DecodeResult::Need => return DecodeResult::Need,
            DecodeResult::Bypass => return DecodeResult::Bypass,
            DecodeResult::Ok { value, consumed } => {
                items.push(value);
                cursor += consumed;
            }
        }
    }
    ok(ctor(items), cursor + 1)
}

fn decode_map(rest: &[u8], depth: usize) -> DecodeResult {
    let (len_str, header_len) = match read_line(rest) {
        LineResult::Need => return DecodeResult::Need,
        LineResult::Bad => return DecodeResult::Bypass,
        LineResult::Ok(s, c) => (s, c),
    };
    let Ok(n) = len_str.parse::<i64>() else {
        return DecodeResult::Bypass;
    };
    if n < 0 {
        return DecodeResult::Bypass;
    }
    let Ok(n_usize) = usize::try_from(n) else {
        return DecodeResult::Bypass;
    };
    if n_usize > MAX_TOP_ELEMENTS {
        return DecodeResult::Bypass;
    }
    let mut entries = Vec::with_capacity(n_usize.min(16));
    let mut cursor = header_len;
    for _ in 0..n_usize {
        let k = match decode(&rest[cursor..], depth + 1) {
            DecodeResult::Need => return DecodeResult::Need,
            DecodeResult::Bypass => return DecodeResult::Bypass,
            DecodeResult::Ok { value, consumed } => {
                cursor += consumed;
                value
            }
        };
        let v = match decode(&rest[cursor..], depth + 1) {
            DecodeResult::Need => return DecodeResult::Need,
            DecodeResult::Bypass => return DecodeResult::Bypass,
            DecodeResult::Ok { value, consumed } => {
                cursor += consumed;
                value
            }
        };
        entries.push((k, v));
    }
    ok(RespValue::Map(entries), cursor + 1)
}

enum LineResult {
    Ok(String, usize),
    Need,
    Bad,
}

/// Read a single `text\r\n` line from `buf`. The returned `consumed`
/// counts the terminator.
fn read_line(buf: &[u8]) -> LineResult {
    let Some(pos) = find_crlf(buf) else {
        return LineResult::Need;
    };
    let Ok(s) = std::str::from_utf8(&buf[..pos]) else {
        return LineResult::Bad;
    };
    LineResult::Ok(s.to_string(), pos + 2)
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Fold a fully-decoded `RespValue` into a top-level [`RedisRecord`].
/// `is_push_tag` is true when the top-level type byte was `>`, so we
/// can emit a [`RedisRecord::Push`] instead of a generic array.
fn classify(value: RespValue, dir: Direction, is_push_tag: bool) -> RedisRecord {
    match value {
        RespValue::SimpleString(s) => RedisRecord::SimpleString(s),
        RespValue::Error(s) => RedisRecord::Error(s),
        RespValue::Integer(i) => RedisRecord::Integer(i),
        RespValue::BulkString(b) => RedisRecord::BulkString(b),
        RespValue::Null => RedisRecord::Null,
        RespValue::Boolean(b) => RedisRecord::Boolean(b),
        RespValue::Double(d) => RedisRecord::Double(d),
        RespValue::BigNumber(s) => RedisRecord::BigNumber(s),
        RespValue::VerbatimString { format, content } => {
            RedisRecord::VerbatimString { format, content }
        }
        RespValue::Map(entries) => RedisRecord::Map(entries),
        RespValue::Set(items) => RedisRecord::Set(items),
        RespValue::Array(None) => RedisRecord::Array(Vec::new()),
        RespValue::Array(Some(items)) => {
            if is_push_tag {
                RedisRecord::Push(items)
            } else {
                classify_array(items, dir)
            }
        }
    }
}

fn classify_array(items: Vec<RespValue>, dir: Direction) -> RedisRecord {
    if matches!(dir, Direction::Tx) && all_bulk(&items) {
        let mut it = items.into_iter();
        let Some(RespValue::BulkString(Some(first))) = it.next() else {
            return RedisRecord::Array(it.collect());
        };
        let name = String::from_utf8_lossy(&first).to_ascii_uppercase();
        let args: Vec<RespValue> = it.collect();
        let (name, args) = redact(&name, args);
        RedisRecord::Command { name, args }
    } else {
        RedisRecord::Array(items)
    }
}

fn all_bulk(items: &[RespValue]) -> bool {
    !items.is_empty()
        && items
            .iter()
            .all(|v| matches!(v, RespValue::BulkString(Some(_))))
}

/// Apply command-specific argument redaction. Returns the (possibly
/// rewritten) name and a sanitised argument list.
fn redact(name: &str, args: Vec<RespValue>) -> (String, Vec<RespValue>) {
    match name {
        "AUTH" => ("AUTH".to_string(), Vec::new()),
        "HELLO" => ("HELLO".to_string(), redact_hello(&args)),
        _ => (name.to_string(), args),
    }
}

/// `HELLO [protover [AUTH username password [SETNAME clientname]]]`
/// Redact the password (the arg immediately after the `AUTH` keyword +
/// username).
fn redact_hello(args: &[RespValue]) -> Vec<RespValue> {
    let mut out: Vec<RespValue> = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let as_str = match &args[i] {
            RespValue::BulkString(Some(b)) => {
                std::str::from_utf8(b).ok().map(str::to_ascii_uppercase)
            }
            _ => None,
        };
        out.push(args[i].clone());
        if as_str.as_deref() == Some("AUTH") && i + 2 < args.len() {
            out.push(args[i + 1].clone());
            out.push(RespValue::BulkString(Some(b"<redacted>".to_vec())));
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(buf: &[u8], dir: Direction) -> RedisParserOutput {
        let mut p = RedisParser::default();
        p.parse(buf, dir)
    }

    #[test]
    fn inline_ping() {
        let out = parse_one(b"PING\r\n", Direction::Tx);
        match out {
            RedisParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 6);
                match record {
                    RedisRecord::Command { name, args } => {
                        assert_eq!(name, "PING");
                        assert!(args.is_empty());
                    }
                    other => panic!("expected Command, got {other:?}"),
                }
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn array_set_command() {
        let buf = b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
        match parse_one(buf, Direction::Tx) {
            RedisParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                match record {
                    RedisRecord::Command { name, args } => {
                        assert_eq!(name, "SET");
                        assert_eq!(args.len(), 2);
                        match &args[0] {
                            RespValue::BulkString(Some(b)) => assert_eq!(b, b"foo"),
                            _ => panic!("arg0 bulk"),
                        }
                        match &args[1] {
                            RespValue::BulkString(Some(b)) => assert_eq!(b, b"bar"),
                            _ => panic!("arg1 bulk"),
                        }
                    }
                    other => panic!("expected Command, got {other:?}"),
                }
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn simple_string_reply() {
        match parse_one(b"+OK\r\n", Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::SimpleString(s),
                consumed,
            } => {
                assert_eq!(s, "OK");
                assert_eq!(consumed, 5);
            }
            _ => panic!("expected SimpleString"),
        }
    }

    #[test]
    fn error_reply() {
        match parse_one(b"-ERR x\r\n", Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::Error(s),
                ..
            } => {
                assert_eq!(s, "ERR x");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn integer_reply() {
        match parse_one(b":42\r\n", Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::Integer(n),
                ..
            } => {
                assert_eq!(n, 42);
            }
            _ => panic!("expected Integer"),
        }
    }

    #[test]
    fn bulk_reply() {
        match parse_one(b"$5\r\nhello\r\n", Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::BulkString(Some(b)),
                consumed,
            } => {
                assert_eq!(b, b"hello");
                assert_eq!(consumed, 11);
            }
            _ => panic!("expected BulkString"),
        }
    }

    #[test]
    fn null_bulk() {
        match parse_one(b"$-1\r\n", Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::BulkString(None),
                consumed,
            } => {
                assert_eq!(consumed, 5);
            }
            _ => panic!("expected null BulkString"),
        }
    }

    #[test]
    fn nested_array() {
        let buf = b"*2\r\n*2\r\n:1\r\n:2\r\n$3\r\nabc\r\n";
        match parse_one(buf, Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::Array(items),
                consumed,
            } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(items.len(), 2);
                match &items[0] {
                    RespValue::Array(Some(inner)) => {
                        assert_eq!(inner.len(), 2);
                        assert!(matches!(inner[0], RespValue::Integer(1)));
                        assert!(matches!(inner[1], RespValue::Integer(2)));
                    }
                    _ => panic!("expected nested array"),
                }
                match &items[1] {
                    RespValue::BulkString(Some(b)) => assert_eq!(b, b"abc"),
                    _ => panic!("expected bulk"),
                }
            }
            _ => panic!("expected Array"),
        }
    }

    #[test]
    fn resp3_map() {
        let buf = b"%2\r\n$1\r\na\r\n:1\r\n$1\r\nb\r\n:2\r\n";
        match parse_one(buf, Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::Map(entries),
                consumed,
            } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(entries.len(), 2);
                match (&entries[0].0, &entries[0].1) {
                    (RespValue::BulkString(Some(k)), RespValue::Integer(1)) => {
                        assert_eq!(k, b"a");
                    }
                    other => panic!("unexpected entry 0: {other:?}"),
                }
                match (&entries[1].0, &entries[1].1) {
                    (RespValue::BulkString(Some(k)), RespValue::Integer(2)) => {
                        assert_eq!(k, b"b");
                    }
                    other => panic!("unexpected entry 1: {other:?}"),
                }
            }
            _ => panic!("expected Map"),
        }
    }

    #[test]
    fn auth_is_redacted() {
        let buf = b"*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n";
        match parse_one(buf, Direction::Tx) {
            RedisParserOutput::Record {
                record: RedisRecord::Command { name, args },
                ..
            } => {
                assert_eq!(name, "AUTH");
                assert!(args.is_empty(), "AUTH args must be dropped");
            }
            _ => panic!("expected AUTH command"),
        }
    }

    #[test]
    fn hello_auth_password_redacted() {
        let buf = b"*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n$6\r\nsecret\r\n";
        match parse_one(buf, Direction::Tx) {
            RedisParserOutput::Record {
                record: RedisRecord::Command { name, args },
                ..
            } => {
                assert_eq!(name, "HELLO");
                let last = args.last().expect("has last arg");
                match last {
                    RespValue::BulkString(Some(b)) => {
                        assert_eq!(b, b"<redacted>");
                    }
                    other => panic!("last arg: {other:?}"),
                }
                for a in &args {
                    if let RespValue::BulkString(Some(b)) = a {
                        assert_ne!(b, b"secret");
                    }
                }
            }
            _ => panic!("expected HELLO command"),
        }
    }

    #[test]
    fn partial_buffer_returns_need() {
        let buf = b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nba";
        match parse_one(buf, Direction::Tx) {
            RedisParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
    }

    #[test]
    fn malformed_length_is_skip_not_panic() {
        let buf = b"$abc\r\nhello\r\n";
        match parse_one(buf, Direction::Rx) {
            RedisParserOutput::Skip(n) => {
                assert_eq!(n, buf.len());
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn non_type_byte_rx_bypasses() {
        let buf = b"\x16\x03\x01"; // TLS noise
        match parse_one(buf, Direction::Rx) {
            RedisParserOutput::Skip(_) => {}
            _ => panic!("expected Skip"),
        }
    }

    #[test]
    fn push_type_at_top_level() {
        let buf = b">2\r\n$7\r\nmessage\r\n$5\r\nhello\r\n";
        match parse_one(buf, Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::Push(items),
                consumed,
            } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(items.len(), 2);
                match (&items[0], &items[1]) {
                    (RespValue::BulkString(Some(a)), RespValue::BulkString(Some(b))) => {
                        assert_eq!(a, b"message");
                        assert_eq!(b, b"hello");
                    }
                    other => panic!("unexpected items: {other:?}"),
                }
            }
            other => panic!("expected Push, got {other:?}"),
        }
    }

    #[test]
    fn boolean_and_double_and_null() {
        assert!(matches!(
            parse_one(b"#t\r\n", Direction::Rx),
            RedisParserOutput::Record {
                record: RedisRecord::Boolean(true),
                ..
            }
        ));
        assert!(matches!(
            parse_one(b"#f\r\n", Direction::Rx),
            RedisParserOutput::Record {
                record: RedisRecord::Boolean(false),
                ..
            }
        ));
        match parse_one(b",2.5\r\n", Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::Double(d),
                ..
            } => {
                assert!((d - 2.5).abs() < 1e-9);
            }
            _ => panic!("expected double"),
        }
        assert!(matches!(
            parse_one(b"_\r\n", Direction::Rx),
            RedisParserOutput::Record {
                record: RedisRecord::Null,
                ..
            }
        ));
    }

    #[test]
    fn verbatim_string() {
        let buf = b"=15\r\ntxt:Some string\r\n";
        match parse_one(buf, Direction::Rx) {
            RedisParserOutput::Record {
                record: RedisRecord::VerbatimString { format, content },
                consumed,
            } => {
                assert_eq!(format, "txt");
                assert_eq!(content, "Some string");
                assert_eq!(consumed, buf.len());
            }
            _ => panic!("expected Verbatim"),
        }
    }

    #[test]
    fn display_lines() {
        assert_eq!(
            RedisRecord::SimpleString("PONG".into()).display_line(),
            "+PONG"
        );
        assert_eq!(RedisRecord::Integer(42).display_line(), "(integer) 42");
        assert_eq!(
            RedisRecord::Command {
                name: "GET".into(),
                args: vec![RespValue::BulkString(Some(b"foo".to_vec()))]
            }
            .display_line(),
            "GET \"foo\""
        );
    }

    #[test]
    fn depth_limit_bypasses() {
        // Build *1\r\n *1\r\n ... nested beyond MAX_DEPTH.
        let mut buf = Vec::new();
        for _ in 0..(MAX_DEPTH + 2) {
            buf.extend_from_slice(b"*1\r\n");
        }
        buf.extend_from_slice(b":1\r\n");
        match parse_one(&buf, Direction::Rx) {
            RedisParserOutput::Skip(_) => {}
            other => panic!("expected Skip on depth overflow, got {other:?}"),
        }
    }
}
