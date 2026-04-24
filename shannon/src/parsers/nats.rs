//! NATS protocol parser (core + JetStream control framing).
//!
//! NATS is a line-based text protocol: every operation is a CRLF-terminated
//! ASCII line. A handful of operations (PUB, HPUB, MSG, HMSG) carry a raw
//! byte payload that follows the control line and is itself terminated by
//! CRLF. HPUB / HMSG additionally declare a header block in the NATS/1.0
//! MIME-style format.
//!
//! Reference: <https://docs.nats.io/reference/reference-protocols/nats-protocol>.
//!
//! Design notes / bounds:
//!
//! - Subjects are capped at 1024 bytes; longer lines are treated as a parse
//!   failure (`Skip`) rather than truncated silently.
//! - Header blocks are truncated to 4 KiB in the emitted record, though the
//!   parser still advances past the full declared size on the wire.
//! - `info_json` (INFO / CONNECT payload) is truncated to 2 KiB after
//!   redaction.
//! - Payload previews are capped at 256 bytes; `payload_bytes` always
//!   reflects the full declared size.
//! - In CONNECT's JSON, any field whose key matches
//!   `(?i)(auth_token|token|pass|password|jwt|nkey|sig)` has its value
//!   replaced with `"<redacted>"` before the JSON is stored.
//! - The parser is stateless across records: each call decodes one
//!   complete operation (control line plus any payload) from the head of
//!   `buf` and returns how many bytes were consumed.
//! - Never panics on malformed input; unrecognised first tokens flip the
//!   parser into a terminal bypass state.

use crate::events::Direction;

/// Maximum subject length we accept.
const MAX_SUBJECT: usize = 1024;
/// Maximum captured payload preview.
const MAX_PAYLOAD_PREVIEW: usize = 256;
/// Maximum retained header-block bytes.
const MAX_HEADER_BYTES: usize = 4096;
/// Maximum retained info_json length.
const MAX_INFO_JSON: usize = 2048;
/// Maximum total bytes for a single payload (sanity cap on `<#bytes>`).
const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum control-line length we'll tolerate before declaring bypass.
const MAX_CONTROL_LINE: usize = 8192;

/// Parser state machine. One instance per (connection, direction).
#[derive(Debug, Default)]
pub struct NatsParser {
    bypass: bool,
}

/// Result of one parse step. Mirrors [`crate::parsers::http1::ParserOutput`].
#[derive(Debug)]
pub enum NatsParserOutput {
    Need,
    Record { record: NatsRecord, consumed: usize },
    Skip(usize),
}

/// One decoded NATS operation.
#[derive(Clone, Debug)]
pub struct NatsRecord {
    pub direction: Direction,
    pub op: NatsOp,
    pub subject: Option<String>,
    pub reply_to: Option<String>,
    pub sid: Option<String>,
    pub queue_group: Option<String>,
    /// Declared payload size from the control line (PUB/MSG/HPUB/HMSG).
    pub payload_bytes: Option<u32>,
    /// Up to [`MAX_PAYLOAD_PREVIEW`] bytes of the actual payload.
    pub payload_preview: Option<Vec<u8>>,
    /// Header block for HPUB/HMSG (may be multi-line), truncated to
    /// [`MAX_HEADER_BYTES`].
    pub headers: Option<String>,
    /// Quoted error text from `-ERR '<msg>'`.
    pub error_message: Option<String>,
    /// JSON body for INFO / CONNECT, post-redaction and truncated to
    /// [`MAX_INFO_JSON`].
    pub info_json: Option<String>,
}

/// NATS protocol operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatsOp {
    Info,
    Connect,
    Pub,
    Hpub,
    Sub,
    Unsub,
    Msg,
    Hmsg,
    Ping,
    Pong,
    Ok,
    Err,
    /// Verb matched the ASCII-command sanity check but isn't one we
    /// recognise (kept for forward-compat with server extensions).
    Other(String),
}

impl NatsRecord {
    /// Render a single-line, human-readable summary.
    #[must_use]
    pub fn display_line(&self) -> String {
        match &self.op {
            NatsOp::Info => {
                format!("INFO {}", self.info_json.as_deref().unwrap_or(""))
            }
            NatsOp::Connect => {
                format!("CONNECT {}", self.info_json.as_deref().unwrap_or(""))
            }
            NatsOp::Pub => {
                let subj = self.subject.as_deref().unwrap_or("");
                let reply = self
                    .reply_to
                    .as_deref()
                    .map(|r| format!(" -> {r}"))
                    .unwrap_or_default();
                let bytes = self.payload_bytes.unwrap_or(0);
                format!("PUB {subj}{reply} ({bytes} bytes)")
            }
            NatsOp::Hpub => {
                let subj = self.subject.as_deref().unwrap_or("");
                let reply = self
                    .reply_to
                    .as_deref()
                    .map(|r| format!(" -> {r}"))
                    .unwrap_or_default();
                let bytes = self.payload_bytes.unwrap_or(0);
                format!("HPUB {subj}{reply} ({bytes} bytes, with headers)")
            }
            NatsOp::Sub => {
                let subj = self.subject.as_deref().unwrap_or("");
                let sid = self.sid.as_deref().unwrap_or("");
                let q = self
                    .queue_group
                    .as_deref()
                    .map(|q| format!(" queue={q}"))
                    .unwrap_or_default();
                format!("SUB {subj}{q} sid={sid}")
            }
            NatsOp::Unsub => {
                let sid = self.sid.as_deref().unwrap_or("");
                format!("UNSUB {sid}")
            }
            NatsOp::Msg => {
                let subj = self.subject.as_deref().unwrap_or("");
                let sid = self.sid.as_deref().unwrap_or("");
                let reply = self
                    .reply_to
                    .as_deref()
                    .map(|r| format!(" -> {r}"))
                    .unwrap_or_default();
                let bytes = self.payload_bytes.unwrap_or(0);
                format!("MSG {subj} sid={sid}{reply} ({bytes} bytes)")
            }
            NatsOp::Hmsg => {
                let subj = self.subject.as_deref().unwrap_or("");
                let sid = self.sid.as_deref().unwrap_or("");
                let reply = self
                    .reply_to
                    .as_deref()
                    .map(|r| format!(" -> {r}"))
                    .unwrap_or_default();
                let bytes = self.payload_bytes.unwrap_or(0);
                format!("HMSG {subj} sid={sid}{reply} ({bytes} bytes, with headers)")
            }
            NatsOp::Ping => "PING".to_string(),
            NatsOp::Pong => "PONG".to_string(),
            NatsOp::Ok => "+OK".to_string(),
            NatsOp::Err => {
                format!("-ERR '{}'", self.error_message.as_deref().unwrap_or(""))
            }
            NatsOp::Other(v) => v.clone(),
        }
    }
}

impl NatsParser {
    /// Decode one NATS operation from the head of `buf`. Returns `Need`
    /// if more bytes are required, `Record` with the number of bytes
    /// consumed on success, or `Skip` (terminal bypass) on malformed or
    /// non-NATS input.
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> NatsParserOutput {
        if self.bypass {
            return NatsParserOutput::Skip(buf.len());
        }
        if buf.is_empty() {
            return NatsParserOutput::Need;
        }

        let Some(line_end) = find_crlf(buf) else {
            if buf.len() > MAX_CONTROL_LINE {
                self.bypass = true;
                return NatsParserOutput::Skip(buf.len());
            }
            return NatsParserOutput::Need;
        };

        // Quick sanity check: first non-space byte must start an ASCII
        // command token. Pure binary / TLS noise bypasses here.
        if !is_plausible_command_start(&buf[..line_end]) {
            self.bypass = true;
            return NatsParserOutput::Skip(buf.len());
        }

        let line = &buf[..line_end];
        let after_line = line_end + 2;

        // Split verb from args.
        let (verb, rest) = split_verb(line);
        let verb_up = ascii_upper(verb);

        match verb_up.as_str() {
            "PING" => single_line(NatsOp::Ping, dir, after_line),
            "PONG" => single_line(NatsOp::Pong, dir, after_line),
            "+OK" => single_line(NatsOp::Ok, dir, after_line),
            "-ERR" => parse_err(rest, dir, after_line),
            "INFO" => parse_info_like(NatsOp::Info, rest, dir, after_line, false),
            "CONNECT" => parse_info_like(NatsOp::Connect, rest, dir, after_line, true),
            "SUB" => parse_sub(rest, dir, after_line),
            "UNSUB" => parse_unsub(rest, dir, after_line),
            "PUB" => self.parse_pub(buf, rest, dir, line_end),
            "HPUB" => self.parse_hpub(buf, rest, dir, line_end),
            "MSG" => self.parse_msg(buf, rest, dir, line_end),
            "HMSG" => self.parse_hmsg(buf, rest, dir, line_end),
            other => {
                // Looked like a plausible verb but not one we know; emit
                // as Other so downstream still sees it.
                if !is_verb_token(other) {
                    self.bypass = true;
                    return NatsParserOutput::Skip(buf.len());
                }
                NatsParserOutput::Record {
                    record: record(NatsOp::Other(other.to_string()), dir),
                    consumed: after_line,
                }
            }
        }
    }

    fn parse_pub(
        &mut self,
        full: &[u8],
        rest: &[u8],
        dir: Direction,
        line_end: usize,
    ) -> NatsParserOutput {
        // PUB <subject> [reply-to] <#bytes>\r\n<payload>\r\n
        let tokens = tokenize(rest);
        let (subject, reply_to, bytes) = match tokens.len() {
            2 => (tokens[0].clone(), None, tokens[1].clone()),
            3 => (tokens[0].clone(), Some(tokens[1].clone()), tokens[2].clone()),
            _ => {
                self.bypass = true;
                return NatsParserOutput::Skip(full.len());
            }
        };
        let Some(n_bytes) = parse_u64(&bytes) else {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        };
        if n_bytes > MAX_PAYLOAD_BYTES || subject.len() > MAX_SUBJECT {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        }
        let n = n_bytes as usize;
        let header_len = line_end + 2;
        let total = header_len + n + 2;
        if full.len() < total {
            return NatsParserOutput::Need;
        }
        if full[header_len + n] != b'\r' || full[header_len + n + 1] != b'\n' {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        }
        let payload = &full[header_len..header_len + n];
        let mut rec = record(NatsOp::Pub, dir);
        rec.subject = Some(subject);
        rec.reply_to = reply_to;
        rec.payload_bytes = Some(u32_saturating(n_bytes));
        rec.payload_preview = Some(payload[..payload.len().min(MAX_PAYLOAD_PREVIEW)].to_vec());
        NatsParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }

    fn parse_hpub(
        &mut self,
        full: &[u8],
        rest: &[u8],
        dir: Direction,
        line_end: usize,
    ) -> NatsParserOutput {
        // HPUB <subject> [reply-to] <#header-bytes> <#total-bytes>\r\n
        //   <headers>\r\n\r\n<payload>\r\n
        let tokens = tokenize(rest);
        let (subject, reply_to, hdr_bytes, total_bytes) = match tokens.len() {
            3 => (tokens[0].clone(), None, tokens[1].clone(), tokens[2].clone()),
            4 => (
                tokens[0].clone(),
                Some(tokens[1].clone()),
                tokens[2].clone(),
                tokens[3].clone(),
            ),
            _ => {
                self.bypass = true;
                return NatsParserOutput::Skip(full.len());
            }
        };
        let (Some(hdr_n), Some(total_n)) = (parse_u64(&hdr_bytes), parse_u64(&total_bytes)) else {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        };
        if hdr_n > total_n
            || total_n > MAX_PAYLOAD_BYTES
            || subject.len() > MAX_SUBJECT
        {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        }
        let hdr = hdr_n as usize;
        let total = total_n as usize;
        let header_line_end = line_end + 2;
        let wire_total = header_line_end + total + 2;
        if full.len() < wire_total {
            return NatsParserOutput::Need;
        }
        if full[header_line_end + total] != b'\r' || full[header_line_end + total + 1] != b'\n' {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        }
        let header_block = &full[header_line_end..header_line_end + hdr];
        let payload = &full[header_line_end + hdr..header_line_end + total];
        let payload_len = total.saturating_sub(hdr);

        let mut rec = record(NatsOp::Hpub, dir);
        rec.subject = Some(subject);
        rec.reply_to = reply_to;
        rec.payload_bytes = Some(u32_saturating(payload_len as u64));
        rec.payload_preview =
            Some(payload[..payload.len().min(MAX_PAYLOAD_PREVIEW)].to_vec());
        rec.headers = Some(stringify_headers(header_block));
        NatsParserOutput::Record {
            record: rec,
            consumed: wire_total,
        }
    }

    fn parse_msg(
        &mut self,
        full: &[u8],
        rest: &[u8],
        dir: Direction,
        line_end: usize,
    ) -> NatsParserOutput {
        // MSG <subject> <sid> [reply-to] <#bytes>\r\n<payload>\r\n
        let tokens = tokenize(rest);
        let (subject, sid, reply_to, bytes) = match tokens.len() {
            3 => (
                tokens[0].clone(),
                tokens[1].clone(),
                None,
                tokens[2].clone(),
            ),
            4 => (
                tokens[0].clone(),
                tokens[1].clone(),
                Some(tokens[2].clone()),
                tokens[3].clone(),
            ),
            _ => {
                self.bypass = true;
                return NatsParserOutput::Skip(full.len());
            }
        };
        let Some(n_bytes) = parse_u64(&bytes) else {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        };
        if n_bytes > MAX_PAYLOAD_BYTES || subject.len() > MAX_SUBJECT {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        }
        let n = n_bytes as usize;
        let header_len = line_end + 2;
        let total = header_len + n + 2;
        if full.len() < total {
            return NatsParserOutput::Need;
        }
        if full[header_len + n] != b'\r' || full[header_len + n + 1] != b'\n' {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        }
        let payload = &full[header_len..header_len + n];
        let mut rec = record(NatsOp::Msg, dir);
        rec.subject = Some(subject);
        rec.sid = Some(sid);
        rec.reply_to = reply_to;
        rec.payload_bytes = Some(u32_saturating(n_bytes));
        rec.payload_preview = Some(payload[..payload.len().min(MAX_PAYLOAD_PREVIEW)].to_vec());
        NatsParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }

    fn parse_hmsg(
        &mut self,
        full: &[u8],
        rest: &[u8],
        dir: Direction,
        line_end: usize,
    ) -> NatsParserOutput {
        // HMSG <subject> <sid> [reply-to] <#header-bytes> <#total-bytes>\r\n
        //   <headers>\r\n\r\n<payload>\r\n
        let tokens = tokenize(rest);
        let (subject, sid, reply_to, hdr_bytes, total_bytes) = match tokens.len() {
            4 => (
                tokens[0].clone(),
                tokens[1].clone(),
                None,
                tokens[2].clone(),
                tokens[3].clone(),
            ),
            5 => (
                tokens[0].clone(),
                tokens[1].clone(),
                Some(tokens[2].clone()),
                tokens[3].clone(),
                tokens[4].clone(),
            ),
            _ => {
                self.bypass = true;
                return NatsParserOutput::Skip(full.len());
            }
        };
        let (Some(hdr_n), Some(total_n)) = (parse_u64(&hdr_bytes), parse_u64(&total_bytes)) else {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        };
        if hdr_n > total_n
            || total_n > MAX_PAYLOAD_BYTES
            || subject.len() > MAX_SUBJECT
        {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        }
        let hdr = hdr_n as usize;
        let total = total_n as usize;
        let header_line_end = line_end + 2;
        let wire_total = header_line_end + total + 2;
        if full.len() < wire_total {
            return NatsParserOutput::Need;
        }
        if full[header_line_end + total] != b'\r' || full[header_line_end + total + 1] != b'\n' {
            self.bypass = true;
            return NatsParserOutput::Skip(full.len());
        }
        let header_block = &full[header_line_end..header_line_end + hdr];
        let payload = &full[header_line_end + hdr..header_line_end + total];
        let payload_len = total.saturating_sub(hdr);

        let mut rec = record(NatsOp::Hmsg, dir);
        rec.subject = Some(subject);
        rec.sid = Some(sid);
        rec.reply_to = reply_to;
        rec.payload_bytes = Some(u32_saturating(payload_len as u64));
        rec.payload_preview =
            Some(payload[..payload.len().min(MAX_PAYLOAD_PREVIEW)].to_vec());
        rec.headers = Some(stringify_headers(header_block));
        NatsParserOutput::Record {
            record: rec,
            consumed: wire_total,
        }
    }
}

fn record(op: NatsOp, dir: Direction) -> NatsRecord {
    NatsRecord {
        direction: dir,
        op,
        subject: None,
        reply_to: None,
        sid: None,
        queue_group: None,
        payload_bytes: None,
        payload_preview: None,
        headers: None,
        error_message: None,
        info_json: None,
    }
}

fn single_line(op: NatsOp, dir: Direction, consumed: usize) -> NatsParserOutput {
    NatsParserOutput::Record {
        record: record(op, dir),
        consumed,
    }
}

fn parse_err(rest: &[u8], dir: Direction, consumed: usize) -> NatsParserOutput {
    // -ERR '<message>'
    let s = std::str::from_utf8(rest).unwrap_or("").trim();
    let message = s
        .strip_prefix('\'')
        .and_then(|t| t.strip_suffix('\''))
        .map_or_else(|| s.to_string(), str::to_string);
    let mut rec = record(NatsOp::Err, dir);
    rec.error_message = Some(message);
    NatsParserOutput::Record {
        record: rec,
        consumed,
    }
}

fn parse_info_like(
    op: NatsOp,
    rest: &[u8],
    dir: Direction,
    consumed: usize,
    redact: bool,
) -> NatsParserOutput {
    let json = std::str::from_utf8(rest).unwrap_or("").trim().to_string();
    let processed = if redact {
        redact_credentials(&json)
    } else {
        json
    };
    let truncated = truncate_str(&processed, MAX_INFO_JSON);
    let mut rec = record(op, dir);
    rec.info_json = Some(truncated);
    NatsParserOutput::Record {
        record: rec,
        consumed,
    }
}

fn parse_sub(rest: &[u8], dir: Direction, consumed: usize) -> NatsParserOutput {
    // SUB <subject> [queue-group] <sid>
    let tokens = tokenize(rest);
    let (subject, queue, sid) = match tokens.len() {
        2 => (tokens[0].clone(), None, tokens[1].clone()),
        3 => (
            tokens[0].clone(),
            Some(tokens[1].clone()),
            tokens[2].clone(),
        ),
        _ => return NatsParserOutput::Skip(consumed),
    };
    if subject.len() > MAX_SUBJECT {
        return NatsParserOutput::Skip(consumed);
    }
    let mut rec = record(NatsOp::Sub, dir);
    rec.subject = Some(subject);
    rec.queue_group = queue;
    rec.sid = Some(sid);
    NatsParserOutput::Record {
        record: rec,
        consumed,
    }
}

fn parse_unsub(rest: &[u8], dir: Direction, consumed: usize) -> NatsParserOutput {
    // UNSUB <sid> [max-msgs]
    let tokens = tokenize(rest);
    let sid = match tokens.len() {
        1 | 2 => tokens[0].clone(),
        _ => return NatsParserOutput::Skip(consumed),
    };
    let mut rec = record(NatsOp::Unsub, dir);
    rec.sid = Some(sid);
    NatsParserOutput::Record {
        record: rec,
        consumed,
    }
}

/// Split first whitespace-separated token off a line, returning
/// `(verb_bytes, remainder_bytes)`. Leading whitespace is skipped.
fn split_verb(line: &[u8]) -> (&[u8], &[u8]) {
    let start = line
        .iter()
        .position(|b| !is_space(*b))
        .unwrap_or(line.len());
    let tail = &line[start..];
    let end = tail.iter().position(|b| is_space(*b)).unwrap_or(tail.len());
    (&tail[..end], &tail[end..])
}

fn ascii_upper(b: &[u8]) -> String {
    let s = std::str::from_utf8(b).unwrap_or("");
    s.to_ascii_uppercase()
}

fn tokenize(rest: &[u8]) -> Vec<String> {
    std::str::from_utf8(rest)
        .unwrap_or("")
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect()
}

fn parse_u64(s: &str) -> Option<u64> {
    s.parse::<u64>().ok()
}

fn u32_saturating(n: u64) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

const fn is_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// The first non-space byte of a NATS control line must be a printable
/// ASCII character that could start a verb. This rejects binary protocols
/// (TLS records, framed binary) before we attempt to parse.
fn is_plausible_command_start(line: &[u8]) -> bool {
    let Some(&first) = line.iter().find(|b| !is_space(**b)) else {
        return false;
    };
    first.is_ascii_alphabetic() || first == b'+' || first == b'-'
}

/// Is `s` plausibly a verb-like token (ASCII letters and a few allowed
/// signs) — used to reject noise that happened to contain a CRLF early.
fn is_verb_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 16
        && s.bytes()
            .all(|b| b.is_ascii_alphabetic() || b == b'+' || b == b'-' || b == b'_')
}

fn stringify_headers(block: &[u8]) -> String {
    let keep = block.len().min(MAX_HEADER_BYTES);
    String::from_utf8_lossy(&block[..keep]).into_owned()
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    // Find a UTF-8 safe boundary at or below `max`.
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s[..cut].to_string()
}

/// Scrub any JSON string field whose key is sensitive. Operates textually
/// (no full JSON parse) so that partially-valid server output still gets
/// redacted. Falls back to returning the input unchanged when the JSON
/// can't be understood at all.
fn redact_credentials(json: &str) -> String {
    // Fast path: regex over the string. We deliberately tolerate
    // whitespace and support both `"pass":"x"` and `"pass" : "x"`. We
    // only redact string values — numbers/bools are left alone.
    let sensitive = [
        "auth_token",
        "token",
        "pass",
        "password",
        "jwt",
        "nkey",
        "sig",
    ];
    let mut out = String::with_capacity(json.len());
    let bytes = json.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Look for a JSON key opener: `"<key>"` then optional whitespace,
        // then `:`, then optional whitespace, then a string value `"..."`.
        if bytes[i] != b'"' {
            // Copy a run of non-quote bytes as a string slice (preserves
            // UTF-8; no byte-level mangling).
            let run_start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            out.push_str(&json[run_start..i]);
            continue;
        }
        // Find the end of the key (unescaped quote).
        let Some(key_end) = find_string_end(bytes, i + 1) else {
            // Unterminated string: just copy the rest.
            out.push_str(&json[i..]);
            break;
        };
        let key = &json[i + 1..key_end];
        let key_lower = key.to_ascii_lowercase();
        let is_sensitive = sensitive.iter().any(|k| key_lower.contains(*k));
        // Find the colon (if this is actually a key).
        let mut j = key_end + 1;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b':' {
            // Not a key-value pair; copy the string as-is.
            out.push_str(&json[i..=key_end]);
            i = key_end + 1;
            continue;
        }
        // Skip colon + whitespace.
        let mut k = j + 1;
        while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
            k += 1;
        }
        // We only redact when value is a string.
        if is_sensitive && k < bytes.len() && bytes[k] == b'"' {
            let Some(val_end) = find_string_end(bytes, k + 1) else {
                out.push_str(&json[i..]);
                break;
            };
            out.push_str(&json[i..=key_end]);
            out.push_str(&json[key_end + 1..k]);
            out.push_str("\"<redacted>\"");
            i = val_end + 1;
        } else {
            out.push_str(&json[i..=key_end]);
            i = key_end + 1;
        }
    }
    out
}

/// Find the end index (inclusive position of closing `"`) of a JSON
/// string starting at `start` (i.e. the byte *after* the opening quote).
/// Returns None if unterminated.
fn find_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Skip escaped byte.
                i += 2;
            }
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(buf: &[u8], dir: Direction) -> NatsParserOutput {
        let mut p = NatsParser::default();
        p.parse(buf, dir)
    }

    #[test]
    fn ping_and_pong() {
        match parse_one(b"PING\r\n", Direction::Tx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 6);
                assert!(matches!(record.op, NatsOp::Ping));
            }
            other => panic!("expected Record, got {other:?}"),
        }
        match parse_one(b"PONG\r\n", Direction::Rx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 6);
                assert!(matches!(record.op, NatsOp::Pong));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn ok_reply() {
        match parse_one(b"+OK\r\n", Direction::Rx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 5);
                assert!(matches!(record.op, NatsOp::Ok));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn err_with_quoted_message() {
        match parse_one(b"-ERR 'Unknown Protocol Operation'\r\n", Direction::Rx) {
            NatsParserOutput::Record { record, .. } => {
                assert!(matches!(record.op, NatsOp::Err));
                assert_eq!(
                    record.error_message.as_deref(),
                    Some("Unknown Protocol Operation")
                );
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn pub_basic() {
        let buf = b"PUB foo 11\r\nHello World\r\n";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert!(matches!(record.op, NatsOp::Pub));
                assert_eq!(record.subject.as_deref(), Some("foo"));
                assert_eq!(record.payload_bytes, Some(11));
                assert_eq!(record.payload_preview.as_deref(), Some(&b"Hello World"[..]));
                assert!(record.reply_to.is_none());
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn pub_with_reply_to() {
        let buf = b"PUB foo INBOX.42 5\r\nhello\r\n";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.subject.as_deref(), Some("foo"));
                assert_eq!(record.reply_to.as_deref(), Some("INBOX.42"));
                assert_eq!(record.payload_bytes, Some(5));
                assert_eq!(record.payload_preview.as_deref(), Some(&b"hello"[..]));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn msg_with_reply_to() {
        let buf = b"MSG foo.bar 9 INBOX.77 3\r\nhey\r\n";
        match parse_one(buf, Direction::Rx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert!(matches!(record.op, NatsOp::Msg));
                assert_eq!(record.subject.as_deref(), Some("foo.bar"));
                assert_eq!(record.sid.as_deref(), Some("9"));
                assert_eq!(record.reply_to.as_deref(), Some("INBOX.77"));
                assert_eq!(record.payload_bytes, Some(3));
                assert_eq!(record.payload_preview.as_deref(), Some(&b"hey"[..]));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn sub_with_queue_group() {
        let buf = b"SUB foo workers 1\r\n";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert!(matches!(record.op, NatsOp::Sub));
                assert_eq!(record.subject.as_deref(), Some("foo"));
                assert_eq!(record.queue_group.as_deref(), Some("workers"));
                assert_eq!(record.sid.as_deref(), Some("1"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn sub_without_queue_group() {
        let buf = b"SUB foo 1\r\n";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.subject.as_deref(), Some("foo"));
                assert!(record.queue_group.is_none());
                assert_eq!(record.sid.as_deref(), Some("1"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn unsub_with_max_msgs() {
        let buf = b"UNSUB 1 5\r\n";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert!(matches!(record.op, NatsOp::Unsub));
                assert_eq!(record.sid.as_deref(), Some("1"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn hpub_with_two_headers_and_body() {
        // Header block: "NATS/1.0\r\nA: 1\r\nB: 2\r\n\r\n" = 24 bytes
        let hdr = b"NATS/1.0\r\nA: 1\r\nB: 2\r\n\r\n";
        assert_eq!(hdr.len(), 24);
        let body = b"hello";
        let mut buf = Vec::new();
        buf.extend_from_slice(b"HPUB foo 24 29\r\n");
        buf.extend_from_slice(hdr);
        buf.extend_from_slice(body);
        buf.extend_from_slice(b"\r\n");
        match parse_one(&buf, Direction::Tx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert!(matches!(record.op, NatsOp::Hpub));
                assert_eq!(record.subject.as_deref(), Some("foo"));
                assert_eq!(record.payload_bytes, Some(5));
                assert_eq!(record.payload_preview.as_deref(), Some(&b"hello"[..]));
                let h = record.headers.expect("headers");
                assert!(h.contains("NATS/1.0"));
                assert!(h.contains("A: 1"));
                assert!(h.contains("B: 2"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn hmsg_with_reply_to() {
        let hdr = b"NATS/1.0\r\nX: y\r\n\r\n";
        assert_eq!(hdr.len(), 18);
        let body = b"data";
        let mut buf = Vec::new();
        buf.extend_from_slice(b"HMSG foo 1 INBOX.9 18 22\r\n");
        buf.extend_from_slice(hdr);
        buf.extend_from_slice(body);
        buf.extend_from_slice(b"\r\n");
        match parse_one(&buf, Direction::Rx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert!(matches!(record.op, NatsOp::Hmsg));
                assert_eq!(record.subject.as_deref(), Some("foo"));
                assert_eq!(record.sid.as_deref(), Some("1"));
                assert_eq!(record.reply_to.as_deref(), Some("INBOX.9"));
                assert_eq!(record.payload_bytes, Some(4));
                assert_eq!(record.payload_preview.as_deref(), Some(&b"data"[..]));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn info_json_kept() {
        let buf = b"INFO {\"server_id\":\"abc\",\"version\":\"2.10\"}\r\n";
        match parse_one(buf, Direction::Rx) {
            NatsParserOutput::Record { record, .. } => {
                assert!(matches!(record.op, NatsOp::Info));
                let j = record.info_json.expect("json");
                assert!(j.contains("server_id"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn connect_auth_token_redacted() {
        let buf = b"CONNECT {\"verbose\":false,\"auth_token\":\"s3cret-token\",\"name\":\"c\"}\r\n";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Record { record, .. } => {
                assert!(matches!(record.op, NatsOp::Connect));
                let j = record.info_json.expect("json");
                assert!(
                    j.contains("\"<redacted>\""),
                    "expected redaction marker in {j:?}"
                );
                assert!(!j.contains("s3cret-token"), "token leaked: {j:?}");
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn connect_pass_and_jwt_redacted() {
        let buf =
            b"CONNECT {\"user\":\"bob\",\"pass\":\"hunter2\",\"jwt\":\"eyJ.aaa.bbb\"}\r\n";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Record { record, .. } => {
                let j = record.info_json.expect("json");
                assert!(!j.contains("hunter2"));
                assert!(!j.contains("eyJ.aaa.bbb"));
                assert!(j.contains("\"user\":\"bob\""));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn partial_buffer_returns_need() {
        // Control line complete but payload short.
        let buf = b"PUB foo 11\r\nHello";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
    }

    #[test]
    fn partial_control_line_returns_need() {
        let buf = b"PUB foo ";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
    }

    #[test]
    fn garbage_bypasses() {
        let buf = b"\x00\x01\x02\x03\r\n";
        match parse_one(buf, Direction::Rx) {
            NatsParserOutput::Skip(n) => assert_eq!(n, buf.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn unknown_verb_that_looks_plausible_is_other() {
        let buf = b"LAMEDUCK\r\n";
        match parse_one(buf, Direction::Rx) {
            NatsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                match record.op {
                    NatsOp::Other(v) => assert_eq!(v, "LAMEDUCK"),
                    other => panic!("expected Other, got {other:?}"),
                }
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn malformed_pub_missing_bytes_bypasses() {
        let buf = b"PUB foo\r\n";
        match parse_one(buf, Direction::Tx) {
            NatsParserOutput::Skip(n) => assert_eq!(n, buf.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn pub_missing_payload_crlf_bypasses() {
        // 11 bytes declared but no trailing CRLF after body.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"PUB foo 11\r\nHello WorldX"); // garbage instead of CRLF
        buf.extend_from_slice(b"Y"); // total 14 bytes of "payload+tail"
        // Needs 11 payload + 2 CRLF = 13 bytes after header; buf has enough.
        // Feed full length to force check.
        let enough = b"PUB foo 11\r\nHello WorldXY";
        match parse_one(enough, Direction::Tx) {
            NatsParserOutput::Skip(n) => assert_eq!(n, enough.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn display_line_formats() {
        let mut r = record(NatsOp::Pub, Direction::Tx);
        r.subject = Some("foo".into());
        r.payload_bytes = Some(11);
        assert_eq!(r.display_line(), "PUB foo (11 bytes)");

        let mut r = record(NatsOp::Sub, Direction::Tx);
        r.subject = Some("foo".into());
        r.queue_group = Some("w".into());
        r.sid = Some("1".into());
        assert_eq!(r.display_line(), "SUB foo queue=w sid=1");

        let mut r = record(NatsOp::Err, Direction::Rx);
        r.error_message = Some("boom".into());
        assert_eq!(r.display_line(), "-ERR 'boom'");
    }

    #[test]
    fn case_insensitive_verbs() {
        match parse_one(b"ping\r\n", Direction::Tx) {
            NatsParserOutput::Record { record, .. } => {
                assert!(matches!(record.op, NatsOp::Ping));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn redact_preserves_other_fields() {
        let input = r#"{"user":"u","password":"p","port":4222}"#;
        let out = redact_credentials(input);
        assert!(out.contains("\"user\":\"u\""));
        assert!(out.contains("\"port\":4222"));
        assert!(out.contains("\"password\":\"<redacted>\""));
    }

    #[test]
    fn redact_numeric_password_left_alone() {
        // We only redact string-valued credentials; non-string values are
        // passed through unchanged (uncommon in practice).
        let input = r#"{"password":1234}"#;
        let out = redact_credentials(input);
        assert!(out.contains("1234"));
    }
}
