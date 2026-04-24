//! `MongoDB` wire-protocol parser.
//!
//! Focuses on the modern `OP_MSG` opcode (2013) and its primary body
//! section (kind 0), decoding just enough BSON to pull out a command
//! summary: command name, target collection, database, and a truncated
//! render of the first few fields. Legacy opcodes are recognised but not
//! decoded — they show up as records with a terse textual summary.
//!
//! Framing reference:
//!   <https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/>
//!
//! BSON reference:
//!   <https://bsonspec.org/spec.html>
//!
//! Rules implemented:
//!
//! 1. Every message starts with a 16-byte `MsgHeader` in little-endian:
//!    messageLength (incl. header), requestID, responseTo, opCode.
//! 2. For `OP_MSG` (2013), after the header comes a 4-byte flagBits
//!    word, then a stream of sections until the message length is
//!    consumed. If flagBit 0 (checksumPresent) is set, the final 4
//!    bytes are a CRC checksum and aren't part of the sections.
//!     - Section kind 0: a single BSON document (the command body).
//!     - Section kind 1: 4-byte size, null-terminated identifier, and
//!       a run of BSON documents up to the declared size.
//! 3. Legacy opcodes (1, 2001..=2007, 2010..=2012) are surfaced with a
//!    stock summary rather than fully decoded.
//! 4. On framing errors or unknown opcodes the parser switches to
//!    `Bypass` and skips the remainder of the stream — it never
//!    panics and never allocates unboundedly.

use std::fmt::Write as _;

use crate::events::Direction;

/// `MongoDB`'s documented maximum message size (48 MiB).
const MAX_MESSAGE_LEN: u32 = 48 * 1024 * 1024;
const HEADER_LEN: usize = 16;
const MAX_SUMMARY_BYTES: usize = 256;
/// Cap on the number of BSON elements we render into the summary. Even
/// without this cap the byte budget would stop us eventually; this just
/// bounds CPU on pathologically wide documents.
const MAX_SUMMARY_ELEMS: usize = 16;
/// Cap on recursion depth through nested BSON sub-documents/arrays.
const MAX_BSON_DEPTH: u8 = 8;

// Known opcodes. We recognise these for sanity-check purposes; only 2013
// gets real decoding.
const OP_REPLY: i32 = 1;
const OP_UPDATE: i32 = 2001;
const OP_INSERT: i32 = 2002;
const OP_QUERY: i32 = 2004;
const OP_GET_MORE: i32 = 2005;
const OP_DELETE: i32 = 2006;
const OP_KILL_CURSORS: i32 = 2007;
const OP_COMPRESSED: i32 = 2012;
const OP_MSG: i32 = 2013;

/// Parser state. One instance per (connection, direction).
pub struct MongoParser {
    state: State,
}

impl std::fmt::Debug for MongoParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MongoParser").finish()
    }
}

impl Default for MongoParser {
    fn default() -> Self {
        Self {
            state: State::Framing,
        }
    }
}

#[derive(PartialEq, Eq)]
enum State {
    /// Ready to read the next `MsgHeader`.
    Framing,
    /// Stream doesn't look like Mongo — drop everything.
    Bypass,
}

/// Outcome of a single `parse` call.
#[derive(Debug)]
pub enum MongoParserOutput {
    /// Not enough bytes buffered yet.
    Need,
    /// One complete record decoded.
    Record {
        record: MongoRecord,
        consumed: usize,
    },
    /// Drop `n` bytes (either junk or a legacy/compressed message we
    /// didn't fully decode beyond the header-level summary).
    Skip(usize),
}

/// A decoded `MongoDB` message.
#[derive(Debug, Clone)]
pub struct MongoRecord {
    pub request_id: i32,
    pub response_to: i32,
    /// Opcode from the wire header. `2013` for `OP_MSG`.
    pub op_code: i32,
    /// `OP_MSG` flag bits (0 for non-`OP_MSG`).
    pub flags: u32,
    /// First key of the command body document — the command verb such
    /// as `find`, `insert`, `aggregate`. `None` for legacy opcodes.
    pub command_name: Option<String>,
    /// Value of the `$db` field in the body document.
    pub database: Option<String>,
    /// Value of the command verb's string argument (e.g. `users` in
    /// `{ find: "users", ... }`). `None` when the value isn't a string.
    pub collection: Option<String>,
    /// Human-friendly one-liner (truncated to `MAX_SUMMARY_BYTES`).
    pub summary: String,
    /// Length in bytes of the kind-0 body BSON document, or 0 for
    /// non-`OP_MSG` opcodes.
    pub body_bson_len: u32,
    /// Number of sections seen (1 or more for `OP_MSG`; 0 otherwise).
    pub section_count: u8,
    /// Whether flagBit[0] (checksumPresent) was set in `OP_MSG`.
    pub checksum_present: bool,
}

impl MongoRecord {
    /// Convenience for TUI / log output.
    pub fn display_line(&self) -> String {
        self.summary.clone()
    }
}

impl MongoParser {
    /// Parse one message from the start of `buf`. The `dir` argument is
    /// ignored today — `MongoDB` requests and responses share the same
    /// wire framing, and we emit a record for both sides — but it's
    /// kept for API symmetry with other parsers.
    pub fn parse(&mut self, buf: &[u8], _dir: Direction) -> MongoParserOutput {
        if self.state == State::Bypass {
            return MongoParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER_LEN {
            return MongoParserOutput::Need;
        }

        let msg_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let request_id = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let response_to = i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let op_code = i32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);

        // Sanity: reasonable size.
        if (msg_len as usize) < HEADER_LEN || msg_len > MAX_MESSAGE_LEN {
            self.state = State::Bypass;
            return MongoParserOutput::Skip(buf.len());
        }
        // Sanity: opcode is one we know.
        if !is_known_opcode(op_code) {
            self.state = State::Bypass;
            return MongoParserOutput::Skip(buf.len());
        }

        let msg_len_usize = msg_len as usize;
        if buf.len() < msg_len_usize {
            return MongoParserOutput::Need;
        }

        let full = &buf[..msg_len_usize];

        if op_code == OP_MSG {
            if let Ok(rec) = decode_op_msg(full, request_id, response_to) {
                MongoParserOutput::Record {
                    record: rec,
                    consumed: msg_len_usize,
                }
            } else {
                self.state = State::Bypass;
                MongoParserOutput::Skip(buf.len())
            }
        } else {
            let rec = legacy_record(op_code, request_id, response_to);
            MongoParserOutput::Record {
                record: rec,
                consumed: msg_len_usize,
            }
        }
    }
}

const fn is_known_opcode(op: i32) -> bool {
    matches!(op, OP_REPLY | 2001..=2007 | 2010..=2013)
}

fn legacy_record(op_code: i32, request_id: i32, response_to: i32) -> MongoRecord {
    let summary = match op_code {
        OP_REPLY => "OP_REPLY legacy".to_string(),
        OP_UPDATE => "OP_UPDATE legacy".to_string(),
        OP_INSERT => "OP_INSERT legacy".to_string(),
        OP_QUERY => "OP_QUERY legacy".to_string(),
        OP_GET_MORE => "OP_GET_MORE legacy".to_string(),
        OP_DELETE => "OP_DELETE legacy".to_string(),
        OP_KILL_CURSORS => "OP_KILL_CURSORS legacy".to_string(),
        OP_COMPRESSED => "OP_COMPRESSED (compressed payload, not decoded)".to_string(),
        other => format!("opcode {other}"),
    };
    MongoRecord {
        request_id,
        response_to,
        op_code,
        flags: 0,
        command_name: None,
        database: None,
        collection: None,
        summary,
        body_bson_len: 0,
        section_count: 0,
        checksum_present: false,
    }
}

/// Decode a full `OP_MSG` message, including at least one kind-0 body
/// section. Returns `Err(())` on any framing inconsistency.
fn decode_op_msg(full: &[u8], request_id: i32, response_to: i32) -> Result<MongoRecord, ()> {
    // Body layout: [4 flags][sections...][optional 4-byte crc].
    if full.len() < HEADER_LEN + 4 {
        return Err(());
    }
    let flags_off = HEADER_LEN;
    let flags = u32::from_le_bytes([
        full[flags_off],
        full[flags_off + 1],
        full[flags_off + 2],
        full[flags_off + 3],
    ]);
    let checksum_present = (flags & 0x0000_0001) != 0;

    let sections_end = if checksum_present {
        full.len().checked_sub(4).ok_or(())?
    } else {
        full.len()
    };
    let sections_start = flags_off + 4;
    if sections_start > sections_end {
        return Err(());
    }
    let sections = &full[sections_start..sections_end];

    let mut cursor = 0usize;
    let mut section_count: u8 = 0;
    let mut body_summary: Option<BodySummary> = None;
    let mut body_len: u32 = 0;

    while cursor < sections.len() {
        let kind = sections[cursor];
        cursor += 1;
        match kind {
            0 => {
                // Kind 0: one BSON document.
                if cursor + 4 > sections.len() {
                    return Err(());
                }
                let doc_len = read_i32_le(&sections[cursor..])? as usize;
                if doc_len < 5 || cursor + doc_len > sections.len() {
                    return Err(());
                }
                let doc = &sections[cursor..cursor + doc_len];
                // Only keep the first kind-0 we see (spec says exactly
                // one anyway, but be defensive).
                if body_summary.is_none() {
                    body_summary = Some(summarise_body(doc)?);
                    body_len = doc_len as u32;
                }
                cursor += doc_len;
            }
            1 => {
                // Kind 1: size (4) | cstring id | documents ...
                if cursor + 4 > sections.len() {
                    return Err(());
                }
                let sec_size = read_i32_le(&sections[cursor..])? as usize;
                if sec_size < 4 || cursor + sec_size > sections.len() {
                    return Err(());
                }
                // We don't need to walk the inner documents for the
                // summary, just skip the whole section.
                cursor += sec_size;
            }
            _ => return Err(()),
        }
        section_count = section_count.saturating_add(1);
    }

    let body = body_summary.ok_or(())?;

    // Compose the final user-visible summary string.
    let mut rendered = String::with_capacity(MAX_SUMMARY_BYTES);
    if let Some(cmd) = &body.command_name {
        rendered.push_str(cmd);
    } else {
        rendered.push_str("op_msg");
    }
    rendered.push(' ');
    match (&body.database, &body.collection) {
        (Some(db), Some(coll)) => {
            rendered.push_str(db);
            rendered.push('.');
            rendered.push_str(coll);
        }
        (Some(db), None) => rendered.push_str(db),
        (None, Some(coll)) => rendered.push_str(coll),
        (None, None) => rendered.push('?'),
    }
    rendered.push(' ');
    rendered.push_str(&body.fields_render);
    truncate_summary(&mut rendered, MAX_SUMMARY_BYTES);

    Ok(MongoRecord {
        request_id,
        response_to,
        op_code: OP_MSG,
        flags,
        command_name: body.command_name,
        database: body.database,
        collection: body.collection,
        summary: rendered,
        body_bson_len: body_len,
        section_count,
        checksum_present,
    })
}

/// What the BSON summariser extracts from the body document.
struct BodySummary {
    command_name: Option<String>,
    collection: Option<String>,
    database: Option<String>,
    /// Pre-rendered `{a: 1, b: "c", ...}` snippet.
    fields_render: String,
}

fn summarise_body(doc: &[u8]) -> Result<BodySummary, ()> {
    // doc = [i32 len][elements...][\x00]
    if doc.len() < 5 {
        return Err(());
    }
    let declared = read_i32_le(doc)? as usize;
    if declared != doc.len() || doc[declared - 1] != 0 {
        return Err(());
    }
    let mut cursor = 4usize;
    let end = declared - 1;

    let mut command_name: Option<String> = None;
    let mut collection: Option<String> = None;
    let mut database: Option<String> = None;
    let mut render = String::with_capacity(MAX_SUMMARY_BYTES);
    render.push('{');
    let mut elems_rendered = 0usize;
    let mut truncated = false;
    let mut first = true;

    while cursor < end {
        let type_byte = doc[cursor];
        cursor += 1;
        let (name, after_name) = read_cstring(doc, cursor, end)?;
        cursor = after_name;
        let val_start = cursor;
        let val_span = bson_value_span(type_byte, doc, cursor, end)?;
        cursor += val_span;

        // First element = command verb.
        if command_name.is_none() {
            command_name = Some(name.clone());
            if type_byte == 0x02 {
                // String value.
                if let Some(s) = read_string_value(&doc[val_start..val_start + val_span]) {
                    collection = Some(s);
                }
            }
        }
        if name == "$db" && type_byte == 0x02 {
            if let Some(s) = read_string_value(&doc[val_start..val_start + val_span]) {
                database = Some(s);
            }
        }

        if elems_rendered < MAX_SUMMARY_ELEMS && render.len() < MAX_SUMMARY_BYTES {
            if !first {
                render.push_str(", ");
            }
            first = false;
            render.push_str(&name);
            render.push_str(": ");
            render_value(
                type_byte,
                &doc[val_start..val_start + val_span],
                &mut render,
                0,
            );
            elems_rendered += 1;
        } else {
            truncated = true;
            break;
        }
    }

    if truncated || render.len() >= MAX_SUMMARY_BYTES {
        // Force-mark truncation; the final truncation pass will clamp
        // bytes if necessary.
        render.push('…');
    } else {
        render.push('}');
    }

    Ok(BodySummary {
        command_name,
        collection,
        database,
        fields_render: render,
    })
}

fn render_value(type_byte: u8, val: &[u8], out: &mut String, depth: u8) {
    if out.len() >= MAX_SUMMARY_BYTES {
        return;
    }
    if depth >= MAX_BSON_DEPTH {
        out.push_str("<...>");
        return;
    }
    match type_byte {
        0x01 => {
            // double
            if val.len() >= 8 {
                let bits = u64::from_le_bytes([
                    val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                ]);
                let f = f64::from_bits(bits);
                // Compact rendering.
                let _ = write!(out, "{f}");
            } else {
                out.push_str("<double:bad>");
            }
        }
        0x02 => {
            if let Some(s) = read_string_value(val) {
                out.push('"');
                push_escaped(&s, out);
                out.push('"');
            } else {
                out.push_str("<string:bad>");
            }
        }
        0x03 => {
            // Embedded document.
            render_subdoc(val, out, depth + 1, false);
        }
        0x04 => {
            // Array is just an embedded document with string indices.
            render_subdoc(val, out, depth + 1, true);
        }
        0x05 => {
            // Binary: [i32 len][subtype][bytes]
            if val.len() >= 5 {
                let n = i32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                let _ = write!(out, "<binary:{n}>");
            } else {
                out.push_str("<binary>");
            }
        }
        0x06 => out.push_str("undefined"),
        0x07 => {
            // ObjectId: 12 raw bytes, render as 24-char hex.
            if val.len() >= 12 {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let mut buf = [0u8; 24];
                for (i, b) in val[..12].iter().enumerate() {
                    buf[i * 2] = HEX[(b >> 4) as usize];
                    buf[i * 2 + 1] = HEX[(b & 0x0f) as usize];
                }
                out.push_str("ObjectId(\"");
                // Bytes are ASCII hex by construction.
                out.push_str(std::str::from_utf8(&buf).unwrap_or(""));
                out.push_str("\")");
            } else {
                out.push_str("<oid:bad>");
            }
        }
        0x08 => {
            if val.first() == Some(&1) {
                out.push_str("true");
            } else {
                out.push_str("false");
            }
        }
        0x09 => {
            // UTC datetime: i64 ms since epoch. Render ISO-ish.
            if val.len() >= 8 {
                let ms = i64::from_le_bytes([
                    val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                ]);
                out.push_str(&format_iso_datetime(ms));
            } else {
                out.push_str("<datetime:bad>");
            }
        }
        0x0A => out.push_str("null"),
        0x0B => {
            // Regex: cstring pattern, cstring options.
            let mut idx = 0usize;
            let Some((pat, n1)) = read_cstring_rel(val, idx) else {
                out.push_str("<regex:bad>");
                return;
            };
            idx = n1;
            let Some((flags, _n2)) = read_cstring_rel(val, idx) else {
                out.push_str("<regex:bad>");
                return;
            };
            out.push('/');
            push_escaped(&pat, out);
            out.push('/');
            push_escaped(&flags, out);
        }
        0x0C => out.push_str("<dbpointer>"),
        0x0D => out.push_str("<code>"),
        0x0E => out.push_str("<symbol>"),
        0x0F => out.push_str("<code_w_scope>"),
        0x10 => {
            if val.len() >= 4 {
                let n = i32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                let _ = write!(out, "{n}");
            } else {
                out.push_str("<int32:bad>");
            }
        }
        0x11 => {
            // Timestamp: u32 increment | u32 seconds.
            if val.len() >= 8 {
                let inc = u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                let sec = u32::from_le_bytes([val[4], val[5], val[6], val[7]]);
                let _ = write!(out, "Timestamp({sec}, {inc})");
            } else {
                out.push_str("<ts:bad>");
            }
        }
        0x12 => {
            if val.len() >= 8 {
                let n = i64::from_le_bytes([
                    val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                ]);
                let _ = write!(out, "{n}");
            } else {
                out.push_str("<int64:bad>");
            }
        }
        0x13 => out.push_str("<decimal128:16>"),
        0xFF => out.push_str("<minkey>"),
        0x7F => out.push_str("<maxkey>"),
        other => {
            let _ = write!(out, "<type:{other:#x}>");
        }
    }
}

/// Render an embedded document or array into `out`. Arrays use `[` `]`,
/// objects use `{` `}`. Keys are elided for arrays (they're just
/// positional indices).
fn render_subdoc(doc: &[u8], out: &mut String, depth: u8, is_array: bool) {
    if doc.len() < 5 {
        out.push_str(if is_array { "[]" } else { "{}" });
        return;
    }
    let Ok(declared) = read_i32_le(doc) else {
        out.push_str(if is_array { "[...]" } else { "{...}" });
        return;
    };
    let declared = declared as usize;
    if declared != doc.len() || doc[declared - 1] != 0 {
        out.push_str(if is_array { "[...]" } else { "{...}" });
        return;
    }
    out.push(if is_array { '[' } else { '{' });
    let mut cursor = 4usize;
    let end = declared - 1;
    let mut first = true;
    let mut elems = 0usize;
    while cursor < end && out.len() < MAX_SUMMARY_BYTES {
        if elems >= MAX_SUMMARY_ELEMS {
            out.push_str(", ...");
            break;
        }
        let type_byte = doc[cursor];
        cursor += 1;
        let Ok((name, after_name)) = read_cstring(doc, cursor, end) else {
            out.push_str("...");
            break;
        };
        cursor = after_name;
        let Ok(span) = bson_value_span(type_byte, doc, cursor, end) else {
            out.push_str("...");
            break;
        };
        if !first {
            out.push_str(", ");
        }
        first = false;
        if !is_array {
            out.push_str(&name);
            out.push_str(": ");
        }
        render_value(type_byte, &doc[cursor..cursor + span], out, depth);
        cursor += span;
        elems += 1;
    }
    out.push(if is_array { ']' } else { '}' });
}

fn read_i32_le(buf: &[u8]) -> Result<i32, ()> {
    if buf.len() < 4 {
        return Err(());
    }
    Ok(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

fn read_cstring(doc: &[u8], start: usize, end: usize) -> Result<(String, usize), ()> {
    let mut i = start;
    while i < end && doc[i] != 0 {
        i += 1;
    }
    if i >= end {
        return Err(());
    }
    let s = String::from_utf8_lossy(&doc[start..i]).into_owned();
    Ok((s, i + 1))
}

fn read_cstring_rel(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut i = start;
    while i < buf.len() && buf[i] != 0 {
        i += 1;
    }
    if i >= buf.len() {
        return None;
    }
    Some((String::from_utf8_lossy(&buf[start..i]).into_owned(), i + 1))
}

/// Return the number of bytes occupied by the value of `type_byte`
/// starting at `start` inside `doc` (which ends at `end`, exclusive of
/// the document terminator).
fn bson_value_span(type_byte: u8, doc: &[u8], start: usize, end: usize) -> Result<usize, ()> {
    let avail = end.checked_sub(start).ok_or(())?;
    let span = match type_byte {
        // double | datetime | int64 | timestamp
        0x01 | 0x09 | 0x11 | 0x12 => 8,
        // string | code | symbol: i32 len (incl \0) + bytes
        0x02 | 0x0D | 0x0E => {
            if avail < 4 {
                return Err(());
            }
            let n =
                i32::from_le_bytes([doc[start], doc[start + 1], doc[start + 2], doc[start + 3]]);
            if n < 1 {
                return Err(());
            }
            4 + n as usize
        }
        // embedded document / array: declared size includes the 4-byte prefix
        0x03 | 0x04 => {
            if avail < 4 {
                return Err(());
            }
            let n =
                i32::from_le_bytes([doc[start], doc[start + 1], doc[start + 2], doc[start + 3]]);
            if n < 5 {
                return Err(());
            }
            n as usize
        }
        // binary: i32 len + subtype + bytes
        0x05 => {
            if avail < 5 {
                return Err(());
            }
            let n =
                i32::from_le_bytes([doc[start], doc[start + 1], doc[start + 2], doc[start + 3]]);
            if n < 0 {
                return Err(());
            }
            5 + n as usize
        }
        // undefined | null | minkey | maxkey — value is zero-length
        0x06 | 0x0A | 0xFF | 0x7F => 0,
        // ObjectId
        0x07 => 12,
        // bool
        0x08 => 1,
        // regex: two cstrings
        0x0B => {
            let (_, n1) = read_cstring(doc, start, end)?;
            let (_, n2) = read_cstring(doc, n1, end)?;
            n2 - start
        }
        // dbpointer: string + 12-byte ObjectId
        0x0C => {
            if avail < 4 {
                return Err(());
            }
            let n =
                i32::from_le_bytes([doc[start], doc[start + 1], doc[start + 2], doc[start + 3]]);
            if n < 1 {
                return Err(());
            }
            4 + n as usize + 12
        }
        // code with scope: total i32 length
        0x0F => {
            if avail < 4 {
                return Err(());
            }
            let n =
                i32::from_le_bytes([doc[start], doc[start + 1], doc[start + 2], doc[start + 3]]);
            if n < 8 {
                return Err(());
            }
            n as usize
        }
        // int32
        0x10 => 4,
        // decimal128
        0x13 => 16,
        _ => return Err(()),
    };
    if span > avail {
        return Err(());
    }
    Ok(span)
}

/// Read a BSON string value (type 0x02) from its raw bytes.
fn read_string_value(val: &[u8]) -> Option<String> {
    if val.len() < 4 {
        return None;
    }
    let n = i32::from_le_bytes([val[0], val[1], val[2], val[3]]);
    if n < 1 {
        return None;
    }
    let end = 4 + n as usize;
    if end > val.len() {
        return None;
    }
    // Trailing byte must be \0.
    if val[end - 1] != 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&val[4..end - 1]).into_owned())
}

fn push_escaped(s: &str, out: &mut String) {
    for ch in s.chars() {
        if out.len() >= MAX_SUMMARY_BYTES {
            return;
        }
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Clamp `s` to `max` bytes, respecting UTF-8 boundaries, and append
/// `…` when we actually cut something off. Because `…` itself is 3
/// bytes, we reserve room for it.
fn truncate_summary(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    // Find the largest UTF-8 boundary <= max - 3 (for the ellipsis).
    let budget = max.saturating_sub(3);
    let mut cut = budget;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push('…');
}

/// Best-effort ISO-8601 UTC rendering of milliseconds-since-epoch.
/// Avoids pulling in `chrono`; good enough for log output.
#[allow(clippy::many_single_char_names)]
fn format_iso_datetime(ms: i64) -> String {
    // Split into seconds and millis, treating negatives defensively.
    let (secs, millis) = if ms >= 0 {
        (ms / 1000, (ms % 1000) as u32)
    } else {
        let s = ms.div_euclid(1000);
        let m = ms.rem_euclid(1000) as u32;
        (s, m)
    };
    let (y, mo, d, h, mi, se) = civil_from_days_and_secs(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{se:02}.{millis:03}Z")
}

/// Convert a Unix-epoch second count into a (year, month, day, hour,
/// minute, second) tuple using Howard Hinnant's date algorithms. Works
/// for any int64 input without overflow.
const fn civil_from_days_and_secs(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let day_secs: i64 = 86_400;
    let days = secs.div_euclid(day_secs);
    let time = secs.rem_euclid(day_secs) as u32;
    let h = time / 3600;
    let mi = (time % 3600) / 60;
    let se = time % 60;
    let (y, mo, d) = civil_from_days(days);
    (y, mo, d, h, mi, se)
}

#[allow(clippy::many_single_char_names, clippy::cast_possible_wrap)]
const fn civil_from_days(z: i64) -> (i32, u32, u32) {
    // From H. Hinnant: "days_from_civil" inverse.
    let z = z + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    // yoe <= 399, so the narrowing to i64 can't wrap.
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_wrap,
    clippy::unreadable_literal,
    clippy::explicit_iter_loop,
    clippy::unnecessary_cast,
    clippy::doc_markdown
)]
mod tests {
    use super::*;

    // ------- BSON builder helpers (test only) -------

    fn enc_cstring(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }

    fn enc_string(out: &mut Vec<u8>, s: &str) {
        let len = (s.len() + 1) as i32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }

    /// Build a BSON document from (name, type_byte, value_bytes) items.
    fn bson_doc(elems: &[(&str, u8, Vec<u8>)]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        for (name, ty, val) in elems {
            body.push(*ty);
            enc_cstring(&mut body, name);
            body.extend_from_slice(val);
        }
        body.push(0);
        let total = (body.len() + 4) as i32;
        let mut out = Vec::with_capacity(total as usize);
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn str_val(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        enc_string(&mut v, s);
        v
    }

    fn subdoc_val(inner: Vec<u8>) -> Vec<u8> {
        inner
    }

    /// Wrap an OP_MSG around a kind-0 body document.
    fn op_msg_from_body(body: &[u8], request_id: i32, response_to: i32) -> Vec<u8> {
        let flags: u32 = 0;
        let sections_len = 1 + body.len(); // kind byte + body
        let total = HEADER_LEN + 4 + sections_len;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&request_id.to_le_bytes());
        out.extend_from_slice(&response_to.to_le_bytes());
        out.extend_from_slice(&(OP_MSG as i32).to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.push(0); // kind 0
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn parses_find_command() {
        let filter = bson_doc(&[]);
        let body = bson_doc(&[
            ("find", 0x02, str_val("users")),
            ("filter", 0x03, subdoc_val(filter)),
            ("$db", 0x02, str_val("test")),
        ]);
        let msg = op_msg_from_body(&body, 42, 0);

        let mut p = MongoParser::default();
        match p.parse(&msg, Direction::Tx) {
            MongoParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, msg.len());
                assert_eq!(record.op_code, OP_MSG);
                assert_eq!(record.request_id, 42);
                assert_eq!(record.command_name.as_deref(), Some("find"));
                assert_eq!(record.collection.as_deref(), Some("users"));
                assert_eq!(record.database.as_deref(), Some("test"));
                assert_eq!(record.section_count, 1);
                assert!(!record.checksum_present);
                assert!(record.summary.contains("find"));
                assert!(record.summary.contains("test.users"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn op_compressed_surfaces_without_decode() {
        // OP_COMPRESSED (2012): wrap an arbitrary body blob. We don't
        // decompress, just surface it as a compressed record.
        let body = b"\xde\xad\xbe\xef";
        let total = HEADER_LEN + body.len();
        let mut msg = Vec::with_capacity(total);
        msg.extend_from_slice(&(total as u32).to_le_bytes());
        msg.extend_from_slice(&7i32.to_le_bytes()); // requestID
        msg.extend_from_slice(&0i32.to_le_bytes()); // responseTo
        msg.extend_from_slice(&2012i32.to_le_bytes()); // opCode
        msg.extend_from_slice(body);

        let mut p = MongoParser::default();
        match p.parse(&msg, Direction::Tx) {
            MongoParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, msg.len());
                assert_eq!(record.op_code, 2012);
                assert!(record.command_name.is_none());
                assert!(record.summary.to_lowercase().contains("compressed"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn message_exceeds_buffer_is_need() {
        // Valid header claiming 256 bytes but we only deliver 32.
        let mut msg = Vec::new();
        msg.extend_from_slice(&256u32.to_le_bytes());
        msg.extend_from_slice(&1i32.to_le_bytes());
        msg.extend_from_slice(&0i32.to_le_bytes());
        msg.extend_from_slice(&2013i32.to_le_bytes());
        msg.resize(32, 0);

        let mut p = MongoParser::default();
        match p.parse(&msg, Direction::Tx) {
            MongoParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
    }

    #[test]
    fn message_length_too_small_skips() {
        let mut msg = Vec::new();
        msg.extend_from_slice(&4u32.to_le_bytes()); // less than 16
        msg.extend_from_slice(&0i32.to_le_bytes());
        msg.extend_from_slice(&0i32.to_le_bytes());
        msg.extend_from_slice(&2013i32.to_le_bytes());

        let mut p = MongoParser::default();
        match p.parse(&msg, Direction::Tx) {
            MongoParserOutput::Skip(n) => assert_eq!(n, msg.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn unknown_opcode_bypasses() {
        let mut msg = Vec::new();
        msg.extend_from_slice(&16u32.to_le_bytes());
        msg.extend_from_slice(&0i32.to_le_bytes());
        msg.extend_from_slice(&0i32.to_le_bytes());
        msg.extend_from_slice(&9999i32.to_le_bytes());
        let mut p = MongoParser::default();
        match p.parse(&msg, Direction::Tx) {
            MongoParserOutput::Skip(_) => {}
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn legacy_op_query_is_shallow_record() {
        // OP_QUERY (2004): just claim a 20-byte message with four body
        // bytes. We don't decode the body, we just emit a record.
        let total: u32 = 20;
        let mut msg = Vec::new();
        msg.extend_from_slice(&total.to_le_bytes());
        msg.extend_from_slice(&5i32.to_le_bytes());
        msg.extend_from_slice(&0i32.to_le_bytes());
        msg.extend_from_slice(&2004i32.to_le_bytes());
        msg.extend_from_slice(&[0u8; 4]);

        let mut p = MongoParser::default();
        match p.parse(&msg, Direction::Tx) {
            MongoParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, msg.len());
                assert_eq!(record.op_code, 2004);
                assert!(record.command_name.is_none());
                assert!(record.summary.contains("OP_QUERY"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn huge_document_summary_is_truncated_with_ellipsis() {
        // Build a document with many string fields so we blow past 256
        // bytes and should get a trailing ellipsis.
        let mut elems: Vec<(&str, u8, Vec<u8>)> = Vec::new();
        elems.push(("find", 0x02, str_val("coll")));
        // Static-ish field names to appease the &str borrow rule.
        let names = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
            "juliet", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo",
            "sierra", "tango",
        ];
        for n in names.iter() {
            elems.push((n, 0x02, str_val(&"xxxxxxxxxxxxxxxxxxxx".repeat(2))));
        }
        elems.push(("$db", 0x02, str_val("db")));
        let body = bson_doc(&elems);
        let msg = op_msg_from_body(&body, 1, 0);

        let mut p = MongoParser::default();
        match p.parse(&msg, Direction::Tx) {
            MongoParserOutput::Record { record, .. } => {
                assert!(record.summary.len() <= MAX_SUMMARY_BYTES);
                assert!(
                    record.summary.ends_with('…'),
                    "expected ellipsis, got: {}",
                    record.summary
                );
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn renders_common_bson_types() {
        // Build a document exercising int32, int64, double, bool, null,
        // ObjectId, datetime, array, sub-document, regex.
        let oid: [u8; 12] = [
            0x50, 0x7f, 0x1f, 0x77, 0xbc, 0xf8, 0x6c, 0xd7, 0x99, 0x43, 0x90, 0x11,
        ];
        let array_doc = bson_doc(&[
            ("0", 0x10, 1i32.to_le_bytes().to_vec()),
            ("1", 0x10, 2i32.to_le_bytes().to_vec()),
        ]);
        let sub = bson_doc(&[("x", 0x10, 3i32.to_le_bytes().to_vec())]);
        let mut regex = Vec::new();
        enc_cstring(&mut regex, "^abc");
        enc_cstring(&mut regex, "i");
        let body = bson_doc(&[
            ("cmd", 0x02, str_val("hello")),
            ("n", 0x10, 7i32.to_le_bytes().to_vec()),
            ("big", 0x12, 12345678901234i64.to_le_bytes().to_vec()),
            ("f", 0x01, 2.5f64.to_bits().to_le_bytes().to_vec()),
            ("ok", 0x08, vec![1]),
            ("z", 0x0A, vec![]),
            ("id", 0x07, oid.to_vec()),
            ("t", 0x09, 0i64.to_le_bytes().to_vec()),
            ("arr", 0x04, array_doc),
            ("sub", 0x03, sub),
            ("rx", 0x0B, regex),
            ("$db", 0x02, str_val("d")),
        ]);
        let msg = op_msg_from_body(&body, 1, 0);

        let mut p = MongoParser::default();
        let rec = match p.parse(&msg, Direction::Tx) {
            MongoParserOutput::Record { record, .. } => record,
            other => panic!("expected Record, got {other:?}"),
        };
        let s = &rec.summary;
        assert!(s.contains("cmd"));
        assert!(s.contains("ObjectId("));
        assert!(s.contains("1970-01-01T00:00:00.000Z"));
    }

    #[test]
    fn display_line_mirrors_summary() {
        let body = bson_doc(&[
            ("ping", 0x10, 1i32.to_le_bytes().to_vec()),
            ("$db", 0x02, str_val("admin")),
        ]);
        let msg = op_msg_from_body(&body, 1, 0);
        let mut p = MongoParser::default();
        let MongoParserOutput::Record { record, .. } = p.parse(&msg, Direction::Tx) else {
            panic!("expected Record");
        };
        assert_eq!(record.display_line(), record.summary);
    }
}
