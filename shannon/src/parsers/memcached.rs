//! Memcached text + binary protocol parser.
//!
//! Covers both wire formats the `memcached` server speaks:
//!
//! 1. The classic **text (ASCII) protocol** — CRLF-delimited command
//!    lines, optionally followed by a `<bytes>`-sized data block + CRLF
//!    for storage commands (`set` / `add` / `replace` / `append` /
//!    `prepend` / `cas`). Server replies are of the form
//!    `VALUE <key> <flags> <bytes>[ <cas>]\r\n<data>\r\nEND\r\n`, along
//!    with the short status words `STORED`, `NOT_STORED`, `EXISTS`,
//!    `NOT_FOUND`, `DELETED`, `TOUCHED`, `OK`, `ERROR`, `CLIENT_ERROR`,
//!    `SERVER_ERROR`, `STAT`, `VERSION`.
//!
//! 2. The **binary protocol** (memcapable spec) — 24-byte fixed header
//!    framing a `(key, extras, value)` triple. Magic byte is `0x80` for
//!    requests and `0x81` for responses; anything else means the stream
//!    isn't memcached at all and we bail.
//!
//! Variant detection is sticky per parser instance: the first byte of
//! the first call picks text vs. binary and we don't re-sniff after
//! that. This matches how real memcached clients behave — they don't
//! mix protocols on one connection.
//!
//! Secrets handling: binary opcodes `0x21` (`SaslAuth`) and `0x22`
//! (`SaslStep`) carry credentials in their key/value body; we emit a
//! record with the opcode labelled `McOp::Auth` and strip the key /
//! value entirely.
//!
//! Bounds: keys are capped at the memcached hard limit of 250 bytes;
//! any advertised value is summarised to at most 256 bytes in
//! `raw_summary`; text lines above 4 KiB abort the parse; bodies
//! totalling more than 20 MiB are skipped rather than buffered.

use crate::events::Direction;

/// Memcached's documented maximum key length.
const MAX_KEY_BYTES: usize = 250;
/// How many bytes of a value body we repeat into `raw_summary`.
const MAX_VALUE_SUMMARY: usize = 256;
/// Hard cap on a single text command line (plenty for the largest
/// `stats detail dumpkey` invocation anyone has ever written).
const MAX_TEXT_LINE: usize = 4096;
/// Sanity cap on binary `total_body_len`. Real memcached defaults to
/// 1 MiB; we allow 20 MiB so bumped-up configurations still parse.
const MAX_BODY_BYTES: u32 = 20 * 1024 * 1024;
/// Fixed size of the binary protocol header.
const BIN_HEADER: usize = 24;

/// Parser state machine. One instance per (connection, direction).
///
/// The parser remembers which variant it saw on the first byte so
/// later calls don't have to re-sniff; a connection that opens with
/// binary magic stays binary for its lifetime.
#[derive(Debug, Default)]
pub struct MemcachedParser {
    variant: Option<McVariant>,
    /// Text-protocol body framing: after a storage header line we
    /// need `remaining_body` bytes + a trailing CRLF before the next
    /// command can be read.
    pending_body: Option<PendingBody>,
    /// Sticky bypass flag: once we decide this stream isn't memcached
    /// we keep skipping whatever arrives.
    bypass: bool,
}

#[derive(Debug)]
struct PendingBody {
    op: McOp,
    key: Option<String>,
    value_size: u32,
    flags: Option<u32>,
    exptime: Option<u32>,
    cas: Option<u64>,
}

/// Output of one `parse` step.
#[derive(Debug)]
pub enum McParserOutput {
    /// Not enough bytes buffered yet; caller should wait for more.
    Need,
    /// One complete record is available; `consumed` bytes should be
    /// dropped from the front of the caller's buffer.
    Record { record: McRecord, consumed: usize },
    /// The parser couldn't make sense of `n` bytes; drop them and try
    /// to resync.
    Skip(usize),
}

/// A single decoded memcached request or reply.
#[derive(Debug, Clone)]
pub struct McRecord {
    pub variant: McVariant,
    pub direction: Direction,
    pub op: McOp,
    pub key: Option<String>,
    /// Number of value bytes the wire format advertised. For storage
    /// ops on the request side and `VALUE` lines on the response side.
    pub value_size: Option<u32>,
    pub flags: Option<u32>,
    pub exptime: Option<u32>,
    /// CAS identifier, from a text `cas` line or the binary header.
    pub cas: Option<u64>,
    /// Binary-only: status code on a reply (magic `0x81`).
    pub status: Option<u16>,
    /// Binary-only: length of the `extras` section.
    pub extras_len: Option<u8>,
    /// Binary-only: opaque cookie echoed by the server.
    pub opaque: Option<u32>,
    /// Compact human-readable summary suitable for a log line.
    pub raw_summary: String,
}

/// Which wire format the record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McVariant {
    Text,
    Binary,
}

/// Logical memcached operation. `Other`/`TextOther` carry the raw
/// opcode / name for commands we don't specially recognise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McOp {
    // Common cross-variant.
    Get,
    Gets,
    Set,
    Add,
    Replace,
    Append,
    Prepend,
    Cas,
    Delete,
    Incr,
    Decr,
    Flush,
    Stats,
    Quit,
    Version,
    Touch,
    GetAndTouch,
    Noop,
    // Binary extras.
    Auth,
    SaslList,
    Other(u8),
    TextOther(String),
    /// Generic server reply — `STORED`, `NOT_STORED`, `EXISTS`, `END`,
    /// `VALUE …`, `STAT …`, `ERROR`, …
    Response,
}

impl McRecord {
    /// Pretty one-liner for logs / TUI.
    pub fn display_line(&self) -> String {
        self.raw_summary.clone()
    }
}

impl MemcachedParser {
    /// Feed more bytes. Consumes at most one record per call; caller
    /// loops until `Need` is returned.
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> McParserOutput {
        if self.bypass {
            return McParserOutput::Skip(buf.len());
        }
        if buf.is_empty() {
            return McParserOutput::Need;
        }
        // Pick a variant on the first-ever byte and stick with it.
        if self.variant.is_none() {
            let first = buf[0];
            if first == 0x80 || first == 0x81 {
                self.variant = Some(McVariant::Binary);
            } else if looks_like_text_start(buf) {
                self.variant = Some(McVariant::Text);
            } else {
                self.bypass = true;
                return McParserOutput::Skip(buf.len());
            }
        }
        match self.variant {
            Some(McVariant::Binary) => self.parse_binary(buf, dir),
            Some(McVariant::Text) => self.parse_text(buf, dir),
            None => McParserOutput::Need,
        }
    }

    // -----------------------------------------------------------------
    // Text protocol
    // -----------------------------------------------------------------

    fn parse_text(&mut self, buf: &[u8], dir: Direction) -> McParserOutput {
        // If a storage body is outstanding, finish it first.
        if self.pending_body.is_some() {
            return self.finish_text_body(buf, dir);
        }
        // Otherwise read one CRLF-terminated line.
        let Some(line_end) = find_crlf(buf, MAX_TEXT_LINE) else {
            if buf.len() > MAX_TEXT_LINE {
                self.bypass = true;
                return McParserOutput::Skip(buf.len());
            }
            return McParserOutput::Need;
        };
        let line = &buf[..line_end];
        let consumed = line_end + 2;
        let Ok(line_str) = std::str::from_utf8(line) else {
            self.bypass = true;
            return McParserOutput::Skip(buf.len());
        };
        let trimmed = line_str.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return McParserOutput::Skip(consumed);
        }
        // Responses get their own branch; requests, their own.
        if is_text_response_line(trimmed) {
            self.parse_text_response(trimmed, dir, consumed, buf)
        } else {
            self.parse_text_request(trimmed, dir, consumed, buf)
        }
    }

    fn parse_text_request(
        &mut self,
        line: &str,
        dir: Direction,
        consumed: usize,
        buf: &[u8],
    ) -> McParserOutput {
        let mut it = line.split_whitespace();
        let Some(cmd) = it.next() else {
            return McParserOutput::Skip(consumed);
        };
        if cmd.len() > 16 || !cmd.chars().all(|c| c.is_ascii_alphabetic()) {
            self.bypass = true;
            return McParserOutput::Skip(buf.len());
        }
        let lower = cmd.to_ascii_lowercase();
        match lower.as_str() {
            "set" | "add" | "replace" | "append" | "prepend" => {
                self.parse_text_storage(&lower, &mut it, dir, consumed, buf, false)
            }
            "cas" => self.parse_text_storage(&lower, &mut it, dir, consumed, buf, true),
            "get" | "gets" => {
                let keys: Vec<&str> = it.collect();
                let op = if lower == "get" {
                    McOp::Get
                } else {
                    McOp::Gets
                };
                let key = keys.first().map(truncate_key);
                let summary = format!(
                    "{} {} ({} key{})",
                    lower,
                    key.as_deref().unwrap_or("<none>"),
                    keys.len(),
                    if keys.len() == 1 { "" } else { "s" },
                );
                let rec = McRecord {
                    variant: McVariant::Text,
                    direction: dir,
                    op,
                    key,
                    value_size: None,
                    flags: None,
                    exptime: None,
                    cas: None,
                    status: None,
                    extras_len: None,
                    opaque: None,
                    raw_summary: summary,
                };
                McParserOutput::Record {
                    record: rec,
                    consumed,
                }
            }
            "delete" => {
                let key = it.next().map(truncate_key);
                let summary = format!("delete {}", key.as_deref().unwrap_or("<missing>"));
                McParserOutput::Record {
                    record: McRecord {
                        variant: McVariant::Text,
                        direction: dir,
                        op: McOp::Delete,
                        key,
                        value_size: None,
                        flags: None,
                        exptime: None,
                        cas: None,
                        status: None,
                        extras_len: None,
                        opaque: None,
                        raw_summary: summary,
                    },
                    consumed,
                }
            }
            "incr" | "decr" => {
                let key = it.next().map(truncate_key);
                let delta = it.next().unwrap_or("");
                let op = if lower == "incr" {
                    McOp::Incr
                } else {
                    McOp::Decr
                };
                let summary = format!(
                    "{} {} {}",
                    lower,
                    key.as_deref().unwrap_or("<missing>"),
                    delta
                );
                McParserOutput::Record {
                    record: McRecord {
                        variant: McVariant::Text,
                        direction: dir,
                        op,
                        key,
                        value_size: None,
                        flags: None,
                        exptime: None,
                        cas: None,
                        status: None,
                        extras_len: None,
                        opaque: None,
                        raw_summary: summary,
                    },
                    consumed,
                }
            }
            "touch" => {
                let key = it.next().map(truncate_key);
                let exp = it.next().and_then(|s| s.parse::<u32>().ok());
                let summary = format!(
                    "touch {} exp={}",
                    key.as_deref().unwrap_or("<missing>"),
                    exp.unwrap_or(0),
                );
                McParserOutput::Record {
                    record: McRecord {
                        variant: McVariant::Text,
                        direction: dir,
                        op: McOp::Touch,
                        key,
                        value_size: None,
                        flags: None,
                        exptime: exp,
                        cas: None,
                        status: None,
                        extras_len: None,
                        opaque: None,
                        raw_summary: summary,
                    },
                    consumed,
                }
            }
            "gat" | "gats" => {
                let exp = it.next().and_then(|s| s.parse::<u32>().ok());
                let key = it.next().map(truncate_key);
                let summary = format!(
                    "{} {} exp={}",
                    lower,
                    key.as_deref().unwrap_or("<missing>"),
                    exp.unwrap_or(0),
                );
                McParserOutput::Record {
                    record: McRecord {
                        variant: McVariant::Text,
                        direction: dir,
                        op: McOp::GetAndTouch,
                        key,
                        value_size: None,
                        flags: None,
                        exptime: exp,
                        cas: None,
                        status: None,
                        extras_len: None,
                        opaque: None,
                        raw_summary: summary,
                    },
                    consumed,
                }
            }
            "flush_all" => {
                let delay = it.next().and_then(|s| s.parse::<u32>().ok());
                let summary = format!("flush_all delay={}", delay.unwrap_or(0));
                McParserOutput::Record {
                    record: McRecord {
                        variant: McVariant::Text,
                        direction: dir,
                        op: McOp::Flush,
                        key: None,
                        value_size: None,
                        flags: None,
                        exptime: delay,
                        cas: None,
                        status: None,
                        extras_len: None,
                        opaque: None,
                        raw_summary: summary,
                    },
                    consumed,
                }
            }
            "stats" => {
                let sub = it.collect::<Vec<_>>().join(" ");
                let summary = if sub.is_empty() {
                    "stats".to_string()
                } else {
                    format!("stats {sub}")
                };
                McParserOutput::Record {
                    record: McRecord {
                        variant: McVariant::Text,
                        direction: dir,
                        op: McOp::Stats,
                        key: None,
                        value_size: None,
                        flags: None,
                        exptime: None,
                        cas: None,
                        status: None,
                        extras_len: None,
                        opaque: None,
                        raw_summary: summary,
                    },
                    consumed,
                }
            }
            "quit" => McParserOutput::Record {
                record: McRecord {
                    variant: McVariant::Text,
                    direction: dir,
                    op: McOp::Quit,
                    key: None,
                    value_size: None,
                    flags: None,
                    exptime: None,
                    cas: None,
                    status: None,
                    extras_len: None,
                    opaque: None,
                    raw_summary: "quit".into(),
                },
                consumed,
            },
            "version" => McParserOutput::Record {
                record: McRecord {
                    variant: McVariant::Text,
                    direction: dir,
                    op: McOp::Version,
                    key: None,
                    value_size: None,
                    flags: None,
                    exptime: None,
                    cas: None,
                    status: None,
                    extras_len: None,
                    opaque: None,
                    raw_summary: "version".into(),
                },
                consumed,
            },
            _ => {
                let summary = format!("text-cmd {lower}");
                McParserOutput::Record {
                    record: McRecord {
                        variant: McVariant::Text,
                        direction: dir,
                        op: McOp::TextOther(lower),
                        key: None,
                        value_size: None,
                        flags: None,
                        exptime: None,
                        cas: None,
                        status: None,
                        extras_len: None,
                        opaque: None,
                        raw_summary: summary,
                    },
                    consumed,
                }
            }
        }
    }

    fn parse_text_storage<'a>(
        &mut self,
        cmd_lower: &str,
        it: &mut impl Iterator<Item = &'a str>,
        dir: Direction,
        header_consumed: usize,
        buf: &[u8],
        is_cas: bool,
    ) -> McParserOutput {
        let key = it.next().map(truncate_key);
        let flags = it.next().and_then(|s| s.parse::<u32>().ok());
        let exptime = it.next().and_then(|s| s.parse::<u32>().ok());
        let bytes = it.next().and_then(|s| s.parse::<u32>().ok());
        let cas_tok = if is_cas {
            it.next().and_then(|s| s.parse::<u64>().ok())
        } else {
            None
        };
        let Some(vb) = bytes else {
            // Can't proceed without a length; treat as unknown.
            return McParserOutput::Skip(header_consumed);
        };
        if vb > MAX_BODY_BYTES {
            self.bypass = true;
            return McParserOutput::Skip(buf.len());
        }
        let op = match cmd_lower {
            "set" => McOp::Set,
            "add" => McOp::Add,
            "replace" => McOp::Replace,
            "append" => McOp::Append,
            "prepend" => McOp::Prepend,
            "cas" => McOp::Cas,
            _ => McOp::TextOther(cmd_lower.into()),
        };
        // Check we already have the body + trailing CRLF in `buf`.
        let needed = header_consumed + vb as usize + 2;
        if buf.len() < needed {
            // Stash the state so the caller can reinvoke us after more
            // bytes arrive. We did NOT consume the header — return Need
            // so the reconstructor keeps the whole header+partial body.
            self.pending_body = Some(PendingBody {
                op,
                key,
                value_size: vb,
                flags,
                exptime,
                cas: cas_tok,
            });
            // Roll back: pending_body replays the header once body is
            // fully in.
            return McParserOutput::Need;
        }
        let body = &buf[header_consumed..header_consumed + vb as usize];
        // Confirm the trailing CRLF — if missing the framing is
        // corrupted.
        let tail = &buf[header_consumed + vb as usize..needed];
        if tail != b"\r\n" {
            self.bypass = true;
            return McParserOutput::Skip(buf.len());
        }
        let summary = format!(
            "{} {} flags={} exp={} bytes={}{}{}",
            cmd_lower,
            key.as_deref().unwrap_or("<missing>"),
            flags.unwrap_or(0),
            exptime.unwrap_or(0),
            vb,
            cas_tok.map(|c| format!(" cas={c}")).unwrap_or_default(),
            value_preview(body),
        );
        McParserOutput::Record {
            record: McRecord {
                variant: McVariant::Text,
                direction: dir,
                op,
                key,
                value_size: Some(vb),
                flags,
                exptime,
                cas: cas_tok,
                status: None,
                extras_len: None,
                opaque: None,
                raw_summary: summary,
            },
            consumed: needed,
        }
    }

    /// Second-stage body reader: we already stashed a `PendingBody`
    /// and are waiting for the value bytes + CRLF to show up.
    fn finish_text_body(&mut self, buf: &[u8], dir: Direction) -> McParserOutput {
        // We need to find the original header end first: it's the
        // first CRLF in `buf`.
        let Some(line_end) = find_crlf(buf, MAX_TEXT_LINE) else {
            return McParserOutput::Need;
        };
        let header_consumed = line_end + 2;
        let pending = self.pending_body.as_ref().expect("pending_body set");
        let needed = header_consumed + pending.value_size as usize + 2;
        if buf.len() < needed {
            return McParserOutput::Need;
        }
        let body = &buf[header_consumed..header_consumed + pending.value_size as usize];
        let tail = &buf[header_consumed + pending.value_size as usize..needed];
        if tail != b"\r\n" {
            self.bypass = true;
            self.pending_body = None;
            return McParserOutput::Skip(buf.len());
        }
        let p = self.pending_body.take().expect("pending_body");
        let summary = format!(
            "{:?} {} bytes={}{}",
            p.op,
            p.key.as_deref().unwrap_or("<missing>"),
            p.value_size,
            value_preview(body),
        );
        McParserOutput::Record {
            record: McRecord {
                variant: McVariant::Text,
                direction: dir,
                op: p.op,
                key: p.key,
                value_size: Some(p.value_size),
                flags: p.flags,
                exptime: p.exptime,
                cas: p.cas,
                status: None,
                extras_len: None,
                opaque: None,
                raw_summary: summary,
            },
            consumed: needed,
        }
    }

    fn parse_text_response(
        &mut self,
        line: &str,
        dir: Direction,
        header_consumed: usize,
        buf: &[u8],
    ) -> McParserOutput {
        let mut it = line.split_whitespace();
        let word = it.next().unwrap_or("");
        match word {
            "VALUE" => {
                // VALUE <key> <flags> <bytes>[ <cas>]
                let key = it.next().map(truncate_key);
                let flags = it.next().and_then(|s| s.parse::<u32>().ok());
                let bytes = it.next().and_then(|s| s.parse::<u32>().ok());
                let cas = it.next().and_then(|s| s.parse::<u64>().ok());
                let Some(vb) = bytes else {
                    return McParserOutput::Skip(header_consumed);
                };
                if vb > MAX_BODY_BYTES {
                    self.bypass = true;
                    return McParserOutput::Skip(buf.len());
                }
                let needed = header_consumed + vb as usize + 2;
                if buf.len() < needed {
                    return McParserOutput::Need;
                }
                let body = &buf[header_consumed..header_consumed + vb as usize];
                let tail = &buf[header_consumed + vb as usize..needed];
                if tail != b"\r\n" {
                    self.bypass = true;
                    return McParserOutput::Skip(buf.len());
                }
                let summary = format!(
                    "VALUE {} flags={} bytes={}{}{}",
                    key.as_deref().unwrap_or("?"),
                    flags.unwrap_or(0),
                    vb,
                    cas.map(|c| format!(" cas={c}")).unwrap_or_default(),
                    value_preview(body),
                );
                McParserOutput::Record {
                    record: McRecord {
                        variant: McVariant::Text,
                        direction: dir,
                        op: McOp::Response,
                        key,
                        value_size: Some(vb),
                        flags,
                        exptime: None,
                        cas,
                        status: None,
                        extras_len: None,
                        opaque: None,
                        raw_summary: summary,
                    },
                    consumed: needed,
                }
            }
            _ => McParserOutput::Record {
                record: McRecord {
                    variant: McVariant::Text,
                    direction: dir,
                    op: McOp::Response,
                    key: None,
                    value_size: None,
                    flags: None,
                    exptime: None,
                    cas: None,
                    status: None,
                    extras_len: None,
                    opaque: None,
                    raw_summary: line.to_string(),
                },
                consumed: header_consumed,
            },
        }
    }

    // -----------------------------------------------------------------
    // Binary protocol
    // -----------------------------------------------------------------

    fn parse_binary(&mut self, buf: &[u8], dir: Direction) -> McParserOutput {
        if buf.len() < BIN_HEADER {
            return McParserOutput::Need;
        }
        let magic = buf[0];
        if magic != 0x80 && magic != 0x81 {
            self.bypass = true;
            return McParserOutput::Skip(buf.len());
        }
        let opcode = buf[1];
        let key_len = u16::from_be_bytes([buf[2], buf[3]]);
        let extras_len = buf[4];
        // byte 5 is data_type (reserved)
        let status_or_vbucket = u16::from_be_bytes([buf[6], buf[7]]);
        let total_body_len = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let opaque = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let cas = u64::from_be_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]);

        if total_body_len > MAX_BODY_BYTES {
            return McParserOutput::Skip(buf.len());
        }
        if u32::from(key_len) + u32::from(extras_len) > total_body_len {
            self.bypass = true;
            return McParserOutput::Skip(buf.len());
        }

        let frame_len = BIN_HEADER + total_body_len as usize;
        if buf.len() < frame_len {
            return McParserOutput::Need;
        }
        let (op, is_sasl) = classify_binary_op(opcode);

        let key_start = BIN_HEADER + extras_len as usize;
        let value_start = key_start + key_len as usize;
        let value_end = BIN_HEADER + total_body_len as usize;

        let (key, value_preview_str) = if is_sasl {
            (None, String::new()) // redacted
        } else {
            let key = if key_len == 0 {
                None
            } else {
                let raw = &buf[key_start..value_start];
                Some(truncate_key(String::from_utf8_lossy(raw)))
            };
            let vp = if value_start < value_end {
                value_preview(&buf[value_start..value_end])
            } else {
                String::new()
            };
            (key, vp)
        };

        let is_response = magic == 0x81;
        let status = if is_response {
            Some(status_or_vbucket)
        } else {
            None
        };
        let value_size = if value_end > value_start {
            Some((value_end - value_start) as u32)
        } else {
            None
        };

        let summary = if is_sasl {
            format!(
                "[bin {} op={:#04x} opaque={} body={}] <redacted>",
                if is_response { "resp" } else { "req" },
                opcode,
                opaque,
                total_body_len,
            )
        } else {
            format!(
                "[bin {} op={:#04x} key={} bytes={}{}{}]{}",
                if is_response { "resp" } else { "req" },
                opcode,
                key.as_deref().unwrap_or(""),
                value_size.unwrap_or(0),
                status.map(|s| format!(" status={s}")).unwrap_or_default(),
                if cas != 0 {
                    format!(" cas={cas}")
                } else {
                    String::new()
                },
                value_preview_str,
            )
        };

        let rec = McRecord {
            variant: McVariant::Binary,
            direction: dir,
            op,
            key,
            value_size,
            flags: None,
            exptime: None,
            cas: if cas == 0 { None } else { Some(cas) },
            status,
            extras_len: Some(extras_len),
            opaque: Some(opaque),
            raw_summary: summary,
        };
        McParserOutput::Record {
            record: rec,
            consumed: frame_len,
        }
    }
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn looks_like_text_start(buf: &[u8]) -> bool {
    // First token must be up to 16 alpha-ASCII bytes followed by
    // space, tab, CR, or LF.
    let mut n = 0;
    for &b in buf.iter().take(17) {
        if b.is_ascii_alphabetic() {
            n += 1;
        } else if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            return n > 0 && n <= 16;
        } else {
            return false;
        }
    }
    // Ran out of buffer before finding a separator: let the caller
    // retry once more bytes arrive, which is best modelled as
    // "looks plausible".
    n > 0 && n <= 16
}

/// Recognise reply lines (one-word status codes, VALUE, STAT, etc.)
/// so we can branch the text parser on direction-independent content.
fn is_text_response_line(line: &str) -> bool {
    let word = line.split_whitespace().next().unwrap_or("");
    matches!(
        word,
        "VALUE"
            | "END"
            | "STORED"
            | "NOT_STORED"
            | "EXISTS"
            | "NOT_FOUND"
            | "DELETED"
            | "TOUCHED"
            | "OK"
            | "ERROR"
            | "CLIENT_ERROR"
            | "SERVER_ERROR"
            | "STAT"
            | "VERSION"
            | "BUSY"
            | "RESET"
    )
}

const fn classify_binary_op(opcode: u8) -> (McOp, bool) {
    match opcode {
        // 0x00/0x09 are Get/GetQ; 0x0C/0x0D are GetK/GetKQ. All four
        // are "fetch a value by key" so we fold them into McOp::Get.
        0x00 | 0x09 | 0x0C | 0x0D => (McOp::Get, false),
        0x01 => (McOp::Set, false),
        0x02 => (McOp::Add, false),
        0x03 => (McOp::Replace, false),
        0x04 => (McOp::Delete, false),
        0x05 => (McOp::Incr, false),
        0x06 => (McOp::Decr, false),
        0x07 => (McOp::Quit, false),
        0x08 => (McOp::Flush, false),
        0x0A => (McOp::Noop, false),
        0x0B => (McOp::Version, false),
        0x0E => (McOp::Append, false),
        0x0F => (McOp::Prepend, false),
        0x10 => (McOp::Stats, false),
        0x1C => (McOp::Touch, false),
        0x1D | 0x1E => (McOp::GetAndTouch, false),
        0x20 => (McOp::SaslList, false),
        0x21 | 0x22 => (McOp::Auth, true),
        other => (McOp::Other(other), false),
    }
}

fn find_crlf(buf: &[u8], max: usize) -> Option<usize> {
    let limit = buf.len().min(max);
    buf[..limit].windows(2).position(|w| w == b"\r\n")
}

fn truncate_key<S: AsRef<str>>(s: S) -> String {
    let s = s.as_ref();
    if s.len() <= MAX_KEY_BYTES {
        s.to_string()
    } else {
        let mut cut = MAX_KEY_BYTES;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s[..cut].to_string()
    }
}

fn value_preview(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let take = body.len().min(MAX_VALUE_SUMMARY);
    let slice = &body[..take];
    // Heuristic: if it's all printable ASCII we quote it; otherwise
    // we emit a length tag only.
    if slice
        .iter()
        .all(|&b| (0x20..0x7f).contains(&b) || b == b'\t')
    {
        let tail = if body.len() > take { "…" } else { "" };
        format!(" value={:?}{}", String::from_utf8_lossy(slice), tail)
    } else {
        format!(" value=<{} bytes binary>", body.len())
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(p: &mut MemcachedParser, buf: &[u8], dir: Direction) -> McParserOutput {
        p.parse(buf, dir)
    }

    #[test]
    fn text_set_request() {
        let mut p = MemcachedParser::default();
        let buf = b"set foo 0 60 5\r\nhello\r\n";
        match parse_one(&mut p, buf, Direction::Tx) {
            McParserOutput::Record { record, consumed } => {
                assert_eq!(record.variant, McVariant::Text);
                assert_eq!(record.op, McOp::Set);
                assert_eq!(record.key.as_deref(), Some("foo"));
                assert_eq!(record.value_size, Some(5));
                assert_eq!(record.flags, Some(0));
                assert_eq!(record.exptime, Some(60));
                assert_eq!(consumed, buf.len());
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn text_get_request() {
        let mut p = MemcachedParser::default();
        let buf = b"get foo\r\n";
        match parse_one(&mut p, buf, Direction::Tx) {
            McParserOutput::Record { record, consumed } => {
                assert_eq!(record.op, McOp::Get);
                assert_eq!(record.key.as_deref(), Some("foo"));
                assert_eq!(consumed, buf.len());
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn text_gets_multi_key() {
        let mut p = MemcachedParser::default();
        let buf = b"gets a b c\r\n";
        match parse_one(&mut p, buf, Direction::Tx) {
            McParserOutput::Record { record, .. } => {
                assert_eq!(record.op, McOp::Gets);
                assert_eq!(record.key.as_deref(), Some("a"));
                assert!(record.raw_summary.contains("3 keys"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn text_value_reply() {
        let mut p = MemcachedParser::default();
        let buf = b"VALUE foo 0 5\r\nhello\r\nEND\r\n";
        // First call: the VALUE line + body.
        match parse_one(&mut p, buf, Direction::Rx) {
            McParserOutput::Record { record, consumed } => {
                assert_eq!(record.op, McOp::Response);
                assert_eq!(record.key.as_deref(), Some("foo"));
                assert_eq!(record.value_size, Some(5));
                assert!(consumed > 0);
                // Second call consumes the END line.
                let rest = &buf[consumed..];
                match parse_one(&mut p, rest, Direction::Rx) {
                    McParserOutput::Record { record, consumed } => {
                        assert_eq!(record.op, McOp::Response);
                        assert_eq!(consumed, rest.len());
                    }
                    other => panic!("expected Record for END, got {other:?}"),
                }
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn text_storage_truncated_body_needs_more() {
        let mut p = MemcachedParser::default();
        let buf = b"set foo 0 60 5\r\nhel";
        match parse_one(&mut p, buf, Direction::Tx) {
            McParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
        // Feed the rest and expect a full record.
        let full = b"set foo 0 60 5\r\nhello\r\n";
        match parse_one(&mut p, full, Direction::Tx) {
            McParserOutput::Record { record, consumed } => {
                assert_eq!(record.op, McOp::Set);
                assert_eq!(consumed, full.len());
            }
            other => panic!("expected Record after refill, got {other:?}"),
        }
    }

    #[test]
    fn text_cas_parsed() {
        let mut p = MemcachedParser::default();
        let buf = b"cas foo 0 60 5 12345\r\nhello\r\n";
        match parse_one(&mut p, buf, Direction::Tx) {
            McParserOutput::Record { record, .. } => {
                assert_eq!(record.op, McOp::Cas);
                assert_eq!(record.cas, Some(12345));
                assert_eq!(record.value_size, Some(5));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn binary_get_request() {
        let mut p = MemcachedParser::default();
        // magic, op=Get (0x00), key_len=3, extras=0, dt=0, vbucket=0,
        // total_body=3, opaque=0xdead_beef, cas=0, key="foo"
        let mut hdr = Vec::<u8>::new();
        hdr.push(0x80);
        hdr.push(0x00);
        hdr.extend_from_slice(&3u16.to_be_bytes());
        hdr.push(0);
        hdr.push(0);
        hdr.extend_from_slice(&0u16.to_be_bytes());
        hdr.extend_from_slice(&3u32.to_be_bytes());
        hdr.extend_from_slice(&0xdead_beef_u32.to_be_bytes());
        hdr.extend_from_slice(&0u64.to_be_bytes());
        hdr.extend_from_slice(b"foo");
        match parse_one(&mut p, &hdr, Direction::Tx) {
            McParserOutput::Record { record, consumed } => {
                assert_eq!(record.variant, McVariant::Binary);
                assert_eq!(record.op, McOp::Get);
                assert_eq!(record.key.as_deref(), Some("foo"));
                assert_eq!(record.opaque, Some(0xdead_beef));
                assert_eq!(consumed, hdr.len());
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn binary_sasl_auth_redacted() {
        let mut p = MemcachedParser::default();
        let key = b"PLAIN";
        let value = b"\0user\0s3cr3t!";
        let total = (key.len() + value.len()) as u32;
        let mut frame = Vec::<u8>::new();
        frame.push(0x80);
        frame.push(0x21); // SaslAuth
        frame.extend_from_slice(&(key.len() as u16).to_be_bytes());
        frame.push(0);
        frame.push(0);
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&total.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&0u64.to_be_bytes());
        frame.extend_from_slice(key);
        frame.extend_from_slice(value);
        match parse_one(&mut p, &frame, Direction::Tx) {
            McParserOutput::Record { record, .. } => {
                assert_eq!(record.op, McOp::Auth);
                assert!(record.key.is_none(), "key must be stripped");
                assert!(
                    !record.raw_summary.contains("s3cr3t"),
                    "summary must not leak credentials: {}",
                    record.raw_summary,
                );
                assert!(!record.raw_summary.contains("PLAIN"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn binary_invalid_magic_bypass() {
        let mut p = MemcachedParser::default();
        // First byte 0x55 is neither binary magic nor a plausible text
        // command start (uppercase is fine for looks_like_text_start,
        // but the subsequent text-layer sanity check on `cmd` will
        // also reject). Use a non-ascii first byte to fail both.
        let buf = [0xffu8, 0x01, 0x02, 0x03];
        match parse_one(&mut p, &buf, Direction::Tx) {
            McParserOutput::Skip(n) => assert_eq!(n, buf.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn text_delete_incr() {
        let mut p = MemcachedParser::default();
        let buf = b"delete foo\r\n";
        match parse_one(&mut p, buf, Direction::Tx) {
            McParserOutput::Record { record, .. } => {
                assert_eq!(record.op, McOp::Delete);
                assert_eq!(record.key.as_deref(), Some("foo"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
        let mut p = MemcachedParser::default();
        let buf = b"incr ctr 3\r\n";
        match parse_one(&mut p, buf, Direction::Tx) {
            McParserOutput::Record { record, .. } => {
                assert_eq!(record.op, McOp::Incr);
                assert_eq!(record.key.as_deref(), Some("ctr"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn text_short_simple_reply() {
        let mut p = MemcachedParser::default();
        let buf = b"STORED\r\n";
        match parse_one(&mut p, buf, Direction::Rx) {
            McParserOutput::Record { record, consumed } => {
                assert_eq!(record.op, McOp::Response);
                assert_eq!(consumed, buf.len());
                assert!(record.raw_summary.contains("STORED"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn text_line_too_long_bypass() {
        let mut p = MemcachedParser::default();
        // 5 KiB of 'a' and no CRLF.
        let buf = vec![b'a'; 5000];
        match parse_one(&mut p, &buf, Direction::Tx) {
            McParserOutput::Skip(n) => assert_eq!(n, buf.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn truncated_binary_frame_needs_more() {
        let mut p = MemcachedParser::default();
        let buf = [0x80u8, 0x00, 0x00, 0x03]; // only 4 bytes of header
        match parse_one(&mut p, &buf, Direction::Tx) {
            McParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
    }
}
