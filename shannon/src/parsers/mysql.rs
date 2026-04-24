//! `MySQL` client/server protocol parser.
//!
//! Decodes the wire framing described in the MySQL reference manual's
//! "Protocol Basics" chapter. One parser instance handles one direction
//! of one connection and keeps a tiny amount of state: namely whether we
//! have already seen the initial handshake (so we can tell a
//! client-side handshake response from an ordinary command packet).
//!
//! The framing on the wire is uniform: every packet is a 3-byte
//! little-endian length, a 1-byte sequence id, and `length` bytes of
//! payload. Responses may be split across multiple 16 MiB - 1 packets;
//! we deliberately cap each record at 1 MiB and drop any continuation
//! because those are effectively always bulk result-set data we don't
//! want to buffer.
//!
//! We aim to parse just enough to produce useful telemetry — the
//! interesting commands (`COM_QUERY`, `COM_STMT_PREPARE`,
//! `COM_STMT_EXECUTE`) and the four standard response shapes (OK, ERR,
//! EOF, result-set header). Anything we don't recognise collapses to
//! `Other`. Auth credentials never leave the parser:
//! `COM_CHANGE_USER` is emitted field-free.

// These pedantic lints produce mostly noise for a bit-twiddling wire
// parser; the code stays readable without contorting for them.
#![allow(
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::single_match_else,
    clippy::no_effect_underscore_binding,
    clippy::field_reassign_with_default
)]

use crate::events::Direction;

/// Hard per-record cap on captured strings / packet payloads.
const MAX_SQL_BYTES: usize = 8 * 1024;
const MAX_VERSION_BYTES: usize = 256;
const MAX_USER_BYTES: usize = 256;
const MAX_PLUGIN_BYTES: usize = 64;
const MAX_PACKET_BYTES: usize = 1024 * 1024;
/// Absolute upper bound on the length header before we bail and skip.
/// A legal MySQL packet maxes at 16 MiB - 1, but we never want to buffer
/// anything close to that, and a header larger than our per-record cap
/// is an excellent "not MySQL" signal in practice.
const ABSURD_PACKET_LIMIT: u32 = MAX_PACKET_BYTES as u32;
/// How many consecutive garbled sequence ids we'll tolerate before
/// declaring the stream a non-MySQL false-positive and bypassing.
const MAX_SEQ_DESYNC: u8 = 8;

// MySQL capability flags we care about.
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;

// Command byte values.
const COM_QUIT: u8 = 0x01;
const COM_INIT_DB: u8 = 0x02;
const COM_QUERY: u8 = 0x03;
const COM_PING: u8 = 0x0e;
const COM_CHANGE_USER: u8 = 0x11;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_CLOSE: u8 = 0x19;

/// Per-direction MySQL parser state.
#[derive(Default)]
pub struct MysqlParser {
    /// Have we emitted / seen the initial server handshake? On the Tx
    /// side this tells us whether the next client packet is a
    /// HandshakeResponse or an ordinary command; on the Rx side it's
    /// used to detect the protocol-v10 handshake banner.
    handshake_done: bool,
    /// Consecutive packets with out-of-order sequence ids. If this
    /// climbs high we assume we're looking at non-MySQL traffic.
    desync: u8,
    /// Set after a fatal sanity failure — subsequent bytes are dropped.
    bypassed: bool,
    /// When the server just advertised an auth-switch plugin, the next
    /// client packet is raw auth data rather than a command. We skip it
    /// by reporting the packet bytes as `Skip`.
    expect_auth_response: bool,
}

/// A decoded MySQL protocol record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MysqlRecord {
    Handshake {
        server_version: String,
        capabilities: u32,
        auth_plugin: String,
    },
    HandshakeResponse {
        user: String,
        database: Option<String>,
        client_capabilities: u32,
        auth_plugin: String,
    },
    /// COM_QUERY (0x03).
    Query {
        text: String,
    },
    /// COM_STMT_PREPARE (0x16).
    StmtPrepare {
        text: String,
    },
    /// COM_STMT_EXECUTE (0x17).
    StmtExecute {
        stmt_id: u32,
        param_count: u16,
    },
    /// COM_STMT_CLOSE (0x19).
    StmtClose {
        stmt_id: u32,
    },
    /// COM_INIT_DB (0x02).
    InitDb {
        schema: String,
    },
    /// COM_PING (0x0e).
    Ping,
    /// COM_QUIT (0x01).
    Quit,
    /// COM_CHANGE_USER (0x11) — payload redacted (credentials).
    ChangeUser,
    AuthSwitchRequest {
        plugin: String,
    },
    Ok {
        affected_rows: u64,
        last_insert_id: u64,
        status_flags: u16,
        info: String,
    },
    Err {
        code: u16,
        state: String,
        message: String,
    },
    Eof {
        status_flags: u16,
        warnings: u16,
    },
    /// First byte was a length-encoded column count: this is the
    /// header packet of a result set.
    ResultSet {
        column_count: u64,
    },
    /// Unrecognised / unsupported command.
    Other {
        command: u8,
        length: u32,
    },
}

impl MysqlRecord {
    /// Short human-readable single-line rendering for the TUI / logs.
    #[must_use]
    pub fn display_line(&self) -> String {
        match self {
            Self::Handshake {
                server_version,
                auth_plugin,
                ..
            } => {
                format!("HANDSHAKE v{server_version} plugin={auth_plugin}")
            }
            Self::HandshakeResponse {
                user,
                database,
                auth_plugin,
                ..
            } => {
                let db = database.as_deref().unwrap_or("-");
                format!("HANDSHAKE_RESPONSE user={user} db={db} plugin={auth_plugin}")
            }
            Self::Query { text } => format!("QUERY {text}"),
            Self::StmtPrepare { text } => format!("STMT PREPARE {text}"),
            Self::StmtExecute {
                stmt_id,
                param_count,
            } => {
                format!("STMT EXECUTE id={stmt_id} params={param_count}")
            }
            Self::StmtClose { stmt_id } => format!("STMT CLOSE id={stmt_id}"),
            Self::InitDb { schema } => format!("INIT_DB {schema}"),
            Self::Ping => "PING".to_string(),
            Self::Quit => "QUIT".to_string(),
            Self::ChangeUser => "CHANGE_USER".to_string(),
            Self::AuthSwitchRequest { plugin } => format!("AUTH_SWITCH {plugin}"),
            Self::Ok {
                affected_rows,
                last_insert_id,
                status_flags,
                info,
            } => {
                if info.is_empty() {
                    format!(
                        "OK rows={affected_rows} insert_id={last_insert_id} status={status_flags:#06x}"
                    )
                } else {
                    format!(
                        "OK rows={affected_rows} insert_id={last_insert_id} status={status_flags:#06x} {info}"
                    )
                }
            }
            Self::Err {
                code,
                state,
                message,
            } => {
                format!("ERR {code} [{state}] {message}")
            }
            Self::Eof {
                status_flags,
                warnings,
            } => {
                format!("EOF status={status_flags:#06x} warnings={warnings}")
            }
            Self::ResultSet { column_count } => format!("RESULT_SET cols={column_count}"),
            Self::Other { command, length } => {
                format!("CMD {command:#04x} len={length}")
            }
        }
    }
}

/// Outcome of one `parse` call.
pub enum MysqlParserOutput {
    /// More bytes are required before another decision can be made.
    Need,
    /// A full record is ready; `consumed` bytes of the input were used.
    Record {
        record: MysqlRecord,
        consumed: usize,
    },
    /// `n` bytes should be dropped. Used for (a) non-MySQL bypass and
    /// (b) oversize/uninteresting packets we choose to skip past.
    Skip(usize),
}

impl MysqlParser {
    /// Parse the front of `buf`. Safe to call repeatedly; internally
    /// capped so it never panics and never allocates unboundedly.
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> MysqlParserOutput {
        if self.bypassed {
            return MysqlParserOutput::Skip(buf.len());
        }
        // Need the 4-byte packet header first.
        if buf.len() < 4 {
            return MysqlParserOutput::Need;
        }
        let length = u32::from(buf[0]) | (u32::from(buf[1]) << 8) | (u32::from(buf[2]) << 16);
        let _seq = buf[3];

        // Absurd length — either we've lost sync or the stream isn't MySQL.
        if length > ABSURD_PACKET_LIMIT {
            self.bypassed = true;
            return MysqlParserOutput::Skip(buf.len());
        }

        let total = 4usize.saturating_add(length as usize);
        if buf.len() < total {
            return MysqlParserOutput::Need;
        }
        let payload = &buf[4..total];

        // Empty packet — nothing useful, just advance.
        if payload.is_empty() {
            return MysqlParserOutput::Skip(total);
        }

        let record = match dir {
            Direction::Rx => self.parse_server(payload),
            Direction::Tx => self.parse_client(payload),
        };

        match record {
            Some(rec) => {
                self.desync = 0;
                MysqlParserOutput::Record {
                    record: rec,
                    consumed: total,
                }
            }
            None => {
                self.desync = self.desync.saturating_add(1);
                if self.desync >= MAX_SEQ_DESYNC {
                    self.bypassed = true;
                    return MysqlParserOutput::Skip(buf.len());
                }
                MysqlParserOutput::Skip(total)
            }
        }
    }

    fn parse_server(&mut self, payload: &[u8]) -> Option<MysqlRecord> {
        // First server packet is the protocol-v10 handshake.
        if !self.handshake_done {
            if let Some(rec) = parse_handshake_v10(payload) {
                self.handshake_done = true;
                return Some(rec);
            }
            // First server packet wasn't a handshake: treat stream as
            // unknown but still try to parse as a regular response so
            // we don't lose signal on mid-stream captures.
            self.handshake_done = true;
        }

        let first = payload[0];
        match first {
            0x00 if payload.len() >= 7 => parse_ok(payload, false),
            0xfe if payload.len() >= 7 => parse_ok(payload, true),
            0xfe if payload.len() < 9 => parse_eof(payload),
            0xff => parse_err(payload),
            0xfb => Some(MysqlRecord::Other {
                command: 0xfb,
                length: payload.len() as u32,
            }),
            // AuthSwitchRequest: 0xfe + plugin name + plugin data (when
            // payload is big enough that it isn't the short EOF form).
            0xfe => {
                let rec = parse_auth_switch(payload);
                if rec.is_some() {
                    self.expect_auth_response = true;
                }
                rec
            }
            // Length-encoded column count => result-set header.
            b if b <= 0xfa || b == 0xfc || b == 0xfd => {
                let (count, _) = decode_lenenc_int(payload)?;
                Some(MysqlRecord::ResultSet {
                    column_count: count,
                })
            }
            _ => Some(MysqlRecord::Other {
                command: first,
                length: payload.len() as u32,
            }),
        }
    }

    fn parse_client(&mut self, payload: &[u8]) -> Option<MysqlRecord> {
        if self.expect_auth_response {
            // Raw authentication response — drop silently.
            self.expect_auth_response = false;
            return Some(MysqlRecord::Other {
                command: 0,
                length: payload.len() as u32,
            });
        }

        // First client packet after a server handshake is the
        // HandshakeResponse; after that, it's command packets.
        if self.handshake_done && !matches!(payload.first(), Some(&b) if is_command_byte(b)) {
            if let Some(rec) = parse_handshake_response(payload) {
                return Some(rec);
            }
        }

        let cmd = payload[0];
        let body = &payload[1..];
        match cmd {
            COM_QUIT => Some(MysqlRecord::Quit),
            COM_INIT_DB => Some(MysqlRecord::InitDb {
                schema: clip_utf8(body, MAX_USER_BYTES),
            }),
            COM_QUERY => Some(MysqlRecord::Query {
                text: clip_utf8(body, MAX_SQL_BYTES),
            }),
            COM_PING => Some(MysqlRecord::Ping),
            COM_CHANGE_USER => Some(MysqlRecord::ChangeUser),
            COM_STMT_PREPARE => Some(MysqlRecord::StmtPrepare {
                text: clip_utf8(body, MAX_SQL_BYTES),
            }),
            COM_STMT_EXECUTE => {
                if body.len() < 9 {
                    return None;
                }
                let stmt_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                // Bytes 4..5 flags, 5..9 iteration count. Param count
                // isn't in the header; we approximate it from any
                // null-bitmap that follows when NEW_PARAMS_BOUND=1.
                // To keep the contract simple and cheap we just report
                // 0 when we can't determine it.
                let param_count = 0u16;
                Some(MysqlRecord::StmtExecute {
                    stmt_id,
                    param_count,
                })
            }
            COM_STMT_CLOSE => {
                if body.len() < 4 {
                    return None;
                }
                let stmt_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                Some(MysqlRecord::StmtClose { stmt_id })
            }
            _ => Some(MysqlRecord::Other {
                command: cmd,
                length: (payload.len() - 1) as u32,
            }),
        }
    }
}

fn is_command_byte(b: u8) -> bool {
    // All documented COM_* codes fit in [0x00, 0x1f]. Handshake
    // responses always begin with capability flags, whose low byte is
    // essentially never that small (CLIENT_PROTOCOL_41 alone sets
    // bit 9).
    b <= 0x1f
}

/// Parse an initial handshake-v10 packet.
fn parse_handshake_v10(payload: &[u8]) -> Option<MysqlRecord> {
    let mut c = Cursor::new(payload);
    let protocol = c.u8()?;
    if protocol != 0x0a {
        return None;
    }
    let server_version = c.cstring(MAX_VERSION_BYTES)?;
    let _thread_id = c.u32_le()?;
    let _auth_plugin_data_1 = c.take(8)?;
    let _filler = c.u8()?;
    let cap_lo = c.u16_le()? as u32;
    // Older servers may omit everything after cap_lo.
    if c.remaining() == 0 {
        return Some(MysqlRecord::Handshake {
            server_version,
            capabilities: cap_lo,
            auth_plugin: String::new(),
        });
    }
    let _charset = c.u8()?;
    let _status = c.u16_le()?;
    let cap_hi = c.u16_le()? as u32;
    let capabilities = cap_lo | (cap_hi << 16);
    let auth_plugin_data_len = c.u8().unwrap_or(0);
    // 10 reserved bytes. Some servers send only 6; be lenient.
    c.skip_up_to(10);
    let auth_plugin = if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let part2_len = core::cmp::max(
            13,
            auth_plugin_data_len as usize - 8.min(auth_plugin_data_len as usize),
        );
        // Clamp if truncated.
        let part2_take = part2_len.min(c.remaining());
        let _ = c.take(part2_take);
        if capabilities & CLIENT_PLUGIN_AUTH != 0 {
            c.cstring(MAX_PLUGIN_BYTES).unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    Some(MysqlRecord::Handshake {
        server_version,
        capabilities,
        auth_plugin,
    })
}

/// Parse a CLIENT_PROTOCOL_41 handshake response.
fn parse_handshake_response(payload: &[u8]) -> Option<MysqlRecord> {
    let mut c = Cursor::new(payload);
    let caps = c.u32_le()?;
    if caps & CLIENT_PROTOCOL_41 == 0 {
        // Old 3.23/4.0 handshake response — not worth parsing.
        return None;
    }
    let _max_packet = c.u32_le()?;
    let _charset = c.u8()?;
    let _reserved = c.take(23)?;
    let user = c.cstring(MAX_USER_BYTES)?;
    // Auth response: either length-encoded (when
    // LENENC_CLIENT_DATA set) or 1-byte length followed by that many.
    if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        let (alen, _) = c.lenenc_int()?;
        c.skip_up_to(alen as usize);
    } else if caps & CLIENT_SECURE_CONNECTION != 0 {
        let alen = c.u8()? as usize;
        c.skip_up_to(alen);
    } else {
        // Null-terminated legacy auth string.
        let _ = c.cstring(256);
    }
    let database = if caps & CLIENT_CONNECT_WITH_DB != 0 {
        c.cstring(MAX_USER_BYTES)
    } else {
        None
    };
    let auth_plugin = if caps & CLIENT_PLUGIN_AUTH != 0 {
        c.cstring(MAX_PLUGIN_BYTES).unwrap_or_default()
    } else {
        String::new()
    };
    Some(MysqlRecord::HandshakeResponse {
        user,
        database,
        client_capabilities: caps,
        auth_plugin,
    })
}

fn parse_ok(payload: &[u8], is_eof_form: bool) -> Option<MysqlRecord> {
    // Header byte is payload[0] and is already validated.
    let mut c = Cursor::new(&payload[1..]);
    let (affected_rows, _) = c.lenenc_int()?;
    let (last_insert_id, _) = c.lenenc_int()?;
    let status_flags = c.u16_le().unwrap_or(0);
    let _warnings = c.u16_le().unwrap_or(0);
    let info = clip_utf8(c.rest(), 512);
    // `is_eof_form` flags OKs that use 0xfe (CLIENT_DEPRECATE_EOF).
    // We don't surface the distinction in the record — the caller can
    // check `status_flags & 0x0002` ("more results exist") if needed.
    let _ = is_eof_form;
    Some(MysqlRecord::Ok {
        affected_rows,
        last_insert_id,
        status_flags,
        info,
    })
}

fn parse_err(payload: &[u8]) -> Option<MysqlRecord> {
    if payload.len() < 3 {
        return None;
    }
    let code = u16::from_le_bytes([payload[1], payload[2]]);
    // SQL state marker '#' + 5 byte state is present when
    // CLIENT_PROTOCOL_41 is negotiated; otherwise message starts
    // immediately.
    let (state, msg_start) = if payload.len() >= 9 && payload[3] == b'#' {
        let state = std::str::from_utf8(&payload[4..9])
            .unwrap_or("HY000")
            .to_string();
        (state, 9)
    } else {
        (String::new(), 3)
    };
    let message = clip_utf8(&payload[msg_start..], 512);
    Some(MysqlRecord::Err {
        code,
        state,
        message,
    })
}

fn parse_eof(payload: &[u8]) -> Option<MysqlRecord> {
    // Classic EOF (CLIENT_PROTOCOL_41): 0xfe, 2 byte warnings, 2 byte
    // status flags. Total payload length is 5.
    if payload.len() < 5 {
        return Some(MysqlRecord::Eof {
            status_flags: 0,
            warnings: 0,
        });
    }
    let warnings = u16::from_le_bytes([payload[1], payload[2]]);
    let status_flags = u16::from_le_bytes([payload[3], payload[4]]);
    Some(MysqlRecord::Eof {
        status_flags,
        warnings,
    })
}

fn parse_auth_switch(payload: &[u8]) -> Option<MysqlRecord> {
    // 0xfe + null-terminated plugin name + plugin data.
    let mut c = Cursor::new(&payload[1..]);
    let plugin = c.cstring(MAX_PLUGIN_BYTES)?;
    Some(MysqlRecord::AuthSwitchRequest { plugin })
}

// ---------------- Small byte-slice cursor with lenenc helpers. --------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16_le(&mut self) -> Option<u16> {
        let end = self.pos.checked_add(2)?;
        if end > self.buf.len() {
            return None;
        }
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos = end;
        Some(v)
    }

    fn u32_le(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        if end > self.buf.len() {
            return None;
        }
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos = end;
        Some(v)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Some(s)
    }

    /// Take up to `n` bytes; never fails short.
    fn skip_up_to(&mut self, n: usize) {
        let take = n.min(self.remaining());
        self.pos += take;
    }

    fn cstring(&mut self, max: usize) -> Option<String> {
        let start = self.pos;
        let rel = self.buf[start..].iter().position(|&b| b == 0)?;
        let bytes = &self.buf[start..start + rel];
        self.pos = start + rel + 1;
        Some(clip_utf8(bytes, max))
    }

    fn lenenc_int(&mut self) -> Option<(u64, usize)> {
        let start = self.pos;
        let (v, consumed) = decode_lenenc_int(&self.buf[self.pos..])?;
        self.pos = start + consumed;
        Some((v, consumed))
    }
}

fn decode_lenenc_int(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    match first {
        0xfb => None,
        0xfc => {
            if buf.len() < 3 {
                return None;
            }
            Some((u64::from(u16::from_le_bytes([buf[1], buf[2]])), 3))
        }
        0xfd => {
            if buf.len() < 4 {
                return None;
            }
            let v = u64::from(buf[1]) | (u64::from(buf[2]) << 8) | (u64::from(buf[3]) << 16);
            Some((v, 4))
        }
        0xfe => {
            if buf.len() < 9 {
                return None;
            }
            let v = u64::from_le_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]);
            Some((v, 9))
        }
        0xff => None,
        n => Some((u64::from(n), 1)),
    }
}

/// Clip arbitrary bytes into a `String` with a byte-count ceiling,
/// replacing invalid UTF-8 with the lossy placeholder. We clip on the
/// byte slice first so enormous packets don't allocate.
fn clip_utf8(bytes: &[u8], max: usize) -> String {
    let end = bytes.len().min(max);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

// ============================ tests =========================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a MySQL packet header + payload.
    fn frame(seq: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut out = Vec::with_capacity(4 + payload.len());
        out.push((len & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(seq);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn handshake_v10_mysql_native_password() {
        // Construct a minimal protocol-v10 handshake.
        let mut payload = Vec::new();
        payload.push(0x0a); // protocol
        payload.extend_from_slice(b"8.0.32\0");
        payload.extend_from_slice(&42u32.to_le_bytes()); // thread id
        payload.extend_from_slice(&[1u8; 8]); // auth-plugin-data-1
        payload.push(0); // filler
                         // cap_lo: PROTOCOL_41 (0x0200) | SECURE_CONNECTION (0x8000).
        let cap_lo: u16 = ((CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION) & 0xffff) as u16;
        payload.extend_from_slice(&cap_lo.to_le_bytes());
        payload.push(33); // utf8mb3_general_ci
        payload.extend_from_slice(&0u16.to_le_bytes()); // status
                                                        // cap_hi: PLUGIN_AUTH high bits.
        let cap_hi: u16 = (CLIENT_PLUGIN_AUTH >> 16) as u16;
        payload.extend_from_slice(&cap_hi.to_le_bytes());
        payload.push(21); // auth-plugin-data-len
        payload.extend_from_slice(&[0u8; 10]); // reserved
        payload.extend_from_slice(&[2u8; 13]); // auth-plugin-data-2 (13 bytes min)
        payload.extend_from_slice(b"mysql_native_password\0");

        let wire = frame(0, &payload);
        let mut p = MysqlParser::default();
        match p.parse(&wire, Direction::Rx) {
            MysqlParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, wire.len());
                match record {
                    MysqlRecord::Handshake {
                        server_version,
                        auth_plugin,
                        ..
                    } => {
                        assert_eq!(server_version, "8.0.32");
                        assert_eq!(auth_plugin, "mysql_native_password");
                    }
                    other => panic!("expected Handshake, got {other:?}"),
                }
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn com_query_select_1() {
        let mut p = MysqlParser::default();
        // Skip the handshake phase by marking it done.
        p.handshake_done = true;
        let mut payload = vec![COM_QUERY];
        payload.extend_from_slice(b"SELECT 1");
        let wire = frame(0, &payload);
        match p.parse(&wire, Direction::Tx) {
            MysqlParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, wire.len());
                match record {
                    MysqlRecord::Query { text } => assert_eq!(text, "SELECT 1"),
                    other => panic!("expected Query, got {other:?}"),
                }
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn ok_packet_lenenc() {
        let mut p = MysqlParser::default();
        p.handshake_done = true;
        // 0x00, affected=3, insert_id=0, status=0x0002, warnings=0, info=""
        let payload = vec![0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00];
        let wire = frame(1, &payload);
        match p.parse(&wire, Direction::Rx) {
            MysqlParserOutput::Record { record, .. } => match record {
                MysqlRecord::Ok {
                    affected_rows,
                    status_flags,
                    ..
                } => {
                    assert_eq!(affected_rows, 3);
                    assert_eq!(status_flags, 0x0002);
                }
                other => panic!("expected Ok, got {other:?}"),
            },
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn err_packet_with_state() {
        let mut p = MysqlParser::default();
        p.handshake_done = true;
        // 0xff, code=1064, '#', state=42000, message="You have an error"
        let mut payload = vec![0xff, 0x28, 0x04, b'#'];
        payload.extend_from_slice(b"42000");
        payload.extend_from_slice(b"You have an error");
        let wire = frame(1, &payload);
        match p.parse(&wire, Direction::Rx) {
            MysqlParserOutput::Record { record, .. } => match record {
                MysqlRecord::Err {
                    code,
                    state,
                    message,
                } => {
                    assert_eq!(code, 1064);
                    assert_eq!(state, "42000");
                    assert_eq!(message, "You have an error");
                }
                other => panic!("expected Err, got {other:?}"),
            },
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn com_change_user_redacts_fields() {
        let mut p = MysqlParser::default();
        p.handshake_done = true;
        // Lots of secret-looking bytes; must not surface.
        let mut payload = vec![COM_CHANGE_USER];
        payload.extend_from_slice(b"alice\0supersecretpassword\0mydb\0");
        let wire = frame(0, &payload);
        match p.parse(&wire, Direction::Tx) {
            MysqlParserOutput::Record { record, .. } => {
                assert_eq!(record, MysqlRecord::ChangeUser);
                // Rendered form must not echo the payload.
                let line = record.display_line();
                assert!(!line.contains("alice"));
                assert!(!line.contains("supersecret"));
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn stmt_prepare_then_execute() {
        let mut p = MysqlParser::default();
        p.handshake_done = true;

        let mut prep = vec![COM_STMT_PREPARE];
        prep.extend_from_slice(b"SELECT ? FROM t");
        let wire = frame(0, &prep);
        match p.parse(&wire, Direction::Tx) {
            MysqlParserOutput::Record { record, .. } => match record {
                MysqlRecord::StmtPrepare { text } => assert_eq!(text, "SELECT ? FROM t"),
                other => panic!("expected StmtPrepare, got {other:?}"),
            },
            _ => panic!("expected Record"),
        }

        let mut exec = vec![COM_STMT_EXECUTE];
        exec.extend_from_slice(&7u32.to_le_bytes()); // stmt id
        exec.push(0); // flags
        exec.extend_from_slice(&1u32.to_le_bytes()); // iteration count
        let wire = frame(0, &exec);
        match p.parse(&wire, Direction::Tx) {
            MysqlParserOutput::Record { record, .. } => match record {
                MysqlRecord::StmtExecute { stmt_id, .. } => assert_eq!(stmt_id, 7),
                other => panic!("expected StmtExecute, got {other:?}"),
            },
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn truncated_header_returns_need() {
        let mut p = MysqlParser::default();
        let buf = [0x05u8, 0x00, 0x00]; // only 3 bytes
        assert!(matches!(
            p.parse(&buf, Direction::Tx),
            MysqlParserOutput::Need
        ));
    }

    #[test]
    fn absurd_length_skips() {
        let mut p = MysqlParser::default();
        // Length bytes encode > 16 MiB.
        let buf = [0xff, 0xff, 0xff, 0x00, 0xaa, 0xbb, 0xcc];
        match p.parse(&buf, Direction::Rx) {
            MysqlParserOutput::Skip(n) => assert_eq!(n, buf.len()),
            _ => panic!("expected Skip"),
        }
        // After bypass, any subsequent bytes are also dropped.
        match p.parse(b"garbage", Direction::Rx) {
            MysqlParserOutput::Skip(n) => assert_eq!(n, 7),
            _ => panic!("expected Skip"),
        }
    }

    #[test]
    fn display_line_shapes() {
        let q = MysqlRecord::Query {
            text: "SELECT 1".into(),
        };
        assert_eq!(q.display_line(), "QUERY SELECT 1");
        let ok = MysqlRecord::Ok {
            affected_rows: 3,
            last_insert_id: 0,
            status_flags: 0,
            info: String::new(),
        };
        assert!(ok.display_line().starts_with("OK rows=3"));
    }
}
