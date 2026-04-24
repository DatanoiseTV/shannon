//! Microsoft SQL Server TDS (Tabular Data Stream) — tcp/1433, 1434.
//!
//! TDS frames everything over a single packet header:
//!
//! ```text
//!   u8  type         (0x01 SQL-Batch, 0x02 OldLogin, 0x03 RPC,
//!                     0x04 TabularResult, 0x06 Attention, 0x07 BulkLoad,
//!                     0x0E Transaction, 0x10 Login7, 0x11 SSPI,
//!                     0x12 PreLogin, 0x0F ConnectionClosed)
//!   u8  status       (EOM bit 0, IGNORE 1, RESET 3, RESET_SKIP_TX 4)
//!   u16 length       (BE, including this header)
//!   u16 spid         (BE)
//!   u8  packet_id
//!   u8  window
//!   payload...
//! ```
//!
//! v1 surfaces packet type + length + spid. For Login7 we also dig
//! into the variable-length section that trails the fixed body
//! and surface the UserName / ServerName / AppName strings —
//! MSSQL sends those in UCS-2 LE and the parser decodes them to
//! UTF-8. Login7's password field is obfuscated (nibble-swap +
//! XOR 0xA5) but still trivially recoverable; we intentionally
//! redact it and just flag "password present" so operators know
//! auth is being attempted without shannon leaking it.

use crate::events::Direction;

const HEADER: usize = 8;

pub struct MssqlParser {
    bypass: bool,
}

impl Default for MssqlParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum MssqlParserOutput {
    Need,
    Record { record: MssqlRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct MssqlRecord {
    pub direction: Direction,
    pub packet_type: u8,
    pub type_name: &'static str,
    pub status: u8,
    pub length: u16,
    pub spid: u16,
    pub packet_id: u8,
    pub user_name: Option<String>,
    pub server_name: Option<String>,
    pub app_name: Option<String>,
    pub language: Option<String>,
    pub database: Option<String>,
    pub password_present: bool,
}

impl MssqlRecord {
    pub fn display_line(&self) -> String {
        let u = self
            .user_name
            .as_deref()
            .map(|s| format!(" user={s}"))
            .unwrap_or_default();
        let s = self
            .server_name
            .as_deref()
            .map(|s| format!(" srv={s}"))
            .unwrap_or_default();
        let a = self
            .app_name
            .as_deref()
            .map(|s| format!(" app={s}"))
            .unwrap_or_default();
        let db = self
            .database
            .as_deref()
            .map(|s| format!(" db={s}"))
            .unwrap_or_default();
        let pw = if self.password_present { " pw=<redacted>" } else { "" };
        format!(
            "mssql {} len={} spid={}{u}{s}{a}{db}{pw}",
            self.type_name, self.length, self.spid,
        )
    }
}

impl MssqlParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> MssqlParserOutput {
        if self.bypass {
            return MssqlParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return MssqlParserOutput::Need;
        }
        let packet_type = buf[0];
        if !is_known_type(packet_type) {
            self.bypass = true;
            return MssqlParserOutput::Skip(buf.len());
        }
        let status = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]);
        if (length as usize) < HEADER {
            self.bypass = true;
            return MssqlParserOutput::Skip(buf.len());
        }
        if buf.len() < length as usize {
            return MssqlParserOutput::Need;
        }
        let spid = u16::from_be_bytes([buf[4], buf[5]]);
        let packet_id = buf[6];
        let body = &buf[HEADER..length as usize];
        let (user_name, server_name, app_name, language, database, password_present) =
            if packet_type == 0x10 {
                decode_login7(body)
            } else {
                (None, None, None, None, None, false)
            };
        MssqlParserOutput::Record {
            record: MssqlRecord {
                direction: dir,
                packet_type,
                type_name: type_name(packet_type),
                status,
                length,
                spid,
                packet_id,
                user_name,
                server_name,
                app_name,
                language,
                database,
                password_present,
            },
            consumed: length as usize,
        }
    }
}

/// Login7 structure: 36-byte fixed header then a variable-length
/// table of (u16 offset, u16 length) pairs describing where each
/// string field lives inside the packet (offsets are relative to
/// the start of the TDS packet, i.e. include the 8-byte header).
/// Strings are UCS-2 little-endian.
fn decode_login7(body: &[u8]) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
) {
    // The offset table begins at body offset 36 and has 10-13 pairs
    // depending on TDS version. We care about indices 2 (user),
    // 3 (password), 4 (appname), 5 (server), 6 (language unused slot
    // in some, sname), 9 (database). Layout per [MS-TDS] §2.2.6.4:
    //
    //   0 HostName, 1 UserName, 2 Password, 3 AppName, 4 ServerName,
    //   5 Unused/CltIntName, 6 CltIntName, 7 Language, 8 Database,
    //   ...
    //
    // We only need 1, 2, 3, 4, 7, 8 for a useful summary.
    if body.len() < 36 + 10 * 4 {
        return (None, None, None, None, None, false);
    }
    let table = &body[36..];
    let get = |idx: usize| -> Option<(usize, usize)> {
        let p = idx * 4;
        if table.len() < p + 4 {
            return None;
        }
        let off = u16::from_le_bytes([table[p], table[p + 1]]) as usize;
        let len = u16::from_le_bytes([table[p + 2], table[p + 3]]) as usize;
        if len == 0 {
            return None;
        }
        // Offsets in table are from start of the full TDS packet; we
        // have a body slice that begins at +HEADER, so subtract.
        off.checked_sub(HEADER).map(|b| (b, len))
    };
    let ucs2 = |range: Option<(usize, usize)>| -> Option<String> {
        let (start, count) = range?;
        let bytes = body.get(start..start + count * 2)?;
        let mut s = String::with_capacity(count);
        for chunk in bytes.chunks_exact(2) {
            let u = u16::from_le_bytes([chunk[0], chunk[1]]);
            if let Some(c) = char::from_u32(u as u32) {
                s.push(c);
            }
        }
        Some(s)
    };
    let user = ucs2(get(1));
    let password_present = get(2).is_some();
    let app = ucs2(get(3));
    let server = ucs2(get(4));
    let lang = ucs2(get(7));
    let database = ucs2(get(8));
    (user, server, app, lang, database, password_present)
}

const fn is_known_type(t: u8) -> bool {
    matches!(t, 0x01 | 0x02 | 0x03 | 0x04 | 0x06 | 0x07 | 0x0E | 0x0F | 0x10 | 0x11 | 0x12)
}

const fn type_name(t: u8) -> &'static str {
    match t {
        0x01 => "SQLBatch",
        0x02 => "OldLogin",
        0x03 => "RPC",
        0x04 => "TabularResult",
        0x06 => "Attention",
        0x07 => "BulkLoad",
        0x0E => "Transaction",
        0x0F => "ConnectionClosed",
        0x10 => "Login7",
        0x11 => "SSPI",
        0x12 => "PreLogin",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prelogin_parsed() {
        let buf = [
            0x12, 0x01, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0xff,
        ];
        let mut p = MssqlParser::default();
        match p.parse(&buf, Direction::Tx) {
            MssqlParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 9);
                assert_eq!(record.type_name, "PreLogin");
                assert_eq!(record.length, 9);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_tds_bypasses() {
        let mut p = MssqlParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            MssqlParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_needs_more() {
        let mut p = MssqlParser::default();
        assert!(matches!(p.parse(&[0u8; 4], Direction::Tx), MssqlParserOutput::Need));
    }
}
