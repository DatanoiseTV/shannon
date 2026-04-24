//! Oracle TNS (Transparent Network Substrate) — tcp/1521.
//!
//! Every Oracle DB connection opens with a TNS CONNECT packet
//! whose body contains a plaintext connect descriptor:
//!
//! ```text
//!   (DESCRIPTION=
//!     (ADDRESS=(PROTOCOL=TCP)(HOST=db.example.com)(PORT=1521))
//!     (CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=sqlplus)...)))
//! ```
//!
//! Header (all big-endian):
//!
//! ```text
//!   u16 length
//!   u16 packet checksum   (usually 0)
//!   u8  type              (1 CONNECT, 2 ACCEPT, 4 REFUSE, 5 REDIRECT,
//!                          6 DATA, 11 RESEND, 12 MARKER, 13 ATTENTION,
//!                          14 CONTROL)
//!   u8  flags
//!   u16 header checksum
//! ```
//!
//! CONNECT layout from byte 8:
//!
//! ```text
//!   u16 version         u16 version_compat  u16 service_opts
//!   u16 sdu             u16 tdu             u16 nt_proto
//!   u16 line_turn       u16 value_of_one    u16 connect_data_len
//!   u16 connect_data_off
//!   u32 max_connect_data (newer)  u8 connect_flags_0/1 ...
//!   connect descriptor bytes at `connect_data_off`.
//! ```
//!
//! shannon pulls the packet type name + (for CONNECT) the descriptor
//! and parses SERVICE_NAME / SID / HOST / PROGRAM out of it.

use crate::events::Direction;

const HEADER: usize = 8;

pub struct OracleParser {
    bypass: bool,
}

impl Default for OracleParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum OracleParserOutput {
    Need,
    Record { record: OracleRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct OracleRecord {
    pub direction: Direction,
    pub packet_type: u8,
    pub type_name: &'static str,
    pub length: u16,
    pub service_name: Option<String>,
    pub sid: Option<String>,
    pub host: Option<String>,
    pub program: Option<String>,
    pub user: Option<String>,
    pub descriptor: Option<String>,
}

impl OracleRecord {
    pub fn display_line(&self) -> String {
        let svc = self
            .service_name
            .as_deref()
            .or(self.sid.as_deref())
            .map(|s| format!(" svc={s}"))
            .unwrap_or_default();
        let host = self
            .host
            .as_deref()
            .map(|s| format!(" host={s}"))
            .unwrap_or_default();
        let prog = self
            .program
            .as_deref()
            .map(|s| format!(" program={s}"))
            .unwrap_or_default();
        let user = self
            .user
            .as_deref()
            .map(|s| format!(" user={s}"))
            .unwrap_or_default();
        format!(
            "oracle {} len={}{svc}{host}{prog}{user}",
            self.type_name, self.length,
        )
    }
}

impl OracleParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> OracleParserOutput {
        if self.bypass {
            return OracleParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return OracleParserOutput::Need;
        }
        let length = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        let packet_type = buf[4];
        if !is_known_type(packet_type) {
            self.bypass = true;
            return OracleParserOutput::Skip(buf.len());
        }
        if length < HEADER || length > 65_535 {
            self.bypass = true;
            return OracleParserOutput::Skip(buf.len());
        }
        if buf.len() < length {
            return OracleParserOutput::Need;
        }
        let body = &buf[HEADER..length];
        let (service_name, sid, host, program, user, descriptor) = if packet_type == 1 {
            decode_connect(body)
        } else {
            (None, None, None, None, None, None)
        };
        OracleParserOutput::Record {
            record: OracleRecord {
                direction: dir,
                packet_type,
                type_name: type_name(packet_type),
                length: length as u16,
                service_name,
                sid,
                host,
                program,
                user,
                descriptor,
            },
            consumed: length,
        }
    }
}

fn decode_connect(body: &[u8]) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    // CONNECT body starts with 10 u16 fields; at byte offset 16 (0-based
    // within body) the connect-data offset lives. The connect-data
    // offset is measured from the start of the full packet, so we
    // subtract HEADER to get the offset within `body`.
    //
    // Different server versions add extra fields before the data, so
    // we're permissive: if the declared offset points beyond `body`
    // we fall back to a scan for the first '(' character.
    let desc_start = if body.len() >= 20 {
        // Layout: ...u16 connect_data_len (body[16..18]),
        //          u16 connect_data_off (body[18..20]).
        let off = u16::from_be_bytes([body[18], body[19]]) as usize;
        off.checked_sub(HEADER)
    } else {
        None
    };
    let descriptor_bytes = match desc_start {
        Some(o) if o < body.len() => &body[o..],
        _ => match body.iter().position(|&b| b == b'(') {
            Some(i) => &body[i..],
            None => return (None, None, None, None, None, None),
        },
    };
    let descriptor = std::str::from_utf8(descriptor_bytes)
        .ok()
        .map(|s| s.trim_matches(|c: char| c.is_control() || c == '\0').to_string());

    let d = descriptor.as_deref().unwrap_or("");
    (
        extract_kv(d, "SERVICE_NAME"),
        extract_kv(d, "SID"),
        extract_kv(d, "HOST"),
        extract_kv(d, "PROGRAM"),
        extract_kv(d, "USER"),
        descriptor,
    )
}

fn extract_kv(descriptor: &str, key: &str) -> Option<String> {
    // Find `(KEY=value)` allowing ASCII case-insensitive key.
    let needle = format!("({key}=");
    let lower = descriptor.to_ascii_uppercase();
    let pos = lower.find(&needle)?;
    let after = &descriptor[pos + needle.len()..];
    let end = after.find(')')?;
    Some(after[..end].trim().to_string())
}

const fn is_known_type(t: u8) -> bool {
    matches!(t, 1 | 2 | 3 | 4 | 5 | 6 | 7 | 11 | 12 | 13 | 14)
}

const fn type_name(t: u8) -> &'static str {
    match t {
        1 => "CONNECT",
        2 => "ACCEPT",
        3 => "ACK",
        4 => "REFUSE",
        5 => "REDIRECT",
        6 => "DATA",
        7 => "NULL",
        11 => "RESEND",
        12 => "MARKER",
        13 => "ATTENTION",
        14 => "CONTROL",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_with_service_name() {
        // Build a minimal CONNECT packet.
        let descriptor =
            b"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.example.com)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=sqlplus)(HOST=alice-mac)(USER=alice))))";
        let desc_len = descriptor.len();
        // Body: 22 bytes of u16 header fields before descriptor so
        // connect_data_off = HEADER + 22 = 30.
        let prefix_len = 22usize;
        let connect_off = (HEADER + prefix_len) as u16;
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // version
        body.extend_from_slice(&0u16.to_be_bytes()); // version_compat
        body.extend_from_slice(&0u16.to_be_bytes()); // service_opts
        body.extend_from_slice(&0u16.to_be_bytes()); // sdu
        body.extend_from_slice(&0u16.to_be_bytes()); // tdu
        body.extend_from_slice(&0u16.to_be_bytes()); // nt_proto
        body.extend_from_slice(&0u16.to_be_bytes()); // line_turn
        body.extend_from_slice(&0u16.to_be_bytes()); // value_of_one
        body.extend_from_slice(&(desc_len as u16).to_be_bytes()); // connect_data_len
        body.extend_from_slice(&connect_off.to_be_bytes()); // connect_data_off (byte 16..18)
        body.extend_from_slice(&[0u8; 2]); // padding to make 22 bytes
        assert_eq!(body.len(), prefix_len);
        body.extend_from_slice(descriptor);

        let mut pkt = Vec::new();
        let total = HEADER + body.len();
        pkt.extend_from_slice(&(total as u16).to_be_bytes()); // length
        pkt.extend_from_slice(&0u16.to_be_bytes()); // packet checksum
        pkt.push(1); // CONNECT
        pkt.push(0); // flags
        pkt.extend_from_slice(&0u16.to_be_bytes()); // header checksum
        pkt.extend_from_slice(&body);

        let mut p = OracleParser::default();
        match p.parse(&pkt, Direction::Tx) {
            OracleParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.type_name, "CONNECT");
                assert_eq!(record.service_name.as_deref(), Some("ORCL"));
                assert_eq!(record.host.as_deref(), Some("db.example.com"));
                assert_eq!(record.program.as_deref(), Some("sqlplus"));
                assert_eq!(record.user.as_deref(), Some("alice"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_tns_bypasses() {
        let mut p = OracleParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            OracleParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_needs_more() {
        let mut p = OracleParser::default();
        assert!(matches!(p.parse(&[0u8; 4], Direction::Tx), OracleParserOutput::Need));
    }
}
