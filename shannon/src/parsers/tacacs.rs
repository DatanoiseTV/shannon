//! TACACS+ (RFC 8907) — tcp/49.
//!
//! Cisco's network-device AAA protocol; the enterprise equivalent
//! of RADIUS for managing routers / switches / firewalls. Each
//! message is a 12-byte header followed by an optionally-obfuscated
//! body:
//!
//! ```text
//!   u8  major<<4 | minor
//!   u8  type      (1 AUTHEN, 2 AUTHOR, 3 ACCT)
//!   u8  seq
//!   u8  flags     (bit0 UNENCRYPTED, bit2 SINGLE_CONNECT)
//!   u32 session_id   (BE)
//!   u32 length       (BE)
//! ```
//!
//! The body is XOR-scrambled with a key derived from the shared
//! secret + session_id + seq + version. shannon does not attempt to
//! decode the body — what matters for observability is who's
//! authenticating where, how often, and whether the session is
//! operating in the (deprecated) unencrypted mode that makes
//! credentials readable on the wire. The parser surfaces all of
//! that from the header.

use crate::events::Direction;

const HEADER: usize = 12;

pub struct TacacsParser {
    bypass: bool,
}

impl Default for TacacsParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum TacacsParserOutput {
    Need,
    Record {
        record: TacacsRecord,
        consumed: usize,
    },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct TacacsRecord {
    pub direction: Direction,
    pub major: u8,
    pub minor: u8,
    pub packet_type: u8,
    pub type_name: &'static str,
    pub seq: u8,
    pub flags: u8,
    pub unencrypted: bool,
    pub single_connect: bool,
    pub session_id: u32,
    pub length: u32,
}

impl TacacsRecord {
    pub fn display_line(&self) -> String {
        let enc = if self.unencrypted { " UNENCRYPTED" } else { "" };
        let sc = if self.single_connect {
            " single-conn"
        } else {
            ""
        };
        format!(
            "tacacs+ v{}.{} {} seq={} sess=0x{:08x} len={}{enc}{sc}",
            self.major, self.minor, self.type_name, self.seq, self.session_id, self.length,
        )
    }
}

impl TacacsParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> TacacsParserOutput {
        if self.bypass {
            return TacacsParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return TacacsParserOutput::Need;
        }
        let major = buf[0] >> 4;
        let minor = buf[0] & 0x0f;
        if major != 0xc {
            self.bypass = true;
            return TacacsParserOutput::Skip(buf.len());
        }
        let packet_type = buf[1];
        if !(1..=3).contains(&packet_type) {
            self.bypass = true;
            return TacacsParserOutput::Skip(buf.len());
        }
        let seq = buf[2];
        let flags = buf[3];
        let session_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let length = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if length > 1 << 20 {
            self.bypass = true;
            return TacacsParserOutput::Skip(buf.len());
        }
        let total = HEADER + length as usize;
        if buf.len() < total {
            return TacacsParserOutput::Need;
        }
        TacacsParserOutput::Record {
            record: TacacsRecord {
                direction: dir,
                major,
                minor,
                packet_type,
                type_name: type_name(packet_type),
                seq,
                flags,
                unencrypted: flags & 0x01 != 0,
                single_connect: flags & 0x04 != 0,
                session_id,
                length,
            },
            consumed: total,
        }
    }
}

const fn type_name(t: u8) -> &'static str {
    match t {
        1 => "AUTHEN",
        2 => "AUTHOR",
        3 => "ACCT",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authen_start() {
        let mut buf = Vec::new();
        buf.push(0xc1); // major=c minor=1
        buf.push(1); // AUTHEN
        buf.push(1); // seq
        buf.push(0); // flags
        buf.extend_from_slice(&0xdead_beefu32.to_be_bytes()); // session
        buf.extend_from_slice(&8u32.to_be_bytes()); // length
        buf.extend_from_slice(&[0u8; 8]); // body
        let mut p = TacacsParser::default();
        match p.parse(&buf, Direction::Tx) {
            TacacsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.major, 0xc);
                assert_eq!(record.type_name, "AUTHEN");
                assert_eq!(record.session_id, 0xdead_beef);
                assert!(!record.unencrypted);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn short_needs_more() {
        let mut p = TacacsParser::default();
        assert!(matches!(
            p.parse(&[0u8; 5], Direction::Tx),
            TacacsParserOutput::Need
        ));
    }

    #[test]
    fn non_tacacs_bypasses() {
        let mut p = TacacsParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            TacacsParserOutput::Skip(_)
        ));
    }
}
