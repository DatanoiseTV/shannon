//! EtherNet/IP + CIP encapsulation (Volume 2 of The CIP Networks
//! Library, ODVA spec) on tcp/44818.
//!
//! Encapsulation header (24 bytes, little-endian):
//!
//! ```text
//!   u16 command
//!   u16 length                 (bytes of data following the header)
//!   u32 session handle
//!   u32 status
//!   u64 sender context         (opaque, for request/response matching)
//!   u32 options
//! ```
//!
//! Commands we name: `NOP`, `ListServices`, `ListIdentity`,
//! `ListInterfaces`, `RegisterSession`, `UnRegisterSession`,
//! `SendRRData`, `SendUnitData`, `IndicateStatus`, `Cancel`.
//!
//! Full CIP decoding (service / class / instance / attribute paths,
//! connection manager, forward open, read tag, write tag) is a deeper
//! follow-up pass; the encapsulation record already tells operators
//! who registered a session, who sent what kind of traffic, and
//! surfaces status codes.

use crate::events::Direction;

const HEADER: usize = 24;
const MAX_DATA: usize = 65_511; // max length per spec

pub struct EnipParser {
    bypass: bool,
}

impl Default for EnipParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum EnipParserOutput {
    Need,
    Record { record: EnipRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct EnipRecord {
    pub direction: Direction,
    pub command: u16,
    pub command_name: &'static str,
    pub length: u16,
    pub session_handle: u32,
    pub status: u32,
    pub status_name: &'static str,
    pub sender_context: u64,
    pub options: u32,
}

impl EnipRecord {
    pub fn display_line(&self) -> String {
        format!(
            "enip {} (0x{:04x}) session=0x{:08x} status={} ({}) ctx=0x{:016x} data={}B",
            self.command_name,
            self.command,
            self.session_handle,
            self.status,
            self.status_name,
            self.sender_context,
            self.length,
        )
    }
}

impl EnipParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> EnipParserOutput {
        if self.bypass {
            return EnipParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return EnipParserOutput::Need;
        }
        let command = u16::from_le_bytes([buf[0], buf[1]]);
        let length = u16::from_le_bytes([buf[2], buf[3]]);
        if !is_known_command(command) {
            self.bypass = true;
            return EnipParserOutput::Skip(buf.len());
        }
        if (length as usize) > MAX_DATA {
            self.bypass = true;
            return EnipParserOutput::Skip(buf.len());
        }
        let total = HEADER + length as usize;
        if buf.len() < total {
            return EnipParserOutput::Need;
        }
        let session_handle = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let status = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let sender_context = u64::from_le_bytes([
            buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
        ]);
        let options = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        EnipParserOutput::Record {
            record: EnipRecord {
                direction: dir,
                command,
                command_name: command_name(command),
                length,
                session_handle,
                status,
                status_name: status_name(status),
                sender_context,
                options,
            },
            consumed: total,
        }
    }
}

const fn is_known_command(cmd: u16) -> bool {
    matches!(
        cmd,
        0x0000
            | 0x0004
            | 0x0063
            | 0x0064
            | 0x0065
            | 0x0066
            | 0x006f
            | 0x0070
            | 0x0072
            | 0x0073
    )
}

const fn command_name(cmd: u16) -> &'static str {
    match cmd {
        0x0000 => "NOP",
        0x0004 => "ListServices",
        0x0063 => "ListIdentity",
        0x0064 => "ListInterfaces",
        0x0065 => "RegisterSession",
        0x0066 => "UnRegisterSession",
        0x006f => "SendRRData",
        0x0070 => "SendUnitData",
        0x0072 => "IndicateStatus",
        0x0073 => "Cancel",
        _ => "?",
    }
}

const fn status_name(code: u32) -> &'static str {
    match code {
        0x0000 => "success",
        0x0001 => "invalid or unsupported command",
        0x0002 => "insufficient memory",
        0x0003 => "poorly-formed data",
        0x0064 => "invalid session handle",
        0x0065 => "invalid length",
        0x0069 => "unsupported encapsulation protocol revision",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_session_parsed() {
        // RegisterSession (0x0065), length=4, session=0, status=0,
        // ctx=0xdeadbeefcafebabe, options=0, data=[0x01,0x00,0x00,0x00]
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0065u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0xdead_beef_cafe_babeu64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let mut p = EnipParser::default();
        match p.parse(&buf, Direction::Tx) {
            EnipParserOutput::Record { record, consumed } => {
                assert_eq!(record.command, 0x0065);
                assert_eq!(record.command_name, "RegisterSession");
                assert_eq!(record.length, 4);
                assert_eq!(record.sender_context, 0xdead_beef_cafe_babe);
                assert_eq!(consumed, buf.len());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_enip_bypasses() {
        let mut p = EnipParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n\r\n", Direction::Tx),
            EnipParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_buffer_needs_more() {
        let mut p = EnipParser::default();
        assert!(matches!(p.parse(&[0u8; 12], Direction::Tx), EnipParserOutput::Need));
    }
}
