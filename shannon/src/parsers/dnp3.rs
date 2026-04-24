//! DNP3 over TCP (IEEE 1815) — tcp/20000 default.
//!
//! Link-layer frame layout (all little-endian except the start bytes):
//!
//! ```text
//!   0x05 0x64              (2-byte start)
//!   length                 (1 byte: count from CTRL to end of user data,
//!                           excludes start/length/header-CRC)
//!   ctrl                   (1 byte: DIR/PRM/FCB/FCV + function code)
//!   dest                   (2 bytes LE)
//!   src                    (2 bytes LE)
//!   header CRC             (2 bytes LE)
//!   user data blocks       (each 16 bytes + 2-byte CRC, last may be short)
//! ```
//!
//! We extract the link header fields + function code + source / dest
//! addresses. Transport and Application layers (where the actual
//! binary/analog inputs, commands, time sync, etc. live) are more
//! elaborate; v1 surfaces the link envelope so operators see who talks
//! to whom at what frequency — enough for observability and for
//! spotting anomalous function codes.

use crate::events::Direction;

pub struct Dnp3Parser {
    bypass: bool,
}

impl Default for Dnp3Parser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum Dnp3ParserOutput {
    Need,
    Record { record: Dnp3Record, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct Dnp3Record {
    pub direction: Direction,
    pub length: u8,
    pub dir_bit: bool,    // DIR
    pub prm: bool,        // PRM (primary message)
    pub fcb: bool,        // frame count bit
    pub fcv_or_dfc: bool, // FCV for primary, DFC for secondary
    pub function_code: u8,
    pub function_name: &'static str,
    pub source: u16,
    pub destination: u16,
}

impl Dnp3Record {
    pub fn display_line(&self) -> String {
        let role = if self.prm { "PRI" } else { "SEC" };
        let dir = if self.dir_bit {
            "from-master"
        } else {
            "to-master"
        };
        format!(
            "dnp3 {role} {} {:#04x} ({}) src={} dst={} len={}",
            dir, self.function_code, self.function_name, self.source, self.destination, self.length,
        )
    }
}

impl Dnp3Parser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> Dnp3ParserOutput {
        if self.bypass {
            return Dnp3ParserOutput::Skip(buf.len());
        }
        if buf.len() < 10 {
            return Dnp3ParserOutput::Need;
        }
        if !(buf[0] == 0x05 && buf[1] == 0x64) {
            self.bypass = true;
            return Dnp3ParserOutput::Skip(buf.len());
        }
        let length = buf[2];
        if length < 5 {
            self.bypass = true;
            return Dnp3ParserOutput::Skip(buf.len());
        }
        let ctrl = buf[3];
        let destination = u16::from_le_bytes([buf[4], buf[5]]);
        let source = u16::from_le_bytes([buf[6], buf[7]]);
        // buf[8..10] = header CRC (not validated in v1).

        // Total frame size = 10 header bytes + user-data blocks.
        // user-data count = length - 5 (excluded address bytes + ctrl).
        let user_data_bytes = (length as usize).saturating_sub(5);
        // Each 16-byte block gets a trailing 2-byte CRC; last block
        // may be short.
        let full_blocks = user_data_bytes / 16;
        let last_block_bytes = user_data_bytes % 16;
        let mut extra = full_blocks * 18;
        if last_block_bytes > 0 {
            extra += last_block_bytes + 2;
        }
        let total = 10 + extra;
        if buf.len() < total {
            return Dnp3ParserOutput::Need;
        }

        let dir_bit = ctrl & 0x80 != 0;
        let prm = ctrl & 0x40 != 0;
        let fcb = ctrl & 0x20 != 0;
        let fcv_or_dfc = ctrl & 0x10 != 0;
        let function_code = ctrl & 0x0f;
        let function_name = if prm {
            primary_function_name(function_code)
        } else {
            secondary_function_name(function_code)
        };

        Dnp3ParserOutput::Record {
            record: Dnp3Record {
                direction: dir,
                length,
                dir_bit,
                prm,
                fcb,
                fcv_or_dfc,
                function_code,
                function_name,
                source,
                destination,
            },
            consumed: total,
        }
    }
}

const fn primary_function_name(code: u8) -> &'static str {
    match code {
        0 => "RESET_LINK_STATES",
        1 => "RESET_USER_PROCESS (obsolete)",
        2 => "TEST_LINK_STATES",
        3 => "REQUEST_LINK_STATUS",
        4 => "UNCONFIRMED_USER_DATA",
        // 4 is unconfirmed data; 3 is test link in modern spec.
        // IEEE 1815 current codes:
        9 => "RESET_LINK_STATES_ACK",
        _ => "?",
    }
}

const fn secondary_function_name(code: u8) -> &'static str {
    match code {
        0 => "ACK",
        1 => "NACK",
        11 => "STATUS_OF_LINK",
        14 => "LINK_SERVICE_NOT_FUNCTIONING",
        15 => "LINK_SERVICE_NOT_IMPLEMENTED",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_buffer_needs_more() {
        let mut p = Dnp3Parser::default();
        assert!(matches!(
            p.parse(&[0u8; 5], Direction::Tx),
            Dnp3ParserOutput::Need
        ));
    }

    #[test]
    fn non_dnp3_bypasses() {
        let mut p = Dnp3Parser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n\r\n", Direction::Tx),
            Dnp3ParserOutput::Skip(_)
        ));
    }

    #[test]
    fn reset_link_states_primary() {
        // start=0x05 0x64, len=5 (ctrl + dst + src, no user data),
        // ctrl=0xc0 (DIR=1, PRM=1, FCB=0, FCV=0, func=0 = RESET_LINK_STATES),
        // dst=0x0001, src=0x0002, header crc 0xabcd (not validated).
        let buf: [u8; 10] = [0x05, 0x64, 5, 0xc0, 0x01, 0x00, 0x02, 0x00, 0xab, 0xcd];
        let mut p = Dnp3Parser::default();
        match p.parse(&buf, Direction::Tx) {
            Dnp3ParserOutput::Record { record, consumed } => {
                assert_eq!(record.length, 5);
                assert_eq!(record.destination, 1);
                assert_eq!(record.source, 2);
                assert_eq!(record.function_code, 0);
                assert!(record.prm);
                assert!(record.dir_bit);
                assert_eq!(consumed, 10);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn frame_with_one_user_block() {
        // length = 5 + 16 bytes of user data
        let mut buf = vec![0x05, 0x64, 21, 0xc4, 0x01, 0x00, 0x02, 0x00, 0xde, 0xad];
        // 16 bytes of user data + 2 CRC
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&[0xcc, 0xcc]);
        let mut p = Dnp3Parser::default();
        match p.parse(&buf, Direction::Tx) {
            Dnp3ParserOutput::Record { consumed, .. } => {
                assert_eq!(consumed, buf.len());
            }
            _ => panic!(),
        }
    }
}
