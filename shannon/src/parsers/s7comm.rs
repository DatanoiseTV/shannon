//! Siemens S7comm over ISO-TSAP — tcp/102.
//!
//! Stack layout:
//!
//! ```text
//!   TPKT (RFC 1006, 4 bytes)
//!     0x03 0x00 <len hi> <len lo>     (total length of entire PDU)
//!   COTP (ISO 8073, variable)
//!     <header len - 1> <PDU type> ...
//!   S7comm (starting byte 0x32)
//!     <protocol id 0x32>
//!     <ROSCTR>            0x01 Job | 0x02 Ack | 0x03 AckData | 0x07 Userdata
//!     <redundancy>        u16 BE (usually 0)
//!     <pdu ref>           u16 BE
//!     <param length>      u16 BE
//!     <data length>       u16 BE
//!     (AckData only) <error class><error code> 2 bytes
//!     <params ...>  <data ...>
//! ```
//!
//! We recognise TPKT + COTP + S7comm framing and surface the function
//! code (first parameter byte) with a human name for the common
//! operations: setup communication, read/write variables, upload/
//! download blocks, PLC start/stop, CPU diagnostics.

use crate::events::Direction;

const TPKT_HEADER: usize = 4;
const COTP_DT: u8 = 0xF0;
const S7_MAGIC: u8 = 0x32;

pub struct S7Parser {
    bypass: bool,
}

impl Default for S7Parser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum S7ParserOutput {
    Need,
    Record { record: S7Record, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct S7Record {
    pub direction: Direction,
    pub rosctr: u8,
    pub rosctr_name: &'static str,
    pub pdu_ref: u16,
    pub function_code: Option<u8>,
    pub function_name: &'static str,
    pub error_class: Option<u8>,
    pub error_code: Option<u8>,
    pub param_len: u16,
    pub data_len: u16,
}

impl S7Record {
    pub fn display_line(&self) -> String {
        let err = if let (Some(ec), Some(ecd)) = (self.error_class, self.error_code) {
            if ec != 0 || ecd != 0 {
                format!(" err=0x{ec:02x}{ecd:02x}")
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        format!(
            "s7 {} pduref={} fn=0x{:02x} ({}) param={}B data={}B{}",
            self.rosctr_name,
            self.pdu_ref,
            self.function_code.unwrap_or(0),
            self.function_name,
            self.param_len,
            self.data_len,
            err,
        )
    }
}

impl S7Parser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> S7ParserOutput {
        if self.bypass {
            return S7ParserOutput::Skip(buf.len());
        }
        if buf.len() < TPKT_HEADER {
            return S7ParserOutput::Need;
        }
        // TPKT: version must be 0x03, reserved 0x00.
        if buf[0] != 0x03 || buf[1] != 0x00 {
            self.bypass = true;
            return S7ParserOutput::Skip(buf.len());
        }
        let total = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if total < 7 || total > 65_535 {
            self.bypass = true;
            return S7ParserOutput::Skip(buf.len());
        }
        if buf.len() < total {
            return S7ParserOutput::Need;
        }
        let rest = &buf[TPKT_HEADER..total];
        // COTP header: first byte = header length minus 1, second = PDU type.
        if rest.len() < 2 {
            self.bypass = true;
            return S7ParserOutput::Skip(total);
        }
        let cotp_len = rest[0] as usize;
        let cotp_pdu_type = rest[1];
        if cotp_len + 1 > rest.len() {
            self.bypass = true;
            return S7ParserOutput::Skip(total);
        }
        // Only DT (0xF0) carries user data. CR/CC/DC/etc. emit a lighter record.
        if cotp_pdu_type != COTP_DT {
            let rec = S7Record {
                direction: dir,
                rosctr: 0,
                rosctr_name: match cotp_pdu_type {
                    0xE0 => "COTP CR",
                    0xD0 => "COTP CC",
                    0x80 => "COTP DC",
                    0x50 => "COTP ED",
                    0x70 => "COTP EA",
                    _ => "COTP ?",
                },
                pdu_ref: 0,
                function_code: None,
                function_name: "",
                error_class: None,
                error_code: None,
                param_len: 0,
                data_len: 0,
            };
            return S7ParserOutput::Record { record: rec, consumed: total };
        }
        let s7 = &rest[cotp_len + 1..];
        if s7.is_empty() || s7[0] != S7_MAGIC {
            // Not an S7 message even though TPKT/COTP looked right.
            self.bypass = true;
            return S7ParserOutput::Skip(total);
        }
        if s7.len() < 10 {
            self.bypass = true;
            return S7ParserOutput::Skip(total);
        }
        let rosctr = s7[1];
        let pdu_ref = u16::from_be_bytes([s7[4], s7[5]]);
        let param_len = u16::from_be_bytes([s7[6], s7[7]]);
        let data_len = u16::from_be_bytes([s7[8], s7[9]]);
        let mut cursor = 10usize;
        let (error_class, error_code) = if rosctr == 0x03 && s7.len() >= cursor + 2 {
            let ec = s7[cursor];
            let ecd = s7[cursor + 1];
            cursor += 2;
            (Some(ec), Some(ecd))
        } else {
            (None, None)
        };
        let function_code = if (param_len as usize) > 0 && s7.len() > cursor {
            Some(s7[cursor])
        } else {
            None
        };
        let rec = S7Record {
            direction: dir,
            rosctr,
            rosctr_name: rosctr_name(rosctr),
            pdu_ref,
            function_code,
            function_name: function_code.map(function_name).unwrap_or(""),
            error_class,
            error_code,
            param_len,
            data_len,
        };
        S7ParserOutput::Record { record: rec, consumed: total }
    }
}

const fn rosctr_name(r: u8) -> &'static str {
    match r {
        0x01 => "Job",
        0x02 => "Ack",
        0x03 => "AckData",
        0x07 => "Userdata",
        _ => "?",
    }
}

const fn function_name(code: u8) -> &'static str {
    match code {
        0x00 => "CPU services",
        0x04 => "Read Var",
        0x05 => "Write Var",
        0x1a => "Request download",
        0x1b => "Download block",
        0x1c => "Download ended",
        0x1d => "Start upload",
        0x1e => "Upload",
        0x1f => "End upload",
        0x28 => "PLC Control",
        0x29 => "PLC Stop",
        0xf0 => "Setup communication",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_communication_job() {
        // Build TPKT + COTP-DT + S7 Setup Communication (fn 0xf0).
        //   COTP: 02 f0 80
        //   S7:   32 01 00 00 <pduref=0x0001> <param=8> <data=0>
        //           param: f0 00 00 01 00 01 03 c0
        let cotp = [0x02, 0xf0, 0x80];
        let mut s7 = Vec::new();
        s7.extend_from_slice(&[0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00]);
        s7.extend_from_slice(&[0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0xc0]);
        let total_without_tpkt = cotp.len() + s7.len();
        let total = TPKT_HEADER + total_without_tpkt;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x03, 0x00]);
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&cotp);
        pkt.extend_from_slice(&s7);
        let mut p = S7Parser::default();
        match p.parse(&pkt, Direction::Tx) {
            S7ParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.rosctr, 0x01);
                assert_eq!(record.rosctr_name, "Job");
                assert_eq!(record.function_code, Some(0xf0));
                assert_eq!(record.function_name, "Setup communication");
            }
            _ => panic!("expected record"),
        }
    }

    #[test]
    fn non_s7_bypasses() {
        let mut p = S7Parser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            S7ParserOutput::Skip(_)
        ));
    }

    #[test]
    fn partial_returns_need() {
        let mut p = S7Parser::default();
        assert!(matches!(p.parse(&[0x03, 0x00], Direction::Tx), S7ParserOutput::Need));
    }
}
