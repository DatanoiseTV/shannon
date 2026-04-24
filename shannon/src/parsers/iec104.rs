//! IEC 60870-5-104 — SCADA telecontrol equipment & systems over TCP/2404.
//!
//! Each APDU is:
//! ```text
//!   0x68  [APDU length 1B]  [4 control octets]  [optional ASDU]
//! ```
//!
//! The four control octets encode one of three frame formats:
//!
//! - **I-format** (information transfer): CF1 bit 0 = 0. Carries an
//!   ASDU with TypeID, COT (cause of transmission), originator, and
//!   one or more IOs (information objects).
//! - **S-format** (supervisory): CF1 bits = `0b01`. Numbered
//!   acknowledgement of received I-frames; no ASDU body.
//! - **U-format** (unnumbered): CF1 bits = `0b11`. STARTDT, STOPDT,
//!   TESTFR each in `act`/`con` variants.
//!
//! For v1 we decode the format + the most common type IDs and causes;
//! full per-TypeID IO decoding is per-deployment work (there are
//! hundreds of standard + vendor TypeIDs).

use crate::events::Direction;

const START: u8 = 0x68;
const HEADER: usize = 2; // start + length
const MAX_APDU: usize = 253; // per spec

pub struct Iec104Parser {
    bypass: bool,
}

impl Default for Iec104Parser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum Iec104ParserOutput {
    Need,
    Record {
        record: Iec104Record,
        consumed: usize,
    },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct Iec104Record {
    pub direction: Direction,
    pub apdu_len: u8,
    pub frame: Frame,
}

#[derive(Debug, Clone)]
pub enum Frame {
    /// Information transfer frame.
    I {
        send_seq: u16,
        recv_seq: u16,
        asdu: Option<Asdu>,
    },
    /// Supervisory frame (ack).
    S { recv_seq: u16 },
    /// Unnumbered control frame.
    U { function: UFunction },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UFunction {
    StartDtAct,
    StartDtCon,
    StopDtAct,
    StopDtCon,
    TestFrAct,
    TestFrCon,
    Other(u8),
}

#[derive(Debug, Clone)]
pub struct Asdu {
    pub type_id: u8,
    pub type_name: &'static str,
    pub sq: bool, // sequence flag
    pub num_objects: u8,
    pub cot: u8, // cause of transmission
    pub cot_name: &'static str,
    pub negative_confirm: bool,
    pub test: bool,
    pub originator: u8,
    pub common_address: u16,
}

impl Iec104Record {
    pub fn display_line(&self) -> String {
        match &self.frame {
            Frame::I {
                send_seq,
                recv_seq,
                asdu,
            } => {
                let asdu_s = if let Some(a) = asdu {
                    format!(
                        " asdu={} ({})  cot={} ({})  oa={}  ca={}  objs={}",
                        a.type_id,
                        a.type_name,
                        a.cot,
                        a.cot_name,
                        a.originator,
                        a.common_address,
                        a.num_objects,
                    )
                } else {
                    String::new()
                };
                format!("iec104 I ss={send_seq} rs={recv_seq}{asdu_s}")
            }
            Frame::S { recv_seq } => format!("iec104 S rs={recv_seq}"),
            Frame::U { function } => format!("iec104 U fn={:?}", function),
        }
    }
}

impl Iec104Parser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> Iec104ParserOutput {
        if self.bypass {
            return Iec104ParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return Iec104ParserOutput::Need;
        }
        if buf[0] != START {
            self.bypass = true;
            return Iec104ParserOutput::Skip(buf.len());
        }
        let len = buf[1] as usize;
        if len < 4 || len > MAX_APDU {
            self.bypass = true;
            return Iec104ParserOutput::Skip(buf.len());
        }
        let total = HEADER + len;
        if buf.len() < total {
            return Iec104ParserOutput::Need;
        }
        let ctrl = &buf[2..6];
        let asdu_bytes = &buf[6..total];
        let frame = decode_frame(ctrl, asdu_bytes);
        let rec = Iec104Record {
            direction: dir,
            apdu_len: len as u8,
            frame,
        };
        Iec104ParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }
}

fn decode_frame(ctrl: &[u8], asdu_bytes: &[u8]) -> Frame {
    // CF1 low bits identify format:
    //   xxxxxxx0 = I
    //   xxxxxx01 = S
    //   xxxxxx11 = U
    let cf1 = ctrl[0];
    if cf1 & 0x01 == 0 {
        // I-format: send seq in CF1/CF2 (15-bit with shift), recv seq in CF3/CF4.
        let send_seq = u16::from_le_bytes([cf1, ctrl[1]]) >> 1;
        let recv_seq = u16::from_le_bytes([ctrl[2], ctrl[3]]) >> 1;
        let asdu = if asdu_bytes.is_empty() {
            None
        } else {
            decode_asdu(asdu_bytes)
        };
        Frame::I {
            send_seq,
            recv_seq,
            asdu,
        }
    } else if cf1 & 0x03 == 0x01 {
        // S-format: only recv seq.
        let recv_seq = u16::from_le_bytes([ctrl[2], ctrl[3]]) >> 1;
        Frame::S { recv_seq }
    } else {
        // U-format: identify from CF1 high bits per spec §5.
        let function = match cf1 {
            0x07 => UFunction::StartDtAct,
            0x0b => UFunction::StartDtCon,
            0x13 => UFunction::StopDtAct,
            0x23 => UFunction::StopDtCon,
            0x43 => UFunction::TestFrAct,
            0x83 => UFunction::TestFrCon,
            other => UFunction::Other(other),
        };
        Frame::U { function }
    }
}

fn decode_asdu(body: &[u8]) -> Option<Asdu> {
    if body.len() < 6 {
        return None;
    }
    let type_id = body[0];
    let vsq = body[1];
    let num_objects = vsq & 0x7f;
    let sq = vsq & 0x80 != 0;
    let cot_byte = body[2];
    let cot = cot_byte & 0x3f;
    let negative_confirm = cot_byte & 0x40 != 0;
    let test = cot_byte & 0x80 != 0;
    let originator = body[3];
    let common_address = u16::from_le_bytes([body[4], body[5]]);
    Some(Asdu {
        type_id,
        type_name: type_name(type_id),
        sq,
        num_objects,
        cot,
        cot_name: cot_name(cot),
        negative_confirm,
        test,
        originator,
        common_address,
    })
}

const fn type_name(t: u8) -> &'static str {
    match t {
        1 => "M_SP_NA_1 single-point (no time)",
        3 => "M_DP_NA_1 double-point (no time)",
        5 => "M_ST_NA_1 step position (no time)",
        9 => "M_ME_NA_1 measured normalised (no time)",
        11 => "M_ME_NB_1 measured scaled (no time)",
        13 => "M_ME_NC_1 measured short float (no time)",
        15 => "M_IT_NA_1 integrated totals (no time)",
        30 => "M_SP_TB_1 single-point (CP56Time)",
        31 => "M_DP_TB_1 double-point (CP56Time)",
        36 => "M_ME_TF_1 measured short float (CP56Time)",
        45 => "C_SC_NA_1 single command",
        46 => "C_DC_NA_1 double command",
        50 => "C_SE_NC_1 set-point short float",
        58 => "C_SC_TA_1 single command w/ time",
        100 => "C_IC_NA_1 general interrogation",
        101 => "C_CI_NA_1 counter interrogation",
        102 => "C_RD_NA_1 read command",
        103 => "C_CS_NA_1 clock sync",
        104 => "C_TS_NA_1 test command",
        105 => "C_RP_NA_1 reset process",
        107 => "C_TS_TA_1 test command w/ time",
        110 => "P_ME_NA_1 parameter normalised",
        111 => "P_ME_NB_1 parameter scaled",
        112 => "P_ME_NC_1 parameter short float",
        113 => "P_AC_NA_1 parameter activation",
        120 => "F_FR_NA_1 file ready",
        121 => "F_SR_NA_1 section ready",
        122 => "F_SC_NA_1 call directory / select file",
        123 => "F_LS_NA_1 last section",
        124 => "F_AF_NA_1 ack file / ack section",
        125 => "F_SG_NA_1 segment",
        126 => "F_DR_TA_1 directory",
        _ => "?",
    }
}

const fn cot_name(c: u8) -> &'static str {
    match c {
        1 => "periodic",
        2 => "background scan",
        3 => "spontaneous",
        4 => "initialised",
        5 => "request",
        6 => "activation",
        7 => "activation confirmation",
        8 => "deactivation",
        9 => "deactivation confirmation",
        10 => "activation termination",
        11 => "return info remote cmd",
        12 => "return info local cmd",
        13 => "file transfer",
        20 => "interrogated by general interrogation",
        44 => "unknown type",
        45 => "unknown cause",
        46 => "unknown common address",
        47 => "unknown info object address",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startdt_act() {
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let mut p = Iec104Parser::default();
        match p.parse(&buf, Direction::Tx) {
            Iec104ParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                match record.frame {
                    Frame::U { function } => assert_eq!(function, UFunction::StartDtAct),
                    _ => panic!("expected U-frame"),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn supervisory_ack() {
        // S-format: CF1=0x01, CF2=0x00, CF3/CF4 = recv seq 42 << 1 = 0x54.
        let buf = [0x68, 0x04, 0x01, 0x00, 0x54, 0x00];
        let mut p = Iec104Parser::default();
        match p.parse(&buf, Direction::Rx) {
            Iec104ParserOutput::Record { record, .. } => match record.frame {
                Frame::S { recv_seq } => assert_eq!(recv_seq, 42),
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn i_frame_with_asdu_carries_type_name() {
        // I-frame: CF1=0 CF2=0 CF3/CF4 = 0. ASDU body: type 100 (general
        // interrogation), vsq=1 (1 IO), cot=6 (activation), oa=0,
        // common_address=1.
        let mut buf = vec![0x68, 0x0a, 0x00, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&[100, 0x01, 0x06, 0x00, 0x01, 0x00]);
        let mut p = Iec104Parser::default();
        match p.parse(&buf, Direction::Tx) {
            Iec104ParserOutput::Record { record, .. } => match record.frame {
                Frame::I { asdu: Some(a), .. } => {
                    assert_eq!(a.type_id, 100);
                    assert_eq!(a.cot, 6);
                    assert_eq!(a.common_address, 1);
                    assert!(a.type_name.contains("general interrogation"));
                    assert_eq!(a.cot_name, "activation");
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn non_iec104_bypasses() {
        let mut p = Iec104Parser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            Iec104ParserOutput::Skip(_)
        ));
    }
}
