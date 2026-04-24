//! Microsoft RDP handshake — tcp/3389.
//!
//! RDP runs TPKT + COTP + MCS + GCC + RDP PDUs. The first meaningful
//! security artefact lives in the X.224 Connection Request that
//! kicks off every session: optionally prefixed by the "Cookie:
//! mstshash=<username>\r\n" line some clients send before the
//! rdpNegData block. That username flows in the clear — older
//! Windows servers and misconfigured Gateways accept it as a session
//! hint and log it; shannon surfaces it so operators see which
//! accounts are being sprayed at their RDP frontends.
//!
//! Frame layout:
//!
//! ```text
//!   TPKT (RFC 1006, 4 bytes):
//!     0x03 0x00 <len hi> <len lo>
//!   COTP Connection Request (variable):
//!     <header_len - 1> 0xE0 <dst_ref u16 BE> <src_ref u16 BE> <class>
//!     <optional user data>
//!       "Cookie: mstshash=...\r\n"   (RDP routing token)
//!       rdpNegReq = 0x01 <flags> u16 length u32 requested_protocols
//! ```
//!
//! Supported-protocol flags: 0x01 TLS, 0x02 CredSSP, 0x08 RDSTLS.
//! Plain legacy RDP is 0x00.

use crate::events::Direction;

const TPKT_HEADER: usize = 4;
const COTP_CR: u8 = 0xE0;

pub struct RdpParser {
    bypass: bool,
    done: bool,
}

impl Default for RdpParser {
    fn default() -> Self {
        Self {
            bypass: false,
            done: false,
        }
    }
}

pub enum RdpParserOutput {
    Need,
    Record { record: RdpRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct RdpRecord {
    pub direction: Direction,
    pub kind: RdpKind,
    pub mstshash: Option<String>,
    pub requested_protocols: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpKind {
    ConnectionRequest,
    ConnectionConfirm,
}

impl RdpRecord {
    pub fn display_line(&self) -> String {
        let kind = match self.kind {
            RdpKind::ConnectionRequest => "CR",
            RdpKind::ConnectionConfirm => "CC",
        };
        let user = self
            .mstshash
            .as_deref()
            .map(|s| format!(" mstshash={s}"))
            .unwrap_or_default();
        let protos = self
            .requested_protocols
            .map(|p| format!(" proto={}", format_protocols(p)))
            .unwrap_or_default();
        format!("rdp {kind}{user}{protos}")
    }
}

fn format_protocols(p: u32) -> String {
    if p == 0 {
        return "RDP".to_string();
    }
    let mut out = Vec::new();
    if p & 0x01 != 0 {
        out.push("TLS");
    }
    if p & 0x02 != 0 {
        out.push("CredSSP");
    }
    if p & 0x04 != 0 {
        out.push("CredSSP-EA");
    }
    if p & 0x08 != 0 {
        out.push("RDSTLS");
    }
    if p & 0x10 != 0 {
        out.push("EARLY");
    }
    if out.is_empty() {
        format!("0x{p:x}")
    } else {
        out.join("+")
    }
}

impl RdpParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> RdpParserOutput {
        if self.bypass || self.done {
            return RdpParserOutput::Skip(buf.len());
        }
        if buf.len() < TPKT_HEADER {
            return RdpParserOutput::Need;
        }
        if buf[0] != 0x03 || buf[1] != 0x00 {
            self.bypass = true;
            return RdpParserOutput::Skip(buf.len());
        }
        let total = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if total < 7 || total > 65_535 {
            self.bypass = true;
            return RdpParserOutput::Skip(buf.len());
        }
        if buf.len() < total {
            return RdpParserOutput::Need;
        }
        let rest = &buf[TPKT_HEADER..total];
        if rest.len() < 2 {
            self.bypass = true;
            return RdpParserOutput::Skip(total);
        }
        let cotp_len = rest[0] as usize;
        let pdu_type = rest[1];
        // We only deal with CR (client→server) and CC (server→client).
        let kind = match pdu_type {
            0xE0 => RdpKind::ConnectionRequest,
            0xD0 => RdpKind::ConnectionConfirm,
            _ => {
                self.bypass = true;
                return RdpParserOutput::Skip(total);
            }
        };
        if cotp_len + 1 > rest.len() {
            self.bypass = true;
            return RdpParserOutput::Skip(total);
        }
        let user_data = &rest[cotp_len + 1..];
        let (mstshash, requested_protocols) = match kind {
            RdpKind::ConnectionRequest => decode_connection_request(user_data),
            RdpKind::ConnectionConfirm => decode_connection_confirm(user_data),
        };
        self.done = true;
        RdpParserOutput::Record {
            record: RdpRecord {
                direction: dir,
                kind,
                mstshash,
                requested_protocols,
            },
            consumed: total,
        }
    }
}

fn decode_connection_request(mut ud: &[u8]) -> (Option<String>, Option<u32>) {
    // Optional "Cookie: mstshash=...\r\n"
    let mut mstshash = None;
    if ud.starts_with(b"Cookie: ") {
        if let Some(end) = ud.iter().position(|&b| b == b'\n') {
            if let Ok(line) = std::str::from_utf8(&ud[..end]) {
                if let Some(rest) = line.trim().strip_prefix("Cookie: mstshash=") {
                    mstshash = Some(rest.to_string());
                }
            }
            ud = &ud[end + 1..];
        }
    }
    // rdpNegReq: type 0x01, flags u8, length u16 LE (=8), requested_protocols u32 LE
    let requested_protocols = parse_rdp_neg(ud, 0x01);
    (mstshash, requested_protocols)
}

fn decode_connection_confirm(ud: &[u8]) -> (Option<String>, Option<u32>) {
    // rdpNegRsp = 0x02, or rdpNegFailure = 0x03
    (None, parse_rdp_neg(ud, 0x02))
}

fn parse_rdp_neg(ud: &[u8], expected_type: u8) -> Option<u32> {
    if ud.len() < 8 {
        return None;
    }
    if ud[0] != expected_type {
        return None;
    }
    // ud[1] = flags, ud[2..4] = length LE, ud[4..8] = requested_protocols LE
    let len = u16::from_le_bytes([ud[2], ud[3]]);
    if len != 8 {
        return None;
    }
    Some(u32::from_le_bytes([ud[4], ud[5], ud[6], ud[7]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_request_with_mstshash_and_tls() {
        // TPKT + COTP-CR with "Cookie: mstshash=admin\r\n" + rdpNegReq TLS.
        let cookie = b"Cookie: mstshash=admin\r\n";
        let neg = [0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00]; // TLS
        let mut cotp = vec![0u8; 7]; // placeholder for length byte + fields
        cotp[1] = 0xE0; // CR
        cotp[2] = 0x00;
        cotp[3] = 0x00; // dst_ref
        cotp[4] = 0x00;
        cotp[5] = 0x00; // src_ref
        cotp[6] = 0x00; // class
        let mut ud = Vec::new();
        ud.extend_from_slice(cookie);
        ud.extend_from_slice(&neg);
        let mut rest = Vec::new();
        rest.extend_from_slice(&cotp);
        // cotp_len field (rest[0]) = header_len - 1. Header = 7 bytes → 6.
        rest[0] = 6;
        rest.extend_from_slice(&ud);
        let total = TPKT_HEADER + rest.len();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x03, 0x00]);
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&rest);

        let mut p = RdpParser::default();
        match p.parse(&pkt, Direction::Tx) {
            RdpParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.kind, RdpKind::ConnectionRequest);
                assert_eq!(record.mstshash.as_deref(), Some("admin"));
                assert_eq!(record.requested_protocols, Some(1));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn short_buffer_needs_more() {
        let mut p = RdpParser::default();
        assert!(matches!(
            p.parse(&[0x03, 0x00], Direction::Tx),
            RdpParserOutput::Need
        ));
    }

    #[test]
    fn non_rdp_bypasses() {
        let mut p = RdpParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            RdpParserOutput::Skip(_)
        ));
    }
}
