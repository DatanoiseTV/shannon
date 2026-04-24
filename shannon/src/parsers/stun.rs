//! STUN / TURN (RFC 8489, RFC 8656) — udp/3478, tcp/3478, tls/5349.
//!
//! STUN is the signalling backbone of WebRTC, SIP media, and every
//! NAT-traversal stack. TURN extends STUN with relayed transport for
//! peers that can't hole-punch. Both share the 20-byte header:
//!
//! ```text
//!   u16 type      (0b00<class:2><method:12> — STUN magic in top 2 bits)
//!   u16 length    (attribute-bytes after header, excludes header)
//!   u32 cookie    (0x2112A442 — the "magic cookie")
//!   u8[12] txid   (transaction id — request/response matching)
//!   attributes    (TLV: u16 type, u16 length, value, 4-byte padded)
//! ```
//!
//! Classes: Request, Indication, Success-Response, Error-Response.
//! Common methods: Binding (STUN), Allocate/Refresh/CreatePermission
//! /Send/Data/ChannelBind (TURN). A handful of attributes are named
//! for readability: MAPPED-ADDRESS, XOR-MAPPED-ADDRESS, USERNAME,
//! REALM, NONCE, SOFTWARE, ERROR-CODE.
//!
//! We surface the class + method + first XOR-MAPPED-ADDRESS (the
//! reflexive candidate a client advertises during ICE) and any
//! SOFTWARE string (many stacks leak their exact vendor build here).

use crate::events::Direction;

const HEADER: usize = 20;
const MAGIC: u32 = 0x2112_A442;

pub struct StunParser {
    bypass: bool,
}

impl Default for StunParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum StunParserOutput {
    Need,
    Record { record: StunRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct StunRecord {
    pub direction: Direction,
    pub class: Class,
    pub method: u16,
    pub method_name: &'static str,
    pub length: u16,
    pub transaction_id: [u8; 12],
    pub xor_mapped: Option<MappedAddr>,
    pub mapped: Option<MappedAddr>,
    pub username: Option<String>,
    pub software: Option<String>,
    pub realm: Option<String>,
    pub error_code: Option<u16>,
    pub error_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl Class {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Request => "Request",
            Self::Indication => "Indication",
            Self::SuccessResponse => "Success",
            Self::ErrorResponse => "Error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MappedAddr {
    pub family: u8, // 1 = IPv4, 2 = IPv6
    pub port: u16,
    pub ip: Vec<u8>,
}

impl MappedAddr {
    pub fn display(&self) -> String {
        match self.family {
            1 if self.ip.len() == 4 => format!(
                "{}.{}.{}.{}:{}",
                self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port
            ),
            2 if self.ip.len() == 16 => {
                let groups: Vec<String> = self
                    .ip
                    .chunks_exact(2)
                    .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                    .collect();
                format!("[{}]:{}", groups.join(":"), self.port)
            }
            _ => format!("?:{}", self.port),
        }
    }
}

impl StunRecord {
    pub fn display_line(&self) -> String {
        let addr = self
            .xor_mapped
            .as_ref()
            .or(self.mapped.as_ref())
            .map(|a| format!(" mapped={}", a.display()))
            .unwrap_or_default();
        let sw = self
            .software
            .as_deref()
            .map(|s| format!(" sw=\"{s}\""))
            .unwrap_or_default();
        let user = self
            .username
            .as_deref()
            .map(|s| format!(" user={s}"))
            .unwrap_or_default();
        let err = match (self.error_code, &self.error_reason) {
            (Some(c), Some(r)) => format!(" err={c} \"{r}\""),
            (Some(c), None) => format!(" err={c}"),
            _ => String::new(),
        };
        format!(
            "stun {} {}{}{}{}{}",
            self.class.label(),
            self.method_name,
            addr,
            sw,
            user,
            err,
        )
    }
}

impl StunParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> StunParserOutput {
        if self.bypass {
            return StunParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return StunParserOutput::Need;
        }
        // Top 2 bits of the type word must be zero for classic STUN.
        if buf[0] & 0xc0 != 0 {
            self.bypass = true;
            return StunParserOutput::Skip(buf.len());
        }
        let type_word = u16::from_be_bytes([buf[0], buf[1]]);
        let length = u16::from_be_bytes([buf[2], buf[3]]);
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != MAGIC {
            self.bypass = true;
            return StunParserOutput::Skip(buf.len());
        }
        // Attribute blocks are 4-byte-aligned; header length already
        // excludes the 20 header bytes.
        let total = HEADER + length as usize;
        if buf.len() < total {
            return StunParserOutput::Need;
        }
        let (class, method) = decode_class_method(type_word);
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&buf[8..20]);
        let attrs = &buf[HEADER..total];
        let (xor_mapped, mapped, username, software, realm, error_code, error_reason) =
            decode_attributes(attrs, &transaction_id);
        let rec = StunRecord {
            direction: dir,
            class,
            method,
            method_name: method_name(method),
            length,
            transaction_id,
            xor_mapped,
            mapped,
            username,
            software,
            realm,
            error_code,
            error_reason,
        };
        StunParserOutput::Record { record: rec, consumed: total }
    }
}

fn decode_class_method(type_word: u16) -> (Class, u16) {
    // Method bits scattered per RFC 5389 §6:
    //   method  = M11..M7  M6..M4  M3..M0
    //   type    = 00 M11..M7 C1 M6..M4 C0 M3..M0
    let m_hi = (type_word >> 9) & 0x1f;   // 5 bits
    let m_mid = (type_word >> 5) & 0x07;  // 3 bits
    let m_lo = type_word & 0x0f;          // 4 bits
    let method = (m_hi << 7) | (m_mid << 4) | m_lo;
    let c1 = (type_word >> 8) & 0x01;
    let c0 = (type_word >> 4) & 0x01;
    let class = match (c1, c0) {
        (0, 0) => Class::Request,
        (0, 1) => Class::Indication,
        (1, 0) => Class::SuccessResponse,
        (1, 1) => Class::ErrorResponse,
        _ => unreachable!(),
    };
    (class, method)
}

fn decode_attributes(
    mut attrs: &[u8],
    txid: &[u8; 12],
) -> (
    Option<MappedAddr>,
    Option<MappedAddr>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<u16>,
    Option<String>,
) {
    let mut xor_mapped = None;
    let mut mapped = None;
    let mut username = None;
    let mut software = None;
    let mut realm = None;
    let mut error_code = None;
    let mut error_reason = None;
    while attrs.len() >= 4 {
        let at = u16::from_be_bytes([attrs[0], attrs[1]]);
        let al = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        if attrs.len() < 4 + al {
            break;
        }
        let val = &attrs[4..4 + al];
        match at {
            0x0001 => mapped = decode_mapped(val),
            0x0020 => xor_mapped = decode_xor_mapped(val, txid),
            0x0006 => username = utf8_copy(val),
            0x8022 => software = utf8_copy(val),
            0x0014 => realm = utf8_copy(val),
            0x0009 => {
                // ERROR-CODE:
                //   u16 reserved
                //   u8  class (3..6 -> 300..699 class)
                //   u8  number (0..99)
                //   utf8 reason
                if val.len() >= 4 {
                    let class_b = val[2] & 0x07;
                    let num = val[3];
                    error_code = Some(class_b as u16 * 100 + num as u16);
                    error_reason = utf8_copy(&val[4..]);
                }
            }
            _ => {}
        }
        let padded = (4 + al + 3) & !3;
        if attrs.len() < padded {
            break;
        }
        attrs = &attrs[padded..];
    }
    (xor_mapped, mapped, username, software, realm, error_code, error_reason)
}

fn decode_mapped(val: &[u8]) -> Option<MappedAddr> {
    if val.len() < 4 {
        return None;
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);
    let ip = val[4..].to_vec();
    Some(MappedAddr { family, port, ip })
}

fn decode_xor_mapped(val: &[u8], txid: &[u8; 12]) -> Option<MappedAddr> {
    if val.len() < 4 {
        return None;
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]) ^ 0x2112;
    let mut ip = val[4..].to_vec();
    // Mask: cookie || txid
    let mut mask = [0u8; 16];
    mask[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    mask[4..16].copy_from_slice(txid);
    for (i, b) in ip.iter_mut().enumerate() {
        *b ^= mask[i];
    }
    Some(MappedAddr { family, port, ip })
}

fn utf8_copy(val: &[u8]) -> Option<String> {
    std::str::from_utf8(val).ok().map(|s| s.to_string())
}

const fn method_name(m: u16) -> &'static str {
    match m {
        0x001 => "Binding",
        0x003 => "Allocate",
        0x004 => "Refresh",
        0x006 => "Send",
        0x007 => "Data",
        0x008 => "CreatePermission",
        0x009 => "ChannelBind",
        0x00A => "Connect",
        0x00B => "ConnectionBind",
        0x00C => "ConnectionAttempt",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_empty() {
        // Binding Request: type=0x0001, length=0, magic, txid=12 bytes of 0xaa.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0001u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        buf.extend_from_slice(&[0xaa; 12]);
        let mut p = StunParser::default();
        match p.parse(&buf, Direction::Tx) {
            StunParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.class, Class::Request);
                assert_eq!(record.method, 0x001);
                assert_eq!(record.method_name, "Binding");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn binding_response_with_xor_mapped_v4() {
        // XOR-MAPPED-ADDRESS for 192.0.2.1:1025
        //   port xor 0x2112 = 1025 ^ 0x2112 = 0x2113 xor 0x0401 = 0x2513
        //   ip   xor cookie = c0 00 02 01 ^ 21 12 a4 42 = e1 12 a6 43
        let mut attr_val = vec![0x00, 0x01]; // reserved + family v4
        attr_val.extend_from_slice(&((1025u16 ^ 0x2112).to_be_bytes()));
        let cookie_bytes = MAGIC.to_be_bytes();
        let raw_ip = [192u8, 0, 2, 1];
        let xored: Vec<u8> = raw_ip
            .iter()
            .zip(cookie_bytes.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        attr_val.extend_from_slice(&xored);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0020u16.to_be_bytes());
        body.extend_from_slice(&(attr_val.len() as u16).to_be_bytes());
        body.extend_from_slice(&attr_val);

        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success Response
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        buf.extend_from_slice(&[0u8; 12]);
        buf.extend_from_slice(&body);

        let mut p = StunParser::default();
        match p.parse(&buf, Direction::Rx) {
            StunParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.class, Class::SuccessResponse);
                let a = record.xor_mapped.expect("xor-mapped");
                assert_eq!(a.family, 1);
                assert_eq!(a.port, 1025);
                assert_eq!(a.ip, [192, 0, 2, 1]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_stun_bypasses() {
        let mut p = StunParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n\r\n", Direction::Tx),
            StunParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_buffer_needs_more() {
        let mut p = StunParser::default();
        assert!(matches!(p.parse(&[0u8; 10], Direction::Tx), StunParserOutput::Need));
    }
}
