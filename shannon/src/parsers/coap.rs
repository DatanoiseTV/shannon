//! CoAP (RFC 7252) — udp/5683 (and udp/5684 over DTLS, which stays opaque).
//!
//! CoAP is the "HTTP for constrained devices" — common in Thread / Matter
//! / OCF / LwM2M deployments. Each message is one UDP datagram so there's
//! no streaming reassembly: we either decode the whole datagram or skip
//! it.
//!
//! Frame:
//! ```text
//!   bits  field
//!   0..1  Ver  (must be 1 for RFC 7252)
//!   2..3  Type (CON=0, NON=1, ACK=2, RST=3)
//!   4..7  TKL  (token length, 0..=8; 9..=15 reserved => malformed)
//!   8..15 Code (3-bit class . 5-bit detail; e.g. 0.01=GET, 2.05=Content)
//!  16..31 Message ID (big-endian)
//!         Token (TKL bytes)
//!         Options …
//!  0xFF  Payload marker (optional)
//!         Payload …
//! ```
//!
//! shannon surfaces the message Type, the Code as a human label, the
//! Message ID, the assembled `Uri-Path` (for requests) and the
//! `Content-Format` if present.

use crate::events::Direction;

pub struct CoapParser {
    bypass: bool,
}

impl Default for CoapParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum CoapParserOutput {
    Need,
    Record { record: CoapRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct CoapRecord {
    pub direction: Direction,
    pub message_type: CoapType,
    pub code: u8,
    pub code_label: &'static str,
    pub message_id: u16,
    pub token: Vec<u8>,
    /// Joined `Uri-Path` segments separated by `/`. Empty for responses
    /// and for requests targeting the root.
    pub uri_path: String,
    /// `Uri-Query` segments joined with `&`.
    pub uri_query: String,
    pub content_format: Option<u32>,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoapType {
    Confirmable,
    NonConfirmable,
    Acknowledgement,
    Reset,
}

impl CoapType {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Confirmable => "CON",
            Self::NonConfirmable => "NON",
            Self::Acknowledgement => "ACK",
            Self::Reset => "RST",
        }
    }
}

impl CoapRecord {
    pub fn display_line(&self) -> String {
        let path = if self.uri_path.is_empty() {
            String::new()
        } else {
            format!(" /{}", self.uri_path)
        };
        let query = if self.uri_query.is_empty() {
            String::new()
        } else {
            format!("?{}", self.uri_query)
        };
        let cf = self
            .content_format
            .map(|c| format!(" cf={}", content_format_label(c)))
            .unwrap_or_default();
        format!(
            "coap {} {} mid={}{}{}{} {}B",
            self.message_type.label(),
            self.code_label,
            self.message_id,
            path,
            query,
            cf,
            self.payload_len,
        )
    }
}

impl CoapParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> CoapParserOutput {
        if self.bypass {
            return CoapParserOutput::Skip(buf.len());
        }
        if buf.len() < 4 {
            return CoapParserOutput::Need;
        }

        let b0 = buf[0];
        let version = b0 >> 6;
        let t_raw = (b0 >> 4) & 0x03;
        let tkl = (b0 & 0x0f) as usize;
        if version != 1 || tkl > 8 {
            self.bypass = true;
            return CoapParserOutput::Skip(buf.len());
        }

        let code = buf[1];
        let message_id = u16::from_be_bytes([buf[2], buf[3]]);

        let token_end = 4 + tkl;
        if buf.len() < token_end {
            // Inside one UDP datagram a truncated token means malformed,
            // not "wait for more bytes".
            self.bypass = true;
            return CoapParserOutput::Skip(buf.len());
        }
        let token = buf[4..token_end].to_vec();

        // Options + optional payload. Walk options until we hit the
        // 0xFF payload marker or the end of the buffer.
        let mut p = &buf[token_end..];
        let mut last_option: u32 = 0;
        let mut uri_path_segments: Vec<String> = Vec::new();
        let mut uri_query_segments: Vec<String> = Vec::new();
        let mut content_format: Option<u32> = None;

        loop {
            if p.is_empty() {
                break;
            }
            if p[0] == 0xff {
                p = &p[1..];
                break;
            }
            let head = p[0];
            let mut q = &p[1..];
            let delta_nibble = head >> 4;
            let length_nibble = head & 0x0f;

            let (delta, q1) = match read_extended(delta_nibble, q) {
                Some(v) => v,
                None => {
                    self.bypass = true;
                    return CoapParserOutput::Skip(buf.len());
                }
            };
            q = q1;
            let (length, q2) = match read_extended(length_nibble, q) {
                Some(v) => v,
                None => {
                    self.bypass = true;
                    return CoapParserOutput::Skip(buf.len());
                }
            };
            q = q2;

            if q.len() < length as usize {
                self.bypass = true;
                return CoapParserOutput::Skip(buf.len());
            }
            let value = &q[..length as usize];
            let option_number = last_option + delta;
            last_option = option_number;

            match option_number {
                11 => {
                    // Uri-Path: each option is one segment.
                    if let Ok(s) = std::str::from_utf8(value) {
                        uri_path_segments.push(s.to_string());
                    }
                }
                15 => {
                    if let Ok(s) = std::str::from_utf8(value) {
                        uri_query_segments.push(s.to_string());
                    }
                }
                12 => {
                    content_format = Some(read_uint_be(value));
                }
                _ => {}
            }

            p = &q[length as usize..];
        }

        let payload_len = p.len();

        let message_type = match t_raw {
            0 => CoapType::Confirmable,
            1 => CoapType::NonConfirmable,
            2 => CoapType::Acknowledgement,
            _ => CoapType::Reset,
        };

        CoapParserOutput::Record {
            record: CoapRecord {
                direction: dir,
                message_type,
                code,
                code_label: code_label(code),
                message_id,
                token,
                uri_path: uri_path_segments.join("/"),
                uri_query: uri_query_segments.join("&"),
                content_format,
                payload_len,
            },
            consumed: buf.len(),
        }
    }
}

/// Decode the option-header extended value form (RFC 7252 §3.1).
/// `nibble` is the 4-bit field; values 0..=12 are the literal value,
/// 13 means "1-byte extension follows, add 13", 14 means "2-byte
/// extension follows, add 269", 15 is reserved (must not appear in
/// option fields — only as the payload marker, handled by the caller).
fn read_extended(nibble: u8, rest: &[u8]) -> Option<(u32, &[u8])> {
    match nibble {
        0..=12 => Some((u32::from(nibble), rest)),
        13 => {
            let b = *rest.first()?;
            Some((u32::from(b) + 13, &rest[1..]))
        }
        14 => {
            if rest.len() < 2 {
                return None;
            }
            let v = u16::from_be_bytes([rest[0], rest[1]]);
            Some((u32::from(v) + 269, &rest[2..]))
        }
        _ => None,
    }
}

fn read_uint_be(value: &[u8]) -> u32 {
    let mut v: u32 = 0;
    for &b in value.iter().take(4) {
        v = (v << 8) | u32::from(b);
    }
    v
}

const fn code_label(code: u8) -> &'static str {
    match code {
        0x00 => "Empty",
        // Requests (class 0)
        0x01 => "GET",
        0x02 => "POST",
        0x03 => "PUT",
        0x04 => "DELETE",
        0x05 => "FETCH",
        0x06 => "PATCH",
        0x07 => "iPATCH",
        // Success (class 2)
        0x41 => "2.01 Created",
        0x42 => "2.02 Deleted",
        0x43 => "2.03 Valid",
        0x44 => "2.04 Changed",
        0x45 => "2.05 Content",
        0x5f => "2.31 Continue",
        // Client error (class 4)
        0x80 => "4.00 Bad Request",
        0x81 => "4.01 Unauthorized",
        0x82 => "4.02 Bad Option",
        0x83 => "4.03 Forbidden",
        0x84 => "4.04 Not Found",
        0x85 => "4.05 Method Not Allowed",
        0x86 => "4.06 Not Acceptable",
        0x88 => "4.08 Request Entity Incomplete",
        0x8c => "4.12 Precondition Failed",
        0x8d => "4.13 Request Entity Too Large",
        0x8f => "4.15 Unsupported Content-Format",
        // Server error (class 5)
        0xa0 => "5.00 Internal Server Error",
        0xa1 => "5.01 Not Implemented",
        0xa2 => "5.02 Bad Gateway",
        0xa3 => "5.03 Service Unavailable",
        0xa4 => "5.04 Gateway Timeout",
        0xa5 => "5.05 Proxying Not Supported",
        _ => "?",
    }
}

const fn content_format_label(cf: u32) -> &'static str {
    // RFC 7252 §12.3 + IANA registry for the common cases.
    match cf {
        0 => "text/plain",
        16 => "application/cose-encrypt0",
        40 => "application/link-format",
        41 => "application/xml",
        42 => "application/octet-stream",
        47 => "application/exi",
        50 => "application/json",
        51 => "application/json-patch+json",
        60 => "application/cbor",
        61 => "application/cwt",
        110 => "application/senml+json",
        112 => "application/senml+cbor",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_request_with_uri_path() {
        // CoAP GET /.well-known/core, mid=0x1234, token=0xab
        let buf = vec![
            0x41, // Ver=01, T=CON(00), TKL=1
            0x01, // GET
            0x12, 0x34, // MID
            0xab, // Token
            // Option 11 (Uri-Path) = ".well-known"
            0xbb, // delta=11, length=11
            b'.', b'w', b'e', b'l', b'l', b'-', b'k', b'n', b'o', b'w', b'n',
            // Option 11 (delta=0) = "core"
            0x04, // delta=0, length=4
            b'c', b'o', b'r', b'e',
        ];
        let mut p = CoapParser::default();
        match p.parse(&buf, Direction::Tx) {
            CoapParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.message_type, CoapType::Confirmable);
                assert_eq!(record.code_label, "GET");
                assert_eq!(record.message_id, 0x1234);
                assert_eq!(record.token, vec![0xab]);
                assert_eq!(record.uri_path, ".well-known/core");
                assert_eq!(record.payload_len, 0);
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn parses_response_with_payload_and_content_format() {
        // ACK 2.05 Content, mid=0x1234, no token, Content-Format=40
        // (link-format), payload "</1>".
        let buf = vec![
            0x60, // Ver=01, T=ACK(10), TKL=0
            0x45, // 2.05 Content
            0x12, 0x34, // MID
            // Option 12 (Content-Format) = 40
            0xc1, // delta=12, length=1
            40,   // value
            // Payload marker
            0xff, b'<', b'/', b'1', b'>',
        ];
        let mut p = CoapParser::default();
        match p.parse(&buf, Direction::Rx) {
            CoapParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.message_type, CoapType::Acknowledgement);
                assert_eq!(record.code_label, "2.05 Content");
                assert_eq!(record.content_format, Some(40));
                assert_eq!(record.payload_len, 4);
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn parses_uri_query() {
        // Per RFC 7252 §3.1 the delta nibble can only express 0..=12
        // directly; 13 means "extended-1: add 13 to the next byte".
        // To target option 15 (Uri-Query) we use delta_nibble=13 with
        // ext byte 2  → delta = 13 + 2 = 15.
        let buf = vec![
            0x40, // CON, TKL=0
            0x01, // GET
            0x00, 0x01, // MID
            0xd3, // delta=ext1, length=3
            2,    // delta-ext = 13 + 2 = 15
            b'k', b'=', b'v',
        ];
        let mut p = CoapParser::default();
        match p.parse(&buf, Direction::Tx) {
            CoapParserOutput::Record { record, .. } => {
                assert_eq!(record.uri_query, "k=v");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_non_coap_version() {
        let buf = [0xff, 0x00, 0x00, 0x00];
        let mut p = CoapParser::default();
        assert!(matches!(
            p.parse(&buf, Direction::Tx),
            CoapParserOutput::Skip(_)
        ));
    }

    #[test]
    fn rejects_invalid_tkl() {
        // Ver=01, T=CON, TKL=9 (reserved)
        let buf = [0x49, 0x01, 0x00, 0x00];
        let mut p = CoapParser::default();
        assert!(matches!(
            p.parse(&buf, Direction::Tx),
            CoapParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_needs_more() {
        let mut p = CoapParser::default();
        assert!(matches!(
            p.parse(&[0x40, 0x01], Direction::Tx),
            CoapParserOutput::Need
        ));
    }

    #[test]
    fn parses_extended_option_length() {
        // Single Uri-Path option with length 13 (extended-1 form).
        let mut buf = vec![
            0x40, // CON, TKL=0
            0x01, // GET
            0x00, 0x02, // MID
            0xbd, // delta=11, length=13 (extended)
            0,    // extended length value -> 13 + 0 = 13
        ];
        buf.extend_from_slice(b"thirteenchars");
        let mut p = CoapParser::default();
        match p.parse(&buf, Direction::Tx) {
            CoapParserOutput::Record { record, .. } => {
                assert_eq!(record.uri_path, "thirteenchars");
            }
            _ => panic!(),
        }
    }
}
