//! RADIUS (RFC 2865) — udp/1812 auth, udp/1813 accounting.
//!
//! Packet layout:
//!
//! ```text
//!   u8  code             (Access-Request=1, Access-Accept=2,
//!                         Access-Reject=3, Accounting-Request=4,
//!                         Accounting-Response=5, Access-Challenge=11,
//!                         Status-Server=12, Status-Client=13)
//!   u8  identifier       (matches request ↔ response)
//!   u16 length
//!   u8[16] authenticator
//!   attributes…          (each: u8 type, u8 length, value[])
//! ```
//!
//! RADIUS is the enterprise AAA substrate — WiFi, VPN, network-
//! device logins — and seeing Access-Request / Accept / Reject
//! plus the User-Name attribute gives operators a direct view of
//! who's authenticating to what. User-Password is encrypted with
//! the shared secret so shannon intentionally leaves it alone;
//! Called-Station-Id (the AP BSSID or VPN endpoint), Calling-
//! Station-Id (the MAC of the client), NAS-IP-Address, and
//! NAS-Identifier are all plaintext and surfaced.

use crate::events::Direction;

const HEADER: usize = 20;

pub struct RadiusParser {
    bypass: bool,
}

impl Default for RadiusParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum RadiusParserOutput {
    Need,
    Record { record: RadiusRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct RadiusRecord {
    pub direction: Direction,
    pub code: u8,
    pub code_name: &'static str,
    pub identifier: u8,
    pub length: u16,
    pub user_name: Option<String>,
    pub calling_station: Option<String>,
    pub called_station: Option<String>,
    pub nas_identifier: Option<String>,
    pub nas_ip: Option<[u8; 4]>,
}

impl RadiusRecord {
    pub fn display_line(&self) -> String {
        let u = self
            .user_name
            .as_deref()
            .map(|s| format!(" user={s}"))
            .unwrap_or_default();
        let call = self
            .calling_station
            .as_deref()
            .map(|s| format!(" from={s}"))
            .unwrap_or_default();
        let called = self
            .called_station
            .as_deref()
            .map(|s| format!(" to={s}"))
            .unwrap_or_default();
        let nas = match (self.nas_identifier.as_deref(), self.nas_ip) {
            (Some(s), _) => format!(" nas={s}"),
            (_, Some(ip)) => format!(" nas={}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            _ => String::new(),
        };
        format!(
            "radius {} id={}{}{}{}{}",
            self.code_name, self.identifier, u, call, called, nas,
        )
    }
}

impl RadiusParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> RadiusParserOutput {
        if self.bypass {
            return RadiusParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return RadiusParserOutput::Need;
        }
        let code = buf[0];
        if !is_known_code(code) {
            self.bypass = true;
            return RadiusParserOutput::Skip(buf.len());
        }
        let identifier = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]);
        if (length as usize) < HEADER || (length as usize) > 4096 {
            self.bypass = true;
            return RadiusParserOutput::Skip(buf.len());
        }
        if buf.len() < length as usize {
            return RadiusParserOutput::Need;
        }
        let total = length as usize;
        let mut attrs = &buf[HEADER..total];
        let mut user_name = None;
        let mut calling_station = None;
        let mut called_station = None;
        let mut nas_identifier = None;
        let mut nas_ip = None;
        while attrs.len() >= 2 {
            let t = attrs[0];
            let l = attrs[1] as usize;
            if l < 2 || attrs.len() < l {
                break;
            }
            let v = &attrs[2..l];
            match t {
                1 => user_name = utf8(v),
                4 if v.len() == 4 => nas_ip = Some([v[0], v[1], v[2], v[3]]),
                30 => called_station = utf8(v),
                31 => calling_station = utf8(v),
                32 => nas_identifier = utf8(v),
                _ => {}
            }
            attrs = &attrs[l..];
        }
        RadiusParserOutput::Record {
            record: RadiusRecord {
                direction: dir,
                code,
                code_name: code_name(code),
                identifier,
                length,
                user_name,
                calling_station,
                called_station,
                nas_identifier,
                nas_ip,
            },
            consumed: total,
        }
    }
}

fn utf8(v: &[u8]) -> Option<String> {
    std::str::from_utf8(v).ok().map(|s| s.to_string())
}

const fn is_known_code(c: u8) -> bool {
    matches!(
        c,
        1 | 2 | 3 | 4 | 5 | 11 | 12 | 13 | 40 | 41 | 42 | 43 | 44 | 45
    )
}

const fn code_name(c: u8) -> &'static str {
    match c {
        1 => "Access-Request",
        2 => "Access-Accept",
        3 => "Access-Reject",
        4 => "Accounting-Request",
        5 => "Accounting-Response",
        11 => "Access-Challenge",
        12 => "Status-Server",
        13 => "Status-Client",
        40 => "Disconnect-Request",
        41 => "Disconnect-ACK",
        42 => "Disconnect-NAK",
        43 => "CoA-Request",
        44 => "CoA-ACK",
        45 => "CoA-NAK",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_request_with_username() {
        // Header: code=1, id=42, length=20+6+8=34, auth=16*0
        let user = b"alice";
        let user_attr_len = 2 + user.len();
        let total = HEADER + user_attr_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 1;
        pkt[1] = 42;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[HEADER] = 1; // type User-Name
        pkt[HEADER + 1] = user_attr_len as u8;
        pkt[HEADER + 2..HEADER + 2 + user.len()].copy_from_slice(user);
        let mut p = RadiusParser::default();
        match p.parse(&pkt, Direction::Tx) {
            RadiusParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, total);
                assert_eq!(record.code, 1);
                assert_eq!(record.code_name, "Access-Request");
                assert_eq!(record.user_name.as_deref(), Some("alice"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_radius_bypasses() {
        let mut p = RadiusParser::default();
        let mut pkt = vec![0u8; HEADER];
        pkt[0] = 99; // unknown code
        assert!(matches!(p.parse(&pkt, Direction::Tx), RadiusParserOutput::Skip(_)));
    }

    #[test]
    fn short_needs_more() {
        let mut p = RadiusParser::default();
        assert!(matches!(p.parse(&[0u8; 10], Direction::Tx), RadiusParserOutput::Need));
    }
}
