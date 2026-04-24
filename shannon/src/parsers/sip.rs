//! SIP — Session Initiation Protocol (RFC 3261) on tcp/5060, tls/5061.
//!
//! SIP drives IP telephony, SIP trunks, most VoIP PBXs, video
//! calling, IMS / VoLTE core signalling, unified-comms platforms.
//! The wire format is HTTP-ish: a request line
//! `METHOD Request-URI SIP/2.0` or a status line `SIP/2.0 CODE
//! REASON`, then headers, a blank line, optional body (usually
//! an SDP offer / answer).
//!
//! The parser reads exactly one message per invocation. Body length
//! is taken from `Content-Length:`; the final message is consumed
//! only when we've seen all the body bytes. Over UDP one PDU = one
//! datagram and Content-Length may be absent — the parser still
//! works so long as the caller hands in one datagram at a time.
//!
//! Surfaced fields: method / status code, Request-URI, top `Via`
//! branch, `From`, `To`, `Call-ID`, `User-Agent` or `Server`, and
//! `Contact`. Auth credentials in a `Proxy-Authorization` or
//! `Authorization` header get flagged as sensitive for shannon's
//! credential classifier.

use crate::events::Direction;

pub struct SipParser {
    bypass: bool,
}

impl Default for SipParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum SipParserOutput {
    Need,
    Record { record: SipRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct SipRecord {
    pub direction: Direction,
    pub kind: SipKind,
    pub call_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub via_branch: Option<String>,
    pub contact: Option<String>,
    pub user_agent: Option<String>,
    pub has_auth: bool,
    pub body_len: usize,
}

#[derive(Debug, Clone)]
pub enum SipKind {
    Request { method: String, uri: String },
    Response { code: u16, reason: String },
}

impl SipRecord {
    pub fn display_line(&self) -> String {
        let head = match &self.kind {
            SipKind::Request { method, uri } => format!("{method} {uri}"),
            SipKind::Response { code, reason } => format!("{code} {reason}"),
        };
        let cid = self
            .call_id
            .as_deref()
            .map(|s| format!(" call={s}"))
            .unwrap_or_default();
        let from = self
            .from
            .as_deref()
            .map(|s| format!(" from={s}"))
            .unwrap_or_default();
        let to = self
            .to
            .as_deref()
            .map(|s| format!(" to={s}"))
            .unwrap_or_default();
        let ua = self
            .user_agent
            .as_deref()
            .map(|s| format!(" ua=\"{s}\""))
            .unwrap_or_default();
        let auth = if self.has_auth { " auth=present" } else { "" };
        let body = if self.body_len > 0 {
            format!(" body={}B", self.body_len)
        } else {
            String::new()
        };
        format!("sip {head}{cid}{from}{to}{ua}{auth}{body}")
    }
}

impl SipParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> SipParserOutput {
        if self.bypass {
            return SipParserOutput::Skip(buf.len());
        }
        // Find end-of-headers marker \r\n\r\n (tolerate bare \n\n too).
        let (hdr_end, body_start) = match find_headers_end(buf) {
            Some(v) => v,
            None => {
                // Very long header block without terminator is not SIP.
                if buf.len() > 16 * 1024 {
                    self.bypass = true;
                    return SipParserOutput::Skip(buf.len());
                }
                return SipParserOutput::Need;
            }
        };
        let header_bytes = &buf[..hdr_end];
        let header_str = match std::str::from_utf8(header_bytes) {
            Ok(s) => s,
            Err(_) => {
                self.bypass = true;
                return SipParserOutput::Skip(buf.len());
            }
        };
        let mut lines = header_str
            .split(|c| c == '\r' || c == '\n')
            .filter(|l| !l.is_empty());
        let start_line = match lines.next() {
            Some(l) => l,
            None => {
                self.bypass = true;
                return SipParserOutput::Skip(buf.len());
            }
        };
        let kind = match parse_start_line(start_line) {
            Some(k) => k,
            None => {
                self.bypass = true;
                return SipParserOutput::Skip(buf.len());
            }
        };

        let mut call_id = None;
        let mut from = None;
        let mut to = None;
        let mut via_branch = None;
        let mut contact = None;
        let mut user_agent = None;
        let mut has_auth = false;
        let mut content_length: Option<usize> = None;

        for line in lines {
            let (name, value) = match line.split_once(':') {
                Some(v) => v,
                None => continue,
            };
            let name_l = name.trim().to_ascii_lowercase();
            let value = value.trim();
            match name_l.as_str() {
                "call-id" | "i" => call_id = Some(value.to_string()),
                "from" | "f" => from = Some(value.to_string()),
                "to" | "t" => to = Some(value.to_string()),
                "contact" | "m" => contact = Some(value.to_string()),
                "user-agent" | "server" => user_agent = Some(value.to_string()),
                "via" | "v" if via_branch.is_none() => {
                    via_branch = extract_branch(value).map(|s| s.to_string());
                }
                "authorization" | "proxy-authorization" => has_auth = true,
                "content-length" | "l" => content_length = value.parse().ok(),
                _ => {}
            }
        }

        let body_len_declared = content_length.unwrap_or(0);
        let total = body_start + body_len_declared;
        if buf.len() < total {
            return SipParserOutput::Need;
        }
        let rec = SipRecord {
            direction: dir,
            kind,
            call_id,
            from,
            to,
            via_branch,
            contact,
            user_agent,
            has_auth,
            body_len: body_len_declared,
        };
        SipParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<(usize, usize)> {
    // Prefer CRLFCRLF; fall back to LFLF.
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, i + 4));
        }
    }
    for i in 0..buf.len().saturating_sub(1) {
        if &buf[i..i + 2] == b"\n\n" {
            return Some((i, i + 2));
        }
    }
    None
}

fn parse_start_line(line: &str) -> Option<SipKind> {
    if let Some(rest) = line.strip_prefix("SIP/2.0 ") {
        // Status: "CODE REASON"
        let mut parts = rest.splitn(2, ' ');
        let code = parts.next()?.parse().ok()?;
        let reason = parts.next().unwrap_or("").to_string();
        return Some(SipKind::Response { code, reason });
    }
    // Request: "METHOD URI SIP/2.0"
    let mut parts = line.splitn(3, ' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let proto = parts.next()?;
    if proto != "SIP/2.0" {
        return None;
    }
    if !is_known_method(method) {
        return None;
    }
    Some(SipKind::Request {
        method: method.to_string(),
        uri: uri.to_string(),
    })
}

fn is_known_method(m: &str) -> bool {
    matches!(
        m,
        "INVITE"
            | "ACK"
            | "BYE"
            | "CANCEL"
            | "REGISTER"
            | "OPTIONS"
            | "PRACK"
            | "SUBSCRIBE"
            | "NOTIFY"
            | "PUBLISH"
            | "INFO"
            | "REFER"
            | "MESSAGE"
            | "UPDATE"
    )
}

fn extract_branch(via_value: &str) -> Option<&str> {
    // Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK.abc;rport
    for part in via_value.split(';') {
        if let Some(b) = part.trim().strip_prefix("branch=") {
            return Some(b);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_request_parsed() {
        let msg = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK.abc\r\n\
                    From: \"Alice\" <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
                    To: Bob <sip:bob@biloxi.example.com>\r\n\
                    Call-ID: a84b4c76e66710\r\n\
                    User-Agent: Asterisk PBX 20.2.0\r\n\
                    Content-Length: 0\r\n\
                    \r\n";
        let mut p = SipParser::default();
        match p.parse(msg, Direction::Tx) {
            SipParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, msg.len());
                match record.kind {
                    SipKind::Request { method, uri } => {
                        assert_eq!(method, "INVITE");
                        assert!(uri.contains("bob@biloxi"));
                    }
                    _ => panic!(),
                }
                assert_eq!(record.call_id.as_deref(), Some("a84b4c76e66710"));
                assert_eq!(record.via_branch.as_deref(), Some("z9hG4bK.abc"));
                assert!(record.user_agent.unwrap().starts_with("Asterisk"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn trying_response_parsed() {
        let msg = b"SIP/2.0 100 Trying\r\n\
                    Call-ID: foo\r\n\
                    Content-Length: 0\r\n\
                    \r\n";
        let mut p = SipParser::default();
        match p.parse(msg, Direction::Rx) {
            SipParserOutput::Record { record, .. } => match record.kind {
                SipKind::Response { code, reason } => {
                    assert_eq!(code, 100);
                    assert_eq!(reason, "Trying");
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn auth_flag_set() {
        let msg = b"REGISTER sip:example.com SIP/2.0\r\n\
                    Authorization: Digest username=\"alice\"\r\n\
                    Content-Length: 0\r\n\r\n";
        let mut p = SipParser::default();
        match p.parse(msg, Direction::Tx) {
            SipParserOutput::Record { record, .. } => assert!(record.has_auth),
            _ => panic!(),
        }
    }

    #[test]
    fn http_bypasses() {
        let mut p = SipParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Direction::Tx),
            SipParserOutput::Skip(_)
        ));
    }

    #[test]
    fn partial_returns_need() {
        let mut p = SipParser::default();
        assert!(matches!(
            p.parse(b"INVITE sip:b", Direction::Tx),
            SipParserOutput::Need
        ));
    }
}
