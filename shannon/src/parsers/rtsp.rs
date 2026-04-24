//! RTSP (RFC 2326 / RFC 7826) — tcp/554, tcp/8554.
//!
//! Real Time Streaming Protocol. HTTP-shaped header block but with
//! a different set of verbs (OPTIONS, DESCRIBE, ANNOUNCE, SETUP,
//! PLAY, PAUSE, TEARDOWN, GET_PARAMETER, SET_PARAMETER, REDIRECT,
//! RECORD) and a different protocol token on the start line:
//! `METHOD URI RTSP/1.0` or `RTSP/1.0 CODE REASON`.
//!
//! RTSP is the control channel of essentially every IP surveillance
//! camera, a big chunk of VoD / live-streaming infrastructure, and
//! various media / automation integrations. shannon surfaces the
//! request-URI (often `rtsp://cam/stream1`), CSeq for
//! request↔response matching, session token, transport parameters
//! for SETUP (client/server port / SSRC / interleaved channel).

use crate::events::Direction;

pub struct RtspParser {
    bypass: bool,
}

impl Default for RtspParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum RtspParserOutput {
    Need,
    Record { record: RtspRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct RtspRecord {
    pub direction: Direction,
    pub kind: RtspKind,
    pub cseq: Option<u32>,
    pub session: Option<String>,
    pub transport: Option<String>,
    pub user_agent: Option<String>,
    pub content_length: usize,
}

#[derive(Debug, Clone)]
pub enum RtspKind {
    Request { method: String, uri: String },
    Response { code: u16, reason: String },
}

impl RtspRecord {
    pub fn display_line(&self) -> String {
        let head = match &self.kind {
            RtspKind::Request { method, uri } => format!("{method} {uri}"),
            RtspKind::Response { code, reason } => format!("{code} {reason}"),
        };
        let cseq = self.cseq.map(|n| format!(" cseq={n}")).unwrap_or_default();
        let sess = self
            .session
            .as_deref()
            .map(|s| format!(" session={s}"))
            .unwrap_or_default();
        let tp = self
            .transport
            .as_deref()
            .map(|s| format!(" transport={s:?}"))
            .unwrap_or_default();
        let ua = self
            .user_agent
            .as_deref()
            .map(|s| format!(" ua={s:?}"))
            .unwrap_or_default();
        format!("rtsp {head}{cseq}{sess}{tp}{ua}")
    }
}

impl RtspParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> RtspParserOutput {
        if self.bypass {
            return RtspParserOutput::Skip(buf.len());
        }
        let (hdr_end, body_start) = match find_double_crlf(buf) {
            Some(v) => v,
            None => {
                if buf.len() > 16 * 1024 {
                    self.bypass = true;
                    return RtspParserOutput::Skip(buf.len());
                }
                return RtspParserOutput::Need;
            }
        };
        let header_str = match std::str::from_utf8(&buf[..hdr_end]) {
            Ok(s) => s,
            Err(_) => {
                self.bypass = true;
                return RtspParserOutput::Skip(buf.len());
            }
        };
        let mut lines = header_str
            .split(|c| c == '\r' || c == '\n')
            .filter(|l| !l.is_empty());
        let start_line = match lines.next() {
            Some(l) => l,
            None => {
                self.bypass = true;
                return RtspParserOutput::Skip(buf.len());
            }
        };
        let kind = match parse_start(start_line) {
            Some(k) => k,
            None => {
                self.bypass = true;
                return RtspParserOutput::Skip(buf.len());
            }
        };
        let mut cseq = None;
        let mut session = None;
        let mut transport = None;
        let mut user_agent = None;
        let mut content_length = 0usize;
        for line in lines {
            let (name, value) = match line.split_once(':') {
                Some(v) => v,
                None => continue,
            };
            let name_l = name.trim().to_ascii_lowercase();
            let value = value.trim();
            match name_l.as_str() {
                "cseq" => cseq = value.parse().ok(),
                "session" => session = Some(value.split(';').next().unwrap_or(value).to_string()),
                "transport" => transport = Some(value.to_string()),
                "user-agent" | "server" => user_agent = Some(value.to_string()),
                "content-length" => content_length = value.parse().unwrap_or(0),
                _ => {}
            }
        }
        let total = body_start + content_length;
        if buf.len() < total {
            return RtspParserOutput::Need;
        }
        let rec = RtspRecord {
            direction: dir,
            kind,
            cseq,
            session,
            transport,
            user_agent,
            content_length,
        };
        RtspParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<(usize, usize)> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, i + 4));
        }
    }
    None
}

fn parse_start(line: &str) -> Option<RtspKind> {
    if let Some(rest) = line.strip_prefix("RTSP/1.0 ") {
        let mut parts = rest.splitn(2, ' ');
        let code = parts.next()?.parse().ok()?;
        let reason = parts.next().unwrap_or("").to_string();
        return Some(RtspKind::Response { code, reason });
    }
    let mut parts = line.splitn(3, ' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let proto = parts.next()?;
    if proto != "RTSP/1.0" && proto != "RTSP/2.0" {
        return None;
    }
    if !is_rtsp_method(method) {
        return None;
    }
    Some(RtspKind::Request {
        method: method.to_string(),
        uri: uri.to_string(),
    })
}

fn is_rtsp_method(m: &str) -> bool {
    matches!(
        m,
        "OPTIONS"
            | "DESCRIBE"
            | "ANNOUNCE"
            | "SETUP"
            | "PLAY"
            | "PAUSE"
            | "TEARDOWN"
            | "GET_PARAMETER"
            | "SET_PARAMETER"
            | "REDIRECT"
            | "RECORD"
            | "PLAY_NOTIFY"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_request() {
        let msg = b"OPTIONS rtsp://cam.example.org/stream RTSP/1.0\r\n\
                    CSeq: 1\r\n\
                    User-Agent: curl/8\r\n\
                    \r\n";
        let mut p = RtspParser::default();
        match p.parse(msg, Direction::Tx) {
            RtspParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, msg.len());
                match record.kind {
                    RtspKind::Request { method, uri } => {
                        assert_eq!(method, "OPTIONS");
                        assert!(uri.starts_with("rtsp://"));
                    }
                    _ => panic!(),
                }
                assert_eq!(record.cseq, Some(1));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn setup_with_transport_and_session() {
        let msg = b"SETUP rtsp://cam/trackID=0 RTSP/1.0\r\n\
                    CSeq: 3\r\n\
                    Transport: RTP/AVP;unicast;client_port=7000-7001\r\n\
                    Session: 12345abc;timeout=60\r\n\
                    \r\n";
        let mut p = RtspParser::default();
        match p.parse(msg, Direction::Tx) {
            RtspParserOutput::Record { record, .. } => {
                assert_eq!(record.session.as_deref(), Some("12345abc"));
                assert!(record.transport.unwrap().contains("RTP/AVP"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn response_parsed() {
        let msg = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n";
        let mut p = RtspParser::default();
        match p.parse(msg, Direction::Rx) {
            RtspParserOutput::Record { record, .. } => match record.kind {
                RtspKind::Response { code, reason } => {
                    assert_eq!(code, 200);
                    assert_eq!(reason, "OK");
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn http_bypasses() {
        let mut p = RtspParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Direction::Tx),
            RtspParserOutput::Skip(_)
        ));
    }

    #[test]
    fn partial_returns_need() {
        let mut p = RtspParser::default();
        assert!(matches!(
            p.parse(b"OPTIONS rtsp://", Direction::Tx),
            RtspParserOutput::Need
        ));
    }
}
