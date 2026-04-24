//! SSDP (Simple Service Discovery Protocol) — UPnP device discovery
//! over UDP/1900.
//!
//! Wire format is an HTTP/1.1-shaped message but usually one message per
//! UDP datagram (no body, no chunking). Three message kinds:
//!
//! ```text
//!   M-SEARCH * HTTP/1.1\r\n...                (client → group)
//!   NOTIFY * HTTP/1.1\r\n...                  (device → group)
//!   HTTP/1.1 200 OK\r\n...                    (unicast reply to M-SEARCH)
//! ```
//!
//! We parse the first line + headers and surface the useful fields
//! (`ST`, `NT`, `NTS`, `USN`, `LOCATION`, `SERVER`, `HOST`) in a
//! compact record. Datagrams that don't look like SSDP bypass.

use crate::events::Direction;

const MAX_LINE: usize = 4096;

#[derive(Default)]
pub struct SsdpParser {
    bypass: bool,
}

pub enum SsdpParserOutput {
    Need,
    Record { record: SsdpRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct SsdpRecord {
    pub direction: Direction,
    pub kind: SsdpKind,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsdpKind {
    MSearch,
    Notify,
    Reply,
    Unknown,
}

impl SsdpRecord {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn display_line(&self) -> String {
        match self.kind {
            SsdpKind::MSearch => format!(
                "ssdp M-SEARCH ST={} MAN={}",
                self.header("ST").unwrap_or("-"),
                self.header("MAN").unwrap_or("-"),
            ),
            SsdpKind::Notify => format!(
                "ssdp NOTIFY NT={} NTS={} USN={}",
                self.header("NT").unwrap_or("-"),
                self.header("NTS").unwrap_or("-"),
                self.header("USN").unwrap_or("-"),
            ),
            SsdpKind::Reply => format!(
                "ssdp reply ST={} USN={} LOCATION={} SERVER={}",
                self.header("ST").unwrap_or("-"),
                self.header("USN").unwrap_or("-"),
                self.header("LOCATION").unwrap_or("-"),
                self.header("SERVER").unwrap_or("-"),
            ),
            SsdpKind::Unknown => "ssdp ?".to_string(),
        }
    }
}

impl SsdpParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> SsdpParserOutput {
        if self.bypass {
            return SsdpParserOutput::Skip(buf.len());
        }
        if !buf.is_ascii() {
            self.bypass = true;
            return SsdpParserOutput::Skip(buf.len());
        }
        // Look for the end-of-headers (\r\n\r\n) or the full datagram.
        let body_start = find_double_crlf(buf).map_or(buf.len(), |i| i + 4);
        let head = &buf[..body_start];
        // Split into lines.
        let text = std::str::from_utf8(head).unwrap_or("");
        let mut lines = text.split("\r\n");
        let first = lines.next().unwrap_or("").trim_end();
        let kind = match first {
            l if l.starts_with("M-SEARCH * HTTP/1.") => SsdpKind::MSearch,
            l if l.starts_with("NOTIFY * HTTP/1.") => SsdpKind::Notify,
            l if l.starts_with("HTTP/1.") && l.contains(" 200") => SsdpKind::Reply,
            _ => {
                self.bypass = true;
                return SsdpParserOutput::Skip(buf.len());
            }
        };
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if line.len() > MAX_LINE {
                self.bypass = true;
                return SsdpParserOutput::Skip(buf.len());
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        SsdpParserOutput::Record {
            record: SsdpRecord { direction: dir, kind, headers },
            consumed: buf.len(),
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m_search_parsed() {
        let msg = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
        let mut p = SsdpParser::default();
        match p.parse(msg, Direction::Tx) {
            SsdpParserOutput::Record { record, consumed } => {
                assert_eq!(record.kind, SsdpKind::MSearch);
                assert_eq!(record.header("ST"), Some("ssdp:all"));
                assert_eq!(consumed, msg.len());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn notify_parsed() {
        let msg = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:1900/rootDesc.xml\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nSERVER: Linux/5.10 UPnP/1.0 MiniDLNA/1.3.3\r\nUSN: uuid:abcd::upnp:rootdevice\r\n\r\n";
        let mut p = SsdpParser::default();
        match p.parse(msg, Direction::Tx) {
            SsdpParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, SsdpKind::Notify);
                assert_eq!(record.header("NT"), Some("upnp:rootdevice"));
                assert_eq!(record.header("SERVER"), Some("Linux/5.10 UPnP/1.0 MiniDLNA/1.3.3"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_ssdp_bypasses() {
        let mut p = SsdpParser::default();
        assert!(matches!(p.parse(b"junk\r\n\r\n", Direction::Rx), SsdpParserOutput::Skip(_)));
    }
}
