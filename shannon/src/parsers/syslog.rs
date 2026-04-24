//! Syslog (RFC 3164 legacy + RFC 5424 structured) — udp/514,
//! tcp/514, tcp/601 (non-TLS) and tls/6514.
//!
//! Syslog messages reach the wire as single lines (UDP datagrams)
//! or octet-counted frames (TCP, RFC 6587). The wire format itself
//! varies between legacy and modern:
//!
//! ```text
//!   RFC 3164  : <PRI>Mmm dd HH:MM:SS hostname tag: message
//!   RFC 5424  : <PRI>1 ISOTIMESTAMP hostname app-name procid msgid
//!                      [SD-ELEMENT]... [BOM]UTF8 message
//! ```
//!
//! PRI is `<facility * 8 + severity>`. Facility / severity are
//! decoded per RFC 5424 §6.2.1 into friendly names. For operators
//! what matters is usually: where's this log from (facility),
//! how urgent is it (severity), who sent it (hostname/app), and
//! what does it say (message body). All of that lands on the
//! display line.

use crate::events::Direction;

pub struct SyslogParser {
    bypass: bool,
}

impl Default for SyslogParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum SyslogParserOutput {
    Need,
    Record { record: SyslogRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct SyslogRecord {
    pub direction: Direction,
    pub version: u8,            // 0 for legacy 3164, 1+ for 5424
    pub facility: u8,
    pub facility_name: &'static str,
    pub severity: u8,
    pub severity_name: &'static str,
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub procid: Option<String>,
    pub msgid: Option<String>,
    pub message: String,
}

impl SyslogRecord {
    pub fn display_line(&self) -> String {
        let host = self.hostname.as_deref().unwrap_or("-");
        let app = self.app_name.as_deref().unwrap_or("-");
        format!(
            "syslog {} {} {} {}: {}",
            self.facility_name, self.severity_name, host, app, self.message,
        )
    }
}

impl SyslogParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> SyslogParserOutput {
        if self.bypass {
            return SyslogParserOutput::Skip(buf.len());
        }
        if buf.is_empty() {
            return SyslogParserOutput::Need;
        }
        // Optional RFC 6587 octet-counting framing: "<len> <msg>".
        // Detect by leading digit + space, then use the declared
        // length; otherwise fall through to the inline \n-delimited
        // form.
        if buf[0].is_ascii_digit() {
            if let Some((len, prefix_end)) = parse_octet_count(buf) {
                let total = prefix_end + len;
                if buf.len() < total {
                    return SyslogParserOutput::Need;
                }
                return self.parse_line(&buf[prefix_end..total], dir, total);
            }
        }
        // Non-framed: look for \n line terminator or use the whole buf
        // (UDP datagram case).
        if let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line = &buf[..nl];
            return self.parse_line(line, dir, nl + 1);
        }
        // UDP: consume the whole buffer as one message.
        self.parse_line(buf, dir, buf.len())
    }

    fn parse_line(
        &mut self,
        line: &[u8],
        dir: Direction,
        consumed: usize,
    ) -> SyslogParserOutput {
        let s = match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => {
                self.bypass = true;
                return SyslogParserOutput::Skip(consumed);
            }
        };
        let s = s.trim_end_matches(['\r', '\n']);
        // PRI: "<NN>"
        let (pri, rest) = match parse_pri(s) {
            Some(v) => v,
            None => {
                self.bypass = true;
                return SyslogParserOutput::Skip(consumed);
            }
        };
        let facility = pri >> 3;
        let severity = pri & 7;

        // Decide 5424 vs 3164 by a leading "1 " (version).
        let (version, ts, host, app, procid, msgid, msg) = if let Some(rest) = rest.strip_prefix("1 ") {
            parse_5424(rest)
        } else {
            parse_3164(rest)
        };

        let rec = SyslogRecord {
            direction: dir,
            version,
            facility,
            facility_name: facility_name(facility),
            severity,
            severity_name: severity_name(severity),
            timestamp: ts,
            hostname: host,
            app_name: app,
            procid,
            msgid,
            message: msg,
        };
        SyslogParserOutput::Record { record: rec, consumed }
    }
}

fn parse_octet_count(buf: &[u8]) -> Option<(usize, usize)> {
    let space = buf.iter().position(|&b| b == b' ')?;
    if space == 0 || space > 8 {
        return None;
    }
    let num = std::str::from_utf8(&buf[..space]).ok()?;
    let len: usize = num.parse().ok()?;
    Some((len, space + 1))
}

fn parse_pri(s: &str) -> Option<(u8, &str)> {
    let s = s.strip_prefix('<')?;
    let end = s.find('>')?;
    let pri: u8 = s[..end].parse().ok()?;
    Some((pri, &s[end + 1..]))
}

fn parse_5424(rest: &str) -> (u8, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, String) {
    // TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD
    // SP MSG — any field may be "-".
    let mut it = rest.splitn(6, ' ');
    let ts = take_nonempty(&mut it);
    let host = take_nonempty(&mut it);
    let app = take_nonempty(&mut it);
    let proc = take_nonempty(&mut it);
    let msgid = take_nonempty(&mut it);
    let tail = it.next().unwrap_or("");
    // Strip STRUCTURED-DATA block [...] if present; skip BOM if present.
    let tail = tail.trim_start();
    let tail = if tail.starts_with('[') {
        skip_sd(tail)
    } else if tail.starts_with('-') {
        tail.get(1..).unwrap_or("").trim_start()
    } else {
        tail
    };
    let msg = tail.trim_start_matches('\u{feff}').to_string();
    (1, ts, host, app, proc, msgid, msg)
}

fn skip_sd(s: &str) -> &str {
    // Skip balanced [] SD elements. Inside an element, `\"` and `\\`
    // are escapes; `]` ends the element.
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] == b'[' {
        let mut depth = 1;
        i += 1;
        while i < bytes.len() && depth > 0 {
            let b = bytes[i];
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b']' {
                depth -= 1;
            }
            i += 1;
        }
    }
    s[i..].trim_start()
}

fn parse_3164(rest: &str) -> (u8, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, String) {
    // "Mmm dd HH:MM:SS hostname tag[pid]: message" — best-effort.
    let ts_end = find_nth_space(rest, 3);
    let (ts, rest) = match ts_end {
        Some(i) => (Some(rest[..i].to_string()), rest[i + 1..].to_string()),
        None => (None, rest.to_string()),
    };
    let (host, rest) = match rest.split_once(' ') {
        Some((h, r)) => (Some(h.to_string()), r.to_string()),
        None => (None, rest),
    };
    // Tag: up to 32 alnum+_-., followed by `[pid]` optionally then `:`.
    let (tag, procid, msg) = split_3164_tag(&rest);
    (0, ts, host, tag, procid, None, msg)
}

fn find_nth_space(s: &str, n: usize) -> Option<usize> {
    let mut cnt = 0;
    for (i, c) in s.char_indices() {
        if c == ' ' {
            cnt += 1;
            if cnt == n {
                return Some(i);
            }
        }
    }
    None
}

fn split_3164_tag(s: &str) -> (Option<String>, Option<String>, String) {
    let end = s.find(':').unwrap_or(0);
    if end == 0 {
        return (None, None, s.to_string());
    }
    let head = &s[..end];
    let tail = s.get(end + 1..).unwrap_or("").trim_start();
    let (tag, proc) = match head.find('[') {
        Some(i) => {
            let tag = head[..i].to_string();
            let after = &head[i + 1..];
            let proc = after.strip_suffix(']').map(|s| s.to_string());
            (tag, proc)
        }
        None => (head.to_string(), None),
    };
    (Some(tag), proc, tail.to_string())
}

fn take_nonempty<'a>(it: &mut impl Iterator<Item = &'a str>) -> Option<String> {
    match it.next() {
        None => None,
        Some("-") => None,
        Some(s) => Some(s.to_string()),
    }
}

const fn facility_name(f: u8) -> &'static str {
    match f {
        0 => "kern",
        1 => "user",
        2 => "mail",
        3 => "daemon",
        4 => "auth",
        5 => "syslog",
        6 => "lpr",
        7 => "news",
        8 => "uucp",
        9 => "cron",
        10 => "authpriv",
        11 => "ftp",
        12 => "ntp",
        13 => "security",
        14 => "console",
        15 => "cron2",
        16..=23 => "local",
        _ => "?",
    }
}

const fn severity_name(s: u8) -> &'static str {
    match s {
        0 => "emerg",
        1 => "alert",
        2 => "crit",
        3 => "err",
        4 => "warn",
        5 => "notice",
        6 => "info",
        7 => "debug",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5424_sample() {
        let msg = b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8\n";
        let mut p = SyslogParser::default();
        match p.parse(msg, Direction::Rx) {
            SyslogParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, msg.len());
                assert_eq!(record.facility, 4); // auth
                assert_eq!(record.severity, 2); // crit
                assert_eq!(record.version, 1);
                assert_eq!(record.hostname.as_deref(), Some("mymachine.example.com"));
                assert_eq!(record.app_name.as_deref(), Some("su"));
                assert!(record.message.contains("failed for lonvick"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rfc3164_sample() {
        let msg = b"<13>Oct 11 22:14:15 mymachine sudo[1234]: pam_unix(sudo:session): session opened\n";
        let mut p = SyslogParser::default();
        match p.parse(msg, Direction::Rx) {
            SyslogParserOutput::Record { record, .. } => {
                assert_eq!(record.facility, 1); // user
                assert_eq!(record.severity, 5); // notice
                assert_eq!(record.hostname.as_deref(), Some("mymachine"));
                assert_eq!(record.app_name.as_deref(), Some("sudo"));
                assert_eq!(record.procid.as_deref(), Some("1234"));
                assert!(record.message.contains("session opened"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn octet_counted_framing() {
        let inner = b"<34>1 - host app - - - msg";
        let framed_prefix = format!("{} ", inner.len());
        let mut framed = Vec::new();
        framed.extend_from_slice(framed_prefix.as_bytes());
        framed.extend_from_slice(inner);
        let mut p = SyslogParser::default();
        match p.parse(&framed, Direction::Rx) {
            SyslogParserOutput::Record { consumed, record } => {
                assert_eq!(consumed, framed.len());
                assert_eq!(record.hostname.as_deref(), Some("host"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_syslog_bypasses() {
        let mut p = SyslogParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            SyslogParserOutput::Skip(_)
        ));
    }
}
