//! IRC (RFC 1459 / RFC 2812 / IRCv3) — tcp/6667 + tcp/6697 (TLS).
//!
//! Line-oriented text protocol. A message is:
//!
//! ```text
//!   [':' prefix SPACE] command [params...] [':' trailing] CRLF
//!   prefix  = servername | nick['!' user]['@' host]
//!   command = 3+-letter word OR 3-digit numeric reply
//! ```
//!
//! IRC persists for two reasons shannon cares about:
//! 1. Legacy ops / build automation still uses it for notifications.
//! 2. Botnets / C2 frameworks still run IRC control channels.
//!
//! We parse PASS, NICK, USER, JOIN, PART, PRIVMSG, NOTICE, PING,
//! PONG, QUIT, and numeric replies. PASS arguments are redacted on
//! the display line — the most common cleartext credential on IRC.

use crate::events::Direction;

pub struct IrcParser {
    bypass: bool,
}

impl Default for IrcParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum IrcParserOutput {
    Need,
    Record { record: IrcRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct IrcRecord {
    pub direction: Direction,
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
    pub trailing: Option<String>,
    pub redacted: bool,
}

impl IrcRecord {
    pub fn display_line(&self) -> String {
        let pre = self
            .prefix
            .as_deref()
            .map(|s| format!(":{s} "))
            .unwrap_or_default();
        let params_s = if self.redacted {
            self.params
                .iter()
                .enumerate()
                .map(|(i, _)| if i == 0 { "<redacted>" } else { "<...>" })
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            self.params.join(" ")
        };
        let tail = match &self.trailing {
            Some(t) if !self.redacted => format!(" :{t}"),
            _ => String::new(),
        };
        format!("irc {pre}{} {params_s}{tail}", self.command)
    }
}

impl IrcParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> IrcParserOutput {
        if self.bypass {
            return IrcParserOutput::Skip(buf.len());
        }
        let nl = match buf.iter().position(|&b| b == b'\n') {
            Some(n) => n,
            None => {
                if buf.len() > 8192 {
                    self.bypass = true;
                    return IrcParserOutput::Skip(buf.len());
                }
                return IrcParserOutput::Need;
            }
        };
        let end = nl + 1;
        let line_bytes = if nl > 0 && buf[nl - 1] == b'\r' {
            &buf[..nl - 1]
        } else {
            &buf[..nl]
        };
        if line_bytes.is_empty() {
            return IrcParserOutput::Skip(end);
        }
        let line = match std::str::from_utf8(line_bytes) {
            Ok(s) => s,
            Err(_) => {
                self.bypass = true;
                return IrcParserOutput::Skip(buf.len());
            }
        };
        let rec = match parse_line(line, dir) {
            Some(r) => r,
            None => {
                self.bypass = true;
                return IrcParserOutput::Skip(buf.len());
            }
        };
        IrcParserOutput::Record { record: rec, consumed: end }
    }
}

fn parse_line(line: &str, dir: Direction) -> Option<IrcRecord> {
    let mut rest = line;
    let prefix = if let Some(stripped) = rest.strip_prefix(':') {
        let (p, r) = stripped.split_once(' ')?;
        rest = r;
        Some(p.to_string())
    } else {
        None
    };
    let (command, mut rest) = match rest.split_once(' ') {
        Some((c, r)) => (c.to_string(), r),
        None => (rest.to_string(), ""),
    };
    if !is_plausible_command(&command) {
        return None;
    }
    let mut params = Vec::new();
    let mut trailing = None;
    while !rest.is_empty() {
        if let Some(t) = rest.strip_prefix(':') {
            trailing = Some(t.to_string());
            break;
        }
        match rest.split_once(' ') {
            Some((p, r)) => {
                params.push(p.to_string());
                rest = r;
            }
            None => {
                params.push(rest.to_string());
                break;
            }
        }
    }
    let redacted = command.eq_ignore_ascii_case("PASS") || command.eq_ignore_ascii_case("OPER");
    Some(IrcRecord {
        direction: dir,
        prefix,
        command,
        params,
        trailing,
        redacted,
    })
}

fn is_plausible_command(c: &str) -> bool {
    if c.is_empty() || c.len() > 16 {
        return false;
    }
    // Numeric replies: exactly 3 ASCII digits.
    if c.len() == 3 && c.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    // Textual: match a known IRC command. A bare uppercase-letters
    // check would false-positive on HTTP verbs (GET / PUT / …) and
    // other protocols that happen to lead with a word.
    matches!(
        c,
        "PASS"
            | "NICK"
            | "USER"
            | "OPER"
            | "QUIT"
            | "JOIN"
            | "PART"
            | "MODE"
            | "TOPIC"
            | "NAMES"
            | "LIST"
            | "INVITE"
            | "KICK"
            | "VERSION"
            | "STATS"
            | "LINKS"
            | "TIME"
            | "CONNECT"
            | "TRACE"
            | "ADMIN"
            | "INFO"
            | "PRIVMSG"
            | "NOTICE"
            | "WHO"
            | "WHOIS"
            | "WHOWAS"
            | "KILL"
            | "PING"
            | "PONG"
            | "ERROR"
            | "AWAY"
            | "REHASH"
            | "RESTART"
            | "SUMMON"
            | "USERS"
            | "WALLOPS"
            | "USERHOST"
            | "ISON"
            | "SERVICE"
            | "SQUERY"
            | "SILENCE"
            | "KNOCK"
            | "CAP"
            | "ACCOUNT"
            | "AUTHENTICATE"
            | "CHGHOST"
            | "TAGMSG"
            | "BATCH"
            | "MOTD"
            | "LUSERS"
            | "WEBIRC"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privmsg_with_trailing() {
        let mut p = IrcParser::default();
        let buf = b":alice!u@host PRIVMSG #chan :hello world\r\n";
        match p.parse(buf, Direction::Tx) {
            IrcParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.prefix.as_deref(), Some("alice!u@host"));
                assert_eq!(record.command, "PRIVMSG");
                assert_eq!(record.params, vec!["#chan".to_string()]);
                assert_eq!(record.trailing.as_deref(), Some("hello world"));
                assert!(!record.redacted);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn pass_is_redacted() {
        let mut p = IrcParser::default();
        let buf = b"PASS hunter2\r\n";
        match p.parse(buf, Direction::Tx) {
            IrcParserOutput::Record { record, .. } => {
                assert!(record.redacted);
                let line = record.display_line();
                assert!(line.contains("<redacted>"));
                assert!(!line.contains("hunter2"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn numeric_reply() {
        let mut p = IrcParser::default();
        let buf = b":irc.example.org 001 nick :Welcome\r\n";
        match p.parse(buf, Direction::Rx) {
            IrcParserOutput::Record { record, .. } => {
                assert_eq!(record.command, "001");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_irc_bypasses() {
        let mut p = IrcParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            IrcParserOutput::Skip(_)
        ));
    }

    #[test]
    fn partial_line_needs_more() {
        let mut p = IrcParser::default();
        assert!(matches!(p.parse(b"PRIVMSG #c", Direction::Tx), IrcParserOutput::Need));
    }
}
