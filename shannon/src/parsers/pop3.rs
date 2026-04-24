//! POP3 — RFC 1939.
//!
//! Line-oriented ASCII. Client commands are `<VERB> [args]\r\n`; server
//! responses are `+OK <text>\r\n` or `-ERR <text>\r\n`. Some commands
//! (`RETR`, `LIST` without an argument, `TOP`, `UIDL` without argument)
//! trigger a multi-line response terminated by a single line `".\r\n"`.
//!
//! Credentials land in `PASS` and `APOP`. We emit a record naming the
//! command but we never store the argument — the credential bytes never
//! reach userspace beyond the BPF boundary anyway, but defence in depth.
//! `USER` is kept because it's the identity, not the secret.

use crate::events::Direction;

const MAX_LINE: usize = 4096;
const MAX_ARG: usize = 1024;

#[derive(Default)]
pub struct Pop3Parser {
    bypass: bool,
    in_multiline: bool,
}

pub enum Pop3ParserOutput {
    Need,
    Record { record: Pop3Record, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct Pop3Record {
    pub direction: Direction,
    pub kind: Pop3Kind,
    pub args: Vec<String>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pop3Kind {
    // client → server
    User,
    Pass, // credential — args redacted
    Apop, // credential — args redacted
    Quit,
    Stat,
    List,
    Retr,
    Dele,
    Noop,
    Rset,
    Uidl,
    Top,
    Capa,
    Stls,
    Other(String),
    // server → client
    Ok,
    Err,
    // multi-line response body line (not emitted — consumed silently).
}

impl Pop3Record {
    pub fn display_line(&self) -> String {
        match &self.kind {
            Pop3Kind::User => format!("USER {}", self.args.first().map_or("", String::as_str)),
            Pop3Kind::Pass => "PASS <redacted>".to_string(),
            Pop3Kind::Apop => format!(
                "APOP {} <redacted>",
                self.args.first().map_or("", String::as_str)
            ),
            Pop3Kind::Quit => "QUIT".to_string(),
            Pop3Kind::Stat => "STAT".to_string(),
            Pop3Kind::List => format!("LIST{}", maybe_arg(&self.args)),
            Pop3Kind::Retr => format!("RETR{}", maybe_arg(&self.args)),
            Pop3Kind::Dele => format!("DELE{}", maybe_arg(&self.args)),
            Pop3Kind::Noop => "NOOP".to_string(),
            Pop3Kind::Rset => "RSET".to_string(),
            Pop3Kind::Uidl => format!("UIDL{}", maybe_arg(&self.args)),
            Pop3Kind::Top => format!("TOP {}", self.args.join(" ")),
            Pop3Kind::Capa => "CAPA".to_string(),
            Pop3Kind::Stls => "STLS".to_string(),
            Pop3Kind::Other(v) => format!("{v} {}", self.args.join(" ")),
            Pop3Kind::Ok => format!("+OK {}", self.text),
            Pop3Kind::Err => format!("-ERR {}", self.text),
        }
    }
}

fn maybe_arg(a: &[String]) -> String {
    if a.is_empty() {
        String::new()
    } else {
        format!(" {}", a.join(" "))
    }
}

impl Pop3Parser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> Pop3ParserOutput {
        if self.bypass {
            return Pop3ParserOutput::Skip(buf.len());
        }
        let Some(line_end) = find_crlf(buf) else {
            if buf.len() > MAX_LINE {
                self.bypass = true;
                return Pop3ParserOutput::Skip(buf.len());
            }
            return Pop3ParserOutput::Need;
        };
        let line = &buf[..line_end];
        let consumed = line_end + 2;

        // Swallow multi-line response body — lines ending in "." alone
        // terminate it. Every intermediate line is dropped (not emitted)
        // to keep record volume sensible.
        if self.in_multiline {
            if line == b"." {
                self.in_multiline = false;
            }
            return Pop3ParserOutput::Skip(consumed);
        }

        if !line.is_ascii() {
            self.bypass = true;
            return Pop3ParserOutput::Skip(buf.len());
        }
        let text = std::str::from_utf8(line).unwrap_or("").trim();

        match dir {
            Direction::Tx => parse_command(text, consumed),
            Direction::Rx => self.parse_response(text, consumed),
        }
    }
}

fn parse_command(line: &str, consumed: usize) -> Pop3ParserOutput {
    if line.is_empty() {
        return Pop3ParserOutput::Skip(consumed);
    }
    let mut parts = line.splitn(2, ' ');
    let verb = parts.next().unwrap_or("").to_ascii_uppercase();
    let rest = parts.next().unwrap_or("").trim();
    let args: Vec<String> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(' ')
            .map(str::to_string)
            .map(|s| truncate_to(s, MAX_ARG))
            .collect()
    };

    let kind = match verb.as_str() {
        "USER" => Pop3Kind::User,
        "PASS" => Pop3Kind::Pass,
        "APOP" => Pop3Kind::Apop,
        "QUIT" => Pop3Kind::Quit,
        "STAT" => Pop3Kind::Stat,
        "LIST" => Pop3Kind::List,
        "RETR" => Pop3Kind::Retr,
        "DELE" => Pop3Kind::Dele,
        "NOOP" => Pop3Kind::Noop,
        "RSET" => Pop3Kind::Rset,
        "UIDL" => Pop3Kind::Uidl,
        "TOP" => Pop3Kind::Top,
        "CAPA" => Pop3Kind::Capa,
        "STLS" => Pop3Kind::Stls,
        v if v.chars().all(|c| c.is_ascii_alphanumeric()) && !v.is_empty() => {
            Pop3Kind::Other(v.to_string())
        }
        _ => return Pop3ParserOutput::Skip(consumed),
    };

    // Redact credential bytes.
    let args = match kind {
        Pop3Kind::Pass => Vec::new(),
        Pop3Kind::Apop => args.into_iter().take(1).collect(),
        _ => args,
    };

    Pop3ParserOutput::Record {
        record: Pop3Record {
            direction: Direction::Tx,
            kind,
            args,
            text: String::new(),
        },
        consumed,
    }
}

impl Pop3Parser {
    fn parse_response(&mut self, line: &str, consumed: usize) -> Pop3ParserOutput {
        let (kind, text) = if let Some(rest) = line.strip_prefix("+OK") {
            (Pop3Kind::Ok, rest.trim_start().to_string())
        } else if let Some(rest) = line.strip_prefix("-ERR") {
            (Pop3Kind::Err, rest.trim_start().to_string())
        } else {
            self.bypass = true;
            return Pop3ParserOutput::Skip(consumed);
        };
        // Heuristic for multi-line: an +OK response to RETR/LIST/TOP/UIDL
        // opens a data block that ends with ".\r\n". We can't tell which
        // command we're replying to without request/response pairing —
        // apply the heuristic on the response text (numeric digits in the
        // first word frequently = size, suggesting a listing). Simpler:
        // set multi-line whenever the server's +OK ends with "follows" or
        // begins a message listing. Minor false positives just mean we
        // swallow the next ".\r\n" which is harmless.
        if matches!(kind, Pop3Kind::Ok) && (text.contains("follows") || text.ends_with("octets")) {
            self.in_multiline = true;
        }
        Pop3ParserOutput::Record {
            record: Pop3Record {
                direction: Direction::Rx,
                kind,
                args: Vec::new(),
                text,
            },
            consumed,
        }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn truncate_to(mut s: String, n: usize) -> String {
    if s.len() > n {
        s.truncate(n);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(parts: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in parts {
            v.extend_from_slice(p);
        }
        v
    }

    #[test]
    fn user_and_pass_redacted() {
        let mut p = Pop3Parser::default();
        let buf = b"USER alice\r\n";
        let out = p.parse(buf, Direction::Tx);
        match out {
            Pop3ParserOutput::Record { record, consumed } => {
                assert_eq!(record.kind, Pop3Kind::User);
                assert_eq!(record.args, vec!["alice".to_string()]);
                assert_eq!(consumed, buf.len());
            }
            _ => panic!(),
        }

        let buf = fx(&[b"PA", b"SS hunter2\r\n"]);
        let out = p.parse(&buf, Direction::Tx);
        match out {
            Pop3ParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, Pop3Kind::Pass);
                assert!(record.args.is_empty(), "password must be scrubbed");
                assert_eq!(record.display_line(), "PASS <redacted>");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn apop_keeps_user_scrubs_digest() {
        let mut p = Pop3Parser::default();
        let buf = b"APOP alice c4c9334bac560ecc979e58001b3e22fb\r\n";
        match p.parse(buf, Direction::Tx) {
            Pop3ParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, Pop3Kind::Apop);
                assert_eq!(record.args, vec!["alice".to_string()]);
                assert!(record.display_line().contains("<redacted>"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ok_response_parsed() {
        let mut p = Pop3Parser::default();
        let buf = b"+OK 3 messages (320 octets)\r\n";
        match p.parse(buf, Direction::Rx) {
            Pop3ParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, Pop3Kind::Ok);
                assert!(record.text.contains("3 messages"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn multiline_body_swallowed() {
        let mut p = Pop3Parser::default();
        // +OK then 2 body lines then the terminator + another command.
        p.parse(b"+OK 2 follows\r\n", Direction::Rx);
        match p.parse(b"line1\r\n", Direction::Rx) {
            Pop3ParserOutput::Skip(_) => {}
            _ => panic!("body line should skip"),
        }
        match p.parse(b"line2\r\n", Direction::Rx) {
            Pop3ParserOutput::Skip(_) => {}
            _ => panic!(),
        }
        match p.parse(b".\r\n", Direction::Rx) {
            Pop3ParserOutput::Skip(_) => {}
            _ => panic!(),
        }
        // Back to normal state — next line parsed.
        match p.parse(b"+OK bye\r\n", Direction::Rx) {
            Pop3ParserOutput::Record { record, .. } => assert_eq!(record.kind, Pop3Kind::Ok),
            _ => panic!(),
        }
    }

    #[test]
    fn non_ascii_bypasses() {
        let mut p = Pop3Parser::default();
        let buf = b"\xff\xfe\x00\x01junk\r\n";
        assert!(matches!(
            p.parse(buf, Direction::Tx),
            Pop3ParserOutput::Skip(_)
        ));
        // And stays bypassed.
        assert!(matches!(
            p.parse(b"USER alice\r\n", Direction::Tx),
            Pop3ParserOutput::Skip(_)
        ));
    }

    #[test]
    fn partial_line_needs_more() {
        let mut p = Pop3Parser::default();
        assert!(matches!(
            p.parse(b"STAT", Direction::Tx),
            Pop3ParserOutput::Need
        ));
    }
}
