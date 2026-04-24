//! SMTP — RFC 5321 + RFC 2821 + ESMTP extensions.
//!
//! Line-oriented. Client commands: `<VERB> [args]\r\n`. Server replies:
//! `NNN[ -]text\r\n`, where `-` indicates more lines to follow and space
//! indicates the final line of a multi-line reply (5321 §4.2). The `DATA`
//! command transitions to a message-body phase that terminates with
//! `".\r\n"` on a line by itself.
//!
//! Credential surfaces (`AUTH LOGIN`, `AUTH PLAIN`, `AUTH CRAM-MD5`) are
//! observed but the credential itself never leaves the parser — `auth`
//! fields are redacted at the record layer.

use crate::events::Direction;

const MAX_LINE: usize = 4096;

#[derive(Default)]
pub struct SmtpParser {
    bypass: bool,
    in_data: bool,
    /// After the client sends `AUTH LOGIN`, the following two client
    /// lines are the base64 username and then base64 password. Redact
    /// them at the parser layer.
    auth_expect: u8, // remaining base64 lines to redact
}

pub enum SmtpParserOutput {
    Need,
    Record { record: SmtpRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct SmtpRecord {
    pub direction: Direction,
    pub kind: SmtpKind,
    pub args: String,
    pub code: Option<u16>,
    pub text: String,
    pub is_final_line: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpKind {
    // client → server
    Helo,
    Ehlo,
    MailFrom,
    RcptTo,
    Data,
    DataBodyChunk, // internal — not emitted
    DataEnd,
    Rset,
    Noop,
    Quit,
    Vrfy,
    Help,
    StartTls,
    Auth,           // redacted
    AuthContinuation, // redacted base64 line after AUTH LOGIN
    Other(String),
    // server → client
    Reply,
}

impl SmtpRecord {
    pub fn display_line(&self) -> String {
        match &self.kind {
            SmtpKind::Reply => match self.code {
                Some(c) => format!("{c} {}", self.text),
                None => self.text.clone(),
            },
            SmtpKind::Auth => "AUTH <redacted>".to_string(),
            SmtpKind::AuthContinuation => "<auth continuation redacted>".to_string(),
            SmtpKind::Helo => format!("HELO {}", self.args),
            SmtpKind::Ehlo => format!("EHLO {}", self.args),
            SmtpKind::MailFrom => format!("MAIL FROM:{}", self.args),
            SmtpKind::RcptTo => format!("RCPT TO:{}", self.args),
            SmtpKind::Data => "DATA".to_string(),
            SmtpKind::DataEnd => ". (end of DATA)".to_string(),
            SmtpKind::Rset => "RSET".to_string(),
            SmtpKind::Noop => "NOOP".to_string(),
            SmtpKind::Quit => "QUIT".to_string(),
            SmtpKind::Vrfy => format!("VRFY {}", self.args),
            SmtpKind::Help => format!("HELP {}", self.args),
            SmtpKind::StartTls => "STARTTLS".to_string(),
            SmtpKind::Other(v) => format!("{v} {}", self.args),
            SmtpKind::DataBodyChunk => "(data body)".to_string(),
        }
    }
}

impl SmtpParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> SmtpParserOutput {
        if self.bypass {
            return SmtpParserOutput::Skip(buf.len());
        }
        let Some(line_end) = find_crlf(buf) else {
            if buf.len() > MAX_LINE {
                self.bypass = true;
                return SmtpParserOutput::Skip(buf.len());
            }
            return SmtpParserOutput::Need;
        };
        let line = &buf[..line_end];
        let consumed = line_end + 2;

        if !line.is_ascii() && !self.in_data {
            self.bypass = true;
            return SmtpParserOutput::Skip(buf.len());
        }

        // DATA body phase: just skip every line until ".\r\n".
        if self.in_data {
            if line == b"." {
                self.in_data = false;
                return SmtpParserOutput::Record {
                    record: SmtpRecord {
                        direction: Direction::Tx,
                        kind: SmtpKind::DataEnd,
                        args: String::new(),
                        code: None,
                        text: String::new(),
                        is_final_line: true,
                    },
                    consumed,
                };
            }
            return SmtpParserOutput::Skip(consumed);
        }

        let text = std::str::from_utf8(line).unwrap_or("").trim_end();

        match dir {
            Direction::Tx => self.parse_command(text, consumed),
            Direction::Rx => Self::parse_reply(text, consumed),
        }
    }

    fn parse_command(&mut self, line: &str, consumed: usize) -> SmtpParserOutput {
        // Active AUTH LOGIN/CRAM-MD5 expects further base64 lines from the
        // client — redact them.
        if self.auth_expect > 0 {
            self.auth_expect -= 1;
            return SmtpParserOutput::Record {
                record: SmtpRecord {
                    direction: Direction::Tx,
                    kind: SmtpKind::AuthContinuation,
                    args: String::new(),
                    code: None,
                    text: String::new(),
                    is_final_line: true,
                },
                consumed,
            };
        }

        if line.is_empty() {
            return SmtpParserOutput::Skip(consumed);
        }
        let (verb_raw, rest) = line.split_once(' ').unwrap_or((line, ""));
        let verb = verb_raw.to_ascii_uppercase();
        let args = rest.trim().to_string();

        let kind = match verb.as_str() {
            "HELO" => SmtpKind::Helo,
            "EHLO" => SmtpKind::Ehlo,
            "MAIL" => {
                // Args should start with "FROM:".
                if args.to_ascii_uppercase().starts_with("FROM:") {
                    SmtpKind::MailFrom
                } else {
                    SmtpKind::Other(verb)
                }
            }
            "RCPT" => {
                if args.to_ascii_uppercase().starts_with("TO:") {
                    SmtpKind::RcptTo
                } else {
                    SmtpKind::Other(verb)
                }
            }
            "DATA" => {
                self.in_data = true;
                SmtpKind::Data
            }
            "RSET" => SmtpKind::Rset,
            "NOOP" => SmtpKind::Noop,
            "QUIT" => SmtpKind::Quit,
            "VRFY" => SmtpKind::Vrfy,
            "HELP" => SmtpKind::Help,
            "STARTTLS" => SmtpKind::StartTls,
            "AUTH" => {
                // `AUTH LOGIN` expects 2 base64 continuations.
                // `AUTH PLAIN <base64>` is single-line — arg itself is a
                // credential, redact.
                // `AUTH CRAM-MD5` expects 1 continuation.
                let upper = args.to_ascii_uppercase();
                if upper.starts_with("LOGIN") {
                    self.auth_expect = 2;
                } else if upper.starts_with("CRAM-MD5") {
                    self.auth_expect = 1;
                }
                SmtpKind::Auth
            }
            v if v.chars().all(|c| c.is_ascii_alphabetic()) && !v.is_empty() => {
                SmtpKind::Other(v.to_string())
            }
            _ => return SmtpParserOutput::Skip(consumed),
        };

        let args = match kind {
            SmtpKind::Auth => String::new(),
            _ => args,
        };
        let kind_for_final = matches!(kind, SmtpKind::Data);
        SmtpParserOutput::Record {
            record: SmtpRecord {
                direction: Direction::Tx,
                kind,
                args,
                code: None,
                text: String::new(),
                is_final_line: !kind_for_final,
            },
            consumed,
        }
    }

    fn parse_reply(line: &str, consumed: usize) -> SmtpParserOutput {
        if line.len() < 3 {
            return SmtpParserOutput::Skip(consumed);
        }
        let code_str = &line[..3];
        let Ok(code) = code_str.parse::<u16>() else {
            return SmtpParserOutput::Skip(consumed);
        };
        if !(100..=599).contains(&code) {
            return SmtpParserOutput::Skip(consumed);
        }
        let sep = line.as_bytes().get(3).copied().unwrap_or(b' ');
        let is_final = sep != b'-';
        let text = line.get(4..).unwrap_or("").to_string();
        SmtpParserOutput::Record {
            record: SmtpRecord {
                direction: Direction::Rx,
                kind: SmtpKind::Reply,
                args: String::new(),
                code: Some(code),
                text,
                is_final_line: is_final,
            },
            consumed,
        }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_parsed() {
        let mut p = SmtpParser::default();
        match p.parse(b"220 mail.example.com ESMTP\r\n", Direction::Rx) {
            SmtpParserOutput::Record { record, .. } => {
                assert_eq!(record.code, Some(220));
                assert!(record.text.contains("ESMTP"));
                assert!(record.is_final_line);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn multi_line_ehlo_reply() {
        let mut p = SmtpParser::default();
        let a = p.parse(b"250-mail.example.com\r\n", Direction::Rx);
        match a {
            SmtpParserOutput::Record { record, .. } => {
                assert_eq!(record.code, Some(250));
                assert!(!record.is_final_line);
            }
            _ => panic!(),
        }
        let b = p.parse(b"250 AUTH LOGIN PLAIN\r\n", Direction::Rx);
        match b {
            SmtpParserOutput::Record { record, .. } => {
                assert!(record.is_final_line);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn auth_login_redacts_continuations() {
        let mut p = SmtpParser::default();
        match p.parse(b"AUTH LOGIN\r\n", Direction::Tx) {
            SmtpParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, SmtpKind::Auth);
                assert!(record.display_line().contains("<redacted>"));
            }
            _ => panic!(),
        }
        // Two base64 continuation lines — redacted.
        for _ in 0..2 {
            match p.parse(b"dXNlcjpwYXNz\r\n", Direction::Tx) {
                SmtpParserOutput::Record { record, .. } => {
                    assert_eq!(record.kind, SmtpKind::AuthContinuation);
                }
                _ => panic!(),
            }
        }
    }

    #[test]
    fn auth_plain_single_line_redacts_args() {
        let mut p = SmtpParser::default();
        match p.parse(b"AUTH PLAIN AHVzZXIAcGFzcw==\r\n", Direction::Tx) {
            SmtpParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, SmtpKind::Auth);
                assert!(record.args.is_empty());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn mail_and_rcpt() {
        let mut p = SmtpParser::default();
        match p.parse(b"MAIL FROM:<alice@example.com>\r\n", Direction::Tx) {
            SmtpParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, SmtpKind::MailFrom);
                assert!(record.args.contains("alice"));
            }
            _ => panic!(),
        }
        match p.parse(b"RCPT TO:<bob@example.net>\r\n", Direction::Tx) {
            SmtpParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, SmtpKind::RcptTo);
                assert!(record.args.contains("bob"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn data_body_swallowed() {
        let mut p = SmtpParser::default();
        match p.parse(b"DATA\r\n", Direction::Tx) {
            SmtpParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, SmtpKind::Data);
            }
            _ => panic!(),
        }
        assert!(matches!(p.parse(b"Subject: hi\r\n", Direction::Tx), SmtpParserOutput::Skip(_)));
        assert!(matches!(p.parse(b"\r\n", Direction::Tx), SmtpParserOutput::Skip(_)));
        assert!(matches!(p.parse(b"hello world\r\n", Direction::Tx), SmtpParserOutput::Skip(_)));
        match p.parse(b".\r\n", Direction::Tx) {
            SmtpParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, SmtpKind::DataEnd);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_ascii_bypasses() {
        let mut p = SmtpParser::default();
        assert!(matches!(
            p.parse(b"\xff\xfe junk\r\n", Direction::Rx),
            SmtpParserOutput::Skip(_)
        ));
    }
}
