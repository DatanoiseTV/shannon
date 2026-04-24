//! FTP control channel (RFC 959) — tcp/21.
//!
//! Line-oriented, `\r\n`-terminated ASCII. Client commands are 3-4
//! letter verbs (USER, PASS, RETR, STOR, …) followed by arguments;
//! the server replies with `<code><sp-or-dash><text>` where `-`
//! marks a multi-line reply whose terminator repeats the code plus
//! a space.
//!
//! We surface command + argument per client line (redacting PASS)
//! and reply-code + first line of text per server response. Shannon
//! calls out USER + PASS pairs as a credential signal — FTP is the
//! classic cleartext-password wire and operators often don't
//! realise it's still in the environment until they see shannon log
//! a login.

use crate::events::Direction;

pub struct FtpParser {
    bypass: bool,
}

impl Default for FtpParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum FtpParserOutput {
    Need,
    Record { record: FtpRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct FtpRecord {
    pub direction: Direction,
    pub kind: FtpKind,
}

#[derive(Debug, Clone)]
pub enum FtpKind {
    Command { verb: String, arg: Option<String>, redacted: bool },
    Reply { code: u16, text: String, continuation: bool },
}

impl FtpRecord {
    pub fn display_line(&self) -> String {
        match &self.kind {
            FtpKind::Command { verb, arg, redacted } => match (arg, redacted) {
                (_, true) => format!("ftp C {verb} <redacted>"),
                (Some(a), _) => format!("ftp C {verb} {a}"),
                (None, _) => format!("ftp C {verb}"),
            },
            FtpKind::Reply { code, text, continuation } => {
                let sep = if *continuation { "-" } else { " " };
                format!("ftp S {code}{sep}{text}")
            }
        }
    }
}

impl FtpParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> FtpParserOutput {
        if self.bypass {
            return FtpParserOutput::Skip(buf.len());
        }
        // One record per CRLF-terminated line.
        let nl = match buf.iter().position(|&b| b == b'\n') {
            Some(n) => n,
            None => {
                // Absurdly long single line without \n looks wrong for FTP.
                if buf.len() > 4096 {
                    self.bypass = true;
                    return FtpParserOutput::Skip(buf.len());
                }
                return FtpParserOutput::Need;
            }
        };
        let end = nl + 1;
        let line_bytes = if nl > 0 && buf[nl - 1] == b'\r' {
            &buf[..nl - 1]
        } else {
            &buf[..nl]
        };
        // Empty lines happen; consume and pretend we need more.
        if line_bytes.is_empty() {
            return FtpParserOutput::Skip(end);
        }
        let line = match std::str::from_utf8(line_bytes) {
            Ok(s) => s,
            Err(_) => {
                self.bypass = true;
                return FtpParserOutput::Skip(buf.len());
            }
        };
        let kind = match dir {
            Direction::Tx => parse_command(line),
            Direction::Rx => parse_reply(line),
        };
        match kind {
            Some(k) => FtpParserOutput::Record {
                record: FtpRecord { direction: dir, kind: k },
                consumed: end,
            },
            None => {
                self.bypass = true;
                FtpParserOutput::Skip(buf.len())
            }
        }
    }
}

fn parse_command(line: &str) -> Option<FtpKind> {
    let mut parts = line.splitn(2, ' ');
    let verb = parts.next()?.to_ascii_uppercase();
    if !is_known_verb(&verb) {
        return None;
    }
    let arg = parts.next().map(|s| s.to_string()).filter(|s| !s.is_empty());
    let redacted = verb == "PASS" || verb == "ACCT";
    Some(FtpKind::Command { verb, arg, redacted })
}

fn is_known_verb(v: &str) -> bool {
    matches!(
        v,
        "USER"
            | "PASS"
            | "ACCT"
            | "CWD"
            | "CDUP"
            | "SMNT"
            | "QUIT"
            | "REIN"
            | "PORT"
            | "PASV"
            | "EPRT"
            | "EPSV"
            | "TYPE"
            | "STRU"
            | "MODE"
            | "RETR"
            | "STOR"
            | "STOU"
            | "APPE"
            | "ALLO"
            | "REST"
            | "RNFR"
            | "RNTO"
            | "ABOR"
            | "DELE"
            | "RMD"
            | "MKD"
            | "PWD"
            | "LIST"
            | "NLST"
            | "SITE"
            | "SYST"
            | "STAT"
            | "HELP"
            | "NOOP"
            | "FEAT"
            | "OPTS"
            | "AUTH"
            | "ADAT"
            | "PBSZ"
            | "PROT"
            | "CCC"
            | "MIC"
            | "CONF"
            | "ENC"
            | "MLSD"
            | "MLST"
            | "MDTM"
            | "SIZE"
            | "XCUP"
            | "XCWD"
            | "XMKD"
            | "XPWD"
            | "XRMD"
    )
}

fn parse_reply(line: &str) -> Option<FtpKind> {
    // Reply lines begin with a 3-digit code; multi-line continuations
    // use '-' after the code, final line uses space.
    let bytes = line.as_bytes();
    if bytes.len() < 4 || !bytes[..3].iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let sep = bytes[3];
    if sep != b' ' && sep != b'-' {
        return None;
    }
    let code: u16 = line[..3].parse().ok()?;
    let text = line.get(4..).unwrap_or("").to_string();
    Some(FtpKind::Reply { code, text, continuation: sep == b'-' })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_then_pass_redacts() {
        let mut p = FtpParser::default();
        let mut buf = b"USER alice\r\nPASS hunter2\r\n".to_vec();
        let mut off = 0;
        // USER alice
        match p.parse(&buf[off..], Direction::Tx) {
            FtpParserOutput::Record { record, consumed } => {
                match record.kind {
                    FtpKind::Command { verb, arg, redacted } => {
                        assert_eq!(verb, "USER");
                        assert_eq!(arg.as_deref(), Some("alice"));
                        assert!(!redacted);
                    }
                    _ => panic!(),
                }
                off += consumed;
            }
            _ => panic!(),
        }
        // PASS hunter2 — redacted
        match p.parse(&buf[off..], Direction::Tx) {
            FtpParserOutput::Record { record, consumed: _ } => match record.kind {
                FtpKind::Command { verb, redacted, .. } => {
                    assert_eq!(verb, "PASS");
                    assert!(redacted);
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
        // silence unused
        let _ = &mut buf;
    }

    #[test]
    fn server_banner_parsed() {
        let mut p = FtpParser::default();
        let buf = b"220 (vsFTPd 3.0.3)\r\n";
        match p.parse(buf, Direction::Rx) {
            FtpParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                match record.kind {
                    FtpKind::Reply { code, text, continuation } => {
                        assert_eq!(code, 220);
                        assert!(text.contains("vsFTPd"));
                        assert!(!continuation);
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn multiline_continuation() {
        let mut p = FtpParser::default();
        let buf = b"211-Features:\r\n";
        match p.parse(buf, Direction::Rx) {
            FtpParserOutput::Record { record, .. } => match record.kind {
                FtpKind::Reply { code, continuation, .. } => {
                    assert_eq!(code, 211);
                    assert!(continuation);
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn partial_line_needs_more() {
        let mut p = FtpParser::default();
        assert!(matches!(p.parse(b"USER al", Direction::Tx), FtpParserOutput::Need));
    }

    #[test]
    fn non_ftp_command_bypasses() {
        let mut p = FtpParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            FtpParserOutput::Skip(_)
        ));
    }
}
