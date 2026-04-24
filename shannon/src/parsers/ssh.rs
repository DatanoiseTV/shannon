//! SSH — we surface the protocol banner (RFC 4253 §4.2) only.
//!
//! The full SSH transport is binary-packet-protocol after the banner
//! and becomes encrypted with NEWKEYS; observing anything beyond the
//! banner requires hooking libssh / OpenSSH symbols via uprobes
//! (roadmap). The banner alone is high-value for posture monitoring:
//! it tells you client and server versions, which is enough to detect
//! outdated / vulnerable SSH deployments.
//!
//! Banner format: `SSH-<protoversion>-<softwareversion>[ <comments>]\r\n`.
//! Each side sends one banner line before binary packets start. Some
//! servers send additional lines (MOTD / policy banners) before the
//! `SSH-` line; we skip up to 8 non-`SSH-` lines then give up.

use crate::events::Direction;

const MAX_BANNER_LINE: usize = 255;
const MAX_PRELUDE_LINES: usize = 8;

pub struct SshParser {
    state: State,
}

impl Default for SshParser {
    fn default() -> Self {
        Self {
            state: State::SeekingBanner(0),
        }
    }
}

enum State {
    SeekingBanner(u8),
    Done,
    Bypass,
}

pub enum SshParserOutput {
    Need,
    Record { record: SshRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct SshRecord {
    pub direction: Direction,
    pub proto_version: String,    // e.g. "2.0"
    pub software_version: String, // e.g. "OpenSSH_9.6p1"
    pub comments: Option<String>,
}

impl SshRecord {
    pub fn display_line(&self) -> String {
        let via = match self.direction {
            Direction::Tx => "SSH-client",
            Direction::Rx => "SSH-server",
        };
        let c = self
            .comments
            .as_deref()
            .map(|s| format!(" [{s}]"))
            .unwrap_or_default();
        format!(
            "{via} proto={} software={}{c}",
            self.proto_version, self.software_version
        )
    }
}

impl SshParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> SshParserOutput {
        match self.state {
            State::Bypass | State::Done => {
                return SshParserOutput::Skip(buf.len());
            }
            State::SeekingBanner(_) => {}
        }
        // Find CRLF or LF terminator.
        let Some(mut eol) = buf.iter().position(|&b| b == b'\n') else {
            if buf.len() > MAX_BANNER_LINE * MAX_PRELUDE_LINES as usize {
                self.state = State::Bypass;
                return SshParserOutput::Skip(buf.len());
            }
            return SshParserOutput::Need;
        };
        // Ensure line is plausibly ASCII.
        let line_with_crlf_end = eol + 1;
        let end = if eol > 0 && buf[eol - 1] == b'\r' {
            eol - 1
        } else {
            eol
        };
        let line = &buf[..end];
        if !line.is_ascii() {
            self.state = State::Bypass;
            return SshParserOutput::Skip(buf.len());
        }
        if !line.starts_with(b"SSH-") {
            // Maybe a prelude line. Count it; if we've exceeded the
            // budget, bypass.
            let State::SeekingBanner(ref mut used) = self.state else {
                self.state = State::Bypass;
                return SshParserOutput::Skip(buf.len());
            };
            *used += 1;
            if *used as usize > MAX_PRELUDE_LINES {
                self.state = State::Bypass;
                return SshParserOutput::Skip(buf.len());
            }
            return SshParserOutput::Skip(line_with_crlf_end);
        }

        // SSH-<proto>-<software>[ <comments>]
        let s = std::str::from_utf8(line).unwrap_or("");
        let rest = &s[4..];
        let (proto_version, rest) = match rest.split_once('-') {
            Some((p, r)) => (p.to_string(), r),
            None => {
                self.state = State::Bypass;
                return SshParserOutput::Skip(line_with_crlf_end);
            }
        };
        let (software_version, comments) = match rest.split_once(' ') {
            Some((sw, cmt)) => (sw.to_string(), Some(cmt.to_string())),
            None => (rest.to_string(), None),
        };
        // After banner we stop participating; the rest of the stream is
        // binary-packet protocol and (once NEWKEYS runs) encrypted.
        eol = line_with_crlf_end;
        self.state = State::Done;
        SshParserOutput::Record {
            record: SshRecord {
                direction: dir,
                proto_version,
                software_version,
                comments,
            },
            consumed: eol,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssh_server_banner() {
        let buf = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";
        let mut p = SshParser::default();
        match p.parse(buf, Direction::Rx) {
            SshParserOutput::Record { record, consumed } => {
                assert_eq!(record.proto_version, "2.0");
                assert_eq!(record.software_version, "OpenSSH_9.6p1");
                assert_eq!(record.comments.as_deref(), Some("Ubuntu-3ubuntu13.5"));
                assert_eq!(consumed, buf.len());
            }
            _ => panic!(),
        }
        // After the banner the parser goes Done and just skips the rest.
        match p.parse(b"binary garbage", Direction::Rx) {
            SshParserOutput::Skip(_) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn prelude_line_skipped() {
        let mut p = SshParser::default();
        // First a policy banner line, then the real SSH banner.
        match p.parse(b"By accessing this system you agree...\r\n", Direction::Rx) {
            SshParserOutput::Skip(n) => {
                assert_eq!(n, "By accessing this system you agree...\r\n".len());
            }
            _ => panic!(),
        }
        match p.parse(b"SSH-2.0-Acme_1.2\r\n", Direction::Rx) {
            SshParserOutput::Record { record, .. } => {
                assert_eq!(record.software_version, "Acme_1.2");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_ssh_bypasses() {
        let mut p = SshParser::default();
        // Fill the prelude budget with non-SSH garbage.
        for _ in 0..(MAX_PRELUDE_LINES + 1) {
            let _ = p.parse(b"garbage\r\n", Direction::Rx);
        }
        assert!(matches!(
            p.parse(b"SSH-2.0-x\r\n", Direction::Rx),
            SshParserOutput::Skip(_)
        ));
    }

    #[test]
    fn partial_returns_need() {
        let mut p = SshParser::default();
        assert!(matches!(
            p.parse(b"SSH-2.0", Direction::Rx),
            SshParserOutput::Need
        ));
    }
}
