//! Telnet (RFC 854) — tcp/23.
//!
//! Half-duplex byte stream interleaved with IAC (0xFF) command
//! sequences for option negotiation. Text arrives character by
//! character in either direction; credentials, commands, and
//! server responses all cross the wire in cleartext.
//!
//! The parser strips IAC negotiations and emits two kinds of
//! records per direction:
//!
//!   - `Negotiation { cmd, option }` — the DO / DON'T / WILL /
//!     WON'T / SB / SE handshake. Mostly boring but helps operators
//!     confirm we're actually looking at Telnet and not just bytes
//!     that happen to start with 0xFF.
//!   - `Text(line)` — a CRLF- or LF-terminated line of plaintext
//!     drawn from the payload with any IAC sub-sequences stripped.
//!     That's where "Login:", "Password:", the user's typed
//!     characters, and command output all surface.

use crate::events::Direction;

const IAC: u8 = 0xFF;
const SB: u8 = 0xFA;
const SE: u8 = 0xF0;

pub struct TelnetParser {
    bypass: bool,
    line: Vec<u8>,
}

impl Default for TelnetParser {
    fn default() -> Self {
        Self {
            bypass: false,
            line: Vec::new(),
        }
    }
}

pub enum TelnetParserOutput {
    Need,
    Record {
        record: TelnetRecord,
        consumed: usize,
    },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct TelnetRecord {
    pub direction: Direction,
    pub kind: TelnetKind,
}

#[derive(Debug, Clone)]
pub enum TelnetKind {
    Negotiation { cmd: u8, option: u8 },
    Text(String),
}

impl TelnetRecord {
    pub fn display_line(&self) -> String {
        match &self.kind {
            TelnetKind::Negotiation { cmd, option } => {
                format!("telnet IAC {} {}", cmd_name(*cmd), option_name(*option))
            }
            TelnetKind::Text(s) => format!("telnet text {s:?}"),
        }
    }
}

const fn cmd_name(c: u8) -> &'static str {
    match c {
        0xFB => "WILL",
        0xFC => "WON'T",
        0xFD => "DO",
        0xFE => "DON'T",
        0xFA => "SB",
        0xF0 => "SE",
        0xF1 => "NOP",
        0xF2 => "DM",
        0xF3 => "BRK",
        0xF4 => "IP",
        0xF5 => "AO",
        0xF6 => "AYT",
        0xF7 => "EC",
        0xF8 => "EL",
        0xF9 => "GA",
        _ => "?",
    }
}

const fn option_name(o: u8) -> &'static str {
    match o {
        0 => "BINARY",
        1 => "ECHO",
        3 => "SUPPRESS-GA",
        5 => "STATUS",
        24 => "TERM-TYPE",
        31 => "NAWS",
        32 => "TERM-SPEED",
        33 => "REMOTE-FLOW",
        34 => "LINEMODE",
        35 => "X-DISPLAY",
        36 => "ENV",
        39 => "NEW-ENV",
        _ => "?",
    }
}

impl TelnetParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> TelnetParserOutput {
        if self.bypass {
            return TelnetParserOutput::Skip(buf.len());
        }
        // Scan byte by byte, handle IAC sequences and newlines.
        let mut i = 0usize;
        while i < buf.len() {
            let b = buf[i];
            if b == IAC {
                // Need at least 2 bytes for a command.
                if i + 1 >= buf.len() {
                    break;
                }
                let c = buf[i + 1];
                if c == IAC {
                    // Escaped 0xFF → literal byte.
                    self.line.push(IAC);
                    i += 2;
                    continue;
                }
                if c == SB {
                    // Subnegotiation: skip to IAC SE.
                    let mut j = i + 2;
                    while j + 1 < buf.len() {
                        if buf[j] == IAC && buf[j + 1] == SE {
                            j += 2;
                            break;
                        }
                        j += 1;
                    }
                    if j > buf.len() {
                        break;
                    }
                    return TelnetParserOutput::Record {
                        record: TelnetRecord {
                            direction: dir,
                            kind: TelnetKind::Negotiation { cmd: SB, option: 0 },
                        },
                        consumed: j,
                    };
                }
                // 3-byte commands (WILL/WON'T/DO/DON'T) have an option.
                match c {
                    0xFB | 0xFC | 0xFD | 0xFE => {
                        if i + 2 >= buf.len() {
                            break;
                        }
                        let opt = buf[i + 2];
                        return TelnetParserOutput::Record {
                            record: TelnetRecord {
                                direction: dir,
                                kind: TelnetKind::Negotiation {
                                    cmd: c,
                                    option: opt,
                                },
                            },
                            consumed: i + 3,
                        };
                    }
                    // 2-byte commands.
                    _ => {
                        return TelnetParserOutput::Record {
                            record: TelnetRecord {
                                direction: dir,
                                kind: TelnetKind::Negotiation { cmd: c, option: 0 },
                            },
                            consumed: i + 2,
                        };
                    }
                }
            }
            if b == b'\n' {
                let s = std::str::from_utf8(&self.line).unwrap_or("").to_string();
                let cleaned = s.trim_end_matches('\r').to_string();
                self.line.clear();
                return TelnetParserOutput::Record {
                    record: TelnetRecord {
                        direction: dir,
                        kind: TelnetKind::Text(cleaned),
                    },
                    consumed: i + 1,
                };
            }
            // Printable-ish characters become part of the line. Don't
            // explode — cap buffered line to 4 KiB to dodge runaway
            // non-text flows.
            if self.line.len() < 4096 {
                self.line.push(b);
            }
            i += 1;
        }
        if i == 0 {
            return TelnetParserOutput::Need;
        }
        TelnetParserOutput::Skip(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn will_echo_negotiation() {
        // IAC WILL ECHO (0xFF 0xFB 0x01)
        let buf = [0xFF, 0xFB, 0x01];
        let mut p = TelnetParser::default();
        match p.parse(&buf, Direction::Rx) {
            TelnetParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 3);
                match record.kind {
                    TelnetKind::Negotiation { cmd, option } => {
                        assert_eq!(cmd, 0xFB);
                        assert_eq!(option, 1);
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn plaintext_line_extracted() {
        // Server sends "Login: " and then a CR LF to a prompt, client
        // types "admin" + CRLF. Test just the CRLF-terminated piece.
        let mut p = TelnetParser::default();
        let buf = b"Login: admin\r\n";
        // Our parser treats bytes up to \n as a line; CRLF is stripped.
        match p.parse(buf, Direction::Tx) {
            TelnetParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                match record.kind {
                    TelnetKind::Text(s) => assert_eq!(s, "Login: admin"),
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn subneg_skipped_to_se() {
        // IAC SB ... IAC SE
        let buf = [0xFF, 0xFA, 24, 1, b'x', b'y', 0xFF, 0xF0];
        let mut p = TelnetParser::default();
        match p.parse(&buf, Direction::Rx) {
            TelnetParserOutput::Record { consumed, .. } => {
                assert_eq!(consumed, buf.len());
            }
            _ => panic!(),
        }
    }
}
