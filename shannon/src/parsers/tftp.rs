//! TFTP (RFC 1350 + RFC 2347) — udp/69.
//!
//! Trivial file transfer protocol still shows up everywhere:
//! PXE boot, router firmware pushes, industrial controller
//! provisioning, appliance bulk updates. Each packet starts with
//! a 2-byte opcode (BE):
//!
//! ```text
//!   1 RRQ    filename\0 mode\0 [opt\0 val\0]...
//!   2 WRQ    filename\0 mode\0 [opt\0 val\0]...
//!   3 DATA   u16 block  data[0..512]
//!   4 ACK    u16 block
//!   5 ERROR  u16 code   message\0
//!   6 OACK   opt\0 val\0 [opt\0 val\0]...
//! ```
//!
//! Surfaced: opcode, filename (for RRQ/WRQ), transfer mode,
//! option names/values (e.g. `blksize=1024`, `tsize=0`), block
//! number for DATA/ACK, error code + message for ERROR.

use crate::events::Direction;

pub struct TftpParser {
    bypass: bool,
}

impl Default for TftpParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum TftpParserOutput {
    Need,
    Record { record: TftpRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct TftpRecord {
    pub direction: Direction,
    pub kind: TftpKind,
}

#[derive(Debug, Clone)]
pub enum TftpKind {
    Read { filename: String, mode: String, options: Vec<(String, String)> },
    Write { filename: String, mode: String, options: Vec<(String, String)> },
    Data { block: u16, bytes: usize },
    Ack { block: u16 },
    Error { code: u16, code_name: &'static str, message: String },
    Oack { options: Vec<(String, String)> },
}

impl TftpRecord {
    pub fn display_line(&self) -> String {
        match &self.kind {
            TftpKind::Read { filename, mode, options } => {
                format!("tftp RRQ file={filename:?} mode={mode}{}", fmt_opts(options))
            }
            TftpKind::Write { filename, mode, options } => {
                format!("tftp WRQ file={filename:?} mode={mode}{}", fmt_opts(options))
            }
            TftpKind::Data { block, bytes } => {
                format!("tftp DATA block={block} bytes={bytes}")
            }
            TftpKind::Ack { block } => format!("tftp ACK block={block}"),
            TftpKind::Error { code, code_name, message } => {
                format!("tftp ERROR {code} ({code_name}) {message:?}")
            }
            TftpKind::Oack { options } => format!("tftp OACK{}", fmt_opts(options)),
        }
    }
}

fn fmt_opts(o: &[(String, String)]) -> String {
    if o.is_empty() {
        String::new()
    } else {
        let parts: Vec<String> = o.iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!(" opts=[{}]", parts.join(","))
    }
}

impl TftpParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> TftpParserOutput {
        if self.bypass {
            return TftpParserOutput::Skip(buf.len());
        }
        if buf.len() < 2 {
            return TftpParserOutput::Need;
        }
        let op = u16::from_be_bytes([buf[0], buf[1]]);
        let body = &buf[2..];
        let kind = match op {
            1 | 2 => {
                let mut parts = split_nul(body);
                let filename = match parts.next() {
                    Some(s) => s.to_string(),
                    None => {
                        self.bypass = true;
                        return TftpParserOutput::Skip(buf.len());
                    }
                };
                let mode = match parts.next() {
                    Some(s) => s.to_string(),
                    None => {
                        self.bypass = true;
                        return TftpParserOutput::Skip(buf.len());
                    }
                };
                let options = collect_kv(&mut parts);
                if op == 1 {
                    TftpKind::Read { filename, mode, options }
                } else {
                    TftpKind::Write { filename, mode, options }
                }
            }
            3 => {
                if body.len() < 2 {
                    self.bypass = true;
                    return TftpParserOutput::Skip(buf.len());
                }
                let block = u16::from_be_bytes([body[0], body[1]]);
                TftpKind::Data { block, bytes: body.len() - 2 }
            }
            4 => {
                if body.len() < 2 {
                    self.bypass = true;
                    return TftpParserOutput::Skip(buf.len());
                }
                let block = u16::from_be_bytes([body[0], body[1]]);
                TftpKind::Ack { block }
            }
            5 => {
                if body.len() < 3 {
                    self.bypass = true;
                    return TftpParserOutput::Skip(buf.len());
                }
                let code = u16::from_be_bytes([body[0], body[1]]);
                let message = std::str::from_utf8(&body[2..])
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string();
                TftpKind::Error { code, code_name: error_name(code), message }
            }
            6 => {
                let mut it = split_nul(body);
                let options = collect_kv(&mut it);
                TftpKind::Oack { options }
            }
            _ => {
                self.bypass = true;
                return TftpParserOutput::Skip(buf.len());
            }
        };
        TftpParserOutput::Record {
            record: TftpRecord { direction: dir, kind },
            consumed: buf.len(),
        }
    }
}

fn split_nul(mut buf: &[u8]) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        if buf.is_empty() {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let s = std::str::from_utf8(&buf[..end]).ok();
        buf = if end < buf.len() { &buf[end + 1..] } else { &[][..] };
        s
    })
}

fn collect_kv<'a>(it: &mut impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    loop {
        let k = match it.next() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => break,
        };
        let v = match it.next() {
            Some(s) => s.to_string(),
            None => break,
        };
        out.push((k, v));
    }
    out
}

const fn error_name(code: u16) -> &'static str {
    match code {
        0 => "not-defined",
        1 => "file-not-found",
        2 => "access-violation",
        3 => "disk-full",
        4 => "illegal-op",
        5 => "unknown-tid",
        6 => "file-exists",
        7 => "no-such-user",
        8 => "option-negotiation-failed",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrq_with_options() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes()); // RRQ
        buf.extend_from_slice(b"pxelinux.0\0");
        buf.extend_from_slice(b"octet\0");
        buf.extend_from_slice(b"blksize\0");
        buf.extend_from_slice(b"1024\0");
        buf.extend_from_slice(b"tsize\0");
        buf.extend_from_slice(b"0\0");
        let mut p = TftpParser::default();
        match p.parse(&buf, Direction::Tx) {
            TftpParserOutput::Record { record, .. } => match record.kind {
                TftpKind::Read { filename, mode, options } => {
                    assert_eq!(filename, "pxelinux.0");
                    assert_eq!(mode, "octet");
                    assert_eq!(options.len(), 2);
                    assert_eq!(options[0], ("blksize".into(), "1024".into()));
                    assert_eq!(options[1], ("tsize".into(), "0".into()));
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn error_file_not_found() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(b"not found\0");
        let mut p = TftpParser::default();
        match p.parse(&buf, Direction::Rx) {
            TftpParserOutput::Record { record, .. } => match record.kind {
                TftpKind::Error { code, code_name, message } => {
                    assert_eq!(code, 1);
                    assert_eq!(code_name, "file-not-found");
                    assert_eq!(message, "not found");
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_op_bypasses() {
        let mut p = TftpParser::default();
        let buf = [0x00u8, 0x10]; // opcode 16 unknown
        assert!(matches!(p.parse(&buf, Direction::Tx), TftpParserOutput::Skip(_)));
    }
}
