//! Kerberos v5 (RFC 4120) — tcp/88 + udp/88.
//!
//! Kerberos rides raw ASN.1 BER, with the KDC flavors wrapped in
//! IMPLICIT `[APPLICATION n]` tags:
//!
//! ```text
//!   0x6A  AS-REQ      0x6B  AS-REP
//!   0x6C  TGS-REQ     0x6D  TGS-REP
//!   0x6E  AP-REQ      0x6F  AP-REP
//!   0x74  KRB-SAFE    0x75  KRB-PRIV
//!   0x76  KRB-CRED    0x7E  KRB-ERROR
//! ```
//!
//! Over TCP the message is prefixed with a 4-byte big-endian length;
//! over UDP the datagram body is exactly the ASN.1 structure.
//!
//! v1 surfaces message type and, for AS-REQ / TGS-REQ specifically,
//! makes a best-effort pass over the body to grab the realm string
//! and the first cname GeneralString — that's the client principal
//! (e.g. `alice@EXAMPLE.COM`) which is the key artefact for AD
//! visibility and AS-REP-roasting detection.

use crate::events::Direction;

pub struct KerberosParser {
    bypass: bool,
    tcp_framed: Option<bool>,
}

impl Default for KerberosParser {
    fn default() -> Self {
        Self {
            bypass: false,
            tcp_framed: None,
        }
    }
}

pub enum KerberosParserOutput {
    Need,
    Record {
        record: KerberosRecord,
        consumed: usize,
    },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct KerberosRecord {
    pub direction: Direction,
    pub msg_type: &'static str,
    pub msg_tag: u8,
    pub realm: Option<String>,
    pub cname: Option<String>,
    pub sname: Option<String>,
    pub error_code: Option<i64>,
}

impl KerberosRecord {
    pub fn display_line(&self) -> String {
        let r = self
            .realm
            .as_deref()
            .map(|s| format!(" realm={s}"))
            .unwrap_or_default();
        let c = self
            .cname
            .as_deref()
            .map(|s| format!(" cname={s}"))
            .unwrap_or_default();
        let s = self
            .sname
            .as_deref()
            .map(|s| format!(" sname={s}"))
            .unwrap_or_default();
        let e = self
            .error_code
            .map(|c| format!(" error={c}"))
            .unwrap_or_default();
        format!("kerberos {}{r}{c}{s}{e}", self.msg_type)
    }
}

impl KerberosParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> KerberosParserOutput {
        if self.bypass {
            return KerberosParserOutput::Skip(buf.len());
        }
        // Determine TCP vs UDP framing on first bytes. TCP mode has a
        // 4-byte BE length prefix followed by an APPLICATION tag; UDP
        // starts directly with the APPLICATION tag.
        if self.tcp_framed.is_none() {
            if buf.is_empty() {
                return KerberosParserOutput::Need;
            }
            if is_kerberos_tag(buf[0]) {
                self.tcp_framed = Some(false);
            } else {
                // Might be TCP framing — sanity-check first 4 bytes as a
                // plausible length and that the 5th byte is a Kerberos
                // APPLICATION tag.
                if buf.len() < 5 {
                    return KerberosParserOutput::Need;
                }
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                if len == 0 || len > 16 * 1024 * 1024 {
                    self.bypass = true;
                    return KerberosParserOutput::Skip(buf.len());
                }
                if !is_kerberos_tag(buf[4]) {
                    self.bypass = true;
                    return KerberosParserOutput::Skip(buf.len());
                }
                self.tcp_framed = Some(true);
            }
        }

        let (body_start, total) = if self.tcp_framed.unwrap() {
            if buf.len() < 4 {
                return KerberosParserOutput::Need;
            }
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            let total = 4 + len;
            if buf.len() < total {
                return KerberosParserOutput::Need;
            }
            (4, total)
        } else {
            // UDP: whole buffer is the message.
            (0, buf.len())
        };

        let body = &buf[body_start..total];
        if body.is_empty() {
            self.bypass = true;
            return KerberosParserOutput::Skip(buf.len());
        }
        let tag = body[0];
        let rec = KerberosRecord {
            direction: dir,
            msg_type: msg_name(tag),
            msg_tag: tag,
            realm: find_first_kerberos_string(body, 2),
            cname: find_cname(body),
            sname: find_sname(body),
            error_code: None,
        };
        KerberosParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }
}

const fn is_kerberos_tag(b: u8) -> bool {
    matches!(
        b,
        0x6A | 0x6B | 0x6C | 0x6D | 0x6E | 0x6F | 0x74 | 0x75 | 0x76 | 0x7E
    )
}

const fn msg_name(tag: u8) -> &'static str {
    match tag {
        0x6A => "AS-REQ",
        0x6B => "AS-REP",
        0x6C => "TGS-REQ",
        0x6D => "TGS-REP",
        0x6E => "AP-REQ",
        0x6F => "AP-REP",
        0x74 => "KRB-SAFE",
        0x75 => "KRB-PRIV",
        0x76 => "KRB-CRED",
        0x7E => "KRB-ERROR",
        _ => "?",
    }
}

/// Best-effort: find the *n*th GeneralString (tag 0x1B) in a BER
/// byte buffer and return its contents. Walks tags top to bottom
/// without constructing a full AST — cheap and gets us the realm
/// reliably because it appears at a known position relative to
/// cname.
fn find_first_kerberos_string(buf: &[u8], min_len: usize) -> Option<String> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == 0x1B {
            // shortform length
            if i + 1 >= buf.len() {
                return None;
            }
            let n = buf[i + 1] as usize;
            if n >= min_len && i + 2 + n <= buf.len() {
                if let Ok(s) = std::str::from_utf8(&buf[i + 2..i + 2 + n]) {
                    if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                        return Some(s.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// cname is PrincipalName `SEQUENCE { [0] name-type INTEGER, [1]
/// name-string SEQUENCE OF GeneralString }`. We locate a context
/// tag [1] (0xA1) containing a SEQUENCE-OF-GeneralString structure
/// and return the first GeneralString inside it.
fn find_cname(buf: &[u8]) -> Option<String> {
    // Shortcut: scan for context tag [1] (0xA1) whose inner bytes
    // begin with a SEQUENCE (0x30) and pick the first 0x1B inside.
    find_principal_string(buf, 0xA1)
}

/// sname has the same PrincipalName shape but lives under context
/// tag [3]. We pick the second GeneralString inside (first is the
/// service class, second is the instance/realm host).
fn find_sname(buf: &[u8]) -> Option<String> {
    let first = find_principal_string(buf, 0xA3)?;
    let rest = find_principal_string_after(buf, 0xA3)?;
    Some(format!("{first}/{rest}"))
}

fn find_principal_string(buf: &[u8], ctx_tag: u8) -> Option<String> {
    let mut i = 0;
    while i + 2 < buf.len() {
        if buf[i] == ctx_tag {
            let (content, content_end) = ber_len(buf, i + 1)?;
            // BER length can claim more bytes than `buf` actually has.
            // Untrusted-byte safety: clamp to the available tail.
            let end = content.checked_add(content_end)?.min(buf.len());
            let inner = &buf[content.min(end)..end];
            if let Some(s) = find_first_kerberos_string(inner, 1) {
                return Some(s);
            }
            return None;
        }
        i += 1;
    }
    None
}

fn find_principal_string_after(buf: &[u8], ctx_tag: u8) -> Option<String> {
    // Same as find_principal_string but returns the *second*
    // GeneralString inside the principal-name sequence (after skipping
    // the first).
    let mut i = 0;
    while i + 2 < buf.len() {
        if buf[i] == ctx_tag {
            let (content, len) = ber_len(buf, i + 1)?;
            // BER length isn't guaranteed to fit; clamp like its sibling
            // helper above.
            let end = content.checked_add(len)?.min(buf.len());
            let inner = &buf[content.min(end)..end];
            // Walk past first 0x1B GeneralString, then find next one.
            let mut j = 0;
            let mut seen = false;
            while j < inner.len() {
                if inner[j] == 0x1B {
                    if j + 1 >= inner.len() {
                        return None;
                    }
                    let n = inner[j + 1] as usize;
                    if !seen {
                        seen = true;
                        j += 2 + n;
                        continue;
                    }
                    if j + 2 + n <= inner.len() {
                        if let Ok(s) = std::str::from_utf8(&inner[j + 2..j + 2 + n]) {
                            if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                                return Some(s.to_string());
                            }
                        }
                    }
                    return None;
                }
                j += 1;
            }
            return None;
        }
        i += 1;
    }
    None
}

/// Minimal BER length decoder. Returns (content_start, content_len).
fn ber_len(buf: &[u8], after_tag_idx: usize) -> Option<(usize, usize)> {
    if after_tag_idx >= buf.len() {
        return None;
    }
    let first = buf[after_tag_idx];
    if first & 0x80 == 0 {
        return Some((after_tag_idx + 1, first as usize));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 || after_tag_idx + 1 + n > buf.len() {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | buf[after_tag_idx + 1 + i] as usize;
    }
    Some((after_tag_idx + 1 + n, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_and_realm() {
        // Tiny synthetic AS-REQ-like body: [APPLICATION 10] (0x6A)
        // then a GeneralString "EXAMPLE.COM" somewhere inside.
        // We don't build a valid SEQUENCE — the parser's scan is
        // tag-agnostic inside the body.
        let realm = b"EXAMPLE.COM";
        let mut body = vec![0x6A, 0x0e]; // APPLICATION 10 len=14
        body.push(0x1B); // GeneralString tag
        body.push(realm.len() as u8);
        body.extend_from_slice(realm);
        // pad to match length (14 = 2 + 11 = 13, add 1 byte)
        body.push(0x00);
        let mut p = KerberosParser::default();
        match p.parse(&body, Direction::Tx) {
            KerberosParserOutput::Record { record, .. } => {
                assert_eq!(record.msg_type, "AS-REQ");
                assert_eq!(record.realm.as_deref(), Some("EXAMPLE.COM"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn tcp_framed_prefix_detected() {
        let realm = b"R";
        let mut body = vec![0x6A, 0x05];
        body.push(0x1B);
        body.push(realm.len() as u8);
        body.extend_from_slice(realm);
        body.push(0x00);
        let mut framed = Vec::new();
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);
        let mut p = KerberosParser::default();
        match p.parse(&framed, Direction::Tx) {
            KerberosParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, framed.len());
                assert_eq!(record.msg_type, "AS-REQ");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_kerberos_bypasses() {
        let mut p = KerberosParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            KerberosParserOutput::Skip(_)
        ));
    }
}
