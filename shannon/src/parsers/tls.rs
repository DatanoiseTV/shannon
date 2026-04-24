//! TLS ClientHello / ServerHello inspection — any port carrying TLS.
//!
//! shannon captures plaintext via uprobes on libssl; this parser
//! reads the record-layer bytes that flow across a raw TCP socket.
//! That's how shannon labels encrypted flows with the SNI their
//! client asked for and the ALPN the server accepted — critical
//! for the service-map view of cloud traffic where most ports are
//! just "443" and only the SNI tells you if it's github, slack,
//! anthropic, or an exfiltration endpoint.
//!
//! We parse exactly two handshake messages:
//!
//! ```text
//!   RecordLayer: u8 type (0x16 Handshake) | u16 version | u16 length
//!   Handshake:   u8 type | u24 length
//!     ClientHello: u16 legacy_version
//!                  u8[32] random
//!                  session_id      (u8 len + bytes)
//!                  cipher_suites   (u16 len + u16[])
//!                  compression     (u8 len + u8[])
//!                  extensions      (u16 len + [u16 type, u16 len, body]*)
//!     ServerHello: u16 legacy_version
//!                  u8[32] random
//!                  session_id      (u8 len + bytes)
//!                  u16 cipher_suite
//!                  u8  compression
//!                  extensions      (u16 len + [u16 type, u16 len, body]*)
//! ```
//!
//! Extensions we pull out: server_name (SNI host_name, type 0),
//! application_layer_protocol_negotiation (ALPN, type 16),
//! supported_versions (for TLS 1.3 detection, type 43).
//!
//! Anything invalid / truncated bypasses so we don't wedge a flow
//! that happened to start with a byte that looked like 0x16.

use crate::events::Direction;

const HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;

pub struct TlsParser {
    bypass: bool,
    done: bool,
}

impl Default for TlsParser {
    fn default() -> Self {
        Self { bypass: false, done: false }
    }
}

pub enum TlsParserOutput {
    Need,
    Record { record: TlsRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct TlsRecord {
    pub direction: Direction,
    pub kind: HelloKind,
    pub record_version: u16,
    pub handshake_version: u16,
    pub negotiated_tls13: bool,
    pub cipher_suites: Vec<u16>,
    pub server_cipher_suite: Option<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    /// Hygiene warnings populated on ServerHello: outdated protocol
    /// version, null / export / RC4 / 3DES cipher families, etc.
    /// Empty on ClientHello — a client advertises everything it can
    /// do and only the *server's* pick is actionable.
    pub warnings: Vec<TlsWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsWarning {
    /// Server picked SSL 3.0 / TLS 1.0 / TLS 1.1 — all withdrawn from
    /// modern Web PKI, in some jurisdictions prohibited for CDE traffic.
    LegacyVersion(&'static str),
    /// Null cipher suite — no encryption at all.
    NullCipher,
    /// Export-grade cipher (40/56-bit key) — FREAK-vulnerable.
    ExportCipher,
    /// RC4 — BEAR / Bar Mitzvah / RFC 7465 prohibited.
    Rc4,
    /// 3DES — SWEET32 birthday-bound.
    TripleDes,
    /// CBC-mode with HMAC-SHA1 — Lucky13 / BEAST territory.
    CbcSha1,
    /// Anonymous Diffie-Hellman — no server authentication.
    AnonymousDh,
}

impl TlsWarning {
    pub fn label(&self) -> String {
        match self {
            Self::LegacyVersion(v) => format!("legacy {v}"),
            Self::NullCipher => "NULL cipher (no encryption)".into(),
            Self::ExportCipher => "EXPORT-grade cipher".into(),
            Self::Rc4 => "RC4 (RFC 7465 prohibited)".into(),
            Self::TripleDes => "3DES (SWEET32)".into(),
            Self::CbcSha1 => "CBC + HMAC-SHA1 (Lucky13)".into(),
            Self::AnonymousDh => "anonymous DH (no auth)".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloKind {
    Client,
    Server,
}

impl TlsRecord {
    pub fn display_line(&self) -> String {
        let kind = match self.kind {
            HelloKind::Client => "ClientHello",
            HelloKind::Server => "ServerHello",
        };
        let ver = format_version(if self.negotiated_tls13 {
            0x0304
        } else {
            self.handshake_version
        });
        let sni = self
            .sni
            .as_deref()
            .map(|s| format!(" sni={s}"))
            .unwrap_or_default();
        let alpn = if self.alpn.is_empty() {
            String::new()
        } else {
            format!(" alpn={}", self.alpn.join(","))
        };
        let cipher = match (self.kind, self.server_cipher_suite, self.cipher_suites.len()) {
            (HelloKind::Server, Some(c), _) => format!(" cipher=0x{c:04x}"),
            (HelloKind::Client, _, n) => format!(" ciphers={n}"),
            _ => String::new(),
        };
        format!("tls {kind} {ver}{sni}{alpn}{cipher}")
    }
}

fn format_version(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL3.0",
        0x0301 => "TLS1.0",
        0x0302 => "TLS1.1",
        0x0303 => "TLS1.2",
        0x0304 => "TLS1.3",
        _ => "?",
    }
}

impl TlsParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> TlsParserOutput {
        if self.bypass || self.done {
            return TlsParserOutput::Skip(buf.len());
        }
        if buf.len() < 5 {
            return TlsParserOutput::Need;
        }
        if buf[0] != HANDSHAKE || buf[1] != 0x03 {
            self.bypass = true;
            return TlsParserOutput::Skip(buf.len());
        }
        let record_version = u16::from_be_bytes([buf[1], buf[2]]);
        let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let total = 5 + rec_len;
        if rec_len == 0 || rec_len > 16_384 {
            self.bypass = true;
            return TlsParserOutput::Skip(buf.len());
        }
        if buf.len() < total {
            return TlsParserOutput::Need;
        }
        let body = &buf[5..total];
        if body.len() < 4 {
            self.bypass = true;
            return TlsParserOutput::Skip(total);
        }
        let hs_type = body[0];
        let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
        if body.len() < 4 + hs_len {
            // We may have a fragmented handshake — only the first record.
            // v1 bails rather than reassembling.
            self.bypass = true;
            return TlsParserOutput::Skip(total);
        }
        let hs = &body[4..4 + hs_len];
        let record = match hs_type {
            CLIENT_HELLO => parse_client_hello(hs, dir, record_version),
            SERVER_HELLO => parse_server_hello(hs, dir, record_version),
            _ => {
                self.bypass = true;
                return TlsParserOutput::Skip(total);
            }
        };
        match record {
            Some(r) => {
                self.done = true;
                TlsParserOutput::Record { record: r, consumed: total }
            }
            None => {
                self.bypass = true;
                TlsParserOutput::Skip(total)
            }
        }
    }
}

fn parse_client_hello(hs: &[u8], dir: Direction, record_version: u16) -> Option<TlsRecord> {
    if hs.len() < 34 {
        return None;
    }
    let handshake_version = u16::from_be_bytes([hs[0], hs[1]]);
    let mut i = 34usize; // 2 ver + 32 random
    let sid_len = *hs.get(i)? as usize;
    i += 1;
    i = i.checked_add(sid_len)?;
    if hs.len() < i + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
    i += 2;
    if hs.len() < i + cs_len || cs_len % 2 != 0 {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    for c in hs[i..i + cs_len].chunks_exact(2) {
        cipher_suites.push(u16::from_be_bytes([c[0], c[1]]));
    }
    i += cs_len;
    let comp_len = *hs.get(i)? as usize;
    i += 1;
    i = i.checked_add(comp_len)?;
    let extensions_bytes = if hs.len() >= i + 2 {
        let ext_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
        i += 2;
        if hs.len() < i + ext_len {
            return None;
        }
        &hs[i..i + ext_len]
    } else {
        &[][..]
    };
    let (sni, alpn, supported_versions) = walk_extensions(extensions_bytes);
    let negotiated_tls13 = supported_versions.iter().any(|&v| v == 0x0304);
    Some(TlsRecord {
        direction: dir,
        kind: HelloKind::Client,
        record_version,
        handshake_version,
        negotiated_tls13,
        cipher_suites,
        server_cipher_suite: None,
        sni,
        alpn,
        warnings: Vec::new(),
    })
}

fn parse_server_hello(hs: &[u8], dir: Direction, record_version: u16) -> Option<TlsRecord> {
    if hs.len() < 34 {
        return None;
    }
    let handshake_version = u16::from_be_bytes([hs[0], hs[1]]);
    let mut i = 34usize;
    let sid_len = *hs.get(i)? as usize;
    i += 1;
    i = i.checked_add(sid_len)?;
    if hs.len() < i + 3 {
        return None;
    }
    let cipher = u16::from_be_bytes([hs[i], hs[i + 1]]);
    i += 2;
    let _compression = hs[i];
    i += 1;
    let extensions_bytes = if hs.len() >= i + 2 {
        let ext_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
        i += 2;
        if hs.len() < i + ext_len {
            return None;
        }
        &hs[i..i + ext_len]
    } else {
        &[][..]
    };
    let (sni, alpn, supported_versions) = walk_extensions(extensions_bytes);
    // Server responds with the *one* version it picked in supported_versions.
    let negotiated_tls13 = supported_versions.iter().any(|&v| v == 0x0304);
    // Actionable protocol-hygiene warnings, server-side only.
    let mut warnings = Vec::new();
    let effective_version = if negotiated_tls13 { 0x0304 } else { handshake_version };
    match effective_version {
        0x0300 => warnings.push(TlsWarning::LegacyVersion("SSL 3.0")),
        0x0301 => warnings.push(TlsWarning::LegacyVersion("TLS 1.0")),
        0x0302 => warnings.push(TlsWarning::LegacyVersion("TLS 1.1")),
        _ => {}
    }
    for w in classify_cipher_suite(cipher) {
        warnings.push(w);
    }
    Some(TlsRecord {
        direction: dir,
        kind: HelloKind::Server,
        record_version,
        handshake_version,
        negotiated_tls13,
        cipher_suites: Vec::new(),
        server_cipher_suite: Some(cipher),
        sni,
        alpn,
        warnings,
    })
}

/// Classify a single TLS cipher suite number into zero or more
/// hygiene warnings. The catalogue covers the cases that actually
/// show up on production networks — NULL / EXPORT / RC4 / 3DES /
/// CBC-SHA1 / anon-DH — without pretending to enumerate every
/// assignment. Anything not flagged here is either modern AEAD (good)
/// or obscure enough that shannon surfaces the suite number raw and
/// lets the operator judge.
fn classify_cipher_suite(id: u16) -> Vec<TlsWarning> {
    let mut out = Vec::new();
    // Well-known TLS_RSA_WITH_NULL_* and TLS_ECDH_*_NULL_* lines.
    if matches!(id, 0x0001 | 0x0002 | 0x003B | 0xC001 | 0xC006 | 0xC00B | 0xC010 | 0xC015) {
        out.push(TlsWarning::NullCipher);
    }
    // EXPORT-grade (40/56-bit). Covers RSA-EXPORT-RC4-40, RSA-EXPORT-
    // DES40-CBC-SHA, DHE-DSS-EXPORT-DES40-CBC-SHA, …
    if matches!(id, 0x0003 | 0x0006 | 0x0008 | 0x000B | 0x000E | 0x0011 | 0x0014 | 0x0017 | 0x0019) {
        out.push(TlsWarning::ExportCipher);
    }
    // RC4 anywhere in the suite.
    if matches!(
        id,
        0x0004 | 0x0005 | 0x0018 | 0x001E
            | 0x0020 | 0x0024 | 0x0028 | 0x002B
            | 0x008A | 0x008E | 0x0092
            | 0xC002 | 0xC007 | 0xC00C | 0xC011 | 0xC016
            | 0xC033
    ) {
        out.push(TlsWarning::Rc4);
    }
    // 3DES-CBC-SHA family.
    if matches!(
        id,
        0x000A | 0x000D | 0x0010 | 0x0013 | 0x0016 | 0x001B
            | 0x008B | 0x008F | 0x0093
            | 0xC003 | 0xC008 | 0xC00D | 0xC012 | 0xC017
    ) {
        out.push(TlsWarning::TripleDes);
    }
    // CBC + HMAC-SHA1 (Lucky13). Very broad list — catch the common
    // AES-{128,256}-CBC-SHA and CAMELLIA-CBC-SHA assignments.
    if matches!(
        id,
        0x002F | 0x0035 | 0x0041 | 0x0084 | 0xC013 | 0xC014 | 0xC027 | 0xC028
    ) {
        out.push(TlsWarning::CbcSha1);
    }
    // Anonymous DH (no authentication).
    if matches!(
        id,
        0x0017 | 0x0018 | 0x0019 | 0x001A | 0x001B | 0x0034 | 0x003A | 0x006C | 0x006D
    ) {
        out.push(TlsWarning::AnonymousDh);
    }
    out
}

fn walk_extensions(mut buf: &[u8]) -> (Option<String>, Vec<String>, Vec<u16>) {
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut supported_versions = Vec::new();
    while buf.len() >= 4 {
        let etype = u16::from_be_bytes([buf[0], buf[1]]);
        let elen = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 4 + elen {
            break;
        }
        let body = &buf[4..4 + elen];
        match etype {
            0 => sni = parse_sni(body),
            16 => alpn = parse_alpn(body),
            43 => parse_supported_versions(body, &mut supported_versions),
            _ => {}
        }
        buf = &buf[4 + elen..];
    }
    (sni, alpn, supported_versions)
}

fn parse_sni(body: &[u8]) -> Option<String> {
    // server_name_list: u16 len, then entries
    //   entry: u8 name_type (0 = host_name), u16 host_name_len, bytes
    if body.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + list_len {
        return None;
    }
    let mut p = 2usize;
    while p + 3 <= 2 + list_len {
        let nt = body[p];
        let nl = u16::from_be_bytes([body[p + 1], body[p + 2]]) as usize;
        p += 3;
        if body.len() < p + nl {
            return None;
        }
        if nt == 0 {
            return std::str::from_utf8(&body[p..p + nl]).ok().map(|s| s.to_string());
        }
        p += nl;
    }
    None
}

fn parse_alpn(body: &[u8]) -> Vec<String> {
    // u16 list_len, then entries of u8 len + bytes
    let mut out = Vec::new();
    if body.len() < 2 {
        return out;
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + list_len {
        return out;
    }
    let mut p = 2usize;
    while p < 2 + list_len {
        let n = body[p] as usize;
        p += 1;
        if body.len() < p + n {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&body[p..p + n]) {
            out.push(s.to_string());
        }
        p += n;
    }
    out
}

fn parse_supported_versions(body: &[u8], out: &mut Vec<u16>) {
    // Client side: u8 len, then u16[] of versions.
    // Server side: single u16 version.
    if body.len() == 2 {
        out.push(u16::from_be_bytes([body[0], body[1]]));
        return;
    }
    if body.is_empty() {
        return;
    }
    let n = body[0] as usize;
    if body.len() < 1 + n || n % 2 != 0 {
        return;
    }
    for c in body[1..1 + n].chunks_exact(2) {
        out.push(u16::from_be_bytes([c[0], c[1]]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello_with_sni(sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        // server_name extension
        let host = sni.as_bytes();
        let mut sni_body = Vec::new();
        let list_len = 3 + host.len();
        sni_body.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_body.push(0); // host_name
        sni_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(host);
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_body);

        // ALPN h2,http/1.1
        let mut alpn_body = Vec::new();
        let protos: &[&[u8]] = &[b"h2", b"http/1.1"];
        let inner_len: usize = protos.iter().map(|p| 1 + p.len()).sum();
        alpn_body.extend_from_slice(&(inner_len as u16).to_be_bytes());
        for p in protos {
            alpn_body.push(p.len() as u8);
            alpn_body.extend_from_slice(p);
        }
        ext.extend_from_slice(&16u16.to_be_bytes());
        ext.extend_from_slice(&(alpn_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&alpn_body);

        // supported_versions: one entry 0x0304
        ext.extend_from_slice(&43u16.to_be_bytes());
        ext.extend_from_slice(&3u16.to_be_bytes());
        ext.push(2); // length byte
        ext.extend_from_slice(&0x0304u16.to_be_bytes());

        let mut hs = Vec::new();
        hs.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy TLS 1.2
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // sid len
        hs.extend_from_slice(&4u16.to_be_bytes()); // cs len
        hs.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        hs.extend_from_slice(&0x1302u16.to_be_bytes()); // TLS_AES_256_GCM_SHA384
        hs.push(1); // comp len
        hs.push(0); // compression null
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut record = Vec::new();
        record.push(HANDSHAKE);
        record.extend_from_slice(&0x0301u16.to_be_bytes()); // record version
        let mut hs_frame = Vec::new();
        hs_frame.push(CLIENT_HELLO);
        hs_frame.extend_from_slice(&[0u8; 3]); // placeholder for u24 len
        hs_frame.extend_from_slice(&hs);
        let hs_len = hs_frame.len() - 4;
        hs_frame[1] = ((hs_len >> 16) & 0xff) as u8;
        hs_frame[2] = ((hs_len >> 8) & 0xff) as u8;
        hs_frame[3] = (hs_len & 0xff) as u8;
        record.extend_from_slice(&(hs_frame.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs_frame);
        record
    }

    #[test]
    fn client_hello_extracts_sni_and_alpn() {
        let buf = client_hello_with_sni("api.example.com");
        let mut p = TlsParser::default();
        match p.parse(&buf, Direction::Tx) {
            TlsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.kind, HelloKind::Client);
                assert_eq!(record.sni.as_deref(), Some("api.example.com"));
                assert_eq!(record.alpn, vec!["h2", "http/1.1"]);
                assert!(record.negotiated_tls13);
                assert_eq!(record.cipher_suites, vec![0x1301, 0x1302]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_tls_bypasses() {
        let mut p = TlsParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n\r\n", Direction::Tx),
            TlsParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_buffer_needs_more() {
        let mut p = TlsParser::default();
        assert!(matches!(p.parse(&[0x16, 0x03, 0x01], Direction::Tx), TlsParserOutput::Need));
    }

    /// Build a minimal ServerHello picking `handshake_version` and
    /// cipher suite. No extensions (so no supported_versions trailer).
    fn server_hello(handshake_version: u16, cipher: u16) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.extend_from_slice(&handshake_version.to_be_bytes()); // legacy ver
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // sid len
        hs.extend_from_slice(&cipher.to_be_bytes());
        hs.push(0); // compression null
        // no extensions block
        let mut record = Vec::new();
        record.push(HANDSHAKE);
        record.extend_from_slice(&0x0303u16.to_be_bytes()); // record version
        let mut hs_frame = Vec::new();
        hs_frame.push(SERVER_HELLO);
        hs_frame.extend_from_slice(&[0u8; 3]); // placeholder for u24 len
        hs_frame.extend_from_slice(&hs);
        let hs_len = hs_frame.len() - 4;
        hs_frame[1] = ((hs_len >> 16) & 0xff) as u8;
        hs_frame[2] = ((hs_len >> 8) & 0xff) as u8;
        hs_frame[3] = (hs_len & 0xff) as u8;
        record.extend_from_slice(&(hs_frame.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs_frame);
        record
    }

    #[test]
    fn server_hello_tls10_rc4_flags_both() {
        // TLS 1.0 (0x0301) + TLS_RSA_WITH_RC4_128_SHA (0x0005).
        let buf = server_hello(0x0301, 0x0005);
        let mut p = TlsParser::default();
        match p.parse(&buf, Direction::Rx) {
            TlsParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, HelloKind::Server);
                assert!(record.warnings.contains(&TlsWarning::LegacyVersion("TLS 1.0")));
                assert!(record.warnings.contains(&TlsWarning::Rc4));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn server_hello_modern_suite_no_warnings() {
        // TLS 1.2 (0x0303) + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f).
        let buf = server_hello(0x0303, 0xc02f);
        let mut p = TlsParser::default();
        match p.parse(&buf, Direction::Rx) {
            TlsParserOutput::Record { record, .. } => {
                assert!(record.warnings.is_empty());
            }
            _ => panic!(),
        }
    }
}
