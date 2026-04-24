//! High-level security warnings.
//!
//! Extends the secrets scanner with logic that isn't a regex but a
//! semantic rule:
//!
//! - **Default credentials**. Matches Basic-auth strings and observed
//!   LOGIN/USER+PASS pairs against a catalogue of widely-used defaults
//!   (admin:admin, root:root, postgres:postgres, etc).
//! - **Plaintext credentials on a non-loopback socket**. Flags Basic
//!   auth / POP3 USER+PASS / IMAP LOGIN / SMTP AUTH that traverse an
//!   interface outside `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`,
//!   `172.16.0.0/12`, `::1/128`, `fe80::/10`.
//! - **Weak TLS**. Flags ClientHello / ServerHello observations with
//!   protocol version < TLS 1.2 (future hook — we don't parse
//!   ClientHello yet; exposed here as an API for when that lands).
//! - **PII**. Shape patterns for credit-card numbers (Luhn-verified),
//!   US SSN, generic IBAN.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct Warning {
    pub kind: WarningKind,
    pub severity: Severity,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarningKind {
    DefaultCredentials,
    PlaintextCredsOnPublic,
    WeakTlsVersion,
    PiiCreditCard,
    PiiSsn,
    PiiIban,
    Other(String),
}

impl WarningKind {
    pub fn label(&self) -> String {
        match self {
            Self::DefaultCredentials => "default_credentials".into(),
            Self::PlaintextCredsOnPublic => "plaintext_creds_on_public".into(),
            Self::WeakTlsVersion => "weak_tls_version".into(),
            Self::PiiCreditCard => "pii_credit_card".into(),
            Self::PiiSsn => "pii_ssn".into(),
            Self::PiiIban => "pii_iban".into(),
            Self::Other(s) => s.clone(),
        }
    }
}

/// Try every warning rule on `(user, password)` observed as a login
/// pair. Returns zero or more findings.
pub fn check_credentials(user: &str, password: &str, peer: Option<IpAddr>) -> Vec<Warning> {
    let mut out = Vec::new();
    if is_default_credential(user, password) {
        out.push(Warning {
            kind: WarningKind::DefaultCredentials,
            severity: Severity::Critical,
            detail: format!("default credential observed: user={user}"),
        });
    }
    if let Some(ip) = peer {
        if !is_private(ip) {
            out.push(Warning {
                kind: WarningKind::PlaintextCredsOnPublic,
                severity: Severity::High,
                detail: format!("plaintext credential crossing public network to {ip}"),
            });
        }
    }
    out
}

/// Scan a captured body for PII shapes.
pub fn scan_pii(bytes: &[u8]) -> Vec<Warning> {
    let mut out = Vec::new();
    if let Ok(text) = std::str::from_utf8(bytes) {
        if find_credit_card(text) {
            out.push(Warning {
                kind: WarningKind::PiiCreditCard,
                severity: Severity::High,
                detail: "credit-card-shaped digits (Luhn-verified) in payload".into(),
            });
        }
        if find_ssn(text) {
            out.push(Warning {
                kind: WarningKind::PiiSsn,
                severity: Severity::High,
                detail: "US SSN shape in payload".into(),
            });
        }
        if find_iban(text) {
            out.push(Warning {
                kind: WarningKind::PiiIban,
                severity: Severity::Medium,
                detail: "IBAN shape in payload".into(),
            });
        }
    }
    out
}

/// Basic-auth decode + credential check. `header_value` is the value of
/// `Authorization:` minus the `Basic ` prefix; caller strips.
pub fn check_basic_auth(encoded: &str, peer: Option<IpAddr>) -> Vec<Warning> {
    let Some(decoded) = base64_decode(encoded.trim()) else {
        return Vec::new();
    };
    let Ok(s) = std::str::from_utf8(&decoded) else {
        return Vec::new();
    };
    if let Some((u, p)) = s.split_once(':') {
        return check_credentials(u, p, peer);
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// Default-credential catalogue.
// ---------------------------------------------------------------------------

fn default_pairs() -> &'static HashSet<(&'static str, &'static str)> {
    static SET: OnceLock<HashSet<(&'static str, &'static str)>> = OnceLock::new();
    SET.get_or_init(|| {
        let mut s = HashSet::new();
        for pair in [
            // Generic.
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", ""),
            ("admin", "123456"),
            ("root", "root"),
            ("root", ""),
            ("root", "toor"),
            ("root", "password"),
            ("user", "user"),
            ("test", "test"),
            ("guest", "guest"),
            // Databases.
            ("postgres", "postgres"),
            ("mysql", "mysql"),
            ("root", "root"),
            ("sa", "sa"),
            ("sa", ""),
            ("oracle", "oracle"),
            ("system", "manager"),
            // Apps.
            ("tomcat", "tomcat"),
            ("manager", "manager"),
            ("admin", "grafana"),
            ("grafana", "grafana"),
            ("elastic", "changeme"),
            ("kibana", "kibana"),
            ("minio", "minio123"),
            ("minioadmin", "minioadmin"),
            ("neo4j", "neo4j"),
            ("jenkins", "jenkins"),
            // Vendors: network gear.
            ("cisco", "cisco"),
            ("ubnt", "ubnt"),
            ("admin", "airlive"),
            ("admin", "hikvision"),
            ("admin", "12345"),
            ("admin", "9999"),
            ("admin", "1234"),
            ("admin", "dahua"),
            // IoT / cameras.
            ("admin", "888888"),
            ("root", "vizxv"),
            ("admin", "admin1234"),
            // MikroTik / RouterOS.
            ("admin", ""),
            // SSH appliances.
            ("pi", "raspberry"),
            ("ubuntu", "ubuntu"),
        ] {
            s.insert(pair);
        }
        s
    })
}

fn is_default_credential(user: &str, pass: &str) -> bool {
    default_pairs().contains(&(user, pass))
}

// ---------------------------------------------------------------------------
// Network helpers.
// ---------------------------------------------------------------------------

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.to_ipv4_mapped().is_some_and(|v4| {
                    v4.is_loopback() || v4.is_private() || v4.is_link_local()
                })
        }
    }
}

// ---------------------------------------------------------------------------
// PII detectors.
// ---------------------------------------------------------------------------

fn find_credit_card(text: &str) -> bool {
    // Heuristic: runs of 13-19 digits (optionally separated by spaces or
    // hyphens) that pass the Luhn algorithm.
    let mut digits = Vec::with_capacity(20);
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c.to_digit(10).unwrap() as u8);
            if digits.len() > 19 {
                digits.remove(0);
            }
            if digits.len() >= 13 && luhn_ok(&digits) {
                return true;
            }
        } else if c == ' ' || c == '-' {
            // keep window
        } else {
            digits.clear();
        }
    }
    false
}

fn luhn_ok(d: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, &v) in d.iter().rev().enumerate() {
        let v = u32::from(v);
        sum += if i % 2 == 1 {
            let doubled = v * 2;
            if doubled > 9 { doubled - 9 } else { doubled }
        } else {
            v
        };
    }
    sum % 10 == 0
}

fn find_ssn(text: &str) -> bool {
    // US SSN: NNN-NN-NNNN, with the bad prefixes (000, 666, 9xx) removed.
    let bytes = text.as_bytes();
    if bytes.len() < 11 {
        return false;
    }
    for i in 0..=bytes.len() - 11 {
        if !bytes[i].is_ascii_digit() || !bytes[i + 1].is_ascii_digit()
            || !bytes[i + 2].is_ascii_digit() || bytes[i + 3] != b'-'
            || !bytes[i + 4].is_ascii_digit() || !bytes[i + 5].is_ascii_digit()
            || bytes[i + 6] != b'-' || !bytes[i + 7].is_ascii_digit()
            || !bytes[i + 8].is_ascii_digit() || !bytes[i + 9].is_ascii_digit()
            || !bytes[i + 10].is_ascii_digit()
        {
            continue;
        }
        let area = &text[i..i + 3];
        if area == "000" || area == "666" || area.starts_with('9') {
            continue;
        }
        // Check word boundaries.
        if i > 0 && bytes[i - 1].is_ascii_digit() {
            continue;
        }
        if i + 11 < bytes.len() && bytes[i + 11].is_ascii_digit() {
            continue;
        }
        return true;
    }
    false
}

fn find_iban(text: &str) -> bool {
    // Very loose: uppercase pair + 2 digits + 11..=30 alphanumerics.
    let bytes = text.as_bytes();
    for i in 0..bytes.len().saturating_sub(15) {
        if bytes[i].is_ascii_uppercase()
            && bytes[i + 1].is_ascii_uppercase()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
        {
            // Count the run.
            let mut j = i + 4;
            while j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
                j += 1;
            }
            let run = j - i;
            if (15..=34).contains(&run) {
                // Rudimentary boundary check.
                if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
                    continue;
                }
                if j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
                    continue;
                }
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Minimal base64 decoder for the Basic-auth path.
// ---------------------------------------------------------------------------

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - b'A' as u32,
            'a'..='z' => c as u32 - b'a' as u32 + 26,
            '0'..='9' => c as u32 - b'0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            c if c.is_whitespace() => continue,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_admin_admin() {
        let w = check_credentials("admin", "admin", None);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].kind, WarningKind::DefaultCredentials);
        assert_eq!(w[0].severity, Severity::Critical);
    }

    #[test]
    fn doesnt_flag_real_creds() {
        assert!(check_credentials("alice", "unique-passphrase", None).is_empty());
    }

    #[test]
    fn public_peer_flagged() {
        let w = check_credentials("alice", "secret", Some("8.8.8.8".parse().unwrap()));
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].kind, WarningKind::PlaintextCredsOnPublic);
    }

    #[test]
    fn private_peer_ok() {
        assert!(check_credentials("alice", "secret", Some("10.0.0.1".parse().unwrap())).is_empty());
    }

    #[test]
    fn luhn_credit_card_detected() {
        let text = "card: 4111 1111 1111 1111 and more";
        assert!(find_credit_card(text));
    }

    #[test]
    fn luhn_bad_number_ignored() {
        let text = "random: 1234567890123456";
        assert!(!find_credit_card(text));
    }

    #[test]
    fn ssn_detected() {
        assert!(find_ssn("contact: 123-45-6789 ready"));
        assert!(!find_ssn("666-12-3456"));
        assert!(!find_ssn("000-12-3456"));
        assert!(!find_ssn("900-12-3456"));
    }

    #[test]
    fn basic_auth_roundtrip_defaults() {
        // 'admin:admin' base64 is 'YWRtaW46YWRtaW4='.
        let w = check_basic_auth("YWRtaW46YWRtaW4=", None);
        assert_eq!(w.len(), 1);
    }
}
