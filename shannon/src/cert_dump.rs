//! X.509 certificate extraction from TLS handshake bytes observed on
//! TCP streams.
//!
//! When `shannon trace --dump-certs DIR` is on, we scan every TCP data
//! event for a TLS handshake `Certificate` message and write each cert
//! in the chain to `DIR/<SHA256[:16]>.der` along with a one-line human
//! summary that the trace output emits inline.
//!
//! We never store the same fingerprint twice in a run (deduped via an
//! in-memory set). For a long-running operator use-case we'd externalise
//! the set to disk; v0.1 keeps it in-process.
//!
//! **Important**: this is certificate **observation**, not validation.
//! We do not check the chain against any trust store — that's the job of
//! the follow-up "rogue CA / pinning detection" feature in the roadmap.

use std::collections::HashSet;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// TLS content type for the Handshake protocol (§6.2.1 of RFC 8446).
const TLS_CT_HANDSHAKE: u8 = 22;
/// Handshake message type `Certificate` (§7.4.2 of RFC 5246).
const HT_CERTIFICATE: u8 = 11;

pub struct CertDumper {
    dir: PathBuf,
    seen: HashSet<[u8; 32]>,
    count: u64,
}

/// Short summary emitted to the operator's trace line.
#[derive(Debug, Clone)]
pub struct CertSummary {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub san_count: usize,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_prefix: String, // first 16 hex chars of SHA-256
    pub saved_path: PathBuf,
    /// Observable trust / hygiene anomalies — e.g. self-signed, weak
    /// signature algorithm, short RSA key, long validity. Populated
    /// inline by the parser; an empty list means "nothing flagged".
    pub anomalies: Vec<CertAnomaly>,
}

/// A single anomaly noticed while inspecting a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertAnomaly {
    /// Issuer DN equals subject DN — self-signed cert. Expected on
    /// trust roots, but on a leaf served by a public-facing endpoint
    /// it's almost always a misconfiguration or a MitM.
    SelfSigned,
    /// Signature algorithm uses MD5 or SHA-1; both have been withdrawn
    /// from the Web PKI.
    WeakSigAlg(String),
    /// RSA modulus shorter than the 2048-bit Web PKI floor.
    ShortRsaKey(u32),
    /// Validity window opens in the future or has already closed.
    OutsideValidity,
    /// Validity window is longer than the 398-day cap the CA/B Forum
    /// (browsers) enforces — common on internal / private-CA certs
    /// that would be rejected on the public internet.
    LongValidity(i64),
}

impl CertAnomaly {
    pub fn label(&self) -> String {
        match self {
            Self::SelfSigned => "self-signed".into(),
            Self::WeakSigAlg(alg) => format!("weak sig-alg {alg}"),
            Self::ShortRsaKey(n) => format!("RSA key {n}b"),
            Self::OutsideValidity => "outside validity window".into(),
            Self::LongValidity(d) => format!("validity {d}d (> 398d CA/B)"),
        }
    }
}

impl CertDumper {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self { dir, seen: HashSet::new(), count: 0 })
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Scan `bytes` for a TLS handshake `Certificate` message. Returns
    /// one `CertSummary` per freshly-saved certificate in the chain
    /// (duplicates by fingerprint are skipped).
    pub fn observe(&mut self, bytes: &[u8]) -> Vec<CertSummary> {
        let mut out = Vec::new();
        // The 5-byte TLS record header precedes the handshake payload:
        //   ContentType(1)  ProtocolVersion(2)  length(2)
        if bytes.len() < 5 {
            return out;
        }
        if bytes[0] != TLS_CT_HANDSHAKE {
            return out;
        }
        let rec_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        if rec_len == 0 || rec_len > bytes.len() - 5 {
            return out;
        }
        let mut p = &bytes[5..5 + rec_len];
        while p.len() >= 4 {
            let ht = p[0];
            let len = (u32::from(p[1]) << 16) | (u32::from(p[2]) << 8) | u32::from(p[3]);
            let len = len as usize;
            if len > p.len() - 4 {
                return out;
            }
            let body = &p[4..4 + len];
            if ht == HT_CERTIFICATE && body.len() >= 3 {
                let list_len = (u32::from(body[0]) << 16)
                    | (u32::from(body[1]) << 8)
                    | u32::from(body[2]);
                let list_len = list_len as usize;
                let mut cursor = &body[3..];
                if list_len > cursor.len() {
                    return out;
                }
                cursor = &cursor[..list_len];
                while cursor.len() >= 3 {
                    let cert_len = (u32::from(cursor[0]) << 16)
                        | (u32::from(cursor[1]) << 8)
                        | u32::from(cursor[2]);
                    let cert_len = cert_len as usize;
                    if cert_len == 0 || cert_len > cursor.len() - 3 {
                        break;
                    }
                    let cert_bytes = &cursor[3..3 + cert_len];
                    // TLS 1.3 CertificateEntry also has a 2-byte extensions
                    // suffix per cert; we peek for it but don't parse.
                    let advance = 3 + cert_len;
                    cursor = &cursor[advance.min(cursor.len())..];
                    if let Some(summary) = self.save_if_new(cert_bytes) {
                        out.push(summary);
                    }
                    // Skip TLS 1.3 extensions block if present: u16 length + bytes.
                    if cursor.len() >= 2 {
                        let ext_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
                        if ext_len + 2 <= cursor.len() {
                            cursor = &cursor[2 + ext_len..];
                        }
                    }
                }
            }
            p = &p[4 + len..];
        }
        out
    }

    fn save_if_new(&mut self, cert_der: &[u8]) -> Option<CertSummary> {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let fp: [u8; 32] = hasher.finalize().into();
        if !self.seen.insert(fp) {
            return None;
        }

        let Ok((_, x509)) = X509Certificate::from_der(cert_der) else {
            return None;
        };
        let subject_cn = common_name(&x509.subject()).unwrap_or_else(|| "(no CN)".to_string());
        let issuer_cn = common_name(&x509.issuer()).unwrap_or_else(|| "(no CN)".to_string());
        let san_count = x509
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(s) => Some(s.general_names.len()),
                _ => None,
            })
            .unwrap_or(0);
        let not_before = x509.validity().not_before.to_string();
        let not_after = x509.validity().not_after.to_string();

        let fp_hex = fp.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let saved_path = self.dir.join(format!("{}.der", &fp_hex[..16]));
        let meta_path = self.dir.join(format!("{}.txt", &fp_hex[..16]));
        if let Err(err) = File::create(&saved_path).and_then(|mut f| f.write_all(cert_der)) {
            tracing::warn!(%err, path = %saved_path.display(), "writing cert");
            return None;
        }
        let meta = format!(
            "subject: {subject_cn}\nissuer:  {issuer_cn}\nsan:     {san_count}\nvalid:   {not_before} → {not_after}\nsha256:  {fp_hex}\n"
        );
        let _ = File::create(&meta_path).and_then(|mut f| f.write_all(meta.as_bytes()));

        let anomalies = detect_anomalies(&x509);

        self.count += 1;
        Some(CertSummary {
            subject_cn,
            issuer_cn,
            san_count,
            not_before,
            not_after,
            fingerprint_prefix: fp_hex[..16].to_string(),
            saved_path,
            anomalies,
        })
    }
}

fn detect_anomalies(x509: &X509Certificate<'_>) -> Vec<CertAnomaly> {
    let mut out = Vec::new();

    // Self-signed: full-DN compare, not just CN — a cert with CN
    // "example.com" but different O/OU is not self-signed.
    if x509.subject() == x509.issuer() {
        out.push(CertAnomaly::SelfSigned);
    }

    // Weak signature algorithm. x509-parser exposes the OID; names
    // map to the common "md5WithRSAEncryption" / "sha1WithRSAEncryption"
    // / "ecdsa-with-SHA1" / "dsa-with-SHA1" etc.
    let sig_alg = x509.signature_algorithm.oid().to_id_string();
    if let Some(weak) = weak_sig_label(&sig_alg) {
        out.push(CertAnomaly::WeakSigAlg(weak.to_string()));
    }

    // Short RSA key. x509-parser's public_key() exposes an `RsaPublicKey`
    // variant when it can parse one; we inspect the modulus length.
    if let Ok(spki) = x509.public_key().parsed() {
        if let public_key::PublicKey::RSA(rsa) = spki {
            let bits = (rsa.modulus.len().saturating_mul(8)) as u32;
            if bits > 0 && bits < 2048 {
                out.push(CertAnomaly::ShortRsaKey(bits));
            }
        }
    }

    // Validity window checks.
    let nb = x509.validity().not_before.timestamp();
    let na = x509.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if now != 0 && (now < nb || now > na) {
        out.push(CertAnomaly::OutsideValidity);
    }
    let days = (na - nb) / 86_400;
    if days > 398 {
        out.push(CertAnomaly::LongValidity(days));
    }

    out
}

fn weak_sig_label(oid: &str) -> Option<&'static str> {
    // Matching the common OID dotted IDs; x509-parser's `to_id_string`
    // returns them in dotted form.
    match oid {
        "1.2.840.113549.1.1.4" => Some("md5WithRSAEncryption"),
        "1.2.840.113549.1.1.5" => Some("sha1WithRSAEncryption"),
        "1.2.840.10040.4.3" => Some("dsa-with-SHA1"),
        "1.2.840.10045.4.1" => Some("ecdsa-with-SHA1"),
        _ => None,
    }
}

fn common_name(name: &X509Name<'_>) -> Option<String> {
    name.iter_common_name().next().and_then(|cn| cn.as_str().ok().map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_tls() {
        let mut d = CertDumper { dir: PathBuf::from("/dev/null"), seen: HashSet::new(), count: 0 };
        assert!(d.observe(b"GET / HTTP/1.1\r\n").is_empty());
        assert!(d.observe(&[22, 3, 3]).is_empty()); // truncated header
    }

    #[test]
    fn ignores_handshake_without_certificate() {
        let mut d = CertDumper { dir: PathBuf::from("/dev/null"), seen: HashSet::new(), count: 0 };
        // TLS record: content type 22, version 0x0303, length 4.
        // Handshake: ClientHello (type 1), length 0 (malformed but we
        // just skip non-Certificate handshake types).
        let payload = [22u8, 3, 3, 0, 4, 1, 0, 0, 0];
        assert!(d.observe(&payload).is_empty());
    }
}
