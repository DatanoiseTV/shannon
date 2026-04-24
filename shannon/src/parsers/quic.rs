//! QUIC v1 (RFC 9000 / 9001) Initial packet inspection — udp/443
//! and every port operators run HTTP/3 on.
//!
//! QUIC Initial packets fully encrypt their payload — including the
//! TLS ClientHello that carries the SNI — but the Initial keys are
//! *deterministic* from the packet's Destination Connection ID
//! (RFC 9001 §5.2). So with no secret material at all shannon can:
//!
//!   1. Recognise a QUIC long-header Initial packet.
//!   2. Derive the client Initial keys (HKDF-Extract with the v1
//!      salt, HKDF-Expand-Label for key / iv / hp).
//!   3. Strip header protection (AES-128-ECB mask over the sampled
//!      ciphertext).
//!   4. Decrypt the payload with AES-128-GCM.
//!   5. Walk the frames, find the CRYPTO frame, feed the resulting
//!      TLS ClientHello bytes to [`crate::parsers::tls`] to get the
//!      SNI + ALPN.
//!
//! The server-side Initial uses a different salt key (`server in`);
//! v1 ships the client side only — that's where SNI lives. Later
//! packets (Handshake, 1-RTT) need keys derived from the TLS
//! master secret, which shannon doesn't have; those stay opaque.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::{AeadInPlace, Aes128Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::events::Direction;
use crate::parsers::tls::{HelloKind, TlsParser, TlsParserOutput, TlsRecord};

/// RFC 9001 §5.2 — initial_salt for QUIC v1. Bytes verbatim.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

pub struct QuicParser {
    bypass: bool,
    done: bool,
}

impl Default for QuicParser {
    fn default() -> Self {
        Self { bypass: false, done: false }
    }
}

pub enum QuicParserOutput {
    Need,
    Record { record: QuicRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct QuicRecord {
    pub direction: Direction,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    /// Populated when a TLS ClientHello was successfully extracted
    /// from the decrypted CRYPTO frame.
    pub tls: Option<TlsRecord>,
}

impl QuicRecord {
    pub fn display_line(&self) -> String {
        let dcid_hex: String = self.dcid.iter().map(|b| format!("{b:02x}")).collect();
        let sni = self
            .tls
            .as_ref()
            .and_then(|t| t.sni.as_deref())
            .map(|s| format!(" sni={s}"))
            .unwrap_or_default();
        let alpn = self
            .tls
            .as_ref()
            .map(|t| {
                if t.alpn.is_empty() {
                    String::new()
                } else {
                    format!(" alpn={}", t.alpn.join(","))
                }
            })
            .unwrap_or_default();
        format!(
            "quic v{:08x} Initial dcid={}{sni}{alpn}",
            self.version, dcid_hex,
        )
    }
}

impl QuicParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> QuicParserOutput {
        if self.bypass || self.done {
            return QuicParserOutput::Skip(buf.len());
        }
        // QUIC long-header: first byte form-bit=1 + fixed-bit=1 =>
        // (buf[0] & 0xc0) == 0xc0.
        if buf.len() < 7 {
            return QuicParserOutput::Need;
        }
        if (buf[0] & 0xc0) != 0xc0 {
            self.bypass = true;
            return QuicParserOutput::Skip(buf.len());
        }
        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        // Only v1 for now. Draft versions share the same Initial-key
        // recipe but different salts.
        if version != 0x0000_0001 {
            self.bypass = true;
            return QuicParserOutput::Skip(buf.len());
        }
        // Long-header types (v1): 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry.
        let long_type = (buf[0] >> 4) & 0x03;
        if long_type != 0 {
            self.bypass = true;
            return QuicParserOutput::Skip(buf.len());
        }
        let dcid_len = buf[5] as usize;
        let after_dcid_len = 6;
        if buf.len() < after_dcid_len + dcid_len + 1 {
            return QuicParserOutput::Need;
        }
        let dcid = buf[after_dcid_len..after_dcid_len + dcid_len].to_vec();
        let scid_len_off = after_dcid_len + dcid_len;
        let scid_len = buf[scid_len_off] as usize;
        let scid_off = scid_len_off + 1;
        if buf.len() < scid_off + scid_len {
            return QuicParserOutput::Need;
        }
        let scid = buf[scid_off..scid_off + scid_len].to_vec();
        let after_scid = scid_off + scid_len;

        // Token length (varint).
        let (token_len, token_vlen) = match read_varint(&buf[after_scid..]) {
            Some(v) => v,
            None => return QuicParserOutput::Need,
        };
        let token_off = after_scid + token_vlen;
        if buf.len() < token_off + token_len as usize {
            return QuicParserOutput::Need;
        }
        let after_token = token_off + token_len as usize;

        // Packet length (varint) — covers packet number + payload.
        let (pkt_len, pkt_vlen) = match read_varint(&buf[after_token..]) {
            Some(v) => v,
            None => return QuicParserOutput::Need,
        };
        let pn_offset = after_token + pkt_vlen;
        let total = pn_offset + pkt_len as usize;
        if buf.len() < total {
            return QuicParserOutput::Need;
        }

        // Derive Initial keys from DCID.
        let (client_key, client_iv, client_hp) = derive_client_initial(&dcid);

        // Sample for header protection: 16 bytes starting at
        // pn_offset + 4 (per RFC 9001 §5.4.2 — we don't know the
        // actual pn length yet, so we use the fixed 4-byte offset).
        if buf.len() < pn_offset + 4 + 16 {
            self.bypass = true;
            return QuicParserOutput::Skip(total);
        }
        let sample_off = pn_offset + 4;
        let mask = hp_mask(&client_hp, &buf[sample_off..sample_off + 16]);

        // Reassemble a mutable header copy + packet-number bytes so we
        // can XOR the protection off without disturbing the source
        // buffer.
        let mut header = buf[..pn_offset].to_vec();
        header[0] ^= mask[0] & 0x0f; // long headers use low 4 bits
        let pn_len = ((header[0] & 0x03) + 1) as usize;
        if pn_offset + pn_len > sample_off {
            // The sample overlaps the packet number — per spec this
            // implies pn_len <= 4 (sample at pn_offset+4). Bail to
            // bypass rather than decrypt garbage.
            self.bypass = true;
            return QuicParserOutput::Skip(total);
        }
        let mut pn_bytes = buf[pn_offset..pn_offset + pn_len].to_vec();
        for i in 0..pn_len {
            pn_bytes[i] ^= mask[1 + i];
        }
        header.extend_from_slice(&pn_bytes);

        // Truncated packet number → full 64-bit pn (for short Initial
        // flights the pn is 0..=3 and the full value equals the
        // reconstructed low bits; no prior-pn state needed).
        let mut pn: u64 = 0;
        for b in &pn_bytes {
            pn = (pn << 8) | *b as u64;
        }

        // Build the 12-byte nonce: IV XOR big-endian pn padded on the
        // left with zeros.
        let mut nonce = client_iv;
        for i in 0..8 {
            nonce[12 - 1 - i] ^= ((pn >> (i * 8)) & 0xff) as u8;
        }

        // Decrypt payload.
        let payload_off = pn_offset + pn_len;
        let payload_end = total;
        let ciphertext = &buf[payload_off..payload_end];
        let mut work = ciphertext.to_vec();
        let plaintext = match aead_decrypt(&client_key, &nonce, &header, &mut work) {
            Some(p) => p,
            None => {
                self.bypass = true;
                return QuicParserOutput::Skip(total);
            }
        };

        // Walk frames to find the CRYPTO frame.
        let crypto_bytes = match find_crypto_frame(plaintext) {
            Some(b) => b,
            None => {
                // No CRYPTO frame in this Initial — not an error, but
                // nothing to do. Emit a record with no TLS.
                self.done = true;
                return QuicParserOutput::Record {
                    record: QuicRecord {
                        direction: dir,
                        version,
                        dcid,
                        scid,
                        tls: None,
                    },
                    consumed: total,
                };
            }
        };

        // CRYPTO payload is raw TLS handshake bytes (not wrapped in a
        // record). Synthesise a TLS record envelope so the existing
        // parser recognises it: 0x16 0x03 0x03 <len_be> <handshake…>.
        let mut envelope = Vec::with_capacity(crypto_bytes.len() + 5);
        envelope.push(0x16);
        envelope.extend_from_slice(&[0x03, 0x03]);
        envelope.extend_from_slice(&(crypto_bytes.len() as u16).to_be_bytes());
        envelope.extend_from_slice(&crypto_bytes);
        let mut tls_parser = TlsParser::default();
        let tls = match tls_parser.parse(&envelope, dir) {
            TlsParserOutput::Record { record, .. }
                if matches!(record.kind, HelloKind::Client) =>
            {
                Some(record)
            }
            _ => None,
        };

        self.done = true;
        QuicParserOutput::Record {
            record: QuicRecord { direction: dir, version, dcid, scid, tls },
            consumed: total,
        }
    }
}

/// Derive (client_key, client_iv, client_hp) — the three keys that
/// together let us strip header protection and AES-GCM-decrypt a
/// client-initiated QUIC Initial per RFC 9001 §5.1.
fn derive_client_initial(dcid: &[u8]) -> ([u8; 16], [u8; 12], [u8; 16]) {
    // HKDF-Extract(salt=INITIAL_SALT_V1, IKM=DCID) is what the
    // `Hkdf::new` constructor already does internally.
    let initial_hk = Hkdf::<Sha256>::new(Some(&INITIAL_SALT_V1), dcid);
    let mut client_initial_secret = [0u8; 32];
    hkdf_expand_label_with(&initial_hk, "client in", &mut client_initial_secret);
    let client_hk = Hkdf::<Sha256>::from_prk(&client_initial_secret).expect("PRK len");
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    hkdf_expand_label_with(&client_hk, "quic key", &mut key);
    hkdf_expand_label_with(&client_hk, "quic iv", &mut iv);
    hkdf_expand_label_with(&client_hk, "quic hp", &mut hp);
    (key, iv, hp)
}

/// HKDF-Expand-Label per RFC 8446 §7.1. `context` is always empty
/// in the QUIC derivations.
fn hkdf_expand_label_with(hk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // context length 0
    hk.expand(&info, out).expect("HKDF expand");
}

/// AES-128-ECB a single 16-byte sample with the header-protection
/// key, return the mask bytes (we use the first 5).
fn hp_mask(hp: &[u8; 16], sample: &[u8]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(hp));
    let mut block = [0u8; 16];
    block.copy_from_slice(&sample[..16]);
    let mut b = GenericArray::from_mut_slice(&mut block);
    cipher.encrypt_block(&mut b);
    block
}

/// AES-128-GCM decrypt. Returns the plaintext slice on success.
fn aead_decrypt<'a>(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &'a mut Vec<u8>,
) -> Option<&'a [u8]> {
    if buf.len() < 16 {
        return None;
    }
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));
    let total = buf.len();
    let split = total - 16;
    let (ct_part, tag) = buf.split_at_mut(split);
    let mut tag_fixed = [0u8; 16];
    tag_fixed.copy_from_slice(tag);
    let nonce_ga = Nonce::from_slice(nonce);
    cipher
        .decrypt_in_place_detached(nonce_ga, aad, ct_part, (&tag_fixed).into())
        .ok()?;
    Some(&buf[..split])
}

/// Variable-length integer per RFC 9000 §16. Returns (value, length).
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let len = 1usize << ((buf[0] >> 6) & 0x03);
    if buf.len() < len {
        return None;
    }
    let mut v = (buf[0] & 0x3f) as u64;
    for b in &buf[1..len] {
        v = (v << 8) | *b as u64;
    }
    Some((v, len))
}

/// Scan the decrypted Initial payload for the first CRYPTO frame
/// (type 0x06) and return its body as a fresh Vec (may reassemble
/// non-zero offsets when the ClientHello is split across multiple
/// CRYPTO frames — v1 only concatenates, doesn't reorder).
fn find_crypto_frame(mut p: &[u8]) -> Option<Vec<u8>> {
    let mut buffered: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();
    while !p.is_empty() {
        let (frame_type, adv) = read_varint(p)?;
        p = p.get(adv..)?;
        match frame_type {
            0x00 => {} // PADDING
            0x01 => {} // PING
            0x06 => {
                let (offset, a) = read_varint(p)?;
                p = p.get(a..)?;
                let (length, a) = read_varint(p)?;
                p = p.get(a..)?;
                let l = length as usize;
                if p.len() < l {
                    return None;
                }
                buffered.insert(offset, p[..l].to_vec());
                p = &p[l..];
            }
            _ => {
                // Unknown frame — bail; we don't decode other frame
                // types in v1.
                return reassemble(&buffered);
            }
        }
    }
    reassemble(&buffered)
}

fn reassemble(chunks: &std::collections::BTreeMap<u64, Vec<u8>>) -> Option<Vec<u8>> {
    if chunks.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    let mut expected: u64 = 0;
    for (offset, bytes) in chunks {
        if *offset != expected {
            // Gap — return what we have so the TLS parser can at least
            // try the prefix.
            break;
        }
        out.extend_from_slice(bytes);
        expected += bytes.len() as u64;
    }
    if out.is_empty() { None } else { Some(out) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_quic() {
        let mut p = QuicParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n\r\n", Direction::Tx),
            QuicParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_needs_more() {
        let mut p = QuicParser::default();
        assert!(matches!(p.parse(&[0xc0, 0, 0], Direction::Tx), QuicParserOutput::Need));
    }

    /// Sample from RFC 9001 Appendix A.1 — decrypt the client Initial
    /// and confirm we recover a ClientHello whose SNI is
    /// "example.com".
    #[test]
    fn rfc9001_client_initial_decrypts() {
        // Packet bytes from RFC 9001 §A.1, "c000000001088394…"
        // (full hex provided by the RFC). Concatenated below.
        let hex = concat!(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
            "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
            "e221af44860018ab0856972e194cd934",
        );
        let buf: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|h| u8::from_str_radix(std::str::from_utf8(h).unwrap(), 16).unwrap())
            .collect();
        let mut p = QuicParser::default();
        match p.parse(&buf, Direction::Tx) {
            QuicParserOutput::Record { record, .. } => {
                assert_eq!(record.version, 0x0000_0001);
                let tls = record.tls.expect("TLS extracted");
                assert_eq!(tls.sni.as_deref(), Some("example.com"));
            }
            other => panic!("unexpected output: {}", match other {
                QuicParserOutput::Need => "Need",
                QuicParserOutput::Skip(_) => "Skip",
                _ => "?",
            }),
        }
    }
}
