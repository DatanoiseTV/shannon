//! WireGuard — udp/51820 (default) and anywhere else operators run it.
//!
//! WireGuard is minimalist: four message types on the wire, each
//! starting with a u8 type + u8[3] reserved (all zero):
//!
//! ```text
//!   1  Handshake Initiation   148 bytes
//!   2  Handshake Response     92  bytes
//!   3  Cookie Reply           64  bytes
//!   4  Transport Data         variable (16-byte AEAD tag trails)
//! ```
//!
//! Handshake Init layout:
//!   u32 type=1 LE          (top byte 0)
//!   u32 sender_index       LE
//!   u8[32] unencrypted_ephemeral   ← X25519 ephemeral public key
//!   u8[48] encrypted_static
//!   u8[28] encrypted_timestamp
//!   u8[16] mac1
//!   u8[16] mac2
//!
//! The ephemeral public key changes every handshake but is always
//! plaintext — it's the signature that says "this flow is
//! WireGuard". We surface it as a hex preview so operators can
//! correlate two observations, and we surface the sender/receiver
//! indices so ongoing data packets can be tied back to the
//! handshake that established them.
//!
//! Transport-data packets carry no identifying fields beyond the
//! receiver index; the payload is AEAD-encrypted. shannon reports
//! the packet type and length for traffic profiling.

use crate::events::Direction;

pub struct WireguardParser {
    bypass: bool,
}

impl Default for WireguardParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum WireguardParserOutput {
    Need,
    Record {
        record: WireguardRecord,
        consumed: usize,
    },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct WireguardRecord {
    pub direction: Direction,
    pub msg_type: u8,
    pub msg_type_name: &'static str,
    pub sender_index: Option<u32>,
    pub receiver_index: Option<u32>,
    pub ephemeral_prefix: Option<String>, // first 8 bytes hex (16 chars)
    pub length: usize,
}

impl WireguardRecord {
    pub fn display_line(&self) -> String {
        let s = self
            .sender_index
            .map(|i| format!(" sender=0x{i:08x}"))
            .unwrap_or_default();
        let r = self
            .receiver_index
            .map(|i| format!(" receiver=0x{i:08x}"))
            .unwrap_or_default();
        let e = self
            .ephemeral_prefix
            .as_deref()
            .map(|s| format!(" eph={s}"))
            .unwrap_or_default();
        format!(
            "wireguard {} len={}{s}{r}{e}",
            self.msg_type_name, self.length,
        )
    }
}

impl WireguardParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> WireguardParserOutput {
        if self.bypass {
            return WireguardParserOutput::Skip(buf.len());
        }
        if buf.len() < 4 {
            return WireguardParserOutput::Need;
        }
        let msg_type = buf[0];
        // Reserved bytes must be zero per spec.
        if buf[1] != 0 || buf[2] != 0 || buf[3] != 0 {
            self.bypass = true;
            return WireguardParserOutput::Skip(buf.len());
        }
        let (expected_len, kind) = match msg_type {
            1 => (148usize, "HandshakeInit"),
            2 => (92usize, "HandshakeResponse"),
            3 => (64usize, "CookieReply"),
            4 => (buf.len().max(16), "TransportData"),
            _ => {
                self.bypass = true;
                return WireguardParserOutput::Skip(buf.len());
            }
        };
        // For fixed-length types the packet must be at least that
        // long; transport packets are length-variable.
        if msg_type != 4 && buf.len() < expected_len {
            return WireguardParserOutput::Need;
        }
        let total = if msg_type == 4 {
            buf.len()
        } else {
            expected_len
        };
        let (sender_index, receiver_index, ephemeral_prefix) = match msg_type {
            1 => {
                let si = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let eph = &buf[8..40];
                let prefix: String = eph[..8].iter().map(|b| format!("{b:02x}")).collect();
                (Some(si), None, Some(prefix))
            }
            2 => {
                let si = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let ri = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
                (Some(si), Some(ri), None)
            }
            3 => {
                let ri = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                (None, Some(ri), None)
            }
            4 => {
                let ri = if buf.len() >= 8 {
                    Some(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]))
                } else {
                    None
                };
                (None, ri, None)
            }
            _ => (None, None, None),
        };
        WireguardParserOutput::Record {
            record: WireguardRecord {
                direction: dir,
                msg_type,
                msg_type_name: kind,
                sender_index,
                receiver_index,
                ephemeral_prefix,
                length: total,
            },
            consumed: total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_init_148_bytes() {
        let mut buf = vec![0u8; 148];
        buf[0] = 1;
        // sender_index = 0xdeadbeef
        buf[4..8].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        // ephemeral = aa bb cc dd ee ff 00 11 ...
        let eph_start = 8usize;
        for (i, b) in [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]
            .iter()
            .enumerate()
        {
            buf[eph_start + i] = *b;
        }
        let mut p = WireguardParser::default();
        match p.parse(&buf, Direction::Tx) {
            WireguardParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 148);
                assert_eq!(record.msg_type_name, "HandshakeInit");
                assert_eq!(record.sender_index, Some(0xdead_beef));
                assert_eq!(record.ephemeral_prefix.as_deref(), Some("aabbccddeeff0011"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn reserved_nonzero_bypasses() {
        let mut p = WireguardParser::default();
        let buf = [1u8, 0xff, 0, 0];
        assert!(matches!(
            p.parse(&buf, Direction::Tx),
            WireguardParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_needs_more() {
        let mut p = WireguardParser::default();
        assert!(matches!(
            p.parse(&[1u8, 0, 0], Direction::Tx),
            WireguardParserOutput::Need
        ));
    }
}
