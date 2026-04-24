//! NTLM message classifier — surfaces NTLMSSP exchange details
//! observed inside any decoded payload (HTTP `Authorization: NTLM
//! …`, SMB SessionSetup, LDAP SASL GSS-SPNEGO …).
//!
//! The interesting message for an operator is **Type 3**
//! (Authenticate): it carries the user name, target computer name
//! (NetBIOS), domain name, and the LM/NT response. The response
//! is offline-crackable; the user/domain identity is in cleartext.
//!
//! Wire layout (NT-LAN-Manager Authentication Protocol, MS-NLMP):
//!
//! ```text
//!   u8[8]  signature   = "NTLMSSP\0"
//!   u32    message_type LE   1=Negotiate, 2=Challenge, 3=Authenticate
//!   ...
//! ```
//!
//! Type 3 fields (offsets into the message body):
//!
//! ```text
//!   12  LmChallengeResponse fields  (u16 len, u16 maxlen, u32 offset)
//!   20  NtChallengeResponse fields
//!   28  DomainName fields
//!   36  UserName fields
//!   44  Workstation fields
//!   ...
//! ```
//!
//! Each "fields" tuple gives a range inside the payload; the strings
//! are UCS-2 LE when the NTLMSSP_NEGOTIATE_UNICODE flag is set
//! (which is essentially always in modern stacks).

const SIG: &[u8] = b"NTLMSSP\0";

/// What the classifier recovered from one NTLMSSP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmFinding {
    pub message_type: u32,
    pub kind: NtlmKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtlmKind {
    /// Type 1: client → server "what NTLM features do you support?".
    /// We surface the OEM workstation / domain when present.
    Negotiate {
        workstation: Option<String>,
        domain: Option<String>,
    },
    /// Type 2: server → client challenge. Carries the 8-byte server
    /// challenge and the target name (the server's NetBIOS name).
    Challenge {
        target_name: Option<String>,
        server_challenge_hex: String,
    },
    /// Type 3: client → server response. Carries username + domain +
    /// workstation in cleartext, plus the LM/NT challenge response
    /// (which is offline-crackable for weak passwords). We surface
    /// the identity strings; the response itself is intentionally
    /// not redacted away because the hash IS the wire-cracked
    /// signal — we mark it as such so downstream redaction can
    /// strip it.
    Authenticate {
        user: Option<String>,
        domain: Option<String>,
        workstation: Option<String>,
        nt_response_len: usize,
    },
}

impl NtlmFinding {
    pub fn display_line(&self) -> String {
        match &self.kind {
            NtlmKind::Negotiate {
                workstation,
                domain,
            } => format!(
                "ntlm Type1 Negotiate ws={} dom={}",
                workstation.as_deref().unwrap_or("-"),
                domain.as_deref().unwrap_or("-"),
            ),
            NtlmKind::Challenge {
                target_name,
                server_challenge_hex,
            } => format!(
                "ntlm Type2 Challenge target={} chal={server_challenge_hex}",
                target_name.as_deref().unwrap_or("-"),
            ),
            NtlmKind::Authenticate {
                user,
                domain,
                workstation,
                nt_response_len,
            } => format!(
                "ntlm Type3 Authenticate user={}\\\\{} ws={} nt_resp={}B",
                domain.as_deref().unwrap_or("-"),
                user.as_deref().unwrap_or("-"),
                workstation.as_deref().unwrap_or("-"),
                nt_response_len,
            ),
        }
    }
}

/// Scan `bytes` for the first NTLMSSP message and decode its
/// interesting fields. Returns `None` if nothing matched.
pub fn classify(bytes: &[u8]) -> Option<NtlmFinding> {
    let pos = find_signature(bytes)?;
    let msg = &bytes[pos..];
    if msg.len() < 12 {
        return None;
    }
    let message_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    let kind = match message_type {
        1 => decode_type1(msg)?,
        2 => decode_type2(msg)?,
        3 => decode_type3(msg)?,
        _ => return None,
    };
    Some(NtlmFinding { message_type, kind })
}

fn find_signature(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < SIG.len() {
        return None;
    }
    for i in 0..=bytes.len() - SIG.len() {
        if &bytes[i..i + SIG.len()] == SIG {
            return Some(i);
        }
    }
    None
}

fn decode_type1(msg: &[u8]) -> Option<NtlmKind> {
    // Type 1 layout: sig(8) type(4) flags(4) DomainSec(8) WsSec(8) ...
    // OEM strings (ASCII) follow at the offsets given in the
    // security buffers. Often the strings are empty.
    if msg.len() < 32 {
        return None;
    }
    let domain = read_secbuf_oem(msg, 16);
    let ws = read_secbuf_oem(msg, 24);
    Some(NtlmKind::Negotiate {
        workstation: ws,
        domain,
    })
}

fn decode_type2(msg: &[u8]) -> Option<NtlmKind> {
    // Type 2 layout: sig(8) type(4) TargetNameSec(8) flags(4)
    //   ServerChallenge(8) Reserved(8) TargetInfoSec(8) ...
    if msg.len() < 48 {
        return None;
    }
    let target_name = read_secbuf_unicode(msg, 12);
    let chal = &msg[24..32];
    let chal_hex: String = chal.iter().map(|b| format!("{b:02x}")).collect();
    Some(NtlmKind::Challenge {
        target_name,
        server_challenge_hex: chal_hex,
    })
}

fn decode_type3(msg: &[u8]) -> Option<NtlmKind> {
    // Type 3 layout (MS-NLMP §2.2.1.3):
    //   sig(8) type(4)
    //   12  LmChallengeResponseFields  (8)
    //   20  NtChallengeResponseFields  (8)
    //   28  DomainNameFields           (8)
    //   36  UserNameFields             (8)
    //   44  WorkstationFields          (8)
    //   52  EncryptedRandomSessionKey  (8)
    //   60  NegotiateFlags             (4)
    //   ...
    if msg.len() < 64 {
        return None;
    }
    let nt_resp_len = u16::from_le_bytes([msg[20], msg[21]]) as usize;
    let domain = read_secbuf_unicode(msg, 28);
    let user = read_secbuf_unicode(msg, 36);
    let ws = read_secbuf_unicode(msg, 44);
    Some(NtlmKind::Authenticate {
        user,
        domain,
        workstation: ws,
        nt_response_len: nt_resp_len,
    })
}

/// Read an MS-NLMP "security buffer" (u16 len, u16 maxlen, u32
/// offset-from-start-of-msg) at `field_off` and return the
/// referenced bytes interpreted as UCS-2LE.
fn read_secbuf_unicode(msg: &[u8], field_off: usize) -> Option<String> {
    let (start, len) = read_secbuf(msg, field_off)?;
    let bytes = msg.get(start..start + len)?;
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return None;
    }
    let mut s = String::with_capacity(bytes.len() / 2);
    for c in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([c[0], c[1]]);
        if let Some(ch) = char::from_u32(u as u32) {
            s.push(ch);
        }
    }
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Same shape, but bytes are ASCII / OEM (used in Type 1).
fn read_secbuf_oem(msg: &[u8], field_off: usize) -> Option<String> {
    let (start, len) = read_secbuf(msg, field_off)?;
    let bytes = msg.get(start..start + len)?;
    if bytes.is_empty() {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

fn read_secbuf(msg: &[u8], field_off: usize) -> Option<(usize, usize)> {
    if msg.len() < field_off + 8 {
        return None;
    }
    let len = u16::from_le_bytes([msg[field_off], msg[field_off + 1]]) as usize;
    let off = u32::from_le_bytes([
        msg[field_off + 4],
        msg[field_off + 5],
        msg[field_off + 6],
        msg[field_off + 7],
    ]) as usize;
    if len == 0 || off.saturating_add(len) > msg.len() {
        return None;
    }
    Some((off, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a realistic Type 3 Authenticate message with cleartext
    /// `EVILCORP\\alice` from workstation `LAPTOP01`. NT-Response is
    /// a fake 24-byte blob just to give the length field something.
    fn build_type3(user: &str, domain: &str, ws: &str) -> Vec<u8> {
        let user_u: Vec<u8> = user.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let dom_u: Vec<u8> = domain
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let ws_u: Vec<u8> = ws.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let nt_resp = vec![0xaau8; 24];

        // Layout offsets inside `msg`:
        //   header (64 bytes through NegotiateFlags inclusive)
        //   then payload section: lm_resp, nt_resp, domain, user, ws
        let header_len = 64usize;
        let lm_off = header_len;
        let lm_len = 0; // we omit LM response
        let nt_off = lm_off + lm_len;
        let nt_len = nt_resp.len();
        let dom_off = nt_off + nt_len;
        let dom_len = dom_u.len();
        let user_off = dom_off + dom_len;
        let user_len = user_u.len();
        let ws_off = user_off + user_len;
        let ws_len = ws_u.len();

        let mut msg = Vec::with_capacity(ws_off + ws_len);
        msg.extend_from_slice(SIG); // 0..8
        msg.extend_from_slice(&3u32.to_le_bytes()); // 8..12 type=3
                                                    // 12..20 LmChallengeResponseFields
        msg.extend_from_slice(&(lm_len as u16).to_le_bytes());
        msg.extend_from_slice(&(lm_len as u16).to_le_bytes());
        msg.extend_from_slice(&(lm_off as u32).to_le_bytes());
        // 20..28 NtChallengeResponseFields
        msg.extend_from_slice(&(nt_len as u16).to_le_bytes());
        msg.extend_from_slice(&(nt_len as u16).to_le_bytes());
        msg.extend_from_slice(&(nt_off as u32).to_le_bytes());
        // 28..36 DomainNameFields
        msg.extend_from_slice(&(dom_len as u16).to_le_bytes());
        msg.extend_from_slice(&(dom_len as u16).to_le_bytes());
        msg.extend_from_slice(&(dom_off as u32).to_le_bytes());
        // 36..44 UserNameFields
        msg.extend_from_slice(&(user_len as u16).to_le_bytes());
        msg.extend_from_slice(&(user_len as u16).to_le_bytes());
        msg.extend_from_slice(&(user_off as u32).to_le_bytes());
        // 44..52 WorkstationFields
        msg.extend_from_slice(&(ws_len as u16).to_le_bytes());
        msg.extend_from_slice(&(ws_len as u16).to_le_bytes());
        msg.extend_from_slice(&(ws_off as u32).to_le_bytes());
        // 52..60 EncryptedRandomSessionKey (zeroed)
        msg.extend_from_slice(&[0u8; 8]);
        // 60..64 NegotiateFlags
        msg.extend_from_slice(&0u32.to_le_bytes());
        // payload
        msg.extend_from_slice(&nt_resp);
        msg.extend_from_slice(&dom_u);
        msg.extend_from_slice(&user_u);
        msg.extend_from_slice(&ws_u);
        msg
    }

    #[test]
    fn type3_extracts_user_domain_workstation() {
        let msg = build_type3("alice", "EVILCORP", "LAPTOP01");
        let f = classify(&msg).expect("found");
        assert_eq!(f.message_type, 3);
        match f.kind {
            NtlmKind::Authenticate {
                user,
                domain,
                workstation,
                nt_response_len,
            } => {
                assert_eq!(user.as_deref(), Some("alice"));
                assert_eq!(domain.as_deref(), Some("EVILCORP"));
                assert_eq!(workstation.as_deref(), Some("LAPTOP01"));
                assert_eq!(nt_response_len, 24);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn type2_extracts_server_challenge() {
        // Minimal Type 2 with no target name + a fixed server
        // challenge.
        let mut msg = Vec::new();
        msg.extend_from_slice(SIG);
        msg.extend_from_slice(&2u32.to_le_bytes());
        // TargetNameFields zeroed out
        msg.extend_from_slice(&[0u8; 8]);
        // Flags
        msg.extend_from_slice(&0u32.to_le_bytes());
        // ServerChallenge
        msg.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        // Reserved + TargetInfoFields
        msg.extend_from_slice(&[0u8; 16]);
        let f = classify(&msg).expect("found");
        match f.kind {
            NtlmKind::Challenge {
                server_challenge_hex,
                ..
            } => {
                assert_eq!(server_challenge_hex, "0123456789abcdef");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn embedded_in_arbitrary_buffer_found() {
        // Pretend it's the body of an HTTP Authorization header that
        // got base64-decoded — NTLMSSP magic preceded by junk.
        let inner = build_type3("bob", "DOM", "WS");
        let mut buf = Vec::new();
        buf.extend_from_slice(b"prefix garbage prefix garbage ");
        buf.extend_from_slice(&inner);
        buf.extend_from_slice(b" trailing junk");
        let f = classify(&buf).expect("found");
        assert_eq!(f.message_type, 3);
    }

    #[test]
    fn no_signature_returns_none() {
        assert!(classify(b"GET / HTTP/1.1\r\n").is_none());
    }
}
