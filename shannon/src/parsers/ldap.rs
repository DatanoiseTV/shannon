//! LDAP (RFC 4511) — binary protocol over `tcp/389` or `tcp/636`
//! (LDAPS over TLS).
//!
//! LDAP messages are ASN.1 BER-encoded SEQUENCEs. We don't pull in a
//! full ASN.1 crate; we decode just enough of the envelope to identify
//! the operation and extract the security-relevant bits:
//!
//! - **BindRequest** (application 0): the DN + authentication. For the
//!   simple-auth case this is **the cleartext password on the wire** —
//!   our record surfaces the DN but scrubs the password bytes.
//! - **BindResponse** (application 1): result code (0 = success; 49 =
//!   invalidCredentials; 48 = inappropriateAuthentication; ...).
//! - **SearchRequest** (application 3): base DN + filter scope.
//! - **UnbindRequest** (application 2), **Abandon** (application 16),
//!   **Extended** (application 23) — surfaced as labels.
//!
//! Unknown operations surface with their numeric application tag so
//! even rare ops show up as a trace line.

use crate::events::Direction;

const MAX_PDU: usize = 4 * 1024 * 1024;

#[derive(Default)]
pub struct LdapParser {
    bypass: bool,
}

pub enum LdapParserOutput {
    Need,
    Record { record: LdapRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct LdapRecord {
    pub direction: Direction,
    pub message_id: i64,
    pub op: LdapOp,
}

#[derive(Debug, Clone)]
pub enum LdapOp {
    BindRequest {
        version: i64,
        dn: String,
        auth_mech: AuthMech,
    },
    BindResponse {
        result_code: u32,
        matched_dn: String,
        message: String,
    },
    SearchRequest {
        base_dn: String,
        scope: u8,
    },
    SearchResultEntry {
        dn: String,
    },
    SearchResultDone {
        result_code: u32,
    },
    UnbindRequest,
    AbandonRequest,
    ExtendedRequest {
        oid: String,
    },
    ExtendedResponse {
        result_code: u32,
        oid: Option<String>,
    },
    ModifyRequest {
        dn: String,
    },
    AddRequest {
        dn: String,
    },
    DelRequest {
        dn: String,
    },
    Other {
        application_tag: u8,
    },
}

#[derive(Debug, Clone)]
pub enum AuthMech {
    Simple, // password is redacted — never stored
    Sasl { mechanism: String },
    Unknown(u8),
}

impl LdapRecord {
    pub fn display_line(&self) -> String {
        match &self.op {
            LdapOp::BindRequest {
                version,
                dn,
                auth_mech,
            } => {
                let auth = match auth_mech {
                    AuthMech::Simple => "simple <redacted>".to_string(),
                    AuthMech::Sasl { mechanism } => format!("sasl {mechanism}"),
                    AuthMech::Unknown(n) => format!("auth=?{n}"),
                };
                format!(
                    "id={} BIND v{} dn={} {}",
                    self.message_id,
                    version,
                    truncate(dn, 80),
                    auth,
                )
            }
            LdapOp::BindResponse {
                result_code,
                matched_dn,
                message,
            } => format!(
                "id={} BIND-RESP code={} ({})  dn={}  msg={}",
                self.message_id,
                result_code,
                result_code_name(*result_code),
                truncate(matched_dn, 64),
                truncate(message, 64),
            ),
            LdapOp::SearchRequest { base_dn, scope } => format!(
                "id={} SEARCH base={} scope={}",
                self.message_id,
                truncate(base_dn, 80),
                scope_name(*scope),
            ),
            LdapOp::SearchResultEntry { dn } => {
                format!("id={} ENTRY dn={}", self.message_id, truncate(dn, 80))
            }
            LdapOp::SearchResultDone { result_code } => {
                format!("id={} SEARCH-DONE code={}", self.message_id, result_code)
            }
            LdapOp::UnbindRequest => format!("id={} UNBIND", self.message_id),
            LdapOp::AbandonRequest => format!("id={} ABANDON", self.message_id),
            LdapOp::ExtendedRequest { oid } => {
                format!("id={} EXT-REQ oid={}", self.message_id, oid)
            }
            LdapOp::ExtendedResponse { result_code, oid } => format!(
                "id={} EXT-RESP code={} oid={}",
                self.message_id,
                result_code,
                oid.as_deref().unwrap_or("-"),
            ),
            LdapOp::ModifyRequest { dn } => {
                format!("id={} MODIFY dn={}", self.message_id, truncate(dn, 80))
            }
            LdapOp::AddRequest { dn } => {
                format!("id={} ADD dn={}", self.message_id, truncate(dn, 80))
            }
            LdapOp::DelRequest { dn } => {
                format!("id={} DEL dn={}", self.message_id, truncate(dn, 80))
            }
            LdapOp::Other { application_tag } => {
                format!("id={} op=app-{}", self.message_id, application_tag)
            }
        }
    }
}

fn result_code_name(c: u32) -> &'static str {
    match c {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        8 => "strongerAuthRequired",
        10 => "referral",
        32 => "noSuchObject",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        53 => "unwillingToPerform",
        _ => "?",
    }
}

fn scope_name(n: u8) -> &'static str {
    match n {
        0 => "base",
        1 => "one",
        2 => "sub",
        3 => "children",
        _ => "?",
    }
}

fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
        &s[..n]
    }
}

impl LdapParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> LdapParserOutput {
        if self.bypass {
            return LdapParserOutput::Skip(buf.len());
        }
        if buf.is_empty() {
            return LdapParserOutput::Need;
        }
        // LDAP PDUs are always SEQUENCE (0x30).
        if buf[0] != 0x30 {
            self.bypass = true;
            return LdapParserOutput::Skip(buf.len());
        }
        let (pdu_len, len_bytes) = match ber_length(&buf[1..]) {
            Some(v) => v,
            None => {
                // Not enough bytes to decide on length.
                if buf.len() > 16 {
                    self.bypass = true;
                    return LdapParserOutput::Skip(buf.len());
                }
                return LdapParserOutput::Need;
            }
        };
        let header_bytes = 1 + len_bytes;
        let total = header_bytes + pdu_len;
        if pdu_len == 0 || pdu_len > MAX_PDU {
            self.bypass = true;
            return LdapParserOutput::Skip(buf.len());
        }
        if buf.len() < total {
            return LdapParserOutput::Need;
        }
        let payload = &buf[header_bytes..total];
        let Some(record) = decode_message(payload, dir) else {
            self.bypass = true;
            return LdapParserOutput::Skip(total);
        };
        LdapParserOutput::Record {
            record,
            consumed: total,
        }
    }
}

/// Decode a BER length byte(s). Returns (length_value, bytes_consumed).
/// Short form: < 128 = direct value. Long form: 0x80 | N followed by N
/// bytes of big-endian length.
fn ber_length(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.is_empty() {
        return None;
    }
    let b = buf[0];
    if b & 0x80 == 0 {
        return Some((b as usize, 1));
    }
    let n = (b & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    if buf.len() < 1 + n {
        return None;
    }
    let mut v = 0usize;
    for i in 0..n {
        v = (v << 8) | buf[1 + i] as usize;
    }
    Some((v, 1 + n))
}

fn decode_message(mut payload: &[u8], dir: Direction) -> Option<LdapRecord> {
    // messageID INTEGER
    let (msg_id, rest) = take_tagged(payload, 0x02)?;
    payload = rest;
    let message_id = ber_integer(msg_id);
    // protocolOp — application-class tagged. Top two bits = 01, next
    // bit P/C (1 = constructed for most ops, 0 for some primitives),
    // bottom 5 bits = op tag.
    if payload.is_empty() {
        return None;
    }
    let op_tag_byte = payload[0];
    let class = (op_tag_byte >> 6) & 0x03;
    if class != 1 {
        return None;
    }
    let app_tag = op_tag_byte & 0x1f;
    let (op_body_len, op_len_bytes) = ber_length(&payload[1..])?;
    let op_header = 1 + op_len_bytes;
    if payload.len() < op_header + op_body_len {
        return None;
    }
    let op_body = &payload[op_header..op_header + op_body_len];
    let op = decode_op(app_tag, op_body, dir)?;
    Some(LdapRecord {
        direction: dir,
        message_id,
        op,
    })
}

fn decode_op(app_tag: u8, body: &[u8], _dir: Direction) -> Option<LdapOp> {
    match app_tag {
        0 => {
            // BindRequest: { version INTEGER, name LDAPDN, authentication CHOICE }
            let (version_body, rest) = take_tagged(body, 0x02)?;
            let version = ber_integer(version_body);
            let (dn_body, rest) = take_tagged(rest, 0x04)?;
            let dn = String::from_utf8_lossy(dn_body).into_owned();
            let auth_mech = if rest.is_empty() {
                AuthMech::Unknown(0xff)
            } else {
                let tag = rest[0];
                let ctx = tag & 0x1f;
                match ctx {
                    0 => AuthMech::Simple,
                    3 => {
                        // SASL: { mechanism OCTET STRING, credentials OPTIONAL }
                        let (_, inner_len_bytes) = ber_length(&rest[1..])?;
                        let sasl_body = &rest[1 + inner_len_bytes..];
                        let mech = take_tagged(sasl_body, 0x04)
                            .map(|(b, _)| String::from_utf8_lossy(b).into_owned())
                            .unwrap_or_default();
                        AuthMech::Sasl { mechanism: mech }
                    }
                    other => AuthMech::Unknown(other),
                }
            };
            Some(LdapOp::BindRequest {
                version,
                dn,
                auth_mech,
            })
        }
        1 => {
            // BindResponse: { LDAPResult components }
            let (code, matched_dn, message) = decode_ldap_result(body)?;
            Some(LdapOp::BindResponse {
                result_code: code,
                matched_dn,
                message,
            })
        }
        2 => Some(LdapOp::UnbindRequest),
        3 => {
            // SearchRequest: { baseObject LDAPDN, scope ENUMERATED, ... }
            let (dn_body, rest) = take_tagged(body, 0x04)?;
            let dn = String::from_utf8_lossy(dn_body).into_owned();
            let scope = take_tagged(rest, 0x0a)
                .map(|(b, _)| b.first().copied().unwrap_or(0))
                .unwrap_or(0);
            Some(LdapOp::SearchRequest { base_dn: dn, scope })
        }
        4 => {
            let (dn_body, _) = take_tagged(body, 0x04)?;
            let dn = String::from_utf8_lossy(dn_body).into_owned();
            Some(LdapOp::SearchResultEntry { dn })
        }
        5 => {
            let (code, _, _) = decode_ldap_result(body)?;
            Some(LdapOp::SearchResultDone { result_code: code })
        }
        6 => {
            let (dn_body, _) = take_tagged(body, 0x04)?;
            let dn = String::from_utf8_lossy(dn_body).into_owned();
            Some(LdapOp::ModifyRequest { dn })
        }
        8 => {
            let (dn_body, _) = take_tagged(body, 0x04)?;
            let dn = String::from_utf8_lossy(dn_body).into_owned();
            Some(LdapOp::AddRequest { dn })
        }
        10 => {
            // DelRequest: [APPLICATION 10] LDAPDN  (primitive)
            let dn = String::from_utf8_lossy(body).into_owned();
            Some(LdapOp::DelRequest { dn })
        }
        16 => Some(LdapOp::AbandonRequest),
        23 => {
            // ExtendedRequest: SEQUENCE { requestName [0] LDAPOID, requestValue [1] OPTIONAL }
            // Context-specific [0] primitive = 0x80.
            if body.is_empty() {
                return None;
            }
            if body[0] == 0x80 {
                let (_, len_bytes) = ber_length(&body[1..])?;
                let (oid_len, _) = ber_length(&body[1..])?;
                let start = 1 + len_bytes;
                let oid = String::from_utf8_lossy(&body[start..start + oid_len]).into_owned();
                Some(LdapOp::ExtendedRequest { oid })
            } else {
                Some(LdapOp::ExtendedRequest { oid: String::new() })
            }
        }
        24 => {
            // ExtendedResponse: SEQUENCE { LDAPResult components, [10] responseName, [11] responseValue }
            let (code, _, _) = decode_ldap_result(body)?;
            Some(LdapOp::ExtendedResponse {
                result_code: code,
                oid: None,
            })
        }
        _ => Some(LdapOp::Other {
            application_tag: app_tag,
        }),
    }
}

fn decode_ldap_result(body: &[u8]) -> Option<(u32, String, String)> {
    // resultCode ENUMERATED
    let (code_body, rest) = take_tagged(body, 0x0a)?;
    let code = code_body
        .iter()
        .fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
    let (matched_dn_body, rest) = take_tagged(rest, 0x04).unwrap_or((&b""[..], rest));
    let matched_dn = String::from_utf8_lossy(matched_dn_body).into_owned();
    let (msg_body, _rest) = take_tagged(rest, 0x04).unwrap_or((&b""[..], rest));
    let msg = String::from_utf8_lossy(msg_body).into_owned();
    Some((code, matched_dn, msg))
}

/// Take a BER-encoded TLV where the tag matches `expected_tag`. Returns
/// the value bytes and the remainder after the TLV.
fn take_tagged(buf: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if buf.is_empty() || buf[0] != expected_tag {
        return None;
    }
    let (len, len_bytes) = ber_length(&buf[1..])?;
    let header = 1 + len_bytes;
    if buf.len() < header + len {
        return None;
    }
    Some((&buf[header..header + len], &buf[header + len..]))
}

fn ber_integer(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    let mut acc: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        acc = (acc << 8) | i64::from(b);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_request_simple_redacts_password() {
        // Hand-rolled BIND request:
        //   SEQUENCE (0x30, len X) {
        //     INTEGER messageID 1 (0x02 0x01 0x01)
        //     [APPLICATION 0, constructed] (0x60, len Y) {
        //       INTEGER version 3 (0x02 0x01 0x03)
        //       OCTET STRING name "cn=admin,dc=example,dc=org"
        //           (0x04 len 26 <chars>)
        //       [0] simple password "s3cr3t"  (0x80 len 6 <chars>)
        //     }
        //   }
        let name = b"cn=admin,dc=example,dc=org";
        let pass = b"s3cr3t";
        let mut bind_inner = Vec::new();
        bind_inner.extend_from_slice(&[0x02, 0x01, 0x03]);
        bind_inner.push(0x04);
        bind_inner.push(name.len() as u8);
        bind_inner.extend_from_slice(name);
        bind_inner.push(0x80);
        bind_inner.push(pass.len() as u8);
        bind_inner.extend_from_slice(pass);

        let mut bind_tlv = Vec::new();
        bind_tlv.push(0x60);
        bind_tlv.push(bind_inner.len() as u8);
        bind_tlv.extend_from_slice(&bind_inner);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x02, 0x01, 0x01]); // msgID
        body.extend_from_slice(&bind_tlv);

        let mut pdu = Vec::new();
        pdu.push(0x30);
        pdu.push(body.len() as u8);
        pdu.extend_from_slice(&body);

        let mut p = LdapParser::default();
        match p.parse(&pdu, Direction::Tx) {
            LdapParserOutput::Record { record, consumed } => {
                assert_eq!(record.message_id, 1);
                match &record.op {
                    LdapOp::BindRequest {
                        version,
                        dn,
                        auth_mech,
                    } => {
                        assert_eq!(*version, 3);
                        assert_eq!(dn, "cn=admin,dc=example,dc=org");
                        assert!(matches!(auth_mech, AuthMech::Simple));
                    }
                    _ => panic!("expected BindRequest"),
                }
                let line = record.display_line();
                assert!(line.contains("<redacted>"));
                assert!(!line.contains("s3cr3t"));
                assert_eq!(consumed, pdu.len());
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn non_ldap_bypasses() {
        let mut p = LdapParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            LdapParserOutput::Skip(_)
        ));
    }
}
