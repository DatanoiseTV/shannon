//! SNMP v1 / v2c (RFC 3416) — udp/161 agent, udp/162 trap.
//!
//! SNMP rides ASN.1 BER. A v1/v2c message is:
//!
//! ```text
//!   SEQUENCE {
//!     INTEGER     version      (0 = v1, 1 = v2c, 3 = v3 — v3 is USM
//!                                and not yet decoded here)
//!     OCTET STR   community    (plaintext auth token — the reason this
//!                                protocol is a security headline)
//!     [n] IMPLICIT pdu {
//!       INTEGER   request-id
//!       INTEGER   error-status
//!       INTEGER   error-index
//!       SEQUENCE  variable-bindings {
//!         SEQUENCE { OID name; value }
//!         ...
//!       }
//!     }
//!   }
//! ```
//!
//! The PDU is wrapped in a context-specific IMPLICIT tag whose number
//! encodes the PDU type (0 = GetRequest, 1 = GetNextRequest, 2 =
//! GetResponse, 3 = SetRequest, 4 = v1-Trap, 5 = GetBulkRequest, 6 =
//! InformRequest, 7 = v2-Trap, 8 = Report).
//!
//! shannon surfaces the version, community string (so operators can
//! spot "public" / "private" / vendor defaults still in production),
//! PDU type name, request id, error status, and the first varbind OID
//! — enough to tell a `GET sysDescr.0` poll from a `SET community=`
//! reconfiguration attempt.

use crate::events::Direction;

pub struct SnmpParser {
    bypass: bool,
}

impl Default for SnmpParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum SnmpParserOutput {
    Need,
    Record { record: SnmpRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct SnmpRecord {
    pub direction: Direction,
    pub version: u8,          // wire: 0 = v1, 1 = v2c, 3 = v3
    pub version_name: &'static str,
    pub community: Option<String>,
    pub pdu_type: Option<u8>,
    pub pdu_type_name: &'static str,
    pub request_id: Option<i64>,
    pub error_status: Option<i64>,
    pub first_oid: Option<String>,
}

impl SnmpRecord {
    pub fn display_line(&self) -> String {
        let comm = self
            .community
            .as_deref()
            .map(|s| format!(" community=\"{s}\""))
            .unwrap_or_default();
        let rid = self
            .request_id
            .map(|r| format!(" reqid={r}"))
            .unwrap_or_default();
        let es = self
            .error_status
            .filter(|&s| s != 0)
            .map(|s| format!(" err={s}"))
            .unwrap_or_default();
        let oid = self
            .first_oid
            .as_deref()
            .map(|s| format!(" oid={s}"))
            .unwrap_or_default();
        format!(
            "snmp {} {}{comm}{rid}{es}{oid}",
            self.version_name, self.pdu_type_name,
        )
    }
}

impl SnmpParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> SnmpParserOutput {
        if self.bypass {
            return SnmpParserOutput::Skip(buf.len());
        }
        // Outer wrapper: SEQUENCE
        if buf.is_empty() {
            return SnmpParserOutput::Need;
        }
        if buf[0] != 0x30 {
            self.bypass = true;
            return SnmpParserOutput::Skip(buf.len());
        }
        let (seq_content_off, seq_len) = match ber_len(buf, 1) {
            Some(v) => v,
            None => return SnmpParserOutput::Need,
        };
        let total = seq_content_off + seq_len;
        if buf.len() < total {
            return SnmpParserOutput::Need;
        }
        let seq = &buf[seq_content_off..total];

        // version INTEGER
        let (version, rest) = match read_integer(seq) {
            Some(v) => v,
            None => {
                self.bypass = true;
                return SnmpParserOutput::Skip(total);
            }
        };
        let version_u8 = version.clamp(0, 255) as u8;
        if !matches!(version_u8, 0 | 1 | 3) {
            self.bypass = true;
            return SnmpParserOutput::Skip(total);
        }
        // For v3 we bail politely — USM encoding is different and we
        // don't decode it yet.
        if version_u8 == 3 {
            let rec = SnmpRecord {
                direction: dir,
                version: version_u8,
                version_name: "v3",
                community: None,
                pdu_type: None,
                pdu_type_name: "USM",
                request_id: None,
                error_status: None,
                first_oid: None,
            };
            return SnmpParserOutput::Record { record: rec, consumed: total };
        }

        // community OCTET STRING
        let (community_bytes, rest) = match read_octet_string(rest) {
            Some(v) => v,
            None => {
                self.bypass = true;
                return SnmpParserOutput::Skip(total);
            }
        };
        let community = std::str::from_utf8(community_bytes).ok().map(|s| s.to_string());

        // PDU: context-specific IMPLICIT tag 0xAn
        let (pdu_type, pdu_content) = match read_pdu(rest) {
            Some(v) => v,
            None => {
                let rec = SnmpRecord {
                    direction: dir,
                    version: version_u8,
                    version_name: version_name(version_u8),
                    community,
                    pdu_type: None,
                    pdu_type_name: "?",
                    request_id: None,
                    error_status: None,
                    first_oid: None,
                };
                return SnmpParserOutput::Record { record: rec, consumed: total };
            }
        };
        let (request_id, rest) = read_integer(pdu_content).unzip();
        let (error_status, rest) = match rest {
            Some(r) => read_integer(r).unzip(),
            None => (None, None),
        };
        // Skip error_index
        let rest = match rest {
            Some(r) => read_integer(r).map(|(_, rem)| rem),
            None => None,
        };
        // varbindings SEQUENCE { SEQUENCE { OID, value } ... }
        let first_oid = rest.and_then(|r| {
            let (seq_body, _) = read_sequence(r)?;
            let (first_vb, _) = read_sequence(seq_body)?;
            let (oid_bytes, _) = read_oid(first_vb)?;
            Some(decode_oid(oid_bytes))
        });

        let rec = SnmpRecord {
            direction: dir,
            version: version_u8,
            version_name: version_name(version_u8),
            community,
            pdu_type: Some(pdu_type),
            pdu_type_name: pdu_type_name(pdu_type),
            request_id,
            error_status,
            first_oid,
        };
        SnmpParserOutput::Record { record: rec, consumed: total }
    }
}

fn read_pdu(buf: &[u8]) -> Option<(u8, &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    if tag & 0xe0 != 0xa0 {
        return None;
    }
    let pdu_type = tag & 0x1f;
    let (content, len) = ber_len(buf, 1)?;
    buf.get(content..content + len).map(|body| (pdu_type, body))
}

fn read_sequence(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.is_empty() || buf[0] != 0x30 {
        return None;
    }
    let (content, len) = ber_len(buf, 1)?;
    let body = buf.get(content..content + len)?;
    Some((body, content + len))
}

fn read_integer(buf: &[u8]) -> Option<(i64, &[u8])> {
    if buf.is_empty() || buf[0] != 0x02 {
        return None;
    }
    let (content, len) = ber_len(buf, 1)?;
    if len == 0 || len > 9 {
        return None;
    }
    let bytes = buf.get(content..content + len)?;
    let mut val: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for b in bytes {
        val = (val << 8) | (*b as i64 & 0xff);
    }
    Some((val, &buf[content + len..]))
}

fn read_octet_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.is_empty() || buf[0] != 0x04 {
        return None;
    }
    let (content, len) = ber_len(buf, 1)?;
    let body = buf.get(content..content + len)?;
    Some((body, &buf[content + len..]))
}

fn read_oid(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.is_empty() || buf[0] != 0x06 {
        return None;
    }
    let (content, len) = ber_len(buf, 1)?;
    let body = buf.get(content..content + len)?;
    Some((body, &buf[content + len..]))
}

fn decode_oid(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let first = body[0];
    let a = (first / 40) as u64;
    let b = (first % 40) as u64;
    out.push_str(&format!("{a}.{b}"));
    let mut acc: u64 = 0;
    for &byte in &body[1..] {
        acc = (acc << 7) | ((byte & 0x7f) as u64);
        if byte & 0x80 == 0 {
            out.push('.');
            out.push_str(&acc.to_string());
            acc = 0;
        }
    }
    out
}

fn ber_len(buf: &[u8], after_tag_idx: usize) -> Option<(usize, usize)> {
    if after_tag_idx >= buf.len() {
        return None;
    }
    let first = buf[after_tag_idx];
    if first & 0x80 == 0 {
        return Some((after_tag_idx + 1, first as usize));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || after_tag_idx + 1 + n > buf.len() {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | buf[after_tag_idx + 1 + i] as usize;
    }
    Some((after_tag_idx + 1 + n, len))
}

const fn version_name(v: u8) -> &'static str {
    match v {
        0 => "v1",
        1 => "v2c",
        3 => "v3",
        _ => "?",
    }
}

const fn pdu_type_name(t: u8) -> &'static str {
    match t {
        0 => "GetRequest",
        1 => "GetNextRequest",
        2 => "GetResponse",
        3 => "SetRequest",
        4 => "Trapv1",
        5 => "GetBulkRequest",
        6 => "InformRequest",
        7 => "Trapv2",
        8 => "Report",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_get_request() -> Vec<u8> {
        // Build a plausible SNMP v2c GetRequest for 1.3.6.1.2.1.1.1.0.
        //   OID encoded: 2b 06 01 02 01 01 01 00
        //   varbind:     30 0c 06 08 <oid> 05 00
        //   varbinds:    30 0e <vb>
        //   pdu (0xa0): request-id=1, err=0, err-index=0, varbinds
        //     a0 ?? 02 01 01 02 01 00 02 01 00 30 0e 30 0c 06 08 ... 05 00
        //   outer SEQ  wrapping version=1 + community="public" + pdu
        let oid_bytes = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let mut vb = vec![0x30, 0x0c, 0x06, oid_bytes.len() as u8];
        vb.extend_from_slice(&oid_bytes);
        vb.extend_from_slice(&[0x05, 0x00]); // value NULL
        let mut vbs = vec![0x30, vb.len() as u8];
        vbs.extend_from_slice(&vb);
        let mut pdu_content = Vec::new();
        pdu_content.extend_from_slice(&[0x02, 0x01, 0x01]); // request-id 1
        pdu_content.extend_from_slice(&[0x02, 0x01, 0x00]); // err 0
        pdu_content.extend_from_slice(&[0x02, 0x01, 0x00]); // err-index 0
        pdu_content.extend_from_slice(&vbs);
        let mut pdu = vec![0xa0, pdu_content.len() as u8];
        pdu.extend_from_slice(&pdu_content);

        let mut seq = Vec::new();
        seq.extend_from_slice(&[0x02, 0x01, 0x01]); // version v2c (=1)
        let comm = b"public";
        seq.extend_from_slice(&[0x04, comm.len() as u8]);
        seq.extend_from_slice(comm);
        seq.extend_from_slice(&pdu);

        let mut outer = vec![0x30, seq.len() as u8];
        outer.extend_from_slice(&seq);
        outer
    }

    #[test]
    fn v2c_get_request() {
        let buf = build_get_request();
        let mut p = SnmpParser::default();
        match p.parse(&buf, Direction::Tx) {
            SnmpParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.version_name, "v2c");
                assert_eq!(record.community.as_deref(), Some("public"));
                assert_eq!(record.pdu_type_name, "GetRequest");
                assert_eq!(record.request_id, Some(1));
                assert_eq!(record.first_oid.as_deref(), Some("1.3.6.1.2.1.1.1.0"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_snmp_bypasses() {
        let mut p = SnmpParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n", Direction::Tx),
            SnmpParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_needs_more() {
        let mut p = SnmpParser::default();
        assert!(matches!(p.parse(&[0x30], Direction::Tx), SnmpParserOutput::Need));
    }
}
