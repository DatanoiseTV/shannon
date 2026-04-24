//! DNS wire format (RFC 1035 + 3596 + 2671 for EDNS).
//!
//! Works on either plain DNS (udp/53, tcp/53) or mDNS (udp/5353). The
//! caller gives us the raw DNS message bytes; we emit one record per
//! message with questions + answers decoded.
//!
//! We handle name compression, the common resource-record types (A,
//! AAAA, CNAME, NS, MX, PTR, TXT, SRV, SOA, CAA, HTTPS, SVCB), and tag
//! responses with the DNS rcode. Unknown rtypes surface as `Rtype::Other`.

use crate::events::Direction;

const MAX_NAME_HOPS: u32 = 16;
const MAX_LABEL_LEN: usize = 63;
const MAX_MESSAGE: usize = 65_535;

pub struct DnsParser {
    multicast: bool,
}

impl Default for DnsParser {
    fn default() -> Self {
        Self { multicast: false }
    }
}

impl DnsParser {
    /// Treat this parser instance as an mDNS scanner. Affects only
    /// display (prefixes records with `mdns` vs `dns`).
    pub fn new_mdns() -> Self {
        Self { multicast: true }
    }
}

pub enum DnsParserOutput {
    Need,
    Record { record: DnsRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub multicast: bool,
    pub direction: Direction,
    pub id: u16,
    pub flags: u16,
    pub rcode: u8,
    pub is_response: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: Rtype,
    pub rclass: u16,
    pub ttl: u32,
    pub data: RrData,
}

#[derive(Debug, Clone)]
pub enum Rtype {
    A,
    Aaaa,
    Cname,
    Ns,
    Mx,
    Ptr,
    Txt,
    Srv,
    Soa,
    Caa,
    Https,
    Svcb,
    Other(u16),
}

#[derive(Debug, Clone)]
pub enum RrData {
    A(std::net::Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Name(String),                   // CNAME, NS, PTR
    Mx { priority: u16, host: String },
    Txt(Vec<String>),
    Srv { priority: u16, weight: u16, port: u16, target: String },
    Soa { mname: String, rname: String, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    Caa { flags: u8, tag: String, value: String },
    Raw(Vec<u8>),
}

impl DnsRecord {
    pub fn display_line(&self) -> String {
        let proto = if self.multicast { "mdns" } else { "dns" };
        if self.is_response {
            if self.answers.is_empty() {
                format!(
                    "{proto} id={} rcode={} (no answers)",
                    self.id,
                    rcode_name(self.rcode)
                )
            } else {
                let first_q = self.questions.first().map(|q| q.name.as_str()).unwrap_or("");
                let first_a = self.answers.first().map(render_rrdata).unwrap_or_default();
                format!(
                    "{proto} id={} rcode={}  {} -> {}",
                    self.id,
                    rcode_name(self.rcode),
                    first_q,
                    first_a,
                )
            }
        } else {
            let qs = self
                .questions
                .iter()
                .map(|q| format!("{} {}", rtype_name(q.qtype), q.name))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{proto} id={} ? {qs}", self.id)
        }
    }
}

fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        9 => "NOTAUTH",
        _ => "?",
    }
}

fn rtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        257 => "CAA",
        64 => "SVCB",
        65 => "HTTPS",
        _ => "?",
    }
}

fn render_rrdata(rr: &ResourceRecord) -> String {
    match &rr.data {
        RrData::A(ip) => ip.to_string(),
        RrData::Aaaa(ip) => ip.to_string(),
        RrData::Name(n) => n.clone(),
        RrData::Mx { priority, host } => format!("{priority} {host}"),
        RrData::Txt(parts) => parts.join(" "),
        RrData::Srv { priority, weight, port, target } => format!("{priority} {weight} {port} {target}"),
        RrData::Soa { mname, rname, serial, .. } => format!("{mname} {rname} {serial}"),
        RrData::Caa { flags, tag, value } => format!("{flags} {tag} \"{value}\""),
        RrData::Raw(b) => format!("<{} bytes>", b.len()),
    }
}

impl DnsParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> DnsParserOutput {
        if buf.len() < 12 {
            if buf.len() > MAX_MESSAGE {
                return DnsParserOutput::Skip(buf.len());
            }
            return DnsParserOutput::Need;
        }
        // Try to parse the whole buffer as one DNS message. For UDP this
        // is correct; for TCP the caller strips the 2-byte length prefix
        // before calling us.
        let Some(parsed) = decode(buf) else {
            return DnsParserOutput::Skip(buf.len());
        };
        let rec = DnsRecord {
            multicast: self.multicast,
            direction: dir,
            id: parsed.id,
            flags: parsed.flags,
            rcode: (parsed.flags & 0x000f) as u8,
            is_response: parsed.flags & 0x8000 != 0,
            questions: parsed.questions,
            answers: parsed.answers,
            authorities: parsed.authorities,
            additionals: parsed.additionals,
        };
        DnsParserOutput::Record { record: rec, consumed: buf.len() }
    }
}

struct Parsed {
    id: u16,
    flags: u16,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authorities: Vec<ResourceRecord>,
    additionals: Vec<ResourceRecord>,
}

fn decode(buf: &[u8]) -> Option<Parsed> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut pos = 12usize;
    let mut questions = Vec::with_capacity(qd.min(32));
    for _ in 0..qd {
        let (name, np) = read_name(buf, pos)?;
        pos = np;
        if pos + 4 > buf.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        pos += 4;
        questions.push(Question { name, qtype, qclass });
    }
    let answers = read_rrset(buf, &mut pos, an)?;
    let authorities = read_rrset(buf, &mut pos, ns)?;
    let additionals = read_rrset(buf, &mut pos, ar)?;
    Some(Parsed { id, flags, questions, answers, authorities, additionals })
}

fn read_rrset(buf: &[u8], pos: &mut usize, n: usize) -> Option<Vec<ResourceRecord>> {
    let mut out = Vec::with_capacity(n.min(32));
    for _ in 0..n {
        let (name, np) = read_name(buf, *pos)?;
        *pos = np;
        if *pos + 10 > buf.len() {
            return None;
        }
        let rtype_raw = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
        let rclass = u16::from_be_bytes([buf[*pos + 2], buf[*pos + 3]]);
        let ttl = u32::from_be_bytes([
            buf[*pos + 4],
            buf[*pos + 5],
            buf[*pos + 6],
            buf[*pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([buf[*pos + 8], buf[*pos + 9]]) as usize;
        *pos += 10;
        if *pos + rdlen > buf.len() {
            return None;
        }
        let rdata = &buf[*pos..*pos + rdlen];
        let (rtype, data) = decode_rdata(buf, rtype_raw, rdata)?;
        *pos += rdlen;
        out.push(ResourceRecord { name, rtype, rclass, ttl, data });
    }
    Some(out)
}

fn decode_rdata(msg: &[u8], rtype: u16, rd: &[u8]) -> Option<(Rtype, RrData)> {
    Some(match rtype {
        1 if rd.len() == 4 => (
            Rtype::A,
            RrData::A(std::net::Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3])),
        ),
        28 if rd.len() == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(rd);
            (Rtype::Aaaa, RrData::Aaaa(std::net::Ipv6Addr::from(a)))
        }
        5 => {
            let (n, _) = read_name_in(msg, rd, 0)?;
            (Rtype::Cname, RrData::Name(n))
        }
        2 => {
            let (n, _) = read_name_in(msg, rd, 0)?;
            (Rtype::Ns, RrData::Name(n))
        }
        12 => {
            let (n, _) = read_name_in(msg, rd, 0)?;
            (Rtype::Ptr, RrData::Name(n))
        }
        15 if rd.len() >= 3 => {
            let priority = u16::from_be_bytes([rd[0], rd[1]]);
            let (host, _) = read_name_in(msg, rd, 2)?;
            (Rtype::Mx, RrData::Mx { priority, host })
        }
        16 => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < rd.len() {
                let l = rd[i] as usize;
                i += 1;
                if i + l > rd.len() {
                    break;
                }
                parts.push(String::from_utf8_lossy(&rd[i..i + l]).into_owned());
                i += l;
            }
            (Rtype::Txt, RrData::Txt(parts))
        }
        33 if rd.len() >= 7 => {
            let priority = u16::from_be_bytes([rd[0], rd[1]]);
            let weight = u16::from_be_bytes([rd[2], rd[3]]);
            let port = u16::from_be_bytes([rd[4], rd[5]]);
            let (target, _) = read_name_in(msg, rd, 6)?;
            (Rtype::Srv, RrData::Srv { priority, weight, port, target })
        }
        6 => {
            let (mname, off1) = read_name_in(msg, rd, 0)?;
            let (rname, off2) = read_name_in(msg, rd, off1)?;
            if off2 + 20 > rd.len() {
                return None;
            }
            let p = &rd[off2..];
            (
                Rtype::Soa,
                RrData::Soa {
                    mname,
                    rname,
                    serial: u32::from_be_bytes([p[0], p[1], p[2], p[3]]),
                    refresh: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
                    retry: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
                    expire: u32::from_be_bytes([p[12], p[13], p[14], p[15]]),
                    minimum: u32::from_be_bytes([p[16], p[17], p[18], p[19]]),
                },
            )
        }
        257 if rd.len() >= 3 => {
            let flags = rd[0];
            let tag_len = rd[1] as usize;
            if 2 + tag_len > rd.len() {
                return None;
            }
            let tag = String::from_utf8_lossy(&rd[2..2 + tag_len]).into_owned();
            let value =
                String::from_utf8_lossy(&rd[2 + tag_len..]).into_owned();
            (Rtype::Caa, RrData::Caa { flags, tag, value })
        }
        64 => (Rtype::Svcb, RrData::Raw(rd.to_vec())),
        65 => (Rtype::Https, RrData::Raw(rd.to_vec())),
        other => (Rtype::Other(other), RrData::Raw(rd.to_vec())),
    })
}

fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let (s, next) = read_name_rec(msg, start, 0)?;
    Some((s, next))
}

fn read_name_in(msg: &[u8], rd: &[u8], start: usize) -> Option<(String, usize)> {
    // rd is a sub-slice of msg for DNS RDATA; names inside RDATA may use
    // compression pointers referencing the whole msg.
    // Find rd's offset inside msg so we can rebase.
    let rd_ptr = rd.as_ptr() as usize;
    let msg_ptr = msg.as_ptr() as usize;
    if rd_ptr < msg_ptr || rd_ptr + rd.len() > msg_ptr + msg.len() {
        // Not a sub-slice of msg — fall back to in-rd parsing (no
        // pointer compression) by building a synthetic wrapper.
        let (s, n) = read_name_rec(rd, start, 0)?;
        return Some((s, n));
    }
    let base = rd_ptr - msg_ptr;
    let (s, next) = read_name_rec(msg, base + start, 0)?;
    Some((s, next - base))
}

fn read_name_rec(msg: &[u8], mut pos: usize, hops: u32) -> Option<(String, usize)> {
    if hops > MAX_NAME_HOPS {
        return None;
    }
    let mut out = String::with_capacity(64);
    let jumped = false;
    let mut return_pos = pos;

    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos];
        if len == 0 {
            pos += 1;
            if !jumped {
                return_pos = pos;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Pointer: next 14 bits.
            if pos + 1 >= msg.len() {
                return None;
            }
            let p = (((len & 0x3f) as usize) << 8) | msg[pos + 1] as usize;
            if !jumped {
                return_pos = pos + 2;
            }
            let _ = jumped; // kept for clarity of the loop invariants
            pos = p;
            // Recurse so we don't loop forever.
            let (part, _) = read_name_rec(msg, pos, hops + 1)?;
            if !out.is_empty() && !part.is_empty() {
                out.push('.');
            }
            out.push_str(&part);
            break;
        }
        let len = len as usize;
        if len > MAX_LABEL_LEN || pos + 1 + len > msg.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&msg[pos + 1..pos + 1 + len]));
        pos += 1 + len;
        if !jumped {
            return_pos = pos;
        }
    }
    Some((out, return_pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A hand-crafted A-record query for example.com.
    const QUERY_EXAMPLE_COM_A: &[u8] = &[
        0x12, 0x34, // id
        0x01, 0x00, // flags: recursion desired
        0x00, 0x01, // qdcount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ancount/nscount/arcount
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // root
        0x00, 0x01, // qtype A
        0x00, 0x01, // qclass IN
    ];

    #[test]
    fn parses_query() {
        let mut p = DnsParser::default();
        match p.parse(QUERY_EXAMPLE_COM_A, Direction::Tx) {
            DnsParserOutput::Record { record, consumed } => {
                assert_eq!(record.id, 0x1234);
                assert!(!record.is_response);
                assert_eq!(record.questions.len(), 1);
                assert_eq!(record.questions[0].name, "example.com");
                assert_eq!(consumed, QUERY_EXAMPLE_COM_A.len());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_response_with_a_record() {
        // Same query, then answer for 93.184.216.34 with TTL 3600.
        let mut pkt = QUERY_EXAMPLE_COM_A.to_vec();
        pkt[2] = 0x81;
        pkt[3] = 0x80; // response, recursion available
        pkt[7] = 0x01; // ancount = 1
        // Answer: pointer to name at offset 12, type A, class IN, TTL, rdlen 4.
        pkt.extend_from_slice(&[
            0xc0, 0x0c, // ptr
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x0e, 0x10,
            0x00, 0x04,
            93, 184, 216, 34,
        ]);
        let mut p = DnsParser::default();
        match p.parse(&pkt, Direction::Rx) {
            DnsParserOutput::Record { record, .. } => {
                assert!(record.is_response);
                assert_eq!(record.answers.len(), 1);
                match &record.answers[0].data {
                    RrData::A(ip) => assert_eq!(ip.octets(), [93, 184, 216, 34]),
                    _ => panic!("expected A"),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn short_buffer_needs_more() {
        let mut p = DnsParser::default();
        assert!(matches!(p.parse(&[0u8; 8], Direction::Tx), DnsParserOutput::Need));
    }
}
