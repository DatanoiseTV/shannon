//! DHCP v4 (RFC 2131) — udp/67 server, udp/68 client.
//!
//! Fixed 236-byte header followed by a magic cookie `0x63825363`
//! and TLV options. shannon decodes:
//!
//!   - op (BOOTREQUEST / BOOTREPLY)
//!   - the assigned yiaddr and gateway giaddr
//!   - client hardware address (chaddr / MAC)
//!   - option 53 DHCP Message Type (DISCOVER / OFFER / REQUEST /
//!     DECLINE / ACK / NAK / RELEASE / INFORM)
//!   - option 12 Host Name (useful for building the MAC → hostname
//!     → IP triangle that populates the service map)
//!   - option 50 Requested IP, option 54 Server ID, option 55
//!     Parameter Request List, option 60 Vendor Class Identifier
//!     (often leaks device model: "MSFT 5.0", "android-dhcp-13",
//!     iPhone6,1 …).

use crate::events::Direction;

const MIN_HEADER: usize = 240; // 236-byte BOOTP + 4-byte magic cookie

pub struct DhcpParser {
    bypass: bool,
}

impl Default for DhcpParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum DhcpParserOutput {
    Need,
    Record { record: DhcpRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct DhcpRecord {
    pub direction: Direction,
    pub op: u8,
    pub op_name: &'static str,
    pub xid: u32,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 6], // first 6 bytes = MAC for htype=ethernet
    pub msg_type: Option<u8>,
    pub msg_type_name: &'static str,
    pub hostname: Option<String>,
    pub requested_ip: Option<[u8; 4]>,
    pub server_id: Option<[u8; 4]>,
    pub vendor_class: Option<String>,
}

impl DhcpRecord {
    pub fn display_line(&self) -> String {
        let hn = self
            .hostname
            .as_deref()
            .map(|s| format!(" hostname={s}"))
            .unwrap_or_default();
        let vc = self
            .vendor_class
            .as_deref()
            .map(|s| format!(" vendor=\"{s}\""))
            .unwrap_or_default();
        format!(
            "dhcp {} {} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} yiaddr={}.{}.{}.{}{hn}{vc}",
            self.op_name,
            self.msg_type_name,
            self.chaddr[0], self.chaddr[1], self.chaddr[2],
            self.chaddr[3], self.chaddr[4], self.chaddr[5],
            self.yiaddr[0], self.yiaddr[1], self.yiaddr[2], self.yiaddr[3],
        )
    }
}

impl DhcpParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> DhcpParserOutput {
        if self.bypass {
            return DhcpParserOutput::Skip(buf.len());
        }
        if buf.len() < MIN_HEADER {
            return DhcpParserOutput::Need;
        }
        let op = buf[0];
        if op != 1 && op != 2 {
            self.bypass = true;
            return DhcpParserOutput::Skip(buf.len());
        }
        // Magic cookie at offset 236.
        if buf[236..240] != [0x63, 0x82, 0x53, 0x63] {
            self.bypass = true;
            return DhcpParserOutput::Skip(buf.len());
        }
        let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ciaddr = [buf[12], buf[13], buf[14], buf[15]];
        let yiaddr = [buf[16], buf[17], buf[18], buf[19]];
        let siaddr = [buf[20], buf[21], buf[22], buf[23]];
        let giaddr = [buf[24], buf[25], buf[26], buf[27]];
        let mut chaddr = [0u8; 6];
        chaddr.copy_from_slice(&buf[28..34]);

        let mut opts = &buf[240..];
        let mut msg_type = None;
        let mut hostname = None;
        let mut requested_ip = None;
        let mut server_id = None;
        let mut vendor_class = None;
        while !opts.is_empty() {
            let tag = opts[0];
            if tag == 0xff {
                break;
            }
            if tag == 0x00 {
                opts = &opts[1..];
                continue;
            }
            if opts.len() < 2 {
                break;
            }
            let l = opts[1] as usize;
            if opts.len() < 2 + l {
                break;
            }
            let v = &opts[2..2 + l];
            match tag {
                12 if !v.is_empty() => {
                    hostname = std::str::from_utf8(v).ok().map(|s| s.to_string());
                }
                50 if v.len() == 4 => requested_ip = Some([v[0], v[1], v[2], v[3]]),
                53 if v.len() == 1 => msg_type = Some(v[0]),
                54 if v.len() == 4 => server_id = Some([v[0], v[1], v[2], v[3]]),
                60 if !v.is_empty() => {
                    vendor_class = std::str::from_utf8(v).ok().map(|s| s.to_string());
                }
                _ => {}
            }
            opts = &opts[2 + l..];
        }
        let msg_type_name = msg_type.map(dhcp_msg_name).unwrap_or("?");
        DhcpParserOutput::Record {
            record: DhcpRecord {
                direction: dir,
                op,
                op_name: if op == 1 { "BOOTREQUEST" } else { "BOOTREPLY" },
                xid,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                chaddr,
                msg_type,
                msg_type_name,
                hostname,
                requested_ip,
                server_id,
                vendor_class,
            },
            consumed: buf.len(),
        }
    }
}

const fn dhcp_msg_name(t: u8) -> &'static str {
    match t {
        1 => "DISCOVER",
        2 => "OFFER",
        3 => "REQUEST",
        4 => "DECLINE",
        5 => "ACK",
        6 => "NAK",
        7 => "RELEASE",
        8 => "INFORM",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_with_hostname() {
        let mut buf = vec![0u8; MIN_HEADER];
        buf[0] = 1; // BOOTREQUEST
        buf[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        // MAC 01:02:03:04:05:06
        buf[28..34].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        buf[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        // Options: 53=1 (DISCOVER), 12="phone", 60="android", end=0xff
        buf.extend_from_slice(&[53, 1, 1]);
        buf.extend_from_slice(&[12, 5, b'p', b'h', b'o', b'n', b'e']);
        buf.extend_from_slice(&[60, 7, b'a', b'n', b'd', b'r', b'o', b'i', b'd']);
        buf.push(0xff);

        let mut p = DhcpParser::default();
        match p.parse(&buf, Direction::Tx) {
            DhcpParserOutput::Record { record, .. } => {
                assert_eq!(record.op, 1);
                assert_eq!(record.xid, 0xdead_beef);
                assert_eq!(record.msg_type, Some(1));
                assert_eq!(record.msg_type_name, "DISCOVER");
                assert_eq!(record.hostname.as_deref(), Some("phone"));
                assert_eq!(record.vendor_class.as_deref(), Some("android"));
                assert_eq!(record.chaddr, [1, 2, 3, 4, 5, 6]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_dhcp_bypasses() {
        let mut p = DhcpParser::default();
        let buf = vec![0u8; MIN_HEADER]; // op=0 is invalid
        assert!(matches!(p.parse(&buf, Direction::Tx), DhcpParserOutput::Skip(_)));
    }

    #[test]
    fn short_needs_more() {
        let mut p = DhcpParser::default();
        assert!(matches!(p.parse(&[0u8; 100], Direction::Tx), DhcpParserOutput::Need));
    }
}
