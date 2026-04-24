//! BACnet/IP (ASHRAE 135 Annex J) — udp/47808 default.
//!
//! BACnet is the dominant building-automation protocol: HVAC
//! controllers, VAV boxes, lighting relays, access-control panels,
//! chillers, boilers, energy meters. Shannon sees BACnet frames once
//! the UDP capture path is wired; the parser is written against the
//! BVLC + NPDU + APDU layering described in Annex J.
//!
//! ```text
//!   BVLC header (4 bytes, big-endian):
//!     u8 type       always 0x81 for BACnet/IP
//!     u8 function   0x00..=0x0B
//!     u16 length    entire BVLC PDU including this header
//!
//!   NPDU (variable):
//!     u8 version    0x01
//!     u8 control    bit7=NSDU/APDU, bit5=has_dest, bit3=has_src,
//!                   bit2=reply_expected, bits0..=1=priority
//!     if has_dest:  u16 DNET, u8 DLEN, DADDR[DLEN]
//!     if has_src:   u16 SNET, u8 SLEN, SADDR[SLEN]
//!     if has_dest:  u8 hop_count
//!     if NSDU:      u8 message_type (+ optional vendor u16)
//!
//!   APDU first byte top-4 bits = PDU type:
//!     0 Confirmed-Request, 1 Unconfirmed-Request, 2 Simple-ACK,
//!     3 Complex-ACK, 4 Segment-ACK, 5 Error, 6 Reject, 7 Abort
//! ```
//!
//! Surfaced fields: BVLC function name, NPDU addressing (SNET/SADDR
//! → DNET/DADDR) when present, APDU type name, and the service
//! choice for Confirmed-Request / Unconfirmed-Request (ReadProperty,
//! WriteProperty, Who-Is, I-Am, COV notifications, …).

use crate::events::Direction;

pub struct BacnetParser {
    bypass: bool,
}

impl Default for BacnetParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum BacnetParserOutput {
    Need,
    Record {
        record: BacnetRecord,
        consumed: usize,
    },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct BacnetRecord {
    pub direction: Direction,
    pub bvlc_function: u8,
    pub bvlc_function_name: &'static str,
    pub bvlc_length: u16,
    pub npdu: Option<Npdu>,
    pub apdu: Option<Apdu>,
}

#[derive(Debug, Clone)]
pub struct Npdu {
    pub version: u8,
    pub control: u8,
    pub is_network_message: bool,
    pub expects_reply: bool,
    pub priority: u8,
    pub src: Option<BacAddr>,
    pub dst: Option<BacAddr>,
    pub hop_count: Option<u8>,
    pub network_message_type: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct BacAddr {
    pub net: u16,
    pub addr: Vec<u8>, // empty for broadcast
}

#[derive(Debug, Clone)]
pub struct Apdu {
    pub pdu_type: u8,
    pub pdu_type_name: &'static str,
    pub service_choice: Option<u8>,
    pub service_name: &'static str,
}

impl BacnetRecord {
    pub fn display_line(&self) -> String {
        let addr = match &self.npdu {
            Some(n) => {
                let s = n
                    .src
                    .as_ref()
                    .map(|a| format_addr("src", a))
                    .unwrap_or_default();
                let d = n
                    .dst
                    .as_ref()
                    .map(|a| format_addr("dst", a))
                    .unwrap_or_default();
                if s.is_empty() && d.is_empty() {
                    String::new()
                } else {
                    format!(
                        " {s}{}{d}",
                        if !s.is_empty() && !d.is_empty() {
                            " "
                        } else {
                            ""
                        }
                    )
                }
            }
            None => String::new(),
        };
        let apdu = match &self.apdu {
            Some(a) => format!(" {} {}", a.pdu_type_name, a.service_name),
            None => String::new(),
        };
        format!(
            "bacnet {} ({}) len={}{}{}",
            self.bvlc_function_name, self.bvlc_function, self.bvlc_length, addr, apdu,
        )
    }
}

fn format_addr(label: &str, a: &BacAddr) -> String {
    if a.addr.is_empty() {
        format!("{label}=bcast@{}", a.net)
    } else {
        let hex: String = a.addr.iter().map(|b| format!("{b:02x}")).collect();
        format!("{label}={}/{hex}", a.net)
    }
}

impl BacnetParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> BacnetParserOutput {
        if self.bypass {
            return BacnetParserOutput::Skip(buf.len());
        }
        if buf.len() < 4 {
            return BacnetParserOutput::Need;
        }
        // BVLC type 0x81 = BACnet/IP. Anything else isn't us.
        if buf[0] != 0x81 {
            self.bypass = true;
            return BacnetParserOutput::Skip(buf.len());
        }
        let function = buf[1];
        if !is_known_bvlc_function(function) {
            self.bypass = true;
            return BacnetParserOutput::Skip(buf.len());
        }
        let bvlc_length = u16::from_be_bytes([buf[2], buf[3]]);
        let total = bvlc_length as usize;
        if total < 4 {
            self.bypass = true;
            return BacnetParserOutput::Skip(buf.len());
        }
        if buf.len() < total {
            return BacnetParserOutput::Need;
        }
        // Body follows BVLC header. Forwarded-NPDU inserts a 6-byte
        // originating B/IP address before the NPDU; step over it.
        let mut p = 4usize;
        if function == 0x04 && total >= p + 6 {
            p += 6;
        }
        let body = &buf[p..total];
        let (npdu, apdu) = decode_npdu_apdu(body);
        let rec = BacnetRecord {
            direction: dir,
            bvlc_function: function,
            bvlc_function_name: bvlc_function_name(function),
            bvlc_length,
            npdu,
            apdu,
        };
        BacnetParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }
}

fn decode_npdu_apdu(body: &[u8]) -> (Option<Npdu>, Option<Apdu>) {
    if body.len() < 2 || body[0] != 0x01 {
        return (None, None);
    }
    let control = body[1];
    let has_dest = control & 0x20 != 0;
    let has_src = control & 0x08 != 0;
    let is_network_message = control & 0x80 != 0;
    let expects_reply = control & 0x04 != 0;
    let priority = control & 0x03;
    let mut i = 2usize;
    let dst = if has_dest {
        if body.len() < i + 3 {
            return (None, None);
        }
        let net = u16::from_be_bytes([body[i], body[i + 1]]);
        let dlen = body[i + 2] as usize;
        i += 3;
        if body.len() < i + dlen {
            return (None, None);
        }
        let addr = body[i..i + dlen].to_vec();
        i += dlen;
        Some(BacAddr { net, addr })
    } else {
        None
    };
    let src = if has_src {
        if body.len() < i + 3 {
            return (None, None);
        }
        let net = u16::from_be_bytes([body[i], body[i + 1]]);
        let slen = body[i + 2] as usize;
        i += 3;
        if body.len() < i + slen {
            return (None, None);
        }
        let addr = body[i..i + slen].to_vec();
        i += slen;
        Some(BacAddr { net, addr })
    } else {
        None
    };
    let hop_count = if has_dest {
        if body.len() <= i {
            return (None, None);
        }
        let h = body[i];
        i += 1;
        Some(h)
    } else {
        None
    };
    let (network_message_type, apdu) = if is_network_message {
        let nmt = body.get(i).copied();
        (nmt, None)
    } else if body.len() > i {
        let apdu_buf = &body[i..];
        (None, decode_apdu(apdu_buf))
    } else {
        (None, None)
    };
    let npdu = Npdu {
        version: 0x01,
        control,
        is_network_message,
        expects_reply,
        priority,
        src,
        dst,
        hop_count,
        network_message_type,
    };
    (Some(npdu), apdu)
}

fn decode_apdu(buf: &[u8]) -> Option<Apdu> {
    if buf.is_empty() {
        return None;
    }
    let pdu_type = (buf[0] >> 4) & 0x0f;
    let (service_choice, service_name) = match pdu_type {
        0x0 => {
            // Confirmed-Request (20.1.2):
            //   byte 0: pdu_type<<4 | SEG<<3 | MORE<<2 | SA<<1 | 0
            //   byte 1: max-segments (3b) | max-apdu (4b)
            //   byte 2: invoke ID
            //   byte 3 (if SEG): sequence number
            //   byte 4 (if SEG): proposed window size
            //   byte X: service choice
            let has_seg = buf[0] & 0x08 != 0;
            let mut j = 3usize;
            if has_seg {
                j += 2;
            }
            let sc = buf.get(j).copied();
            (sc, sc.map(confirmed_service_name).unwrap_or(""))
        }
        0x1 => {
            // Unconfirmed-Request: [type] [service_choice]
            let sc = buf.get(1).copied();
            (sc, sc.map(unconfirmed_service_name).unwrap_or(""))
        }
        _ => (None, ""),
    };
    Some(Apdu {
        pdu_type,
        pdu_type_name: apdu_type_name(pdu_type),
        service_choice,
        service_name,
    })
}

const fn is_known_bvlc_function(f: u8) -> bool {
    f <= 0x0B
}

const fn bvlc_function_name(f: u8) -> &'static str {
    match f {
        0x00 => "BVLC-Result",
        0x01 => "Write-Broadcast-Distribution-Table",
        0x02 => "Read-Broadcast-Distribution-Table",
        0x03 => "Read-Broadcast-Distribution-Table-Ack",
        0x04 => "Forwarded-NPDU",
        0x05 => "Register-Foreign-Device",
        0x06 => "Read-Foreign-Device-Table",
        0x07 => "Read-Foreign-Device-Table-Ack",
        0x08 => "Delete-Foreign-Device-Table-Entry",
        0x09 => "Distribute-Broadcast-To-Network",
        0x0A => "Original-Unicast-NPDU",
        0x0B => "Original-Broadcast-NPDU",
        _ => "?",
    }
}

const fn apdu_type_name(t: u8) -> &'static str {
    match t {
        0x0 => "Confirmed-Request",
        0x1 => "Unconfirmed-Request",
        0x2 => "Simple-ACK",
        0x3 => "Complex-ACK",
        0x4 => "Segment-ACK",
        0x5 => "Error",
        0x6 => "Reject",
        0x7 => "Abort",
        _ => "?",
    }
}

const fn confirmed_service_name(c: u8) -> &'static str {
    match c {
        0 => "acknowledgeAlarm",
        1 => "confirmedCOVNotification",
        2 => "confirmedEventNotification",
        3 => "getAlarmSummary",
        4 => "getEnrollmentSummary",
        5 => "subscribeCOV",
        6 => "atomicReadFile",
        7 => "atomicWriteFile",
        8 => "addListElement",
        9 => "removeListElement",
        10 => "createObject",
        11 => "deleteObject",
        12 => "readProperty",
        14 => "readPropertyMultiple",
        15 => "writeProperty",
        16 => "writePropertyMultiple",
        17 => "deviceCommunicationControl",
        18 => "confirmedPrivateTransfer",
        19 => "confirmedTextMessage",
        20 => "reinitializeDevice",
        21 => "vtOpen",
        22 => "vtClose",
        23 => "vtData",
        24 => "authenticate (withdrawn)",
        25 => "requestKey (withdrawn)",
        26 => "readRange",
        27 => "lifeSafetyOperation",
        28 => "subscribeCOVProperty",
        29 => "getEventInformation",
        _ => "?",
    }
}

const fn unconfirmed_service_name(c: u8) -> &'static str {
    match c {
        0 => "i-Am",
        1 => "i-Have",
        2 => "unconfirmedCOVNotification",
        3 => "unconfirmedEventNotification",
        4 => "unconfirmedPrivateTransfer",
        5 => "unconfirmedTextMessage",
        6 => "timeSynchronization",
        7 => "who-Has",
        8 => "who-Is",
        9 => "utcTimeSynchronization",
        10 => "writeGroup",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_is_broadcast() {
        // BVLC: 81 0b 00 0c (Original-Broadcast-NPDU, length 12)
        // NPDU: 01 20 (dst present + broadcast) ffff 00 (net=0xffff, dlen=0 -> global)
        //       ff (hop count)
        // APDU: 10 08 (Unconfirmed-Request | Who-Is)
        let buf = [
            0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08,
        ];
        let mut p = BacnetParser::default();
        match p.parse(&buf, Direction::Tx) {
            BacnetParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(record.bvlc_function, 0x0b);
                assert_eq!(record.bvlc_function_name, "Original-Broadcast-NPDU");
                let apdu = record.apdu.expect("apdu");
                assert_eq!(apdu.pdu_type, 1);
                assert_eq!(apdu.service_choice, Some(8));
                assert_eq!(apdu.service_name, "who-Is");
                let npdu = record.npdu.expect("npdu");
                let dst = npdu.dst.expect("dst");
                assert_eq!(dst.net, 0xffff);
                assert!(dst.addr.is_empty());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn read_property_confirmed() {
        // BVLC: 81 0a 00 11 (Original-Unicast-NPDU, length 17)
        // NPDU: 01 04 (expects reply, no src/dst)
        // APDU: 00 04 00 0c ... (Confirmed-Request, maxseg/maxapdu, invokeID, service=12)
        let buf = [
            0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x04, 0x00, 0x0c, 0x0c, 0x01, 0x00, 0x00,
            0x01, 0x19, 0x55,
        ];
        let mut p = BacnetParser::default();
        match p.parse(&buf, Direction::Tx) {
            BacnetParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, buf.len());
                let apdu = record.apdu.expect("apdu");
                assert_eq!(apdu.pdu_type, 0);
                assert_eq!(apdu.service_choice, Some(12));
                assert_eq!(apdu.service_name, "readProperty");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_bacnet_bypasses() {
        let mut p = BacnetParser::default();
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n\r\n", Direction::Tx),
            BacnetParserOutput::Skip(_)
        ));
    }

    #[test]
    fn short_buffer_needs_more() {
        let mut p = BacnetParser::default();
        assert!(matches!(
            p.parse(&[0x81, 0x0a], Direction::Tx),
            BacnetParserOutput::Need
        ));
    }
}
