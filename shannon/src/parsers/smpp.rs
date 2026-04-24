//! SMPP v3.4 — tcp/2775 (and carrier-specific variants).
//!
//! Short Message Peer-to-Peer. The protocol SMS aggregators,
//! telcos, bulk-SMS platforms, and IoT / 2FA providers use to
//! submit and receive messages. Every SMPP PDU is a 16-byte
//! header followed by an optional body:
//!
//! ```text
//!   u32 command_length   (BE, total including header)
//!   u32 command_id       (BE)
//!   u32 command_status   (BE)
//!   u32 sequence_number  (BE)
//!   body ...
//! ```
//!
//! The `command_id` top bit distinguishes request (0) from
//! response (1); the low 16 bits encode the command. For the bind
//! family (bind_transmitter / bind_receiver / bind_transceiver)
//! the body carries the plaintext `system_id` (the carrier-side
//! login name) and `password` — both C-strings. shannon surfaces
//! system_id and redacts the password.

use crate::events::Direction;

const HEADER: usize = 16;

pub struct SmppParser {
    bypass: bool,
}

impl Default for SmppParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum SmppParserOutput {
    Need,
    Record { record: SmppRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct SmppRecord {
    pub direction: Direction,
    pub command_id: u32,
    pub command_name: &'static str,
    pub is_response: bool,
    pub status: u32,
    pub status_name: &'static str,
    pub sequence: u32,
    pub length: u32,
    pub system_id: Option<String>,
    pub password_present: bool,
    pub system_type: Option<String>,
}

impl SmppRecord {
    pub fn display_line(&self) -> String {
        let sid = self
            .system_id
            .as_deref()
            .map(|s| format!(" system_id={s}"))
            .unwrap_or_default();
        let stype = self
            .system_type
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!(" system_type={s}"))
            .unwrap_or_default();
        let pw = if self.password_present {
            " password=<redacted>"
        } else {
            ""
        };
        let resp = if self.is_response { "_resp" } else { "" };
        let status = if self.is_response {
            format!(" status=0x{:08x} ({})", self.status, self.status_name)
        } else {
            String::new()
        };
        format!(
            "smpp {}{} seq={} len={}{sid}{pw}{stype}{status}",
            self.command_name, resp, self.sequence, self.length,
        )
    }
}

impl SmppParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> SmppParserOutput {
        if self.bypass {
            return SmppParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return SmppParserOutput::Need;
        }
        let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if (length as usize) < HEADER || length > 16 * 1024 * 1024 {
            self.bypass = true;
            return SmppParserOutput::Skip(buf.len());
        }
        let command_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let is_response = command_id & 0x8000_0000 != 0;
        let command = command_id & 0x7fff_ffff;
        if !is_known_command(command) {
            self.bypass = true;
            return SmppParserOutput::Skip(buf.len());
        }
        let status = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let sequence = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        if buf.len() < length as usize {
            return SmppParserOutput::Need;
        }
        let body = &buf[HEADER..length as usize];
        let (system_id, password_present, system_type) =
            if !is_response && matches!(command, 0x01 | 0x02 | 0x09) {
                decode_bind(body)
            } else {
                (None, false, None)
            };
        let rec = SmppRecord {
            direction: dir,
            command_id,
            command_name: command_name(command),
            is_response,
            status,
            status_name: status_name(status),
            sequence,
            length,
            system_id,
            password_present,
            system_type,
        };
        SmppParserOutput::Record { record: rec, consumed: length as usize }
    }
}

fn decode_bind(body: &[u8]) -> (Option<String>, bool, Option<String>) {
    // Layout:
    //   C-string system_id (max 16)
    //   C-string password  (max 9)
    //   C-string system_type (max 13)
    //   u8 interface_version
    //   u8 addr_ton
    //   u8 addr_npi
    //   C-string address_range
    let mut it = split_cstrings(body);
    let system_id = it.next().map(|s| s.to_string());
    let password = it.next();
    let system_type = it.next().map(|s| s.to_string());
    (system_id, password.map(|s| !s.is_empty()).unwrap_or(false), system_type)
}

fn split_cstrings(mut buf: &[u8]) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        if buf.is_empty() {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let s = std::str::from_utf8(&buf[..end]).unwrap_or("");
        buf = if end < buf.len() { &buf[end + 1..] } else { &[][..] };
        Some(s)
    })
}

const fn is_known_command(c: u32) -> bool {
    matches!(
        c,
        0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0b | 0x0f | 0x15 | 0x21
            | 0x22 | 0x23 | 0x103 | 0x111 | 0x112 | 0x113
    )
}

const fn command_name(c: u32) -> &'static str {
    match c {
        0x01 => "bind_receiver",
        0x02 => "bind_transmitter",
        0x03 => "query_sm",
        0x04 => "submit_sm",
        0x05 => "deliver_sm",
        0x06 => "unbind",
        0x07 => "replace_sm",
        0x08 => "cancel_sm",
        0x09 => "bind_transceiver",
        0x0b => "outbind",
        0x0f => "enquire_link",
        0x15 => "submit_multi",
        0x21 => "alert_notification",
        0x22 => "data_sm",
        0x23 => "broadcast_sm",
        0x103 => "query_broadcast_sm",
        0x111 => "cancel_broadcast_sm",
        _ => "?",
    }
}

const fn status_name(s: u32) -> &'static str {
    match s {
        0x0000_0000 => "ok",
        0x0000_0001 => "invalid_msg_length",
        0x0000_0002 => "invalid_command_length",
        0x0000_0003 => "invalid_command_id",
        0x0000_0004 => "incorrect_bind_state",
        0x0000_0005 => "already_bound",
        0x0000_0006 => "invalid_priority_flag",
        0x0000_0008 => "system_error",
        0x0000_000e => "bind_failed_invalid_password",
        0x0000_000f => "invalid_system_id",
        0x0000_0045 => "throttling_error",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_bind_transmitter(system_id: &str, password: &str) -> Vec<u8> {
        // body: system_id\0 password\0 system_type\0 if_ver addr_ton addr_npi addr_range\0
        let mut body = Vec::new();
        body.extend_from_slice(system_id.as_bytes());
        body.push(0);
        body.extend_from_slice(password.as_bytes());
        body.push(0);
        body.push(0); // empty system_type
        body.push(0x34); // interface_version 3.4
        body.push(0);
        body.push(0);
        body.push(0); // empty address_range
        let total = HEADER + body.len();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(total as u32).to_be_bytes());
        frame.extend_from_slice(&0x02u32.to_be_bytes()); // bind_transmitter
        frame.extend_from_slice(&0u32.to_be_bytes()); // status
        frame.extend_from_slice(&1u32.to_be_bytes()); // sequence
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn bind_transmitter_extracts_system_id() {
        let frame = build_bind_transmitter("smsgateway", "secret!!");
        let mut p = SmppParser::default();
        match p.parse(&frame, Direction::Tx) {
            SmppParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, frame.len());
                assert_eq!(record.command_name, "bind_transmitter");
                assert_eq!(record.system_id.as_deref(), Some("smsgateway"));
                assert!(record.password_present);
                let line = record.display_line();
                assert!(line.contains("<redacted>"));
                assert!(!line.contains("secret"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_smpp_bypasses() {
        let mut p = SmppParser::default();
        // Length 0x47 = 71 (plausible size) but command_id = 0x45540000
        // which isn't a known SMPP command → bypass.
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n";
        let mut padded = Vec::from(&buf[..]);
        while padded.len() < HEADER {
            padded.push(0);
        }
        assert!(matches!(p.parse(&padded, Direction::Tx), SmppParserOutput::Skip(_)));
    }

    #[test]
    fn short_needs_more() {
        let mut p = SmppParser::default();
        assert!(matches!(p.parse(&[0u8; 4], Direction::Tx), SmppParserOutput::Need));
    }
}
