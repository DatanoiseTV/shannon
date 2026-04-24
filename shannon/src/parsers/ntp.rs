//! NTP (RFC 5905) — udp/123.
//!
//! NTP packets are a fixed 48-byte header:
//!
//! ```text
//!   u8 LI|VN|Mode
//!   u8 stratum
//!   u8 poll   (log2 seconds)
//!   i8 precision (log2 seconds)
//!   u32 root_delay   (fixed-point)
//!   u32 root_dispersion
//!   u8[4] ref_id              (stratum 1: ASCII source; others: IPv4)
//!   u64 ref_timestamp
//!   u64 origin_timestamp
//!   u64 recv_timestamp
//!   u64 transmit_timestamp
//! ```
//!
//! Optional extensions + 4-byte key-id + 16-byte MAC may follow for
//! symmetric-key auth; we skip them. shannon surfaces LI/VN/Mode,
//! stratum, the human-readable ref_id for stratum 1 (GPS, PPS, LOCL,
//! …), and the transmit timestamp so operators can see the server's
//! idea of the current time — useful when correlating network-time
//! anomalies with security incidents.

use crate::events::Direction;

const HEADER: usize = 48;

pub struct NtpParser {
    bypass: bool,
}

impl Default for NtpParser {
    fn default() -> Self {
        Self { bypass: false }
    }
}

pub enum NtpParserOutput {
    Need,
    Record { record: NtpRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct NtpRecord {
    pub direction: Direction,
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub mode_name: &'static str,
    pub stratum: u8,
    pub stratum_name: &'static str,
    pub poll: i8,
    pub precision: i8,
    pub ref_id: [u8; 4],
    pub ref_id_ascii: Option<String>,
    pub transmit_timestamp: u64,
}

impl NtpRecord {
    pub fn display_line(&self) -> String {
        let ref_s = self
            .ref_id_ascii
            .clone()
            .unwrap_or_else(|| format!(
                "{}.{}.{}.{}",
                self.ref_id[0], self.ref_id[1], self.ref_id[2], self.ref_id[3]
            ));
        format!(
            "ntp v{} mode={} ({}) stratum={} ({}) poll=2^{}s ref={ref_s}",
            self.version,
            self.mode,
            self.mode_name,
            self.stratum,
            self.stratum_name,
            self.poll,
        )
    }
}

impl NtpParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> NtpParserOutput {
        if self.bypass {
            return NtpParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return NtpParserOutput::Need;
        }
        let flags = buf[0];
        let leap = flags >> 6;
        let version = (flags >> 3) & 0x07;
        let mode = flags & 0x07;
        if !(1..=4).contains(&version) {
            self.bypass = true;
            return NtpParserOutput::Skip(buf.len());
        }
        let stratum = buf[1];
        let poll = buf[2] as i8;
        let precision = buf[3] as i8;
        let ref_id = [buf[12], buf[13], buf[14], buf[15]];
        let ref_id_ascii = if stratum <= 1 {
            std::str::from_utf8(&ref_id)
                .ok()
                .map(|s| s.trim_end_matches('\0').trim().to_string())
                .filter(|s| !s.is_empty())
        } else {
            None
        };
        let transmit_timestamp = u64::from_be_bytes([
            buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
        ]);
        NtpParserOutput::Record {
            record: NtpRecord {
                direction: dir,
                leap,
                version,
                mode,
                mode_name: mode_name(mode),
                stratum,
                stratum_name: stratum_name(stratum),
                poll,
                precision,
                ref_id,
                ref_id_ascii,
                transmit_timestamp,
            },
            consumed: HEADER,
        }
    }
}

const fn mode_name(m: u8) -> &'static str {
    match m {
        0 => "reserved",
        1 => "symmetric-active",
        2 => "symmetric-passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "control",
        7 => "private",
        _ => "?",
    }
}

const fn stratum_name(s: u8) -> &'static str {
    match s {
        0 => "unspecified",
        1 => "primary",
        2..=15 => "secondary",
        16 => "unsynchronised",
        _ => "reserved",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_request_parsed() {
        let mut buf = vec![0u8; HEADER];
        // LI=0, VN=4, Mode=3 (client): 0b00_100_011 = 0x23
        buf[0] = 0x23;
        buf[1] = 0; // stratum
        buf[2] = 6; // poll 2^6 = 64s
        let mut p = NtpParser::default();
        match p.parse(&buf, Direction::Tx) {
            NtpParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, HEADER);
                assert_eq!(record.version, 4);
                assert_eq!(record.mode, 3);
                assert_eq!(record.mode_name, "client");
                assert_eq!(record.stratum, 0);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn stratum1_refid_ascii() {
        let mut buf = vec![0u8; HEADER];
        buf[0] = 0x24; // v4 mode=server
        buf[1] = 1;    // stratum 1
        buf[12..16].copy_from_slice(b"GPS\0");
        let mut p = NtpParser::default();
        match p.parse(&buf, Direction::Rx) {
            NtpParserOutput::Record { record, .. } => {
                assert_eq!(record.stratum_name, "primary");
                assert_eq!(record.ref_id_ascii.as_deref(), Some("GPS"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn short_needs_more() {
        let mut p = NtpParser::default();
        assert!(matches!(p.parse(&[0u8; 10], Direction::Tx), NtpParserOutput::Need));
    }

    #[test]
    fn non_ntp_bypasses() {
        let mut p = NtpParser::default();
        let junk: [u8; 48] = [0xff; 48]; // version=7 invalid
        assert!(matches!(p.parse(&junk, Direction::Tx), NtpParserOutput::Skip(_)));
    }
}
