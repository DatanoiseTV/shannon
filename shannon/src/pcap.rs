//! libpcap (classic) writer that synthesises IP/TCP frames from captured
//! byte streams. Useful for handing off to Wireshark / tshark / Zeek
//! without requiring those tools to know about shannon's own format.
//!
//! We use link-type `DLT_RAW` (12) — each record is a bare IPv4 or IPv6
//! packet, no Ethernet header. This avoids needing to invent L2
//! addresses and plays well with all common analysers.
//!
//! Synthesised packets carry:
//!
//! - IPv4/IPv6 header with 4-tuple from the observed flow, protocol 6
//!   (TCP), checksum zero (analysers flag but still parse the payload).
//! - TCP header with per-flow sequence counters, PSH+ACK flags on data
//!   segments, ACK numbers derived from the peer's running total so
//!   stream reassembly in Wireshark works cleanly.
//! - Payload = the captured plaintext bytes for the direction.
//!
//! The pcap **does not** include real TLS framing; on a shannon-observed
//! TLS flow we emit the *plaintext* captured via libssl uprobes as the
//! TCP payload. This makes the recording directly analysable; if you
//! want the ciphertext too, pair with `shannon record` which keeps the
//! on-wire bytes in JSONL.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// `DLT_RAW` = 12. Each record is a raw IPv4 or IPv6 packet.
const DLT_RAW: u32 = 101; // DLT_RAW_IP in classic pcap (value differs by system);
                           // wireshark accepts 101 (LINKTYPE_RAW) which is the portable id.
const PCAP_MAGIC: u32 = 0xa1b2c3d4;

const MAX_SNAPLEN: u32 = 65_535;

pub struct PcapWriter {
    file: BufWriter<File>,
    flows: HashMap<FlowId, FlowTcp>,
    packets_written: u64,
}

#[derive(Hash, Eq, PartialEq, Copy, Clone)]
struct FlowId {
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
}

#[derive(Default, Copy, Clone)]
struct FlowTcp {
    seq_client: u32,
    seq_server: u32,
}

pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl PcapWriter {
    pub fn create(path: &Path) -> Result<Self> {
        let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
        let mut w = BufWriter::with_capacity(64 * 1024, f);
        // Classic pcap global header — 24 bytes, little-endian.
        w.write_all(&PCAP_MAGIC.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?; // version major
        w.write_all(&4u16.to_le_bytes())?; // version minor
        w.write_all(&0i32.to_le_bytes())?; // this zone (GMT offset)
        w.write_all(&0u32.to_le_bytes())?; // sigfigs
        w.write_all(&MAX_SNAPLEN.to_le_bytes())?; // snaplen
        w.write_all(&DLT_RAW.to_le_bytes())?; // linktype = raw IP
        Ok(Self { file: w, flows: HashMap::new(), packets_written: 0 })
    }

    pub fn packets(&self) -> u64 {
        self.packets_written
    }

    pub fn flush(&mut self) -> Result<()> {
        self.file.flush()?;
        Ok(())
    }

    /// Write one data segment. `direction` is client→server or server→
    /// client; `src` / `dst` are always the observed 4-tuple endpoints
    /// regardless of direction.
    pub fn write_segment(
        &mut self,
        src: IpAddr,
        sport: u16,
        dst: IpAddr,
        dport: u16,
        direction: Direction,
        payload: &[u8],
    ) -> Result<()> {
        // Cap to snaplen.
        let take = payload.len().min(MAX_SNAPLEN as usize);
        let payload = &payload[..take];

        // Normalise the flow key to (client_ip, client_port, server_ip, server_port).
        // We don't truly know which side is "client" without the handshake,
        // so key by the ordered tuple: lower (ip,port) first.
        let (client, server, swap) = if (src, sport) < (dst, dport) {
            ((src, sport), (dst, dport), false)
        } else {
            ((dst, dport), (src, sport), true)
        };
        let flow = FlowId { src: client.0, sport: client.1, dst: server.0, dport: server.1 };
        let tcp_state = self.flows.entry(flow).or_default();

        let is_c2s = matches!(
            (direction, swap),
            (Direction::ClientToServer, false) | (Direction::ServerToClient, true)
        );
        let (seq, ack) = if is_c2s {
            let s = tcp_state.seq_client;
            tcp_state.seq_client = tcp_state.seq_client.wrapping_add(take as u32);
            (s, tcp_state.seq_server)
        } else {
            let s = tcp_state.seq_server;
            tcp_state.seq_server = tcp_state.seq_server.wrapping_add(take as u32);
            (s, tcp_state.seq_client)
        };

        let (actual_src, actual_src_port, actual_dst, actual_dst_port) = if is_c2s {
            (client.0, client.1, server.0, server.1)
        } else {
            (server.0, server.1, client.0, client.1)
        };

        // Build the IP + TCP + payload.
        let mut pkt: Vec<u8> = Vec::with_capacity(60 + take);
        match (actual_src, actual_dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let ip_total = 20 + 20 + take;
                pkt.push(0x45); // v4, ihl=5
                pkt.push(0); // DSCP+ECN
                pkt.extend_from_slice(&(ip_total as u16).to_be_bytes());
                pkt.extend_from_slice(&0u16.to_be_bytes()); // ID
                pkt.extend_from_slice(&0x4000u16.to_be_bytes()); // flags (DF)
                pkt.push(64); // TTL
                pkt.push(6); // TCP
                pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum (zero; analysers ok)
                pkt.extend_from_slice(&s.octets());
                pkt.extend_from_slice(&d.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let payload_len = 20 + take;
                pkt.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // v6, no TC/flow
                pkt.extend_from_slice(&(payload_len as u16).to_be_bytes());
                pkt.push(6); // next header = TCP
                pkt.push(64); // hop limit
                pkt.extend_from_slice(&s.octets());
                pkt.extend_from_slice(&d.octets());
            }
            _ => {
                // Mixed v4/v6 shouldn't happen on the same flow.
                return Ok(());
            }
        }
        // TCP header.
        pkt.extend_from_slice(&actual_src_port.to_be_bytes());
        pkt.extend_from_slice(&actual_dst_port.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&ack.to_be_bytes());
        pkt.push(0x50); // data offset 5 << 4
        pkt.push(0x18); // flags: PSH + ACK
        pkt.extend_from_slice(&65_535u16.to_be_bytes()); // window
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent
        pkt.extend_from_slice(payload);

        // Per-packet record header.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let ts_sec = now.as_secs() as u32;
        let ts_usec = now.subsec_micros();
        self.file.write_all(&ts_sec.to_le_bytes())?;
        self.file.write_all(&ts_usec.to_le_bytes())?;
        self.file.write_all(&(pkt.len() as u32).to_le_bytes())?; // incl_len
        self.file.write_all(&(pkt.len() as u32).to_le_bytes())?; // orig_len
        self.file.write_all(&pkt)?;
        self.packets_written += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn writes_valid_header_and_packet() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut w = PcapWriter::create(tmp.path()).unwrap();
        w.write_segment(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            Direction::ClientToServer,
            b"GET / HTTP/1.1\r\n\r\n",
        )
        .unwrap();
        w.flush().unwrap();
        drop(w);
        let bytes = std::fs::read(tmp.path()).unwrap();
        // Global header magic LE.
        assert_eq!(&bytes[..4], &PCAP_MAGIC.to_le_bytes());
        // Linktype at offset 20.
        assert_eq!(&bytes[20..24], &DLT_RAW.to_le_bytes());
        // Plenty of bytes for one packet.
        assert!(bytes.len() > 40 + 16 + 20);
    }

    #[test]
    fn v6_packet_roundtrip_headers() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut w = PcapWriter::create(tmp.path()).unwrap();
        let src: IpAddr = "::1".parse().unwrap();
        let dst: IpAddr = "2001:db8::1".parse().unwrap();
        w.write_segment(src, 1234, dst, 443, Direction::ClientToServer, b"hi").unwrap();
        w.flush().unwrap();
        let n = std::fs::metadata(tmp.path()).unwrap().len();
        assert!(n > 24);
    }
}
