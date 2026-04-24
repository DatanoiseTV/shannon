//! OPC-UA binary framing (IEC 62541-6 §7.1.2) — `tcp/4840`.
//!
//! Every message begins with an 8-byte header: 3-byte ASCII message
//! type, 1-byte chunk type, 4-byte little-endian total size (including
//! the header itself).
//!
//! Message types we recognise:
//! - `HEL` — Hello (client → server during TCP handshake)
//! - `ACK` — acknowledge (server reply to Hello)
//! - `ERR` — error
//! - `RHE` — reverse Hello
//! - `OPN` — OpenSecureChannel
//! - `CLO` — CloseSecureChannel
//! - `MSG` — secure channel message (service call)
//!
//! Chunk types:
//! - `F` — final chunk
//! - `C` — intermediate continuation
//! - `A` — abort
//!
//! We decode the header and publish it. The payload after the header
//! is intentionally opaque in v1 — OPC-UA services use OPC-encoded
//! structures which are worth a separate parser pass if a use case
//! justifies it. The header alone is enough to show what's happening
//! on the wire.

use crate::events::Direction;

const HEADER: usize = 8;
const MAX_PDU: usize = 64 * 1024 * 1024; // per spec: very large but bounded

#[derive(Default)]
pub struct OpcuaParser {
    bypass: bool,
}

pub enum OpcuaParserOutput {
    Need,
    Record { record: OpcuaRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct OpcuaRecord {
    pub direction: Direction,
    pub message_type: MessageType,
    pub chunk_type: ChunkType,
    pub size: u32,
    /// For HEL/ACK we extract the ProtocolVersion and endpoint URL
    /// when present; for other types this stays None.
    pub hello_info: Option<HelloInfo>,
    /// For ERR we extract StatusCode + Reason.
    pub err_info: Option<ErrInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageType {
    Hello,
    Ack,
    ReverseHello,
    Err,
    OpenSecureChannel,
    CloseSecureChannel,
    Message,
    Other([u8; 3]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    Final,
    Continue,
    Abort,
    Other(u8),
}

#[derive(Debug, Clone)]
pub struct HelloInfo {
    pub protocol_version: u32,
    pub endpoint_url: String,
}

#[derive(Debug, Clone)]
pub struct ErrInfo {
    pub error: u32,
    pub reason: String,
}

impl OpcuaRecord {
    pub fn display_line(&self) -> String {
        let mt = match &self.message_type {
            MessageType::Hello => "HEL".to_string(),
            MessageType::Ack => "ACK".to_string(),
            MessageType::ReverseHello => "RHE".to_string(),
            MessageType::Err => "ERR".to_string(),
            MessageType::OpenSecureChannel => "OPN".to_string(),
            MessageType::CloseSecureChannel => "CLO".to_string(),
            MessageType::Message => "MSG".to_string(),
            MessageType::Other(b) => {
                String::from_utf8_lossy(b).into_owned()
            }
        };
        let ct = match self.chunk_type {
            ChunkType::Final => "F",
            ChunkType::Continue => "C",
            ChunkType::Abort => "A",
            ChunkType::Other(_) => "?",
        };
        let extra = if let Some(h) = &self.hello_info {
            format!("  v{} endpoint={}", h.protocol_version, truncate(&h.endpoint_url, 80))
        } else if let Some(e) = &self.err_info {
            format!(
                "  err=0x{:08x} reason={}",
                e.error,
                truncate(&e.reason, 80)
            )
        } else {
            String::new()
        };
        format!("opcua {mt}{ct} size={}{extra}", self.size)
    }
}

fn truncate(s: &str, n: usize) -> &str {
    if s.len() <= n { s } else { &s[..n] }
}

impl OpcuaParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> OpcuaParserOutput {
        if self.bypass {
            return OpcuaParserOutput::Skip(buf.len());
        }
        if buf.len() < HEADER {
            return OpcuaParserOutput::Need;
        }
        let mt = parse_message_type(&buf[..3]);
        if matches!(
            mt,
            MessageType::Other(_)
        ) && !is_possible_message_type(&buf[..3])
        {
            self.bypass = true;
            return OpcuaParserOutput::Skip(buf.len());
        }
        let chunk_type = parse_chunk_type(buf[3]);
        let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let size_usize = size as usize;
        if size_usize < HEADER || size_usize > MAX_PDU {
            self.bypass = true;
            return OpcuaParserOutput::Skip(buf.len());
        }
        if buf.len() < size_usize {
            return OpcuaParserOutput::Need;
        }
        let body = &buf[HEADER..size_usize];
        let hello_info = match mt {
            MessageType::Hello | MessageType::Ack | MessageType::ReverseHello => {
                parse_hello(body)
            }
            _ => None,
        };
        let err_info = if matches!(mt, MessageType::Err) { parse_err(body) } else { None };
        OpcuaParserOutput::Record {
            record: OpcuaRecord {
                direction: dir,
                message_type: mt,
                chunk_type,
                size,
                hello_info,
                err_info,
            },
            consumed: size_usize,
        }
    }
}

fn parse_message_type(bytes: &[u8]) -> MessageType {
    match bytes {
        b"HEL" => MessageType::Hello,
        b"ACK" => MessageType::Ack,
        b"RHE" => MessageType::ReverseHello,
        b"ERR" => MessageType::Err,
        b"OPN" => MessageType::OpenSecureChannel,
        b"CLO" => MessageType::CloseSecureChannel,
        b"MSG" => MessageType::Message,
        _ => {
            let mut b = [0u8; 3];
            b.copy_from_slice(bytes);
            MessageType::Other(b)
        }
    }
}

fn is_possible_message_type(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| b.is_ascii_uppercase())
}

fn parse_chunk_type(b: u8) -> ChunkType {
    match b {
        b'F' => ChunkType::Final,
        b'C' => ChunkType::Continue,
        b'A' => ChunkType::Abort,
        other => ChunkType::Other(other),
    }
}

/// Hello body layout:
///   u32 ProtocolVersion
///   u32 ReceiveBufferSize
///   u32 SendBufferSize
///   u32 MaxMessageSize
///   u32 MaxChunkCount
///   String EndpointUrl
///
/// Ack has the same layout minus EndpointUrl.
fn parse_hello(body: &[u8]) -> Option<HelloInfo> {
    if body.len() < 20 {
        return None;
    }
    let version = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let after_fixed = &body[20..];
    let endpoint_url = parse_opcua_string(after_fixed).unwrap_or_default();
    Some(HelloInfo { protocol_version: version, endpoint_url })
}

/// Err body layout:
///   u32 Error (StatusCode)
///   String Reason
fn parse_err(body: &[u8]) -> Option<ErrInfo> {
    if body.len() < 4 {
        return None;
    }
    let error = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let reason = parse_opcua_string(&body[4..]).unwrap_or_default();
    Some(ErrInfo { error, reason })
}

/// OPC-UA `String` = i32 length (-1 = null) + UTF-8 bytes.
fn parse_opcua_string(buf: &[u8]) -> Option<String> {
    if buf.len() < 4 {
        return None;
    }
    let len = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len < 0 {
        return Some(String::new());
    }
    let len = len as usize;
    if len > 4096 || buf.len() < 4 + len {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[4..4 + len]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_parses() {
        // Build a HEL|F, total size = 8 (header) + 20 (fixed) + 4 (strlen) + 5 (bytes).
        let url = b"opc.t";
        let body_len = 20 + 4 + url.len();
        let total = 8 + body_len;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(b"HELF");
        pkt.extend_from_slice(&(total as u32).to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes()); // version
        pkt.extend_from_slice(&65_536u32.to_le_bytes()); // recv buf
        pkt.extend_from_slice(&65_536u32.to_le_bytes()); // send buf
        pkt.extend_from_slice(&1_048_576u32.to_le_bytes()); // max msg
        pkt.extend_from_slice(&0u32.to_le_bytes()); // max chunks
        pkt.extend_from_slice(&(url.len() as i32).to_le_bytes());
        pkt.extend_from_slice(url);

        let mut p = OpcuaParser::default();
        match p.parse(&pkt, Direction::Tx) {
            OpcuaParserOutput::Record { record, consumed } => {
                assert_eq!(record.message_type, MessageType::Hello);
                assert_eq!(record.chunk_type, ChunkType::Final);
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.hello_info.unwrap().endpoint_url, "opc.t");
            }
            _ => panic!("expected record"),
        }
    }

    #[test]
    fn non_opcua_bypasses() {
        let mut p = OpcuaParser::default();
        assert!(matches!(
            p.parse(b"\x16\x03\x01\x00\x50hello!", Direction::Rx),
            OpcuaParserOutput::Skip(_)
        ));
    }

    #[test]
    fn partial_returns_need() {
        let mut p = OpcuaParser::default();
        assert!(matches!(p.parse(b"HELF\x00", Direction::Tx), OpcuaParserOutput::Need));
    }
}
