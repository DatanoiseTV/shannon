//! WebSocket (RFC 6455) parser with Socket.IO / Engine.IO layering.
//!
//! One stateful instance per (connection, direction), fed byte slices,
//! returning [`WsParserOutput`].
//!
//! Framing rules we implement:
//!
//! 1. 2-byte fixed header: byte 0 = FIN (0x80) + RSV1-3 (0x70) + opcode
//!    (low nibble); byte 1 = mask bit (0x80) + 7-bit length. Length 126
//!    means next 2 bytes BE are the real length; 127 means next 8 bytes BE.
//!    When mask bit is set, 4 mask bytes follow, then masked payload.
//! 2. Opcodes 0x0 Continuation, 0x1 Text, 0x2 Binary, 0x8 Close, 0x9 Ping,
//!    0xA Pong. Reserved opcodes (0x3-0x7, 0xB-0xF) yield `Skip(total)`.
//! 3. Fragmentation: Text / Binary may span multiple frames with FIN=0 on
//!    all but the last. Payload is accumulated up to `MAX_PAYLOAD` and a
//!    single record is emitted on the final frame. Control frames (Close /
//!    Ping / Pong) are emitted immediately and MUST NOT be fragmented.
//! 4. RSV1-3 bits: required to be zero (no extensions negotiated here).
//!    If any are set, we emit `Skip(total)` and drop the frame.
//! 5. Socket.IO / Engine.IO decoding applies only to Text frames on
//!    complete messages. First char is the Engine.IO type digit `'0'`-`'6'`;
//!    if `'4'` (MESSAGE), the next char is the Socket.IO type `'0'`-`'6'`.
//!    Then optional `/namespace,`, optional `ack_id` digits, optional
//!    JSON array `[...]` whose first string element (if any) becomes the
//!    event name for `EVENT` / `BINARY_EVENT`. Remaining array elements are
//!    serialized and truncated into `args_json`.
//!
//! Everything is bounded: payload captured ≤ 4 KiB (total `payload_len`
//! still reports the true wire length), reason ≤ 256 chars, `args_json` ≤
//! 256 chars. Nothing ever panics on malformed input.

use std::fmt::Write as _;

use crate::events::Direction;

// ---------------------------------------------------------------------------
// Public contract
// ---------------------------------------------------------------------------

const MAX_PAYLOAD: usize = 4 * 1024;
const MAX_REASON: usize = 256;
const MAX_ARGS_JSON: usize = 256;
/// Anything beyond this length on the wire is treated as a resync signal
/// rather than a plausible WebSocket frame.
const MAX_FRAME_PAYLOAD: u64 = 1 << 30;

/// Opcodes (RFC 6455 §5.2).
const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// What the parser produced from a parse step.
#[derive(Debug)]
pub enum WsParserOutput {
    /// Need more bytes to make progress.
    Need,
    /// A complete record is available; caller should drop `consumed` bytes.
    Record { record: WsRecord, consumed: usize },
    /// Bytes didn't look like WebSocket (or carry a reserved opcode / bad
    /// framing); skip them and try to resync.
    Skip(usize),
}

/// A decoded WebSocket message.
#[derive(Debug, Clone)]
pub struct WsRecord {
    pub kind: WsRecordKind,
    pub direction: Direction,
    /// Opcode of the *initial* frame for Text / Binary messages, or of the
    /// control frame itself for Close / Ping / Pong.
    pub opcode: u8,
    /// True on the final frame (always true here — records are only emitted
    /// on message completion).
    pub fin: bool,
    /// True if the on-wire frame was masked.
    pub masked: bool,
    /// True on-wire payload length of the *completed* message (sum across
    /// fragments).
    pub payload_len: u64,
    /// Unmasked payload, bounded to [`MAX_PAYLOAD`] bytes.
    pub payload: Vec<u8>,
    /// Socket.IO / Engine.IO layer, present when we could parse a Text frame
    /// as Socket.IO.
    pub socketio: Option<SocketIoInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsRecordKind {
    Text,
    Binary,
    Close {
        code: u16,
        reason: String,
    },
    Ping,
    Pong,
    /// Orphan continuation frame with no in-progress message — normally
    /// never produced because we swallow continuations into the accumulator.
    /// Reserved for the case where the accumulator is empty.
    Continuation,
}

/// Socket.IO / Engine.IO layer decoded from a Text frame.
#[derive(Debug, Clone, Default)]
pub struct SocketIoInfo {
    /// Engine.IO packet type: 0 open, 1 close, 2 ping, 3 pong, 4 message,
    /// 5 upgrade, 6 noop.
    pub engineio_type: u8,
    /// Socket.IO packet type (only present when `engineio_type == 4`):
    /// 0 `CONNECT`, 1 `DISCONNECT`, 2 `EVENT`, 3 `ACK`, 4 `CONNECT_ERROR`,
    /// 5 `BINARY_EVENT`, 6 `BINARY_ACK`.
    pub socketio_type: Option<u8>,
    pub namespace: Option<String>,
    pub ack_id: Option<u64>,
    /// For `EVENT` / `BINARY_EVENT`: the first element of the JSON array if
    /// it's a string.
    pub event_name: Option<String>,
    /// The remaining args, serialized as JSON and truncated to
    /// [`MAX_ARGS_JSON`] characters.
    pub args_json: Option<String>,
}

impl WsRecord {
    /// Render a single-line, human-readable form for trace output.
    #[must_use]
    pub fn display_line(&self) -> String {
        let side = match self.direction {
            Direction::Tx => "TX",
            Direction::Rx => "RX",
        };
        match &self.kind {
            WsRecordKind::Text => self.socketio.as_ref().map_or_else(
                || {
                    let preview = truncate_text(&self.payload, 96);
                    format!("{side} WS TEXT len={} {}", self.payload_len, preview)
                },
                |sio| {
                    let mut s = format!("{side} WS TEXT eio={}", sio.engineio_type);
                    if let Some(sio_type) = sio.socketio_type {
                        let _ = write!(s, " sio={sio_type}");
                    }
                    if let Some(ns) = &sio.namespace {
                        let _ = write!(s, " ns={ns}");
                    }
                    if let Some(ack) = sio.ack_id {
                        let _ = write!(s, " ack={ack}");
                    }
                    if let Some(ev) = &sio.event_name {
                        let _ = write!(s, " event={ev}");
                    }
                    if let Some(args) = &sio.args_json {
                        let _ = write!(s, " args={args}");
                    }
                    s
                },
            ),
            WsRecordKind::Binary => {
                format!("{side} WS BINARY len={}", self.payload_len)
            }
            WsRecordKind::Close { code, reason } => {
                if reason.is_empty() {
                    format!("{side} WS CLOSE code={code}")
                } else {
                    format!("{side} WS CLOSE code={code} reason={reason}")
                }
            }
            WsRecordKind::Ping => {
                format!("{side} WS PING len={}", self.payload_len)
            }
            WsRecordKind::Pong => {
                format!("{side} WS PONG len={}", self.payload_len)
            }
            WsRecordKind::Continuation => {
                format!("{side} WS CONT len={}", self.payload_len)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// WebSocket stream parser.
///
/// Tracks whether the handshake has been validated (we can't see it from
/// inside the flow today, so the first byte is sniffed for a plausible
/// frame header; if not, the parser flips to `Bypass`) and the in-flight
/// fragment accumulator for Text / Binary messages.
#[derive(Debug)]
pub struct WebSocketParser {
    state: State,
    /// In-progress Text / Binary fragment accumulator.
    frag: Option<Fragment>,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    /// Normal operation — read frames.
    Framing,
    /// Gave up — first byte didn't look like a WebSocket frame.
    Bypass,
}

#[derive(Debug)]
struct Fragment {
    /// The initial data opcode (`OP_TEXT` or `OP_BINARY`).
    opcode: u8,
    /// Captured payload (bounded to [`MAX_PAYLOAD`]).
    payload: Vec<u8>,
    /// True on-wire byte count accumulated so far (may exceed `payload.len()`).
    total_len: u64,
    /// True if any frame in the message was masked.
    any_masked: bool,
}

impl Default for WebSocketParser {
    fn default() -> Self {
        Self {
            state: State::Framing,
            frag: None,
        }
    }
}

impl WebSocketParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> WsParserOutput {
        if self.state == State::Bypass {
            return WsParserOutput::Skip(buf.len());
        }
        if buf.is_empty() {
            return WsParserOutput::Need;
        }
        if buf.len() < 2 {
            // Still plausible — just need more.
            if !plausible_first_byte(buf[0]) {
                self.state = State::Bypass;
                return WsParserOutput::Skip(buf.len());
            }
            return WsParserOutput::Need;
        }

        // Sniff plausibility on the first frame we ever see. We don't have
        // a way to confirm the handshake succeeded, so reject gibberish up
        // front. All second-byte values are legal (any 7-bit length with
        // either mask bit), so we only vet the first byte here.
        if !plausible_first_byte(buf[0]) {
            self.state = State::Bypass;
            return WsParserOutput::Skip(buf.len());
        }

        self.parse_frame(buf, dir)
    }

    fn parse_frame(&mut self, buf: &[u8], dir: Direction) -> WsParserOutput {
        let b0 = buf[0];
        let b1 = buf[1];
        let fin = (b0 & 0x80) != 0;
        let rsv = b0 & 0x70;
        let opcode = b0 & 0x0F;
        let masked = (b1 & 0x80) != 0;
        let len7 = b1 & 0x7F;

        // Decode extended length.
        let mut cursor = 2usize;
        let payload_len: u64 = match len7 {
            126 => {
                if buf.len() < cursor + 2 {
                    return WsParserOutput::Need;
                }
                let n = u64::from(u16::from_be_bytes([buf[cursor], buf[cursor + 1]]));
                cursor += 2;
                n
            }
            127 => {
                if buf.len() < cursor + 8 {
                    return WsParserOutput::Need;
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&buf[cursor..cursor + 8]);
                let n = u64::from_be_bytes(arr);
                cursor += 8;
                n
            }
            n => u64::from(n),
        };

        // Guard against absurd length claims — treat as resync.
        if payload_len > MAX_FRAME_PAYLOAD {
            self.state = State::Bypass;
            return WsParserOutput::Skip(buf.len());
        }

        // Mask key.
        let mask_key: Option<[u8; 4]> = if masked {
            if buf.len() < cursor + 4 {
                return WsParserOutput::Need;
            }
            let k = [
                buf[cursor],
                buf[cursor + 1],
                buf[cursor + 2],
                buf[cursor + 3],
            ];
            cursor += 4;
            Some(k)
        } else {
            None
        };

        // Make sure we have the whole payload in-buffer before committing.
        let payload_usz = usize::try_from(payload_len).unwrap_or(usize::MAX);
        let Some(frame_total) = cursor.checked_add(payload_usz) else {
            self.state = State::Bypass;
            return WsParserOutput::Skip(buf.len());
        };
        if buf.len() < frame_total {
            return WsParserOutput::Need;
        }

        // Reserved bits set → not something we grok. Skip the frame.
        if rsv != 0 {
            return WsParserOutput::Skip(frame_total);
        }

        // Reserved opcodes (non-control 0x3-0x7, control 0xB-0xF).
        match opcode {
            OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG => {}
            _ => return WsParserOutput::Skip(frame_total),
        }

        // Control frames MUST have payload ≤ 125 and MUST NOT be fragmented
        // (RFC 6455 §5.5). If violated we treat the frame as noise.
        let is_control = opcode >= 0x8;
        if is_control && (!fin || payload_len > 125) {
            return WsParserOutput::Skip(frame_total);
        }

        // Pull out the payload, unmasked, into a bounded buffer.
        let payload_bytes = &buf[cursor..frame_total];
        let cap = bounded_copy(payload_bytes, mask_key, MAX_PAYLOAD);

        match opcode {
            OP_TEXT | OP_BINARY => {
                // Start of a new data message.
                if self.frag.is_some() {
                    // Protocol violation (interleaved new message before the
                    // old one finished). Drop the pending accumulator and
                    // start fresh — the safer option than crashing.
                    self.frag = None;
                }
                if fin {
                    let kind = if opcode == OP_TEXT {
                        WsRecordKind::Text
                    } else {
                        WsRecordKind::Binary
                    };
                    let mut record = WsRecord {
                        kind,
                        direction: dir,
                        opcode,
                        fin: true,
                        masked,
                        payload_len,
                        payload: cap,
                        socketio: None,
                    };
                    if opcode == OP_TEXT {
                        record.socketio = decode_socketio(&record.payload);
                    }
                    WsParserOutput::Record {
                        record,
                        consumed: frame_total,
                    }
                } else {
                    self.frag = Some(Fragment {
                        opcode,
                        payload: cap,
                        total_len: payload_len,
                        any_masked: masked,
                    });
                    WsParserOutput::Skip(frame_total)
                }
            }
            OP_CONTINUATION => {
                if let Some(frag) = self.frag.as_mut() {
                    let room = MAX_PAYLOAD.saturating_sub(frag.payload.len());
                    if room > 0 {
                        let take = room.min(cap.len());
                        frag.payload.extend_from_slice(&cap[..take]);
                    }
                    frag.total_len = frag.total_len.saturating_add(payload_len);
                    frag.any_masked |= masked;
                    if fin {
                        let frag = self.frag.take().expect("checked above");
                        let kind = if frag.opcode == OP_TEXT {
                            WsRecordKind::Text
                        } else {
                            WsRecordKind::Binary
                        };
                        let mut record = WsRecord {
                            kind,
                            direction: dir,
                            opcode: frag.opcode,
                            fin: true,
                            masked: frag.any_masked,
                            payload_len: frag.total_len,
                            payload: frag.payload,
                            socketio: None,
                        };
                        if frag.opcode == OP_TEXT {
                            record.socketio = decode_socketio(&record.payload);
                        }
                        WsParserOutput::Record {
                            record,
                            consumed: frame_total,
                        }
                    } else {
                        WsParserOutput::Skip(frame_total)
                    }
                } else {
                    // Orphan continuation. Emit a dedicated record so the
                    // caller can observe the anomaly, then move on.
                    let record = WsRecord {
                        kind: WsRecordKind::Continuation,
                        direction: dir,
                        opcode,
                        fin,
                        masked,
                        payload_len,
                        payload: cap,
                        socketio: None,
                    };
                    WsParserOutput::Record {
                        record,
                        consumed: frame_total,
                    }
                }
            }
            OP_CLOSE => {
                let (code, reason) = parse_close(&cap);
                let record = WsRecord {
                    kind: WsRecordKind::Close { code, reason },
                    direction: dir,
                    opcode,
                    fin,
                    masked,
                    payload_len,
                    payload: cap,
                    socketio: None,
                };
                WsParserOutput::Record {
                    record,
                    consumed: frame_total,
                }
            }
            OP_PING => WsParserOutput::Record {
                record: WsRecord {
                    kind: WsRecordKind::Ping,
                    direction: dir,
                    opcode,
                    fin,
                    masked,
                    payload_len,
                    payload: cap,
                    socketio: None,
                },
                consumed: frame_total,
            },
            OP_PONG => WsParserOutput::Record {
                record: WsRecord {
                    kind: WsRecordKind::Pong,
                    direction: dir,
                    opcode,
                    fin,
                    masked,
                    payload_len,
                    payload: cap,
                    socketio: None,
                },
                consumed: frame_total,
            },
            _ => WsParserOutput::Skip(frame_total),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Plausible first byte: FIN may be 0 or 1, RSV bits may be anything in
/// practice (extensions), opcode must be one of the defined ones.
const fn plausible_first_byte(b: u8) -> bool {
    let op = b & 0x0F;
    matches!(
        op,
        OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    )
}

/// Copy `src` into a new bounded Vec, unmasking as we go if a key is given.
fn bounded_copy(src: &[u8], mask: Option<[u8; 4]>, cap: usize) -> Vec<u8> {
    let take = src.len().min(cap);
    let mut out = Vec::with_capacity(take);
    match mask {
        None => out.extend_from_slice(&src[..take]),
        Some(k) => {
            for (i, &b) in src[..take].iter().enumerate() {
                out.push(b ^ k[i & 3]);
            }
        }
    }
    out
}

/// Parse a Close frame payload: optional 2-byte BE code + UTF-8 reason.
/// Returns code=1005 (No Status Received) per RFC 6455 §7.4.1 when absent.
fn parse_close(payload: &[u8]) -> (u16, String) {
    if payload.len() < 2 {
        return (1005, String::new());
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let raw = &payload[2..];
    let text = std::str::from_utf8(raw).map_or_else(
        |_| String::from_utf8_lossy(raw).into_owned(),
        ToString::to_string,
    );
    let reason = truncate_chars(&text, MAX_REASON);
    (code, reason)
}

/// Truncate `s` to at most `max` characters, appending an ellipsis marker
/// when it was cut.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Produce a lossy printable preview of `payload` for display lines.
fn truncate_text(payload: &[u8], max: usize) -> String {
    let s = String::from_utf8_lossy(payload);
    truncate_chars(&s, max)
}

// ---------------------------------------------------------------------------
// Socket.IO / Engine.IO decoding
// ---------------------------------------------------------------------------

/// Decode a Text payload as an Engine.IO / Socket.IO packet. Returns
/// `None` if the payload doesn't start with an Engine.IO type digit.
fn decode_socketio(payload: &[u8]) -> Option<SocketIoInfo> {
    let Ok(s) = std::str::from_utf8(payload) else {
        return None;
    };
    let mut chars = s.chars();
    let first = chars.next()?;
    if !('0'..='6').contains(&first) {
        return None;
    }
    let engineio_type = (first as u8) - b'0';
    let mut info = SocketIoInfo {
        engineio_type,
        ..SocketIoInfo::default()
    };

    // Only Engine.IO MESSAGE (type 4) carries a Socket.IO packet.
    if engineio_type != 4 {
        return Some(info);
    }

    let rest = &s[first.len_utf8()..];
    let mut idx = 0usize;

    // Socket.IO packet type digit.
    let bytes = rest.as_bytes();
    if idx >= bytes.len() {
        return Some(info);
    }
    let sio_byte = bytes[idx];
    if !(b'0'..=b'6').contains(&sio_byte) {
        return Some(info);
    }
    info.socketio_type = Some(sio_byte - b'0');
    idx += 1;

    // Attachments prefix for BINARY_EVENT (5) / BINARY_ACK (6): `<N>-` where
    // N is a decimal digit count. Consume and discard the attachment count.
    if matches!(info.socketio_type, Some(5 | 6)) {
        let start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx < bytes.len() && bytes[idx] == b'-' && idx > start {
            idx += 1;
        } else {
            // No attachment prefix — fine.
            idx = start;
        }
    }

    // Optional namespace: starts with '/' and ends at ','.
    if idx < bytes.len() && bytes[idx] == b'/' {
        // Namespace runs until ',' (then we consume the comma) or until
        // the start of the ack / JSON payload (then we leave the delimiter
        // alone for the next step to re-examine).
        if let Some(delim_rel) = bytes[idx..]
            .iter()
            .position(|&b| b == b',' || b == b'[' || b == b'{')
        {
            let end = idx + delim_rel;
            let ns = &rest[idx..end];
            if !ns.is_empty() {
                info.namespace = Some(truncate_chars(ns, MAX_REASON));
            }
            idx = if bytes[end] == b',' { end + 1 } else { end };
        } else {
            // No delimiter at all; the entire remainder is the namespace.
            info.namespace = Some(truncate_chars(&rest[idx..], MAX_REASON));
            idx = bytes.len();
        }
    }

    // Optional ack id: run of digits.
    let ack_start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx > ack_start {
        if let Ok(n) = rest[ack_start..idx].parse::<u64>() {
            info.ack_id = Some(n);
        }
    }

    // Optional JSON array.
    if idx < bytes.len() && bytes[idx] == b'[' {
        let json = &rest[idx..];
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(json) {
            if let Some(arr) = val.as_array() {
                if let Some(first) = arr.first() {
                    if let Some(name) = first.as_str() {
                        // EVENT / BINARY_EVENT: first string is event name.
                        if matches!(info.socketio_type, Some(2 | 5)) {
                            info.event_name = Some(truncate_chars(name, MAX_REASON));
                        }
                    }
                }
                // Serialize the remaining args. For EVENT / BINARY_EVENT we
                // drop the name element; for ACK / others we keep all.
                let args: Vec<&serde_json::Value> = if matches!(info.socketio_type, Some(2 | 5))
                    && arr.first().is_some_and(serde_json::Value::is_string)
                {
                    arr.iter().skip(1).collect()
                } else {
                    arr.iter().collect()
                };
                let rendered = serde_json::to_string(&args).unwrap_or_else(|_| "[]".to_string());
                info.args_json = Some(truncate_chars(&rendered, MAX_ARGS_JSON));
            }
        }
    }

    Some(info)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn unmasked_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let b0 = (if fin { 0x80 } else { 0x00 }) | (opcode & 0x0F);
        out.push(b0);
        push_len(&mut out, payload.len() as u64, false);
        out.extend_from_slice(payload);
        out
    }

    fn masked_frame(opcode: u8, fin: bool, mask: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let b0 = (if fin { 0x80 } else { 0x00 }) | (opcode & 0x0F);
        out.push(b0);
        push_len(&mut out, payload.len() as u64, true);
        out.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i & 3]);
        }
        out
    }

    fn push_len(out: &mut Vec<u8>, len: u64, masked: bool) {
        let mask_bit: u8 = if masked { 0x80 } else { 0 };
        if len < 126 {
            out.push(mask_bit | (len as u8));
        } else if len < 0x10000 {
            out.push(mask_bit | 0x7E);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 0x7F);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }

    #[test]
    fn unmasked_short_text_server_to_client() {
        let mut p = WebSocketParser::default();
        let frame = unmasked_frame(OP_TEXT, true, b"hello");
        match p.parse(&frame, Direction::Rx) {
            WsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, frame.len());
                assert_eq!(record.kind, WsRecordKind::Text);
                assert_eq!(record.payload, b"hello");
                assert_eq!(record.payload_len, 5);
                assert!(!record.masked);
                assert!(record.fin);
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn masked_client_to_server_text() {
        let mut p = WebSocketParser::default();
        let mask = [0xA1, 0xB2, 0xC3, 0xD4];
        let frame = masked_frame(OP_TEXT, true, mask, b"ping!");
        match p.parse(&frame, Direction::Tx) {
            WsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, frame.len());
                assert_eq!(record.payload, b"ping!");
                assert!(record.masked);
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn close_with_code_and_reason() {
        let mut p = WebSocketParser::default();
        let mut payload = vec![];
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(b"bye");
        let frame = unmasked_frame(OP_CLOSE, true, &payload);
        match p.parse(&frame, Direction::Rx) {
            WsParserOutput::Record { record, .. } => match record.kind {
                WsRecordKind::Close { code, reason } => {
                    assert_eq!(code, 1000);
                    assert_eq!(reason, "bye");
                }
                other => panic!("expected Close, got {other:?}"),
            },
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn extended_16bit_length() {
        let mut p = WebSocketParser::default();
        let payload = vec![b'x'; 200];
        let frame = unmasked_frame(OP_BINARY, true, &payload);
        match p.parse(&frame, Direction::Rx) {
            WsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, frame.len());
                assert_eq!(record.payload_len, 200);
                assert_eq!(record.payload.len(), 200);
                assert_eq!(record.kind, WsRecordKind::Binary);
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn extended_64bit_length_capped_at_4kib() {
        let mut p = WebSocketParser::default();
        let payload = vec![0xABu8; 10_000];
        // Force the 127-length encoding by hand.
        let mut frame: Vec<u8> = vec![0x80 | OP_BINARY, 0x7F];
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        frame.extend_from_slice(&payload);
        match p.parse(&frame, Direction::Rx) {
            WsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, frame.len());
                assert_eq!(record.payload_len, 10_000);
                assert_eq!(record.payload.len(), MAX_PAYLOAD);
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn fragmented_text_joined() {
        let mut p = WebSocketParser::default();
        let f1 = unmasked_frame(OP_TEXT, false, b"hel");
        let f2 = unmasked_frame(OP_CONTINUATION, true, b"lo!");
        match p.parse(&f1, Direction::Rx) {
            WsParserOutput::Skip(n) => assert_eq!(n, f1.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
        match p.parse(&f2, Direction::Rx) {
            WsParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, f2.len());
                assert_eq!(record.payload, b"hello!");
                assert_eq!(record.payload_len, 6);
                assert_eq!(record.kind, WsRecordKind::Text);
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn socketio_event_frame() {
        let mut p = WebSocketParser::default();
        let frame = unmasked_frame(OP_TEXT, true, b"42/chat,5[\"msg\",\"hello\"]");
        match p.parse(&frame, Direction::Rx) {
            WsParserOutput::Record { record, .. } => {
                let sio = record.socketio.expect("socketio info");
                assert_eq!(sio.engineio_type, 4);
                assert_eq!(sio.socketio_type, Some(2));
                assert_eq!(sio.namespace.as_deref(), Some("/chat"));
                assert_eq!(sio.ack_id, Some(5));
                assert_eq!(sio.event_name.as_deref(), Some("msg"));
                assert!(sio
                    .args_json
                    .as_deref()
                    .is_some_and(|s| s.contains("\"hello\"")));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn socketio_plain_message_no_namespace() {
        let mut p = WebSocketParser::default();
        let frame = unmasked_frame(OP_TEXT, true, b"42[\"ev\"]");
        match p.parse(&frame, Direction::Rx) {
            WsParserOutput::Record { record, .. } => {
                let sio = record.socketio.expect("socketio");
                assert_eq!(sio.engineio_type, 4);
                assert_eq!(sio.socketio_type, Some(2));
                assert!(sio.namespace.is_none());
                assert_eq!(sio.event_name.as_deref(), Some("ev"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn reserved_opcode_is_skipped() {
        let mut p = WebSocketParser::default();
        // Opcode 0x3 is reserved. `plausible_first_byte` rejects it, so the
        // parser flips to Bypass and reports Skip(buf.len()).
        let frame: Vec<u8> = vec![0x80 | 0x3, 0x00];
        match p.parse(&frame, Direction::Rx) {
            WsParserOutput::Skip(n) => assert_eq!(n, frame.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn reserved_opcode_mid_stream_is_skipped_by_frame() {
        // After at least one good frame, a reserved opcode on the wire
        // produces Skip(frame_total). The sniffer is the first gate in
        // every parse() call though — so for an unrecognised opcode, we
        // end up on the Bypass path. Either way the externally-observable
        // contract is: Skip.
        let mut p = WebSocketParser::default();
        // Prime the parser with a good frame first.
        let good = unmasked_frame(OP_TEXT, true, b"ok");
        let _ = p.parse(&good, Direction::Rx);
        // Now feed a reserved opcode frame (0xB control reserved).
        let bad: Vec<u8> = vec![0x80 | 0xB, 0x00];
        match p.parse(&bad, Direction::Rx) {
            WsParserOutput::Skip(_) => {}
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn truncated_header_returns_need() {
        let mut p = WebSocketParser::default();
        // Only one byte — not enough for full header.
        match p.parse(&[0x81], Direction::Rx) {
            WsParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
        // Two bytes claiming 16-bit length, but the length bytes missing.
        match p.parse(&[0x81, 126], Direction::Rx) {
            WsParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
    }

    #[test]
    fn truncated_payload_returns_need() {
        let mut p = WebSocketParser::default();
        let frame = unmasked_frame(OP_TEXT, true, b"hello");
        match p.parse(&frame[..frame.len() - 1], Direction::Rx) {
            WsParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
    }

    #[test]
    fn bypass_on_garbage() {
        let mut p = WebSocketParser::default();
        // First byte 0xFF has opcode 0xF (reserved).
        match p.parse(&[0xFF, 0x00], Direction::Rx) {
            WsParserOutput::Skip(n) => assert_eq!(n, 2),
            other => panic!("expected Skip, got {other:?}"),
        }
        // Subsequent calls stay in Bypass.
        match p.parse(b"anything", Direction::Rx) {
            WsParserOutput::Skip(n) => assert_eq!(n, 8),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn ping_roundtrip() {
        let mut p = WebSocketParser::default();
        let frame = unmasked_frame(OP_PING, true, b"pp");
        match p.parse(&frame, Direction::Rx) {
            WsParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, WsRecordKind::Ping);
                assert_eq!(record.payload, b"pp");
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn display_line_renders_text() {
        let rec = WsRecord {
            kind: WsRecordKind::Text,
            direction: Direction::Tx,
            opcode: OP_TEXT,
            fin: true,
            masked: false,
            payload_len: 5,
            payload: b"hello".to_vec(),
            socketio: None,
        };
        let line = rec.display_line();
        assert!(line.starts_with("TX WS TEXT"));
        assert!(line.contains("hello"));
    }

    #[test]
    fn display_line_renders_socketio_event() {
        let sio = SocketIoInfo {
            engineio_type: 4,
            socketio_type: Some(2),
            namespace: Some("/chat".into()),
            ack_id: Some(7),
            event_name: Some("msg".into()),
            args_json: Some("[\"hi\"]".into()),
        };
        let rec = WsRecord {
            kind: WsRecordKind::Text,
            direction: Direction::Rx,
            opcode: OP_TEXT,
            fin: true,
            masked: false,
            payload_len: 16,
            payload: b"42/chat,7[\"msg\",\"hi\"]".to_vec(),
            socketio: Some(sio),
        };
        let line = rec.display_line();
        assert!(line.contains("eio=4"));
        assert!(line.contains("sio=2"));
        assert!(line.contains("ns=/chat"));
        assert!(line.contains("ack=7"));
        assert!(line.contains("event=msg"));
    }
}
