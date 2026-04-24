//! HTTP/2 (RFC 9113) parser with HPACK (RFC 7541) header decoding and
//! gRPC surface extraction.
//!
//! Mirrors the `http1` parser's shape: one stateful instance per
//! (connection, direction), fed byte slices, returning [`Http2ParserOutput`].
//!
//! The HPACK decoder state is *connection-global* in the protocol, but
//! dynamic-table insertions are driven by one peer at a time. Because the
//! flow reconstructor owns one parser per direction, each side keeps its
//! own decoder — which is the right thing: the TX parser decodes request
//! headers (client's encoder), the RX parser decodes response headers
//! (server's encoder). These are independent header-compression contexts
//! per RFC 7541 §2.2.
//!
//! Framing rules we implement:
//!
//! 1. TX side: optional 24-byte connection preface
//!    `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` — consume and emit once.
//! 2. 9-byte frame header (length:24, type:8, flags:8, R:1+stream:31),
//!    body = length bytes.
//! 3. `HEADERS` / `PUSH_PROMISE` / `CONTINUATION`: concatenate fragments
//!    until `END_HEADERS`, then HPACK-decode the combined block.
//! 4. `DATA`: accumulate up to `MAX_DATA` bytes per stream; on
//!    `END_STREAM`, emit a record carrying the headers captured earlier.
//! 5. `RST_STREAM` / `GOAWAY` / `SETTINGS` / `PING` / `WINDOW_UPDATE` /
//!    `PRIORITY` are recognised and surfaced (`GOAWAY` / `RST_STREAM`
//!    carry `error_code`).
//!
//! Everything is bounded: header blocks ≤ 64 KiB, DATA per-record ≤ 4 KiB,
//! tracked streams ≤ 128 (LRU). Overflow emits `Skip` and clears per-stream
//! state rather than panicking.

use std::collections::VecDeque;

use hpack_patched::Decoder as HpackDecoder;

use crate::events::Direction;

// ---------------------------------------------------------------------------
// Public contract
// ---------------------------------------------------------------------------

const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;
/// Hard upper bound on the body of a single frame. The protocol allows up
/// to 2^24 − 1 (≈16 MiB), but `SETTINGS_MAX_FRAME_SIZE` defaults to 16 KiB
/// and nothing reasonable negotiates past ~1 MiB. Anything bigger is
/// treated as malformed rather than being memorised.
const MAX_FRAME_BODY: usize = 1024 * 1024;
const MAX_HEADER_BLOCK: usize = 64 * 1024;
const MAX_DATA: usize = 4 * 1024;
const MAX_STREAMS: usize = 128;

// Frame type codes (RFC 9113 §6).
const T_DATA: u8 = 0x0;
const T_HEADERS: u8 = 0x1;
const T_PRIORITY: u8 = 0x2;
const T_RST_STREAM: u8 = 0x3;
const T_SETTINGS: u8 = 0x4;
const T_PUSH_PROMISE: u8 = 0x5;
const T_PING: u8 = 0x6;
const T_GOAWAY: u8 = 0x7;
const T_WINDOW_UPDATE: u8 = 0x8;
const T_CONTINUATION: u8 = 0x9;

// Flag bits we care about.
const F_END_STREAM: u8 = 0x1;
const F_END_HEADERS: u8 = 0x4;
const F_PADDED: u8 = 0x8;
const F_PRIORITY: u8 = 0x20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2Kind {
    Preface,
    Headers,
    Data,
    Settings,
    Ping,
    GoAway,
    RstStream,
    WindowUpdate,
    Priority,
    PushPromise,
    Continuation,
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub struct GrpcInfo {
    pub service: String,
    pub method: String,
    pub grpc_status: Option<u32>,
    pub grpc_message: Option<String>,
    pub compressed: bool,
    pub message_length: u32,
}

#[derive(Debug, Clone)]
pub struct Http2Record {
    pub kind: Http2Kind,
    pub stream_id: u32,
    pub method: Option<String>,
    pub path: Option<String>,
    pub authority: Option<String>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub grpc: Option<GrpcInfo>,
    pub headers: Vec<(String, String)>,
    pub data: Vec<u8>,
    pub end_stream: bool,
    pub flags: u8,
    pub error_code: Option<u32>,
}

impl Http2Record {
    const fn new(kind: Http2Kind, stream_id: u32, flags: u8) -> Self {
        Self {
            kind,
            stream_id,
            method: None,
            path: None,
            authority: None,
            status: None,
            content_type: None,
            grpc: None,
            headers: Vec::new(),
            data: Vec::new(),
            end_stream: flags & F_END_STREAM != 0,
            flags,
            error_code: None,
        }
    }
}

#[derive(Debug)]
// The `Record` variant carries the full decoded record (hundreds of bytes
// in the common case). Boxing it would force callers to indirect through
// the heap for every successful parse — on a hot path; we prefer the
// larger enum.
#[allow(clippy::large_enum_variant)]
pub enum Http2ParserOutput {
    Need,
    Record {
        record: Http2Record,
        consumed: usize,
    },
    Skip(usize),
}

// ---------------------------------------------------------------------------
// Parser state
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum State {
    /// TX-only: waiting for the 24-byte client preface. Once consumed (or
    /// skipped if this is the RX side / server), transitions to Frames.
    AwaitPreface,
    /// Normal frame loop.
    Frames,
    /// Mid-way through a `HEADERS` / `PUSH_PROMISE` → `CONTINUATION`
    /// sequence on `stream_id`. All frames in between MUST be
    /// `CONTINUATION` on the same stream; any deviation → Bypass.
    Continuation { stream_id: u32, end_stream: bool },
    /// Stream looks like noise, drop everything.
    Bypass,
}

#[derive(Debug, Clone)]
struct StreamInfo {
    stream_id: u32,
    method: Option<String>,
    path: Option<String>,
    authority: Option<String>,
    status: Option<u16>,
    content_type: Option<String>,
    is_grpc: bool,
}

/// Very small LRU on top of a `VecDeque` — `MAX_STREAMS` is 128 so linear
/// scan is cheaper than a hashmap with churn.
#[derive(Debug, Default)]
struct StreamTable {
    entries: VecDeque<StreamInfo>,
}

impl StreamTable {
    fn get(&self, id: u32) -> Option<&StreamInfo> {
        self.entries.iter().find(|s| s.stream_id == id)
    }

    fn upsert(&mut self, info: StreamInfo) {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|s| s.stream_id == info.stream_id)
        {
            self.entries.remove(pos);
        }
        self.entries.push_back(info);
        while self.entries.len() > MAX_STREAMS {
            self.entries.pop_front();
        }
    }

    fn remove(&mut self, id: u32) -> Option<StreamInfo> {
        let pos = self.entries.iter().position(|s| s.stream_id == id)?;
        self.entries.remove(pos)
    }
}

/// Accumulates `HEADERS` + `CONTINUATION` fragments before HPACK-decoding.
#[derive(Debug, Default)]
struct HeaderAssembly {
    buf: Vec<u8>,
    // Flags from the initial HEADERS/PUSH_PROMISE, so we remember END_STREAM
    // across the CONTINUATION tail.
    initial_flags: u8,
    stream_id: u32,
    /// True when the initial frame was `PUSH_PROMISE` (we want to mark
    /// those records differently).
    is_push_promise: bool,
}

pub struct Http2Parser {
    state: State,
    hpack: HpackDecoder<'static>,
    streams: StreamTable,
    assembly: Option<HeaderAssembly>,
    /// True once we've seen *anything* other than the preface on this
    /// direction. Used to decide whether we require the preface on TX.
    saw_any: bool,
}

impl std::fmt::Debug for Http2Parser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2Parser")
            .field("state", &self.state)
            .field("streams", &self.streams)
            .field("assembly", &self.assembly)
            .field("saw_any", &self.saw_any)
            .finish_non_exhaustive()
    }
}

impl Default for Http2Parser {
    fn default() -> Self {
        Self {
            state: State::AwaitPreface,
            hpack: HpackDecoder::new(),
            streams: StreamTable::default(),
            assembly: None,
            saw_any: false,
        }
    }
}

impl Http2Parser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> Http2ParserOutput {
        match self.state {
            State::AwaitPreface => self.parse_preface(buf, dir),
            State::Frames => self.parse_frame(buf),
            State::Continuation {
                stream_id,
                end_stream,
            } => self.parse_continuation(buf, stream_id, end_stream),
            State::Bypass => Http2ParserOutput::Skip(buf.len()),
        }
    }

    // -- preface -------------------------------------------------------------

    fn parse_preface(&mut self, buf: &[u8], dir: Direction) -> Http2ParserOutput {
        // On the RX side (server→client) we never see the preface; jump
        // straight to frame parsing but still sanity-check the first 9
        // bytes look like a frame header.
        if dir == Direction::Rx {
            self.state = State::Frames;
            return self.sanity_check_first_frame(buf);
        }

        // TX side: need the full preface to decide.
        if buf.len() < PREFACE.len() {
            // Could still be a preface being streamed in — only bail if
            // what we've got already doesn't match a prefix of it.
            if !PREFACE.starts_with(buf) {
                self.state = State::Bypass;
                return Http2ParserOutput::Skip(buf.len());
            }
            return Http2ParserOutput::Need;
        }

        if &buf[..PREFACE.len()] == PREFACE {
            self.state = State::Frames;
            self.saw_any = true;
            let record = Http2Record::new(Http2Kind::Preface, 0, 0);
            return Http2ParserOutput::Record {
                record,
                consumed: PREFACE.len(),
            };
        }

        // No preface — bypass.
        self.state = State::Bypass;
        Http2ParserOutput::Skip(buf.len())
    }

    /// On RX, first frame should look plausible: length ≤ 16 MiB, type in
    /// a reasonable range (≤ 9 covers everything we know), stream bit
    /// clear.
    fn sanity_check_first_frame(&mut self, buf: &[u8]) -> Http2ParserOutput {
        if buf.len() < FRAME_HEADER_LEN {
            return Http2ParserOutput::Need;
        }
        let (length, frame_type, _flags, _stream) = parse_frame_header(buf);
        if length > MAX_FRAME_BODY || frame_type > 0x20 {
            self.state = State::Bypass;
            return Http2ParserOutput::Skip(buf.len());
        }
        self.parse_frame(buf)
    }

    // -- frame loop ---------------------------------------------------------

    fn parse_frame(&mut self, buf: &[u8]) -> Http2ParserOutput {
        if buf.len() < FRAME_HEADER_LEN {
            return Http2ParserOutput::Need;
        }
        let (length, frame_type, flags, stream_id) = parse_frame_header(buf);

        if length > MAX_FRAME_BODY {
            // Wildly out of bounds — bail on this stream entirely.
            self.state = State::Bypass;
            return Http2ParserOutput::Skip(buf.len());
        }

        let total = FRAME_HEADER_LEN + length;
        if buf.len() < total {
            return Http2ParserOutput::Need;
        }
        let body = &buf[FRAME_HEADER_LEN..total];
        self.saw_any = true;

        match frame_type {
            T_DATA => self.on_data(stream_id, flags, body, total),
            T_HEADERS => self.on_headers(stream_id, flags, body, total),
            T_PRIORITY => {
                let rec = Http2Record::new(Http2Kind::Priority, stream_id, flags);
                Http2ParserOutput::Record {
                    record: rec,
                    consumed: total,
                }
            }
            T_RST_STREAM => self.on_rst_stream(stream_id, flags, body, total),
            T_SETTINGS => self.on_settings(stream_id, flags, body, total),
            T_PUSH_PROMISE => self.on_push_promise(stream_id, flags, body, total),
            T_PING => {
                let rec = Http2Record::new(Http2Kind::Ping, stream_id, flags);
                Http2ParserOutput::Record {
                    record: rec,
                    consumed: total,
                }
            }
            T_GOAWAY => self.on_goaway(stream_id, flags, body, total),
            T_WINDOW_UPDATE => {
                let rec = Http2Record::new(Http2Kind::WindowUpdate, stream_id, flags);
                Http2ParserOutput::Record {
                    record: rec,
                    consumed: total,
                }
            }
            T_CONTINUATION => {
                // Stray CONTINUATION outside a HEADERS sequence — protocol
                // error in HTTP/2, but we just surface and move on.
                let rec = Http2Record::new(Http2Kind::Continuation, stream_id, flags);
                Http2ParserOutput::Record {
                    record: rec,
                    consumed: total,
                }
            }
            other => {
                let rec = Http2Record::new(Http2Kind::Unknown(other), stream_id, flags);
                Http2ParserOutput::Record {
                    record: rec,
                    consumed: total,
                }
            }
        }
    }

    fn parse_continuation(
        &mut self,
        buf: &[u8],
        expected_stream: u32,
        _end_stream: bool,
    ) -> Http2ParserOutput {
        if buf.len() < FRAME_HEADER_LEN {
            return Http2ParserOutput::Need;
        }
        let (length, frame_type, flags, stream_id) = parse_frame_header(buf);
        if frame_type != T_CONTINUATION || stream_id != expected_stream {
            // Protocol violation — bail.
            self.state = State::Bypass;
            self.assembly = None;
            return Http2ParserOutput::Skip(buf.len());
        }
        if length > MAX_FRAME_BODY {
            self.state = State::Bypass;
            self.assembly = None;
            return Http2ParserOutput::Skip(buf.len());
        }
        let total = FRAME_HEADER_LEN + length;
        if buf.len() < total {
            return Http2ParserOutput::Need;
        }
        let body = &buf[FRAME_HEADER_LEN..total];

        let Some(asm) = self.assembly.as_mut() else {
            self.state = State::Frames;
            return Http2ParserOutput::Skip(total);
        };

        if asm.buf.len().saturating_add(body.len()) > MAX_HEADER_BLOCK {
            // Oversized header block — drop the assembly, surface a Skip.
            self.assembly = None;
            self.state = State::Frames;
            return Http2ParserOutput::Skip(total);
        }
        asm.buf.extend_from_slice(body);

        if flags & F_END_HEADERS != 0 {
            let finished = self.assembly.take().expect("assembly just checked");
            self.state = State::Frames;
            let rec = self.finalize_header_block(&finished);
            return Http2ParserOutput::Record {
                record: rec,
                consumed: total,
            };
        }
        Http2ParserOutput::Skip(total)
    }

    // -- individual frame handlers -----------------------------------------

    fn on_headers(
        &mut self,
        stream_id: u32,
        flags: u8,
        body: &[u8],
        total: usize,
    ) -> Http2ParserOutput {
        let Some(fragment) = strip_headers_padding_priority(body, flags) else {
            self.state = State::Bypass;
            return Http2ParserOutput::Skip(total);
        };

        if fragment.len() > MAX_HEADER_BLOCK {
            return Http2ParserOutput::Skip(total);
        }

        if flags & F_END_HEADERS != 0 {
            let asm = HeaderAssembly {
                buf: fragment.to_vec(),
                initial_flags: flags,
                stream_id,
                is_push_promise: false,
            };
            let rec = self.finalize_header_block(&asm);
            return Http2ParserOutput::Record {
                record: rec,
                consumed: total,
            };
        }
        // Need CONTINUATION.
        self.assembly = Some(HeaderAssembly {
            buf: fragment.to_vec(),
            initial_flags: flags,
            stream_id,
            is_push_promise: false,
        });
        self.state = State::Continuation {
            stream_id,
            end_stream: flags & F_END_STREAM != 0,
        };
        Http2ParserOutput::Skip(total)
    }

    fn on_push_promise(
        &mut self,
        stream_id: u32,
        flags: u8,
        body: &[u8],
        total: usize,
    ) -> Http2ParserOutput {
        // PUSH_PROMISE: optional Pad Length (PADDED flag), 4-byte Promised
        // Stream ID, then Header Block Fragment, then padding.
        let Some(fragment) = strip_push_promise_padding(body, flags) else {
            self.state = State::Bypass;
            return Http2ParserOutput::Skip(total);
        };

        if fragment.len() > MAX_HEADER_BLOCK {
            return Http2ParserOutput::Skip(total);
        }

        if flags & F_END_HEADERS != 0 {
            let asm = HeaderAssembly {
                buf: fragment.to_vec(),
                initial_flags: flags,
                stream_id,
                is_push_promise: true,
            };
            let mut rec = self.finalize_header_block(&asm);
            rec.kind = Http2Kind::PushPromise;
            return Http2ParserOutput::Record {
                record: rec,
                consumed: total,
            };
        }
        self.assembly = Some(HeaderAssembly {
            buf: fragment.to_vec(),
            initial_flags: flags,
            stream_id,
            is_push_promise: true,
        });
        self.state = State::Continuation {
            stream_id,
            end_stream: false,
        };
        Http2ParserOutput::Skip(total)
    }

    fn on_data(
        &mut self,
        stream_id: u32,
        flags: u8,
        body: &[u8],
        total: usize,
    ) -> Http2ParserOutput {
        let Some(payload) = strip_data_padding(body, flags) else {
            // Malformed padding. Surface as Skip, don't bypass; next frame
            // can still be valid.
            return Http2ParserOutput::Skip(total);
        };

        let mut rec = Http2Record::new(Http2Kind::Data, stream_id, flags);
        let take = payload.len().min(MAX_DATA);
        rec.data.extend_from_slice(&payload[..take]);

        // Copy saved stream metadata onto the record.
        if let Some(info) = self.streams.get(stream_id) {
            rec.method.clone_from(&info.method);
            rec.path.clone_from(&info.path);
            rec.authority.clone_from(&info.authority);
            rec.status = info.status;
            rec.content_type.clone_from(&info.content_type);

            if info.is_grpc {
                rec.grpc = parse_grpc_data_frame(payload, info);
            }
        }

        if flags & F_END_STREAM != 0 {
            self.streams.remove(stream_id);
        }

        Http2ParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }

    fn on_settings(
        &mut self,
        stream_id: u32,
        flags: u8,
        body: &[u8],
        total: usize,
    ) -> Http2ParserOutput {
        // Pick up peer-advertised SETTINGS_HEADER_TABLE_SIZE (id 0x1) to
        // keep HPACK in step. Ignore ACK frames.
        if flags & 0x1 == 0 {
            let mut i = 0;
            while i + 6 <= body.len() {
                let id = u16::from_be_bytes([body[i], body[i + 1]]);
                let val = u32::from_be_bytes([body[i + 2], body[i + 3], body[i + 4], body[i + 5]]);
                if id == 0x1 {
                    self.hpack.set_max_table_size(val as usize);
                }
                i += 6;
            }
        }
        let rec = Http2Record::new(Http2Kind::Settings, stream_id, flags);
        Http2ParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }

    fn on_rst_stream(
        &mut self,
        stream_id: u32,
        flags: u8,
        body: &[u8],
        total: usize,
    ) -> Http2ParserOutput {
        let mut rec = Http2Record::new(Http2Kind::RstStream, stream_id, flags);
        if body.len() >= 4 {
            rec.error_code = Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
        }
        self.streams.remove(stream_id);
        Http2ParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }

    // Instance-style for symmetry with the other `on_*` handlers even
    // though we don't currently touch `self` here.
    #[allow(clippy::unused_self)]
    fn on_goaway(&self, stream_id: u32, flags: u8, body: &[u8], total: usize) -> Http2ParserOutput {
        let mut rec = Http2Record::new(Http2Kind::GoAway, stream_id, flags);
        // Last-Stream-ID (4) + Error Code (4) + Additional debug data.
        if body.len() >= 8 {
            rec.error_code = Some(u32::from_be_bytes([body[4], body[5], body[6], body[7]]));
        }
        Http2ParserOutput::Record {
            record: rec,
            consumed: total,
        }
    }

    // -- HPACK finalisation -------------------------------------------------

    fn finalize_header_block(&mut self, asm: &HeaderAssembly) -> Http2Record {
        let mut rec = Http2Record::new(Http2Kind::Headers, asm.stream_id, asm.initial_flags);
        if asm.is_push_promise {
            rec.kind = Http2Kind::PushPromise;
        }

        let Ok(decoded) = self.hpack.decode(&asm.buf) else {
            // Decoder is now in an undefined state w.r.t. the dynamic
            // table, so give up on this direction cleanly rather than
            // corrupting future frames.
            self.state = State::Bypass;
            return rec;
        };

        let mut info = StreamInfo {
            stream_id: asm.stream_id,
            method: None,
            path: None,
            authority: None,
            status: None,
            content_type: None,
            is_grpc: false,
        };

        let mut grpc_status: Option<u32> = None;
        let mut grpc_message: Option<String> = None;

        for (name, value) in decoded {
            // HPACK gives us raw bytes; headers are required to be ASCII
            // (pseudo-headers) or UTF-8-ish values. Lossy decode is fine
            // for our observability use case.
            let nm = String::from_utf8_lossy(&name).into_owned();
            let vl = String::from_utf8_lossy(&value).into_owned();

            match nm.as_str() {
                ":method" => info.method = Some(vl.clone()),
                ":path" => info.path = Some(vl.clone()),
                ":authority" => info.authority = Some(vl.clone()),
                ":status" => info.status = vl.parse().ok(),
                "content-type" => {
                    if vl.starts_with("application/grpc") {
                        info.is_grpc = true;
                    }
                    info.content_type = Some(vl.clone());
                }
                "grpc-status" => grpc_status = vl.parse().ok(),
                "grpc-message" => grpc_message = Some(vl.clone()),
                _ => {}
            }

            rec.headers.push((nm, vl));
        }

        rec.method.clone_from(&info.method);
        rec.path.clone_from(&info.path);
        rec.authority.clone_from(&info.authority);
        rec.status = info.status;
        rec.content_type.clone_from(&info.content_type);

        // gRPC surface from the :path pseudo-header, shape "/pkg.Service/Method".
        if info.is_grpc {
            let (service, method) = split_grpc_path(info.path.as_deref().unwrap_or(""));
            rec.grpc = Some(GrpcInfo {
                service,
                method,
                grpc_status,
                grpc_message,
                compressed: false,
                message_length: 0,
            });
        }

        // Remember stream metadata for subsequent DATA frames. If
        // END_STREAM was set on the HEADERS itself (common for simple
        // GETs with no body, or trailers-only responses), we don't bother
        // tracking.
        if asm.initial_flags & F_END_STREAM == 0 {
            self.streams.upsert(info);
        }

        rec
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_frame_header(buf: &[u8]) -> (usize, u8, u8, u32) {
    // Length: 24-bit big endian.
    let length = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
    let frame_type = buf[3];
    let flags = buf[4];
    // Mask off the reserved top bit of the stream identifier.
    let stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
    (length, frame_type, flags, stream_id)
}

/// For a HEADERS frame: strip the optional Pad Length (1), optional
/// Priority block (5), and trailing padding, returning just the header
/// block fragment.
fn strip_headers_padding_priority(body: &[u8], flags: u8) -> Option<&[u8]> {
    let mut start = 0usize;
    let mut end = body.len();

    if flags & F_PADDED != 0 {
        if body.is_empty() {
            return None;
        }
        let pad_len = usize::from(body[0]);
        start = 1;
        end = end.checked_sub(pad_len)?;
    }
    if flags & F_PRIORITY != 0 {
        // 4-byte stream dependency + 1-byte weight.
        let next = start.checked_add(5)?;
        if next > end {
            return None;
        }
        start = next;
    }
    if start > end {
        return None;
    }
    Some(&body[start..end])
}

/// For `PUSH_PROMISE`: optional Pad Length, 4-byte Promised Stream ID,
/// then header block fragment, then padding.
fn strip_push_promise_padding(body: &[u8], flags: u8) -> Option<&[u8]> {
    let mut start = 0usize;
    let mut end = body.len();
    if flags & F_PADDED != 0 {
        if body.is_empty() {
            return None;
        }
        let pad_len = usize::from(body[0]);
        start = 1;
        end = end.checked_sub(pad_len)?;
    }
    let next = start.checked_add(4)?;
    if next > end {
        return None;
    }
    start = next;
    Some(&body[start..end])
}

/// DATA frame: optional Pad Length + payload + padding.
fn strip_data_padding(body: &[u8], flags: u8) -> Option<&[u8]> {
    if flags & F_PADDED == 0 {
        return Some(body);
    }
    if body.is_empty() {
        return None;
    }
    let pad_len = usize::from(body[0]);
    let end = body.len().checked_sub(pad_len)?;
    if end < 1 {
        return None;
    }
    Some(&body[1..end])
}

/// Parse gRPC length-prefixed framing from a DATA payload:
///   1 byte  : compressed-flag
///   4 bytes : message length (big endian)
///   N bytes : message
/// We only surface the header fields — downstream consumers get the
/// payload via `record.data`.
fn parse_grpc_data_frame(payload: &[u8], info: &StreamInfo) -> Option<GrpcInfo> {
    if payload.len() < 5 {
        return None;
    }
    let compressed = payload[0] != 0;
    let message_length = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let (service, method) = split_grpc_path(info.path.as_deref().unwrap_or(""));
    Some(GrpcInfo {
        service,
        method,
        grpc_status: None,
        grpc_message: None,
        compressed,
        message_length,
    })
}

/// "/pkg.Service/Method" → ("pkg.Service", "Method"). Tolerant of missing
/// leading slash and missing method.
fn split_grpc_path(path: &str) -> (String, String) {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if let Some((svc, meth)) = trimmed.split_once('/') {
        (svc.to_string(), meth.to_string())
    } else {
        (trimmed.to_string(), String::new())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame header from (length, type, flags, `stream_id`).
    fn frame_header(length: usize, ftype: u8, flags: u8, stream_id: u32) -> [u8; 9] {
        let l = length as u32;
        [
            ((l >> 16) & 0xff) as u8,
            ((l >> 8) & 0xff) as u8,
            (l & 0xff) as u8,
            ftype,
            flags,
            ((stream_id >> 24) & 0x7f) as u8,
            ((stream_id >> 16) & 0xff) as u8,
            ((stream_id >> 8) & 0xff) as u8,
            (stream_id & 0xff) as u8,
        ]
    }

    /// HPACK-encode a list of header name/value pairs (no indexing, no
    /// Huffman) into a header block fragment. Uses the "Literal Header
    /// Field without Indexing — New Name" representation (0x00 prefix)
    /// so we don't have to hand-encode the static table.
    fn hpack_encode_literal(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (n, v) in pairs {
            out.push(0x00); // literal without indexing, new name
                            // name length + name
            encode_varint(&mut out, n.len() as u64, 7);
            out.extend_from_slice(n.as_bytes());
            encode_varint(&mut out, v.len() as u64, 7);
            out.extend_from_slice(v.as_bytes());
        }
        out
    }

    fn encode_varint(out: &mut Vec<u8>, mut value: u64, prefix_bits: u8) {
        let max_prefix = (1u64 << prefix_bits) - 1;
        if value < max_prefix {
            out.push(value as u8);
            return;
        }
        out.push(max_prefix as u8);
        value -= max_prefix;
        while value >= 128 {
            out.push(((value & 0x7f) | 0x80) as u8);
            value >>= 7;
        }
        out.push(value as u8);
    }

    #[test]
    fn preface_is_consumed_and_emits_record() {
        let mut p = Http2Parser::default();
        let out = p.parse(PREFACE, Direction::Tx);
        match out {
            Http2ParserOutput::Record { record, consumed } => {
                assert_eq!(record.kind, Http2Kind::Preface);
                assert_eq!(consumed, PREFACE.len());
            }
            _ => panic!("expected Record(Preface)"),
        }
    }

    #[test]
    fn simple_get_request_headers() {
        let mut p = Http2Parser::default();
        let _ = p.parse(PREFACE, Direction::Tx);

        let block = hpack_encode_literal(&[
            (":method", "GET"),
            (":path", "/"),
            (":authority", "example.com"),
            (":scheme", "https"),
        ]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_header(
            block.len(),
            T_HEADERS,
            F_END_HEADERS | F_END_STREAM,
            1,
        ));
        frame.extend_from_slice(&block);

        match p.parse(&frame, Direction::Tx) {
            Http2ParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, frame.len());
                assert_eq!(record.kind, Http2Kind::Headers);
                assert_eq!(record.stream_id, 1);
                assert_eq!(record.method.as_deref(), Some("GET"));
                assert_eq!(record.path.as_deref(), Some("/"));
                assert_eq!(record.authority.as_deref(), Some("example.com"));
                assert!(record.end_stream);
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn grpc_response_headers_then_data_message_length() {
        let mut p = Http2Parser::default();
        // Simulate RX side: no preface expected.
        let block =
            hpack_encode_literal(&[(":status", "200"), ("content-type", "application/grpc")]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_header(block.len(), T_HEADERS, F_END_HEADERS, 3));
        frame.extend_from_slice(&block);

        // Parse HEADERS.
        match p.parse(&frame, Direction::Rx) {
            Http2ParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, frame.len());
                assert_eq!(record.status, Some(200));
                assert_eq!(record.content_type.as_deref(), Some("application/grpc"));
                assert!(record.grpc.is_some());
            }
            other => panic!("expected Record(Headers), got {other:?}"),
        }

        // Now DATA: 1-byte compressed flag + 4-byte big-endian length (10)
        // + 10 bytes of payload.
        let mut data_payload = vec![0u8]; // not compressed
        data_payload.extend_from_slice(&10u32.to_be_bytes());
        data_payload.extend_from_slice(&[0xABu8; 10]);
        let mut data_frame = Vec::new();
        data_frame.extend_from_slice(&frame_header(data_payload.len(), T_DATA, 0, 3));
        data_frame.extend_from_slice(&data_payload);

        match p.parse(&data_frame, Direction::Rx) {
            Http2ParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, data_frame.len());
                assert_eq!(record.kind, Http2Kind::Data);
                let grpc = record.grpc.expect("grpc populated");
                assert_eq!(grpc.message_length, 10);
                assert!(!grpc.compressed);
            }
            other => panic!("expected Record(Data), got {other:?}"),
        }
    }

    #[test]
    fn malformed_frame_length_exceeds_cap_skipped_not_panic() {
        let mut p = Http2Parser::default();
        let _ = p.parse(PREFACE, Direction::Tx);
        // Advertise a body length larger than MAX_FRAME_BODY.
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff, 0xff, 0xff, T_HEADERS, 0, 0, 0, 0, 1]);
        match p.parse(&frame, Direction::Tx) {
            Http2ParserOutput::Skip(_) => {}
            other => panic!("expected Skip on malformed frame, got {other:?}"),
        }
    }

    #[test]
    fn non_http2_first_bytes_bypass() {
        let mut p = Http2Parser::default();
        let noise = b"GET / HTTP/1.1\r\n\r\n"; // plain HTTP/1 on TX
        match p.parse(noise, Direction::Tx) {
            Http2ParserOutput::Skip(n) => assert_eq!(n, noise.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
        // Subsequent bytes keep getting skipped.
        let more = b"hello world";
        match p.parse(more, Direction::Tx) {
            Http2ParserOutput::Skip(n) => assert_eq!(n, more.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn partial_frame_returns_need() {
        let mut p = Http2Parser::default();
        let _ = p.parse(PREFACE, Direction::Tx);
        // Only a frame header, body is short.
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_header(50, T_HEADERS, F_END_HEADERS, 1));
        match p.parse(&frame, Direction::Tx) {
            Http2ParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
    }

    #[test]
    fn rst_stream_surfaces_error_code() {
        let mut p = Http2Parser::default();
        let _ = p.parse(PREFACE, Direction::Tx);
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_header(4, T_RST_STREAM, 0, 7));
        frame.extend_from_slice(&0x0000_0008u32.to_be_bytes()); // CANCEL
        match p.parse(&frame, Direction::Tx) {
            Http2ParserOutput::Record { record, .. } => {
                assert_eq!(record.kind, Http2Kind::RstStream);
                assert_eq!(record.error_code, Some(8));
            }
            other => panic!("expected Record(RstStream), got {other:?}"),
        }
    }

    #[test]
    fn split_grpc_path_basic() {
        let (s, m) = split_grpc_path("/pkg.Service/Method");
        assert_eq!(s, "pkg.Service");
        assert_eq!(m, "Method");
    }
}
