//! HTTP/1.0 and HTTP/1.1 parser.
//!
//! Implements just enough of RFC 7230 to produce structured records from
//! plaintext byte streams. Delegates the header parse to `httparse`
//! (mature, bounded, no-alloc); handles body framing ourselves because
//! httparse explicitly punts on that.
//!
//! Framing rules we implement:
//!
//! 1. If `Transfer-Encoding: chunked` is present, consume chunks until
//!    the zero-length terminator.
//! 2. Else if `Content-Length: N` is present, consume exactly N bytes.
//! 3. Else for *responses* with no length, consume until connection
//!    close — we emit a record when the direction goes idle (a later
//!    pass in the flow reconstructor; not implemented here yet).
//! 4. Requests with no content-length and no chunked = zero body.
//!
//! Requests arriving on one side and responses on the other are matched
//! up by the flow reconstructor, which owns one parser per direction.

use std::collections::HashMap;

use crate::events::Direction;

const MAX_HEADERS: usize = 64;

/// Parser state machine. One instance per (connection, direction).
pub struct Http1Parser {
    state: State,
    /// Remaining body bytes to consume (content-length path).
    remaining_body: usize,
    /// True if we're inside a chunked body.
    chunked: bool,
    /// Partial info for the currently-being-assembled record.
    current: Option<HeaderInfo>,
}

impl Default for Http1Parser {
    fn default() -> Self {
        Self {
            state: State::Headers,
            remaining_body: 0,
            chunked: false,
            current: None,
        }
    }
}

#[derive(PartialEq, Eq)]
enum State {
    /// Waiting for a complete HTTP header block.
    Headers,
    /// Consuming a fixed-length body.
    Body,
    /// Consuming a chunked body.
    Chunked(ChunkState),
    /// Giving up on this stream — not HTTP/1.
    Bypass,
}

#[derive(PartialEq, Eq)]
enum ChunkState {
    Size,
    Data(usize),
    /// Read trailing CRLF after a chunk's bytes.
    AfterData,
    Trailer,
}

struct HeaderInfo {
    kind: RecordKind,
    method: Option<String>,
    path: Option<String>,
    status: Option<u16>,
    reason: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ParsedRecord {
    pub kind: RecordKind,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// True if the body was captured in full; false if it was truncated.
    pub body_complete: bool,
    /// For chunked / streamed bodies whose total length we don't know
    /// until the end.
    pub total_body_bytes: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Request,
    Response,
}

/// Result of one parse step.
pub enum ParserOutput {
    Need,
    Record { record: ParsedRecord, consumed: usize },
    Skip(usize),
}

impl Http1Parser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> ParserOutput {
        match self.state {
            State::Headers => self.parse_headers(buf, dir),
            State::Body => self.parse_body(buf),
            State::Chunked(_) => self.parse_chunked(buf),
            State::Bypass => ParserOutput::Skip(buf.len()),
        }
    }

    fn parse_headers(&mut self, buf: &[u8], dir: Direction) -> ParserOutput {
        if buf.len() < 4 {
            return ParserOutput::Need;
        }
        // Quick-reject: TX side should look like a method, RX side like
        // "HTTP/". Saves going into httparse on clearly-not-HTTP streams
        // like TLS ciphertext or binary protocols.
        match dir {
            Direction::Tx => {
                if !starts_with_method_letter(buf) {
                    self.state = State::Bypass;
                    return ParserOutput::Skip(buf.len());
                }
            }
            Direction::Rx => {
                if !buf.starts_with(b"HTTP/") {
                    self.state = State::Bypass;
                    return ParserOutput::Skip(buf.len());
                }
            }
        }

        let mut headers_storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
        match dir {
            Direction::Tx => {
                let mut req = httparse::Request::new(&mut headers_storage);
                match req.parse(buf) {
                    Ok(httparse::Status::Complete(len)) => {
                        let headers = collect_headers(req.headers);
                        let method = req.method.unwrap_or("").to_string();
                        let path = req.path.unwrap_or("").to_string();
                        self.current = Some(HeaderInfo {
                            kind: RecordKind::Request,
                            method: Some(method),
                            path: Some(path),
                            status: None,
                            reason: None,
                            headers: headers.clone(),
                            body: Vec::new(),
                        });
                        self.prime_body(&headers);
                        self.finalize_or_start_body(len)
                    }
                    Ok(httparse::Status::Partial) => ParserOutput::Need,
                    Err(_) => {
                        self.state = State::Bypass;
                        ParserOutput::Skip(buf.len())
                    }
                }
            }
            Direction::Rx => {
                let mut resp = httparse::Response::new(&mut headers_storage);
                match resp.parse(buf) {
                    Ok(httparse::Status::Complete(len)) => {
                        let headers = collect_headers(resp.headers);
                        let status = resp.code;
                        let reason = resp.reason.unwrap_or("").to_string();
                        self.current = Some(HeaderInfo {
                            kind: RecordKind::Response,
                            method: None,
                            path: None,
                            status,
                            reason: Some(reason),
                            headers: headers.clone(),
                            body: Vec::new(),
                        });
                        self.prime_body(&headers);
                        self.finalize_or_start_body(len)
                    }
                    Ok(httparse::Status::Partial) => ParserOutput::Need,
                    Err(_) => {
                        self.state = State::Bypass;
                        ParserOutput::Skip(buf.len())
                    }
                }
            }
        }
    }

    /// Prime `remaining_body` / `chunked` from the parsed headers.
    fn prime_body(&mut self, headers: &[(String, String)]) {
        self.remaining_body = 0;
        self.chunked = false;
        let mut te = None;
        let mut cl = None;
        for (name, value) in headers {
            let lname = name.to_ascii_lowercase();
            if lname == "transfer-encoding" {
                te = Some(value.to_ascii_lowercase());
            } else if lname == "content-length" {
                cl = value.parse::<usize>().ok();
            }
        }
        if te.as_deref().is_some_and(|v| v.contains("chunked")) {
            self.chunked = true;
        } else if let Some(n) = cl {
            self.remaining_body = n;
        }
    }

    fn finalize_or_start_body(&mut self, header_len: usize) -> ParserOutput {
        if self.chunked {
            self.state = State::Chunked(ChunkState::Size);
        } else if self.remaining_body > 0 {
            self.state = State::Body;
        } else {
            // No body — emit immediately.
            let rec = self.emit(true);
            return ParserOutput::Record { record: rec, consumed: header_len };
        }
        // We return Skip with the header length so the flow reconstructor
        // drops exactly the header bytes before we start the body phase.
        ParserOutput::Skip(header_len)
    }

    fn parse_body(&mut self, buf: &[u8]) -> ParserOutput {
        if self.remaining_body == 0 {
            let rec = self.emit(true);
            return ParserOutput::Record { record: rec, consumed: 0 };
        }
        let take = buf.len().min(self.remaining_body);
        if take == 0 {
            return ParserOutput::Need;
        }
        if let Some(cur) = self.current.as_mut() {
            let room = 4096usize.saturating_sub(cur.body.len());
            let n = room.min(take);
            cur.body.extend_from_slice(&buf[..n]);
        }
        self.remaining_body -= take;
        if self.remaining_body == 0 {
            let rec = self.emit(true);
            ParserOutput::Record { record: rec, consumed: take }
        } else {
            ParserOutput::Skip(take)
        }
    }

    fn parse_chunked(&mut self, buf: &[u8]) -> ParserOutput {
        let State::Chunked(ref mut cs) = self.state else {
            return ParserOutput::Need;
        };
        match cs {
            ChunkState::Size => {
                let Some(line_end) = find_crlf(buf) else { return ParserOutput::Need };
                let line = &buf[..line_end];
                // Strip any chunk extensions after ';'.
                let size_part =
                    line.iter().position(|&b| b == b';').map_or(line, |i| &line[..i]);
                let Ok(size_str) = std::str::from_utf8(size_part) else {
                    self.state = State::Bypass;
                    return ParserOutput::Skip(buf.len());
                };
                let Ok(size) = usize::from_str_radix(size_str.trim(), 16) else {
                    self.state = State::Bypass;
                    return ParserOutput::Skip(buf.len());
                };
                let consumed = line_end + 2;
                if size == 0 {
                    self.state = State::Chunked(ChunkState::Trailer);
                    ParserOutput::Skip(consumed)
                } else {
                    self.state = State::Chunked(ChunkState::Data(size));
                    ParserOutput::Skip(consumed)
                }
            }
            ChunkState::Data(left) => {
                let left_val = *left;
                if buf.len() < left_val + 2 {
                    return ParserOutput::Need;
                }
                if let Some(cur) = self.current.as_mut() {
                    let room = 4096usize.saturating_sub(cur.body.len());
                    let n = room.min(left_val);
                    cur.body.extend_from_slice(&buf[..n]);
                }
                self.state = State::Chunked(ChunkState::AfterData);
                ParserOutput::Skip(left_val + 2)
            }
            ChunkState::AfterData => {
                // After AfterData, loop to Size.
                self.state = State::Chunked(ChunkState::Size);
                ParserOutput::Need
            }
            ChunkState::Trailer => {
                // Skip optional trailer headers terminated by CRLFCRLF.
                let Some(end) = find_double_crlf(buf) else {
                    return ParserOutput::Need;
                };
                self.state = State::Headers;
                let rec = self.emit(true);
                ParserOutput::Record { record: rec, consumed: end + 4 }
            }
        }
    }

    fn emit(&mut self, body_complete: bool) -> ParsedRecord {
        self.state = State::Headers;
        self.remaining_body = 0;
        self.chunked = false;
        let info =
            self.current.take().expect("emit called without current record");
        let total_body_bytes = info.body.len() as u64;
        ParsedRecord {
            kind: info.kind,
            method: info.method,
            path: info.path,
            status: info.status,
            reason: info.reason,
            headers: info.headers,
            body: info.body,
            body_complete,
            total_body_bytes,
        }
    }
}

fn collect_headers(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(headers.len());
    let mut seen: HashMap<String, usize> = HashMap::with_capacity(headers.len());
    for h in headers {
        if h.name.is_empty() {
            continue;
        }
        let name = h.name.to_string();
        let value = String::from_utf8_lossy(h.value).into_owned();
        if let Some(&idx) = seen.get(&name.to_ascii_lowercase()) {
            let (_, v): &mut (String, String) = &mut out[idx];
            v.push_str(", ");
            v.push_str(&value);
        } else {
            seen.insert(name.to_ascii_lowercase(), out.len());
            out.push((name, value));
        }
    }
    out
}

fn starts_with_method_letter(buf: &[u8]) -> bool {
    buf.first().is_some_and(|b| b.is_ascii_uppercase() && buf[0] != b'H' || {
        // Allow HTTP/0.9-style 'H' only when followed by method letters, not 'T' (would be response).
        // Practically: accept any uppercase letter; response check (starts "HTTP/") has priority at caller.
        b.is_ascii_uppercase()
    })
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_get_no_body() {
        let mut p = Http1Parser::default();
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = p.parse(req, Direction::Tx);
        match out {
            ParserOutput::Record { record, consumed } => {
                assert_eq!(record.kind, RecordKind::Request);
                assert_eq!(record.method.as_deref(), Some("GET"));
                assert_eq!(record.path.as_deref(), Some("/"));
                assert!(record.body.is_empty());
                assert_eq!(consumed, req.len());
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn response_with_content_length() {
        let mut p = Http1Parser::default();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let out1 = p.parse(resp, Direction::Rx);
        let consumed_headers = match out1 {
            ParserOutput::Skip(n) => n,
            _ => panic!("expected Skip for headers"),
        };
        let out2 = p.parse(&resp[consumed_headers..], Direction::Rx);
        match out2 {
            ParserOutput::Record { record, consumed } => {
                assert_eq!(record.status, Some(200));
                assert_eq!(record.body, b"hello");
                assert_eq!(consumed, 5);
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn chunked_response() {
        let mut p = Http1Parser::default();
        let resp =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut offset = 0;
        let mut got = None;
        for _ in 0..20 {
            match p.parse(&resp[offset..], Direction::Rx) {
                ParserOutput::Record { record, consumed } => {
                    offset += consumed;
                    got = Some(record);
                    break;
                }
                ParserOutput::Skip(n) => offset += n,
                ParserOutput::Need => panic!("unexpected Need"),
            }
        }
        let r = got.expect("record");
        assert_eq!(r.status, Some(200));
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn rejects_non_http() {
        let mut p = Http1Parser::default();
        let noise = b"\x16\x03\x01\x00\x50"; // TLS record start
        match p.parse(noise, Direction::Tx) {
            ParserOutput::Skip(_) => {}
            _ => panic!("expected Skip"),
        }
    }
}
