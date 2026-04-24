//! Flow reconstruction and per-connection parser state.
//!
//! One event on the wire rarely corresponds to one L7 message. A single
//! HTTP response might arrive over several `tcp_recvmsg` calls; a single
//! `tcp_sendmsg` might carry two small requests (pipelining). We keep a
//! bounded byte buffer per `(connection, direction)` and feed it to a
//! protocol parser that emits zero or more complete records and reports
//! how many bytes it consumed.
//!
//! Connection identity comes from whichever layer we're observing:
//! - TCP events: `(pid, sock_id)`
//! - TLS events: `(pid, conn_id)` where `conn_id` is an SSL* pointer
//!
//! The two spaces are kept distinct — a TLS-protected HTTP request arrives
//! as both a TLS event (plaintext) and TCP events (ciphertext); we parse
//! the TLS stream and ignore the TCP ciphertext at the parser level.

use std::collections::HashMap;

use crate::events::Direction;
use crate::parsers::{Http1Parser, ParsedRecord, ParserOutput};

/// Upper bound on bytes buffered per `(flow, direction)`. A modest cap
/// prevents a slow / silent consumer from letting memory grow unboundedly
/// when bytes arrive faster than parsers complete. On overflow we drop
/// the oldest bytes — the parser will resync on the next record boundary.
const BUF_CAP: usize = 64 * 1024;

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub enum FlowKey {
    Tcp { pid: u32, sock_id: u64 },
    Tls { pid: u32, conn_id: u64 },
}

#[derive(Default)]
struct HalfFlow {
    buf: Vec<u8>,
    /// Number of bytes we've seen on this half-flow across all events.
    seen: u64,
}

impl HalfFlow {
    fn push(&mut self, bytes: &[u8]) {
        if self.buf.len() + bytes.len() > BUF_CAP {
            // Drop oldest from the front so the latest message is intact.
            // Cheap in practice because BUF_CAP is small and we do this
            // rarely (only on sustained backlog).
            let drop = (self.buf.len() + bytes.len()) - BUF_CAP;
            self.buf.drain(..drop.min(self.buf.len()));
        }
        self.buf.extend_from_slice(bytes);
        self.seen += bytes.len() as u64;
    }

    fn consume(&mut self, n: usize) {
        self.buf.drain(..n.min(self.buf.len()));
    }
}

/// Per-connection parser state. Each flow owns one parser per direction;
/// the parser decides which protocol applies based on the first few bytes.
#[derive(Default)]
struct FlowState {
    tx: HalfFlow,
    rx: HalfFlow,
    parser_tx: Http1Parser,
    parser_rx: Http1Parser,
}

#[derive(Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowTable {
    /// Feed bytes for a flow/direction, returning any complete records
    /// the parser produced.
    pub fn feed(&mut self, key: FlowKey, dir: Direction, bytes: &[u8]) -> Vec<ParsedRecord> {
        let state = self.flows.entry(key).or_default();
        let (half, parser) = match dir {
            Direction::Tx => (&mut state.tx, &mut state.parser_tx),
            Direction::Rx => (&mut state.rx, &mut state.parser_rx),
        };
        half.push(bytes);

        let mut out = Vec::new();
        loop {
            match parser.parse(&half.buf, dir) {
                ParserOutput::Need => break,
                ParserOutput::Record { record, consumed } => {
                    half.consume(consumed);
                    out.push(record);
                }
                ParserOutput::Skip(n) => {
                    half.consume(n);
                }
            }
        }
        out
    }

    /// Drop a flow's buffers — called on ConnEnd so we don't leak state.
    pub fn forget(&mut self, key: &FlowKey) {
        self.flows.remove(key);
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }
}
