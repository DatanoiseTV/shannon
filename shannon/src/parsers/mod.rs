//! L7 protocol parsers.
//!
//! Each parser is a stateful byte-stream decoder for one direction of one
//! connection. It's fed a slice of buffered bytes and returns one of:
//!
//!   - `*ParserOutput::Need` — not enough bytes yet; call again after
//!     more arrive.
//!   - `*ParserOutput::Record` — a complete L7 record is available; the
//!     parser also reports how many bytes it consumed so [`crate::flow`]
//!     can drop them from the buffer.
//!   - `*ParserOutput::Skip(n)` — the bytes looked invalid / unrecognised;
//!     drop `n` and try to resync on the next record boundary.
//!
//! Each parser has its own `*ParserOutput` and `*Record` types so their
//! surfaces can carry protocol-specific fields.

pub mod cassandra;
pub mod http1;
pub mod http2;
pub mod kafka;
pub mod mongodb;
pub mod mysql;
pub mod postgres;
pub mod redis;

// HTTP/1 is used by `flow.rs` as the default parser for plaintext HTTP
// streams. Other parsers are exposed through their own module paths and
// will be wired into the flow dispatcher in a follow-up change.
pub use http1::{Http1Parser, ParsedRecord, ParserOutput};
