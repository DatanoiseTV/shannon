//! L7 protocol parsers.
//!
//! Each parser is a stateful byte-stream decoder for one direction of one
//! connection. It's fed a slice of buffered bytes and returns one of:
//!
//!   - [`ParserOutput::Need`] — not enough bytes yet; call again after
//!     more arrive.
//!   - [`ParserOutput::Record`] — a complete L7 record is available; the
//!     parser also reports how many bytes it consumed so [`crate::flow`]
//!     can drop them from the buffer.
//!   - [`ParserOutput::Skip`] — the bytes looked invalid / unrecognised;
//!     drop `n` and try to resync on the next record boundary.

pub mod http1;

pub use http1::{Http1Parser, ParsedRecord, ParserOutput};
