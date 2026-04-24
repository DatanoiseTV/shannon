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

pub mod bacnet;
pub mod cassandra;
pub mod dnp3;
pub mod dns;
pub mod enip;
pub mod http1;
pub mod http2;
pub mod iec104;
pub mod imap;
pub mod kafka;
pub mod ldap;
pub mod memcached;
pub mod modbus;
pub mod mongodb;
pub mod mqtt;
pub mod mysql;
pub mod nats;
pub mod opcua;
pub mod pop3;
pub mod postgres;
pub mod redis;
pub mod s7comm;
pub mod smtp;
pub mod ssdp;
pub mod ssh;
pub mod websocket;

// No re-exports from here — each parser's symbols are accessed via its
// own module path so the intended types are unambiguous at call sites.
