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

pub mod amqp;
pub mod bacnet;
pub mod cassandra;
pub mod dhcp;
pub mod dnp3;
pub mod dns;
pub mod enip;
pub mod ftp;
pub mod http1;
pub mod http2;
pub mod iec104;
pub mod imap;
pub mod kafka;
pub mod kerberos;
pub mod ldap;
pub mod memcached;
pub mod modbus;
pub mod mongodb;
pub mod mssql;
pub mod mqtt;
pub mod mysql;
pub mod nats;
pub mod ntp;
pub mod opcua;
pub mod oracle;
pub mod pop3;
pub mod postgres;
pub mod radius;
pub mod rdp;
pub mod redis;
pub mod s7comm;
pub mod sip;
pub mod smtp;
pub mod socks;
pub mod ssdp;
pub mod ssh;
pub mod stun;
pub mod syslog;
pub mod tacacs;
pub mod telnet;
pub mod tftp;
pub mod tls;
pub mod websocket;

// No re-exports from here — each parser's symbols are accessed via its
// own module path so the intended types are unambiguous at call sites.
