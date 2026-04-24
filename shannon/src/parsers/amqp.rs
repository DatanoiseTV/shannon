//! AMQP 0.9.1 (RabbitMQ) — tcp/5672, tls/5671.
//!
//! Connections open with the protocol header `b"AMQP\x00\x00\x09\x01"`
//! and then trade framed messages:
//!
//! ```text
//!   u8  type            1=METHOD 2=HEADER 3=BODY 4=HEARTBEAT
//!   u16 channel   (BE)
//!   u32 payload_size (BE)
//!   payload[payload_size]
//!   u8  0xCE end-of-frame
//! ```
//!
//! The METHOD payload starts with `u16 class_id, u16 method_id` and
//! then class-specific argument bytes. We name the common classes
//! (connection, channel, exchange, queue, basic, confirm, tx) and
//! their methods, and surface the exchange / queue / routing-key
//! strings for the ones where they're the first short-string
//! argument (basic.publish, exchange.declare, queue.declare,
//! queue.bind). That's enough to paint a clear picture of what a
//! producer is publishing where and what a consumer is subscribed to.

use crate::events::Direction;

const EOF_MARKER: u8 = 0xCE;

pub struct AmqpParser {
    bypass: bool,
    greeting_checked: bool,
}

impl Default for AmqpParser {
    fn default() -> Self {
        Self {
            bypass: false,
            greeting_checked: false,
        }
    }
}

pub enum AmqpParserOutput {
    Need,
    Record { record: AmqpRecord, consumed: usize },
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct AmqpRecord {
    pub direction: Direction,
    pub kind: AmqpKind,
}

#[derive(Debug, Clone)]
pub enum AmqpKind {
    ProtocolHeader {
        major: u8,
        minor: u8,
        revision: u8,
    },
    Method {
        channel: u16,
        class: u16,
        method: u16,
        class_name: &'static str,
        method_name: &'static str,
        exchange: Option<String>,
        routing_key: Option<String>,
        queue: Option<String>,
    },
    Header {
        channel: u16,
        class: u16,
        body_size: u64,
    },
    Body {
        channel: u16,
        bytes: u32,
    },
    Heartbeat,
}

impl AmqpRecord {
    pub fn display_line(&self) -> String {
        match &self.kind {
            AmqpKind::ProtocolHeader {
                major,
                minor,
                revision,
            } => {
                format!("amqp banner {major}.{minor}.{revision}")
            }
            AmqpKind::Method {
                channel,
                class_name,
                method_name,
                exchange,
                routing_key,
                queue,
                ..
            } => {
                let mut extra = String::new();
                if let Some(e) = exchange {
                    extra.push_str(&format!(" ex={e}"));
                }
                if let Some(rk) = routing_key {
                    extra.push_str(&format!(" rk={rk}"));
                }
                if let Some(q) = queue {
                    extra.push_str(&format!(" q={q}"));
                }
                format!("amqp ch={channel} {class_name}.{method_name}{extra}")
            }
            AmqpKind::Header {
                channel,
                class,
                body_size,
            } => {
                format!("amqp ch={channel} HEADER class={class} body={body_size}B")
            }
            AmqpKind::Body { channel, bytes } => {
                format!("amqp ch={channel} BODY {bytes}B")
            }
            AmqpKind::Heartbeat => "amqp HEARTBEAT".to_string(),
        }
    }
}

impl AmqpParser {
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> AmqpParserOutput {
        if self.bypass {
            return AmqpParserOutput::Skip(buf.len());
        }
        if !self.greeting_checked {
            if buf.len() < 8 {
                return AmqpParserOutput::Need;
            }
            if &buf[..4] == b"AMQP" {
                self.greeting_checked = true;
                return AmqpParserOutput::Record {
                    record: AmqpRecord {
                        direction: dir,
                        kind: AmqpKind::ProtocolHeader {
                            major: buf[5],
                            minor: buf[6],
                            revision: buf[7],
                        },
                    },
                    consumed: 8,
                };
            }
            // Not a client greeting — probably a server-initiated
            // message on an established connection; proceed to frame
            // decoding.
            self.greeting_checked = true;
        }
        if buf.len() < 7 {
            return AmqpParserOutput::Need;
        }
        let ftype = buf[0];
        let channel = u16::from_be_bytes([buf[1], buf[2]]);
        let size = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]) as usize;
        let total = 7 + size + 1;
        if size > 1 << 22 {
            self.bypass = true;
            return AmqpParserOutput::Skip(buf.len());
        }
        if buf.len() < total {
            return AmqpParserOutput::Need;
        }
        if buf[total - 1] != EOF_MARKER {
            self.bypass = true;
            return AmqpParserOutput::Skip(buf.len());
        }
        let payload = &buf[7..total - 1];
        let kind = match ftype {
            1 => decode_method(channel, payload),
            2 => decode_header(channel, payload),
            3 => AmqpKind::Body {
                channel,
                bytes: size as u32,
            },
            4 => AmqpKind::Heartbeat,
            _ => {
                self.bypass = true;
                return AmqpParserOutput::Skip(buf.len());
            }
        };
        AmqpParserOutput::Record {
            record: AmqpRecord {
                direction: dir,
                kind,
            },
            consumed: total,
        }
    }
}

fn decode_method(channel: u16, payload: &[u8]) -> AmqpKind {
    if payload.len() < 4 {
        return AmqpKind::Method {
            channel,
            class: 0,
            method: 0,
            class_name: "?",
            method_name: "?",
            exchange: None,
            routing_key: None,
            queue: None,
        };
    }
    let class = u16::from_be_bytes([payload[0], payload[1]]);
    let method = u16::from_be_bytes([payload[2], payload[3]]);
    let body = &payload[4..];
    let (exchange, routing_key, queue) = decode_method_args(class, method, body);
    AmqpKind::Method {
        channel,
        class,
        method,
        class_name: class_name(class),
        method_name: method_name(class, method),
        exchange,
        routing_key,
        queue,
    }
}

fn decode_header(channel: u16, payload: &[u8]) -> AmqpKind {
    let class = if payload.len() >= 2 {
        u16::from_be_bytes([payload[0], payload[1]])
    } else {
        0
    };
    // weight u16 (payload[2..4]), body-size u64 (payload[4..12])
    let body_size = if payload.len() >= 12 {
        u64::from_be_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
            payload[11],
        ])
    } else {
        0
    };
    AmqpKind::Header {
        channel,
        class,
        body_size,
    }
}

fn decode_method_args(
    class: u16,
    method: u16,
    body: &[u8],
) -> (Option<String>, Option<String>, Option<String>) {
    match (class, method) {
        // basic.publish: reserved-1 u16, exchange shortstr, routing-key shortstr, bits
        (60, 40) => {
            let mut p = 2usize; // skip reserved
            let (ex, p2) = read_shortstr(body, p);
            p = p2;
            let (rk, _) = read_shortstr(body, p);
            (ex, rk, None)
        }
        // basic.consume: reserved-1 u16, queue shortstr, consumer-tag shortstr, bits
        (60, 20) => {
            let mut p = 2usize;
            let (q, _p2) = read_shortstr(body, p);
            let _ = &mut p; // avoid unused
            (None, None, q)
        }
        // basic.deliver: consumer-tag shortstr, delivery-tag u64, redelivered bit,
        //                exchange shortstr, routing-key shortstr
        (60, 60) => {
            let (_ct, p) = read_shortstr(body, 0);
            let p = p + 8 + 1; // delivery-tag + redelivered byte
            let (ex, p2) = read_shortstr(body, p);
            let (rk, _) = read_shortstr(body, p2);
            (ex, rk, None)
        }
        // exchange.declare: reserved u16, exchange shortstr, type shortstr, bits, table
        (40, 10) => {
            let (ex, _) = read_shortstr(body, 2);
            (ex, None, None)
        }
        // queue.declare: reserved u16, queue shortstr, bits, table
        (50, 10) => {
            let (q, _) = read_shortstr(body, 2);
            (None, None, q)
        }
        // queue.bind: reserved u16, queue shortstr, exchange shortstr, routing-key shortstr
        (50, 20) => {
            let (q, p) = read_shortstr(body, 2);
            let (ex, p2) = read_shortstr(body, p);
            let (rk, _) = read_shortstr(body, p2);
            (ex, rk, q)
        }
        _ => (None, None, None),
    }
}

fn read_shortstr(buf: &[u8], off: usize) -> (Option<String>, usize) {
    if buf.len() < off + 1 {
        return (None, off);
    }
    let n = buf[off] as usize;
    let start = off + 1;
    if buf.len() < start + n {
        return (None, off);
    }
    let s = std::str::from_utf8(&buf[start..start + n])
        .ok()
        .map(|s| s.to_string());
    (s, start + n)
}

const fn class_name(c: u16) -> &'static str {
    match c {
        10 => "connection",
        20 => "channel",
        30 => "access",
        40 => "exchange",
        50 => "queue",
        60 => "basic",
        85 => "confirm",
        90 => "tx",
        _ => "?",
    }
}

const fn method_name(class: u16, method: u16) -> &'static str {
    match (class, method) {
        (10, 10) => "start",
        (10, 11) => "start-ok",
        (10, 20) => "secure",
        (10, 21) => "secure-ok",
        (10, 30) => "tune",
        (10, 31) => "tune-ok",
        (10, 40) => "open",
        (10, 41) => "open-ok",
        (10, 50) => "close",
        (10, 51) => "close-ok",
        (20, 10) => "open",
        (20, 11) => "open-ok",
        (20, 40) => "close",
        (20, 41) => "close-ok",
        (40, 10) => "declare",
        (40, 11) => "declare-ok",
        (40, 20) => "delete",
        (40, 21) => "delete-ok",
        (50, 10) => "declare",
        (50, 11) => "declare-ok",
        (50, 20) => "bind",
        (50, 21) => "bind-ok",
        (50, 30) => "purge",
        (50, 31) => "purge-ok",
        (50, 40) => "delete",
        (50, 41) => "delete-ok",
        (50, 50) => "unbind",
        (50, 51) => "unbind-ok",
        (60, 10) => "qos",
        (60, 11) => "qos-ok",
        (60, 20) => "consume",
        (60, 21) => "consume-ok",
        (60, 30) => "cancel",
        (60, 31) => "cancel-ok",
        (60, 40) => "publish",
        (60, 50) => "return",
        (60, 60) => "deliver",
        (60, 70) => "get",
        (60, 71) => "get-ok",
        (60, 72) => "get-empty",
        (60, 80) => "ack",
        (60, 90) => "reject",
        (60, 100) => "recover-async",
        (60, 110) => "recover",
        (60, 111) => "recover-ok",
        (60, 120) => "nack",
        (85, 10) => "select",
        (85, 11) => "select-ok",
        (90, 10) => "select",
        (90, 11) => "select-ok",
        (90, 20) => "commit",
        (90, 21) => "commit-ok",
        (90, 30) => "rollback",
        (90, 31) => "rollback-ok",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_header() {
        let mut p = AmqpParser::default();
        match p.parse(b"AMQP\x00\x00\x09\x01", Direction::Tx) {
            AmqpParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 8);
                match record.kind {
                    AmqpKind::ProtocolHeader {
                        major,
                        minor,
                        revision,
                    } => {
                        assert_eq!((major, minor, revision), (0, 9, 1));
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn basic_publish_with_exchange_and_routing_key() {
        // type=1 METHOD, chan=1, size=computed
        let mut payload = Vec::new();
        payload.extend_from_slice(&60u16.to_be_bytes()); // class basic
        payload.extend_from_slice(&40u16.to_be_bytes()); // method publish
        payload.extend_from_slice(&0u16.to_be_bytes()); // reserved
        payload.push(5);
        payload.extend_from_slice(b"logs1"); // exchange
        payload.push(7);
        payload.extend_from_slice(b"info.ok"); // routing-key
        payload.push(0); // bits

        let mut frame = Vec::new();
        frame.push(1);
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame.push(0xCE);

        // Include a greeting to pass through greeting_checked.
        let mut all = Vec::new();
        all.extend_from_slice(b"AMQP\x00\x00\x09\x01");
        all.extend_from_slice(&frame);

        let mut p = AmqpParser::default();
        // Consume greeting.
        let hdr_consumed = match p.parse(&all, Direction::Tx) {
            AmqpParserOutput::Record { consumed, .. } => consumed,
            _ => panic!(),
        };
        match p.parse(&all[hdr_consumed..], Direction::Tx) {
            AmqpParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, frame.len());
                match record.kind {
                    AmqpKind::Method {
                        class_name,
                        method_name,
                        exchange,
                        routing_key,
                        ..
                    } => {
                        assert_eq!(class_name, "basic");
                        assert_eq!(method_name, "publish");
                        assert_eq!(exchange.as_deref(), Some("logs1"));
                        assert_eq!(routing_key.as_deref(), Some("info.ok"));
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_amqp_bypasses() {
        let mut p = AmqpParser::default();
        // 8 bytes not starting with "AMQP" — parser proceeds to frame
        // decoding, sees type=71 ('G'), which is unknown → bypass.
        assert!(matches!(
            p.parse(b"GET / HTTP/1.1\r\n\r\n", Direction::Tx),
            AmqpParserOutput::Skip(_)
        ));
    }
}
