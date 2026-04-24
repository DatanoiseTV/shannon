//! MQTT 3.1.1 (ISO/IEC 20922) and MQTT v5 parser.
//!
//! Decodes the wire format defined by:
//!
//! - OASIS MQTT 3.1.1: <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>
//! - OASIS MQTT v5:    <https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html>
//!
//! One parser instance decodes one direction of one connection. The parser
//! remembers the negotiated protocol version (from the initial CONNECT
//! packet, which is always client-to-server) so that subsequent
//! CONNACK / PUBLISH / DISCONNECT packets can be decoded correctly — v5
//! adds a properties block to most packet types that 3.1.1 doesn't have.
//!
//! # Wire format recap
//!
//! Every MQTT packet starts with a fixed header:
//!
//! ```text
//!  byte 0  : [ packet type : 4 | flags : 4 ]
//!  bytes 1+: remaining length (variable-byte integer, 1..=4 bytes)
//! ```
//!
//! Strings are length-prefixed (2-byte big-endian length + UTF-8 bytes).
//! v5 adds a "properties" block before the payload of most packets; it
//! itself is prefixed with a variable-byte integer length so we can skip
//! it without decoding individual property identifiers.
//!
//! # Secrets handling
//!
//! MQTT CONNECT carries a password field in the payload. We set
//! [`MqttRecord::has_password`] to `true` when present, but never copy the
//! password bytes into the record — not even a preview. Usernames *are*
//! captured; they're commonly used for routing and auditing.
//!
//! PUBLISH payloads are captured up to [`MAX_PAYLOAD_PREVIEW`] bytes.
//! Callers that want stricter handling (e.g. redact based on topic) can
//! filter downstream — the parser itself is not topic-aware.

use crate::events::Direction;

/// Maximum remaining-length value permitted by the spec (2^28 - 1).
const MAX_REMAINING_LENGTH: u32 = 268_435_455;
/// Cap on captured PUBLISH payload bytes.
const MAX_PAYLOAD_PREVIEW: usize = 256;
/// Cap on captured topic / topic-filter length (chars after UTF-8 decode).
const MAX_TOPIC_CHARS: usize = 1024;
/// Cap on captured client-id length.
const MAX_CLIENT_ID_CHARS: usize = 128;
/// Cap on captured username length.
const MAX_USERNAME_CHARS: usize = 128;
/// Cap on how many topic filters we'll record per SUBSCRIBE packet.
const MAX_SUBSCRIPTIONS: usize = 64;

/// Parser state. One instance per (connection, direction).
#[derive(Debug, Default)]
pub struct MqttParser {
    /// Negotiated protocol level, populated on the first CONNECT we see
    /// on this flow. Defaults to 0 ("unknown") until then — subsequent
    /// packets in the same direction (and the one going the other way,
    /// if the caller shares state via two parsers) read this to pick
    /// between 3.1.1 and v5 framing for CONNACK / DISCONNECT / etc.
    version: u8,
    /// Once we've irrecoverably lost sync, drop everything.
    bypass: bool,
}

/// Result of one parse step. Mirrors [`crate::parsers::http1::ParserOutput`].
#[derive(Debug)]
pub enum MqttParserOutput {
    Need,
    Record { record: MqttRecord, consumed: usize },
    Skip(usize),
}

/// One decoded MQTT control packet. Fields are populated only when
/// meaningful for the packet type (see each field's doc comment).
#[derive(Debug, Clone)]
pub struct MqttRecord {
    /// Protocol version known at the time this packet was decoded. `4`
    /// for MQTT 3.1.1, `5` for MQTT v5, `0` before we've seen CONNECT.
    pub version: u8,
    pub direction: Direction,
    pub packet_type: MqttPacketType,
    /// Packet identifier, populated for PUBLISH (`QoS` > 0), PUBACK,
    /// PUBREC, PUBREL, PUBCOMP, SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK.
    pub packet_id: Option<u16>,
    /// CONNECT — the client identifier.
    pub client_id: Option<String>,
    /// CONNECT — user name, when the user-name flag is set.
    pub username: Option<String>,
    /// CONNECT — set `true` when the password flag is set. We never
    /// capture the bytes.
    pub has_password: bool,
    /// PUBLISH / SUBSCRIBE / UNSUBSCRIBE — primary topic / filter.
    /// (SUBSCRIBE/UNSUBSCRIBE can carry more than one, but we also
    /// populate the full list in [`Self::subscriptions`].)
    pub topic: Option<String>,
    /// PUBLISH — quality-of-service level extracted from fixed-header
    /// flags (0..=2).
    pub qos: Option<u8>,
    /// PUBLISH retain flag.
    pub retain: bool,
    /// PUBLISH duplicate-delivery flag.
    pub dup: bool,
    /// PUBLISH — first [`MAX_PAYLOAD_PREVIEW`] bytes of the application
    /// message.
    pub payload_preview: Option<Vec<u8>>,
    /// v5 reason code on CONNACK / PUBACK / PUBREC / PUBREL / PUBCOMP /
    /// DISCONNECT / AUTH. For CONNACK 3.1.1 this is the "return code"
    /// byte, which lives in the same wire position.
    pub reason_code: Option<u8>,
    /// CONNACK — session-present flag (bit 0 of the connect-ack flags
    /// byte).
    pub session_present: Option<bool>,
    /// SUBSCRIBE — list of `(topic filter, options byte)`. The options
    /// byte is the `QoS` in MQTT 3.1.1 and a bit-packed set of flags in
    /// v5; we return it verbatim.
    pub subscriptions: Vec<(String, u8)>,
}

/// MQTT control packet type, matched on the high nibble of byte 0 of the
/// fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttPacketType {
    Connect,
    Connack,
    Publish,
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    Pingreq,
    Pingresp,
    Disconnect,
    /// MQTT v5 only. Not valid in 3.1.1.
    Auth,
    /// Value `0` is reserved and never legal; we also surface unknown
    /// values (there are none in the spec today, the nibble is 4 bits
    /// and all 16 values are defined, but we keep this for forward
    /// compatibility).
    Reserved(u8),
}

impl MqttPacketType {
    const fn from_nibble(n: u8) -> Self {
        match n {
            1 => Self::Connect,
            2 => Self::Connack,
            3 => Self::Publish,
            4 => Self::Puback,
            5 => Self::Pubrec,
            6 => Self::Pubrel,
            7 => Self::Pubcomp,
            8 => Self::Subscribe,
            9 => Self::Suback,
            10 => Self::Unsubscribe,
            11 => Self::Unsuback,
            12 => Self::Pingreq,
            13 => Self::Pingresp,
            14 => Self::Disconnect,
            15 => Self::Auth,
            other => Self::Reserved(other),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Connack => "CONNACK",
            Self::Publish => "PUBLISH",
            Self::Puback => "PUBACK",
            Self::Pubrec => "PUBREC",
            Self::Pubrel => "PUBREL",
            Self::Pubcomp => "PUBCOMP",
            Self::Subscribe => "SUBSCRIBE",
            Self::Suback => "SUBACK",
            Self::Unsubscribe => "UNSUBSCRIBE",
            Self::Unsuback => "UNSUBACK",
            Self::Pingreq => "PINGREQ",
            Self::Pingresp => "PINGRESP",
            Self::Disconnect => "DISCONNECT",
            Self::Auth => "AUTH",
            Self::Reserved(_) => "RESERVED",
        }
    }
}

impl MqttRecord {
    /// Human-readable one-liner suitable for log output. Deliberately
    /// conservative — does not include the payload preview or username,
    /// since those may be noisy or privacy-sensitive.
    pub fn display_line(&self) -> String {
        let dir = match self.direction {
            Direction::Tx => "->",
            Direction::Rx => "<-",
        };
        let name = self.packet_type.as_str();
        match self.packet_type {
            MqttPacketType::Connect => {
                let cid = self.client_id.as_deref().unwrap_or("");
                let user = if self.username.is_some() {
                    " user=yes"
                } else {
                    ""
                };
                let pw = if self.has_password { " pw=yes" } else { "" };
                format!("{dir} {name} v{} client_id={cid}{user}{pw}", self.version)
            }
            MqttPacketType::Connack => {
                let rc = self.reason_code.unwrap_or(0);
                let sp = self.session_present.unwrap_or(false);
                format!("{dir} {name} session_present={sp} rc={rc}")
            }
            MqttPacketType::Publish => {
                let topic = self.topic.as_deref().unwrap_or("");
                let qos = self.qos.unwrap_or(0);
                let retain = if self.retain { " retain" } else { "" };
                let dup = if self.dup { " dup" } else { "" };
                format!("{dir} {name} topic={topic} qos={qos}{retain}{dup}")
            }
            MqttPacketType::Subscribe | MqttPacketType::Unsubscribe => {
                let pid = self.packet_id.unwrap_or(0);
                let filters: Vec<String> = self
                    .subscriptions
                    .iter()
                    .map(|(t, o)| format!("{t}@{o}"))
                    .collect();
                format!("{dir} {name} id={pid} filters=[{}]", filters.join(","))
            }
            MqttPacketType::Puback
            | MqttPacketType::Pubrec
            | MqttPacketType::Pubrel
            | MqttPacketType::Pubcomp
            | MqttPacketType::Suback
            | MqttPacketType::Unsuback => {
                let pid = self.packet_id.unwrap_or(0);
                let rc = self.reason_code.unwrap_or(0);
                format!("{dir} {name} id={pid} rc={rc}")
            }
            MqttPacketType::Disconnect | MqttPacketType::Auth => {
                let rc = self.reason_code.unwrap_or(0);
                format!("{dir} {name} rc={rc}")
            }
            MqttPacketType::Pingreq | MqttPacketType::Pingresp => {
                format!("{dir} {name}")
            }
            MqttPacketType::Reserved(v) => format!("{dir} RESERVED({v})"),
        }
    }
}

impl MqttParser {
    /// Try to decode one packet from the front of `buf`. The caller feeds
    /// an ever-growing byte stream and slides the window forward by
    /// `consumed` (for `Record`) or `n` (for `Skip`).
    pub fn parse(&mut self, buf: &[u8], dir: Direction) -> MqttParserOutput {
        if self.bypass {
            return MqttParserOutput::Skip(buf.len());
        }
        if buf.is_empty() {
            return MqttParserOutput::Need;
        }
        let first = buf[0];
        let pkt_nibble = first >> 4;
        let flags = first & 0x0F;
        // Packet type 0 is reserved / illegal on the wire.
        if pkt_nibble == 0 {
            self.bypass = true;
            return MqttParserOutput::Skip(buf.len());
        }
        // Decode remaining-length var-int.
        let (remaining_len, vi_len) = match decode_varint_ex(&buf[1..]) {
            VarintResult::Ok(v, n) => (v, n),
            VarintResult::Need => return MqttParserOutput::Need,
            VarintResult::Malformed => {
                self.bypass = true;
                return MqttParserOutput::Skip(buf.len());
            }
        };
        if remaining_len > MAX_REMAINING_LENGTH {
            self.bypass = true;
            return MqttParserOutput::Skip(buf.len());
        }
        let header_len = 1 + vi_len;
        let total_len = header_len + remaining_len as usize;
        if buf.len() < total_len {
            return MqttParserOutput::Need;
        }
        let packet_type = MqttPacketType::from_nibble(pkt_nibble);
        // Fixed-header flag sanity checks per spec §2.1.3. Most packets
        // require specific flag bytes; PUBLISH is the only one with
        // meaningful per-message flags.
        if !flags_valid(packet_type, flags) {
            self.bypass = true;
            return MqttParserOutput::Skip(buf.len());
        }
        let body = &buf[header_len..total_len];
        let record = match packet_type {
            MqttPacketType::Connect => self.decode_connect(body, dir, packet_type),
            MqttPacketType::Connack => self.decode_connack(body, dir, packet_type),
            MqttPacketType::Publish => self.decode_publish(body, dir, packet_type, flags),
            MqttPacketType::Puback
            | MqttPacketType::Pubrec
            | MqttPacketType::Pubrel
            | MqttPacketType::Pubcomp => self.decode_pubx(body, dir, packet_type),
            MqttPacketType::Subscribe => self.decode_subscribe(body, dir, packet_type),
            MqttPacketType::Unsubscribe => self.decode_unsubscribe(body, dir, packet_type),
            MqttPacketType::Suback => self.decode_suback(body, dir, packet_type),
            MqttPacketType::Unsuback => self.decode_unsuback(body, dir, packet_type),
            MqttPacketType::Pingreq | MqttPacketType::Pingresp => {
                // No body expected; ignore any stray bytes.
                Some(self.empty_record(dir, packet_type))
            }
            MqttPacketType::Disconnect => self.decode_disconnect(body, dir, packet_type),
            MqttPacketType::Auth => self.decode_auth(body, dir, packet_type),
            MqttPacketType::Reserved(_) => None,
        };
        // Malformed body but fixed header parsed fine — skip just this
        // packet and try to resync on the next one rather than bypassing
        // the whole flow.
        record.map_or(MqttParserOutput::Skip(total_len), |r| {
            MqttParserOutput::Record {
                record: r,
                consumed: total_len,
            }
        })
    }

    const fn empty_record(&self, dir: Direction, packet_type: MqttPacketType) -> MqttRecord {
        MqttRecord {
            version: self.version,
            direction: dir,
            packet_type,
            packet_id: None,
            client_id: None,
            username: None,
            has_password: false,
            topic: None,
            qos: None,
            retain: false,
            dup: false,
            payload_preview: None,
            reason_code: None,
            session_present: None,
            subscriptions: Vec::new(),
        }
    }

    fn decode_connect(
        &mut self,
        body: &[u8],
        dir: Direction,
        pt: MqttPacketType,
    ) -> Option<MqttRecord> {
        let mut c = Cursor::new(body);
        let proto_name = c.read_string()?;
        // 3.1.1 and v5 use "MQTT"; legacy 3.1 used "MQIsdp". Any other
        // value is malformed.
        if proto_name != "MQTT" && proto_name != "MQIsdp" {
            return None;
        }
        let level = c.read_u8()?;
        let flags = c.read_u8()?;
        let _keep_alive = c.read_u16()?;
        // v5 adds a properties block between keep-alive and the payload.
        if level == 5 {
            let prop_len = c.read_varint()?;
            c.skip(prop_len as usize)?;
        }
        // Payload: client id, [will props, will topic, will payload],
        // [user name], [password].
        let client_id = c.read_string()?;
        let will_flag = flags & 0x04 != 0;
        let user_flag = flags & 0x80 != 0;
        let pw_flag = flags & 0x40 != 0;
        if will_flag {
            if level == 5 {
                let wprop_len = c.read_varint()?;
                c.skip(wprop_len as usize)?;
            }
            // Will topic + will payload; we don't surface these.
            let _wtopic = c.read_string()?;
            let wpl_len = c.read_u16()? as usize;
            c.skip(wpl_len)?;
        }
        let username = if user_flag {
            Some(c.read_string()?)
        } else {
            None
        };
        let has_password = if pw_flag {
            // Password is length-prefixed bytes. Consume but discard.
            let pw_len = c.read_u16()? as usize;
            c.skip(pw_len)?;
            true
        } else {
            false
        };

        // Latch the negotiated version so subsequent packets know how to
        // decode themselves. We only accept 4 or 5 here; anything else
        // stays at 0 (unknown) rather than poisoning later packets with
        // garbage framing assumptions.
        if level == 4 || level == 5 {
            self.version = level;
        }

        Some(MqttRecord {
            version: self.version,
            direction: dir,
            packet_type: pt,
            packet_id: None,
            client_id: Some(truncate_chars(client_id, MAX_CLIENT_ID_CHARS)),
            username: username.map(|u| truncate_chars(u, MAX_USERNAME_CHARS)),
            has_password,
            topic: None,
            qos: None,
            retain: false,
            dup: false,
            payload_preview: None,
            reason_code: None,
            session_present: None,
            subscriptions: Vec::new(),
        })
    }

    fn decode_connack(
        &self,
        body: &[u8],
        dir: Direction,
        pt: MqttPacketType,
    ) -> Option<MqttRecord> {
        let mut c = Cursor::new(body);
        let flags = c.read_u8()?;
        let rc = c.read_u8()?;
        // v5 appends properties after the two acknowledgement bytes; we
        // don't need to read them but we validate the length so a short
        // body still fails cleanly.
        if self.version == 5 {
            let prop_len = c.read_varint()?;
            c.skip(prop_len as usize)?;
        }
        Some(MqttRecord {
            session_present: Some(flags & 0x01 != 0),
            reason_code: Some(rc),
            ..self.empty_record(dir, pt)
        })
    }

    fn decode_publish(
        &self,
        body: &[u8],
        dir: Direction,
        pt: MqttPacketType,
        flags: u8,
    ) -> Option<MqttRecord> {
        let dup = flags & 0x08 != 0;
        let qos = (flags >> 1) & 0x03;
        let retain = flags & 0x01 != 0;
        if qos > 2 {
            return None;
        }
        let mut c = Cursor::new(body);
        let topic = c.read_string()?;
        let packet_id = if qos > 0 { Some(c.read_u16()?) } else { None };
        if self.version == 5 {
            let prop_len = c.read_varint()?;
            c.skip(prop_len as usize)?;
        }
        let payload = c.remaining();
        let take = payload.len().min(MAX_PAYLOAD_PREVIEW);
        let payload_preview = if take == 0 {
            None
        } else {
            Some(payload[..take].to_vec())
        };
        Some(MqttRecord {
            packet_id,
            topic: Some(truncate_chars(topic, MAX_TOPIC_CHARS)),
            qos: Some(qos),
            retain,
            dup,
            payload_preview,
            ..self.empty_record(dir, pt)
        })
    }

    fn decode_pubx(&self, body: &[u8], dir: Direction, pt: MqttPacketType) -> Option<MqttRecord> {
        // 3.1.1 PUBACK/PUBREC/PUBREL/PUBCOMP are exactly 2 bytes (packet
        // id). v5 optionally carries a reason code and properties; if the
        // remaining length is 2 the reason code is implicitly 0x00.
        let mut c = Cursor::new(body);
        let pid = c.read_u16()?;
        let rc = if self.version == 5 && !c.is_empty() {
            let code = c.read_u8()?;
            if !c.is_empty() {
                let prop_len = c.read_varint()?;
                c.skip(prop_len as usize)?;
            }
            Some(code)
        } else {
            Some(0)
        };
        Some(MqttRecord {
            packet_id: Some(pid),
            reason_code: rc,
            ..self.empty_record(dir, pt)
        })
    }

    fn decode_subscribe(
        &self,
        body: &[u8],
        dir: Direction,
        pt: MqttPacketType,
    ) -> Option<MqttRecord> {
        let mut c = Cursor::new(body);
        let pid = c.read_u16()?;
        if self.version == 5 {
            let prop_len = c.read_varint()?;
            c.skip(prop_len as usize)?;
        }
        let mut subs: Vec<(String, u8)> = Vec::new();
        while !c.is_empty() {
            let filter = c.read_string()?;
            let opts = c.read_u8()?;
            if subs.len() < MAX_SUBSCRIPTIONS {
                subs.push((truncate_chars(filter, MAX_TOPIC_CHARS), opts));
            }
        }
        if subs.is_empty() {
            return None;
        }
        let first_topic = subs.first().map(|(t, _)| t.clone());
        Some(MqttRecord {
            packet_id: Some(pid),
            topic: first_topic,
            subscriptions: subs,
            ..self.empty_record(dir, pt)
        })
    }

    fn decode_unsubscribe(
        &self,
        body: &[u8],
        dir: Direction,
        pt: MqttPacketType,
    ) -> Option<MqttRecord> {
        let mut c = Cursor::new(body);
        let pid = c.read_u16()?;
        if self.version == 5 {
            let prop_len = c.read_varint()?;
            c.skip(prop_len as usize)?;
        }
        let mut subs: Vec<(String, u8)> = Vec::new();
        while !c.is_empty() {
            let filter = c.read_string()?;
            if subs.len() < MAX_SUBSCRIPTIONS {
                subs.push((truncate_chars(filter, MAX_TOPIC_CHARS), 0));
            }
        }
        if subs.is_empty() {
            return None;
        }
        let first_topic = subs.first().map(|(t, _)| t.clone());
        Some(MqttRecord {
            packet_id: Some(pid),
            topic: first_topic,
            subscriptions: subs,
            ..self.empty_record(dir, pt)
        })
    }

    fn decode_suback(&self, body: &[u8], dir: Direction, pt: MqttPacketType) -> Option<MqttRecord> {
        let mut c = Cursor::new(body);
        let pid = c.read_u16()?;
        if self.version == 5 {
            let prop_len = c.read_varint()?;
            c.skip(prop_len as usize)?;
        }
        // First return code becomes reason_code; we don't carry the rest.
        let rc = if c.is_empty() {
            None
        } else {
            Some(c.read_u8()?)
        };
        Some(MqttRecord {
            packet_id: Some(pid),
            reason_code: rc,
            ..self.empty_record(dir, pt)
        })
    }

    fn decode_unsuback(
        &self,
        body: &[u8],
        dir: Direction,
        pt: MqttPacketType,
    ) -> Option<MqttRecord> {
        let mut c = Cursor::new(body);
        let pid = c.read_u16()?;
        if self.version == 5 {
            let prop_len = c.read_varint()?;
            c.skip(prop_len as usize)?;
            let rc = if c.is_empty() {
                None
            } else {
                Some(c.read_u8()?)
            };
            Some(MqttRecord {
                packet_id: Some(pid),
                reason_code: rc,
                ..self.empty_record(dir, pt)
            })
        } else {
            // 3.1.1: only packet id, no return codes.
            Some(MqttRecord {
                packet_id: Some(pid),
                ..self.empty_record(dir, pt)
            })
        }
    }

    fn decode_disconnect(
        &self,
        body: &[u8],
        dir: Direction,
        pt: MqttPacketType,
    ) -> Option<MqttRecord> {
        // 3.1.1: zero-length body. v5: optional reason code + properties.
        let mut c = Cursor::new(body);
        let rc = if c.is_empty() {
            None
        } else {
            let code = c.read_u8()?;
            if !c.is_empty() {
                let prop_len = c.read_varint()?;
                c.skip(prop_len as usize)?;
            }
            Some(code)
        };
        Some(MqttRecord {
            reason_code: rc,
            ..self.empty_record(dir, pt)
        })
    }

    fn decode_auth(&self, body: &[u8], dir: Direction, pt: MqttPacketType) -> Option<MqttRecord> {
        // AUTH is v5-only. Body is optional; when present it's a reason
        // code + properties.
        let mut c = Cursor::new(body);
        let rc = if c.is_empty() {
            None
        } else {
            let code = c.read_u8()?;
            if !c.is_empty() {
                let prop_len = c.read_varint()?;
                c.skip(prop_len as usize)?;
            }
            Some(code)
        };
        Some(MqttRecord {
            reason_code: rc,
            ..self.empty_record(dir, pt)
        })
    }
}

/// Fixed-header flag validation per §2.1.3. Returning `false` tells the
/// caller to bypass — the stream is either corrupted or not MQTT.
const fn flags_valid(pt: MqttPacketType, flags: u8) -> bool {
    match pt {
        MqttPacketType::Publish => {
            // QoS 3 is reserved.
            let qos = (flags >> 1) & 0x03;
            qos < 3
        }
        MqttPacketType::Pubrel | MqttPacketType::Subscribe | MqttPacketType::Unsubscribe => {
            flags == 0b0010
        }
        MqttPacketType::Reserved(_) => false,
        // All other packets require flags == 0.
        _ => flags == 0,
    }
}

/// Outcome of a var-int decode. We distinguish "need more input" from
/// "malformed" so the top-level parser can bypass the stream on the
/// latter instead of blocking forever.
#[derive(Debug)]
enum VarintResult {
    /// Successfully decoded: `(value, bytes_consumed)`.
    Ok(u32, usize),
    /// Buffer truncated mid-varint — caller should try again after more
    /// bytes arrive.
    Need,
    /// Five+ continuation bytes / value exceeds the 4-byte maximum.
    Malformed,
}

fn decode_varint_ex(buf: &[u8]) -> VarintResult {
    let mut value: u32 = 0;
    let mut multiplier: u32 = 1;
    for i in 0..4 {
        let Some(&b) = buf.get(i) else {
            return VarintResult::Need;
        };
        let Some(add) = u32::from(b & 0x7F).checked_mul(multiplier) else {
            return VarintResult::Malformed;
        };
        let Some(next) = value.checked_add(add) else {
            return VarintResult::Malformed;
        };
        value = next;
        if b & 0x80 == 0 {
            return VarintResult::Ok(value, i + 1);
        }
        let Some(nm) = multiplier.checked_mul(128) else {
            return VarintResult::Malformed;
        };
        multiplier = nm;
    }
    // Four bytes consumed and we haven't returned → continuation bit was
    // still set on byte 3.
    VarintResult::Malformed
}

/// Thin wrapper used internally where distinguishing Need vs Malformed
/// isn't useful (e.g. inside a fully-materialised packet body).
fn decode_varint(buf: &[u8]) -> Option<(u32, usize)> {
    match decode_varint_ex(buf) {
        VarintResult::Ok(v, n) => Some((v, n)),
        _ => None,
    }
}

/// Truncate a string to at most `max_chars` UTF-8 *characters* (not
/// bytes). Safe on arbitrary UTF-8 since we split at char boundaries.
fn truncate_chars(s: String, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s;
    }
    s.chars().take(max_chars).collect()
}

/// Minimal read-only cursor for decoding MQTT packets. Returns `None` on
/// any underflow so callers can propagate malformed packets up with `?`.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }
    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn read_u16(&mut self) -> Option<u16> {
        let hi = *self.buf.get(self.pos)?;
        let lo = *self.buf.get(self.pos + 1)?;
        self.pos += 2;
        Some((u16::from(hi) << 8) | u16::from(lo))
    }
    fn read_varint(&mut self) -> Option<u32> {
        let (v, used) = decode_varint(&self.buf[self.pos..])?;
        self.pos += used;
        Some(v)
    }
    fn read_string(&mut self) -> Option<String> {
        let len = self.read_u16()? as usize;
        let end = self.pos.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        // MQTT strings are UTF-8 per spec; accept lossy conversion so a
        // few stray bytes don't blow up the whole record.
        Some(String::from_utf8_lossy(slice).into_owned())
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build an MQTT string (2-byte BE length + UTF-8 bytes).
    fn mqstr(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let len = u16::try_from(bytes.len()).expect("test string fits in u16");
        let mut out = Vec::with_capacity(2 + bytes.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    /// Helper: encode a variable-byte integer.
    fn varint(mut v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v > 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
        out
    }

    /// Helper: build a packet. `fixed_hdr0` is the first byte, `body`
    /// is the variable header + payload.
    fn packet(fixed_hdr0: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + body.len());
        out.push(fixed_hdr0);
        out.extend_from_slice(&varint(u32::try_from(body.len()).unwrap()));
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn connect_311_with_username_and_password_redacts_password() {
        // flags: username=1, password=1, clean_session=1 -> 0b1100_0010 = 0xC2
        let mut body = Vec::new();
        body.extend_from_slice(&mqstr("MQTT"));
        body.push(4); // level
        body.push(0xC2); // connect flags
        body.extend_from_slice(&[0x00, 0x3C]); // keep-alive 60
        body.extend_from_slice(&mqstr("client-42"));
        body.extend_from_slice(&mqstr("alice"));
        body.extend_from_slice(&mqstr("supers3cret"));
        let pkt = packet(0x10, &body);

        let mut p = MqttParser::default();
        match p.parse(&pkt, Direction::Tx) {
            MqttParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.version, 4);
                assert_eq!(record.packet_type, MqttPacketType::Connect);
                assert_eq!(record.client_id.as_deref(), Some("client-42"));
                assert_eq!(record.username.as_deref(), Some("alice"));
                assert!(record.has_password);
                // Make sure the password bytes never leaked into any field.
                let debug = format!("{record:?}");
                assert!(!debug.contains("supers3cret"));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn connect_v5_with_properties_block() {
        // v5 CONNECT with a small properties block (0x11 = session expiry
        // interval, u32 value). Properties length varint = 5.
        let mut props = Vec::new();
        props.push(0x11);
        props.extend_from_slice(&30_u32.to_be_bytes());

        let mut body = Vec::new();
        body.extend_from_slice(&mqstr("MQTT"));
        body.push(5); // level
        body.push(0x02); // clean start only
        body.extend_from_slice(&[0x00, 0x3C]);
        body.extend_from_slice(&varint(u32::try_from(props.len()).unwrap()));
        body.extend_from_slice(&props);
        body.extend_from_slice(&mqstr("c5"));
        let pkt = packet(0x10, &body);

        let mut p = MqttParser::default();
        match p.parse(&pkt, Direction::Tx) {
            MqttParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.version, 5);
                assert_eq!(record.client_id.as_deref(), Some("c5"));
                assert!(!record.has_password);
                assert!(record.username.is_none());
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn publish_qos1_with_textual_payload() {
        // First set parser to v4 via a prior CONNECT. Simpler: just
        // parse directly; version stays 0, PUBLISH framing is identical
        // for 3.1.1 (no properties block).
        let mut body = Vec::new();
        body.extend_from_slice(&mqstr("devices/42/temp"));
        body.extend_from_slice(&[0x00, 0x07]); // packet id 7
        body.extend_from_slice(b"hello world");
        // fixed header: type=3 (PUBLISH), flags=qos1<<1 = 0b0010 → 0x32
        let pkt = packet(0x32, &body);

        let mut p = MqttParser::default();
        match p.parse(&pkt, Direction::Tx) {
            MqttParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.packet_type, MqttPacketType::Publish);
                assert_eq!(record.topic.as_deref(), Some("devices/42/temp"));
                assert_eq!(record.qos, Some(1));
                assert_eq!(record.packet_id, Some(7));
                assert_eq!(record.payload_preview.as_deref(), Some(&b"hello world"[..]));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn subscribe_with_two_topic_filters() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x00, 0x0A]); // packet id 10
        body.extend_from_slice(&mqstr("a/b"));
        body.push(0x00); // options / qos 0
        body.extend_from_slice(&mqstr("x/+"));
        body.push(0x01); // qos 1
                         // fixed header: type=8, flags=0b0010 mandatory → 0x82
        let pkt = packet(0x82, &body);

        let mut p = MqttParser::default();
        match p.parse(&pkt, Direction::Tx) {
            MqttParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.packet_type, MqttPacketType::Subscribe);
                assert_eq!(record.packet_id, Some(10));
                assert_eq!(record.subscriptions.len(), 2);
                assert_eq!(record.subscriptions[0], ("a/b".to_string(), 0));
                assert_eq!(record.subscriptions[1], ("x/+".to_string(), 1));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn connack_v5_with_session_present_and_reason_code() {
        let mut p = MqttParser::default();
        // Prime the parser into v5 by running a minimal CONNECT first.
        let mut cbody = Vec::new();
        cbody.extend_from_slice(&mqstr("MQTT"));
        cbody.push(5);
        cbody.push(0x00);
        cbody.extend_from_slice(&[0, 0]);
        cbody.extend_from_slice(&varint(0)); // no properties
        cbody.extend_from_slice(&mqstr(""));
        let cpkt = packet(0x10, &cbody);
        let _ = p.parse(&cpkt, Direction::Tx);

        // CONNACK v5: flags=0x01 (session present), reason=0x00, props len 0.
        let body = [0x01_u8, 0x00, 0x00];
        let pkt = packet(0x20, &body);
        match p.parse(&pkt, Direction::Rx) {
            MqttParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.packet_type, MqttPacketType::Connack);
                assert_eq!(record.session_present, Some(true));
                assert_eq!(record.reason_code, Some(0));
                assert_eq!(record.version, 5);
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn pingreq_and_pingresp_have_empty_bodies() {
        let mut p = MqttParser::default();
        let req = [0xC0_u8, 0x00];
        match p.parse(&req, Direction::Tx) {
            MqttParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 2);
                assert_eq!(record.packet_type, MqttPacketType::Pingreq);
            }
            other => panic!("expected Record, got {other:?}"),
        }
        let resp = [0xD0_u8, 0x00];
        match p.parse(&resp, Direction::Rx) {
            MqttParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, 2);
                assert_eq!(record.packet_type, MqttPacketType::Pingresp);
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn disconnect_v5_with_reason_code() {
        // Prime v5.
        let mut p = MqttParser::default();
        let mut cbody = Vec::new();
        cbody.extend_from_slice(&mqstr("MQTT"));
        cbody.push(5);
        cbody.push(0x00);
        cbody.extend_from_slice(&[0, 0]);
        cbody.extend_from_slice(&varint(0));
        cbody.extend_from_slice(&mqstr(""));
        let cpkt = packet(0x10, &cbody);
        let _ = p.parse(&cpkt, Direction::Tx);

        // DISCONNECT v5: reason 0x04 (Disconnect with Will Message), props len 0.
        let body = [0x04_u8, 0x00];
        let pkt = packet(0xE0, &body);
        match p.parse(&pkt, Direction::Tx) {
            MqttParserOutput::Record { record, consumed } => {
                assert_eq!(consumed, pkt.len());
                assert_eq!(record.packet_type, MqttPacketType::Disconnect);
                assert_eq!(record.reason_code, Some(0x04));
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }

    #[test]
    fn truncated_packet_returns_need() {
        // PUBLISH header advertises remaining length 20 but we only give
        // it 5 bytes of body.
        let mut pkt = Vec::new();
        pkt.push(0x30); // PUBLISH qos 0
        pkt.extend_from_slice(&varint(20));
        pkt.extend_from_slice(&[0, 3, b'a', b'/', b'b']);
        let mut p = MqttParser::default();
        match p.parse(&pkt, Direction::Tx) {
            MqttParserOutput::Need => {}
            other => panic!("expected Need, got {other:?}"),
        }
    }

    #[test]
    fn invalid_control_packet_type_bypasses() {
        // Byte 0 high nibble = 0 is reserved / illegal.
        let pkt = [0x00_u8, 0x00];
        let mut p = MqttParser::default();
        match p.parse(&pkt, Direction::Tx) {
            MqttParserOutput::Skip(n) => assert_eq!(n, pkt.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
        // After bypass, subsequent bytes are skipped wholesale.
        let noise = [0x42_u8, 0x00, 0x01];
        match p.parse(&noise, Direction::Tx) {
            MqttParserOutput::Skip(n) => assert_eq!(n, noise.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn overlong_varint_bypasses() {
        // 5 continuation bytes on the remaining-length varint is illegal.
        let pkt = [0x30_u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut p = MqttParser::default();
        match p.parse(&pkt, Direction::Tx) {
            MqttParserOutput::Skip(n) => assert_eq!(n, pkt.len()),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn varint_decoder_roundtrips() {
        for &v in &[
            0_u32,
            1,
            127,
            128,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            MAX_REMAINING_LENGTH,
        ] {
            let enc = varint(v);
            let (got, used) = decode_varint(&enc).expect("decode");
            assert_eq!(got, v);
            assert_eq!(used, enc.len());
        }
    }

    #[test]
    fn display_line_does_not_leak_payload_or_username() {
        let mut body = Vec::new();
        body.extend_from_slice(&mqstr("t"));
        body.extend_from_slice(&[0, 1]);
        body.extend_from_slice(b"secret-payload-bytes");
        let pkt = packet(0x32, &body);
        let mut p = MqttParser::default();
        let MqttParserOutput::Record { record, .. } = p.parse(&pkt, Direction::Tx) else {
            panic!("record");
        };
        let line = record.display_line();
        assert!(!line.contains("secret-payload-bytes"));
        assert!(line.contains("PUBLISH"));
    }
}
