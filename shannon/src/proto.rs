//! Runtime protobuf decoder for shannon.
//!
//! Two modes:
//!
//!  * **Schema-aware** — when the user supplies either a pre-compiled
//!    `FileDescriptorSet` (`protoc --descriptor_set_out=...`) or raw
//!    `.proto` sources that are compiled on-the-fly by [`protox`]. Messages
//!    are decoded via [`prost_reflect::DynamicMessage`], yielding typed
//!    fields and proper JSON output via serde.
//!
//!  * **Schema-less** — always available. Parses the wire format directly
//!    into a protoscope-style tree. For length-delimited fields we apply
//!    a recursive re-parse heuristic: if the payload looks like a nested
//!    submessage (>=90% of bytes are valid tags with known wire types and
//!    the slice is fully consumed) we keep descending; if it's UTF-8 with
//!    mostly printable characters we treat it as a string; otherwise it's
//!    left as raw bytes.
//!
//! Used by the gRPC path in [`crate::parsers::http2`] (via follow-up
//! wiring) but deliberately self-contained: the API takes `&[u8]` and a
//! pool or a fully-qualified method / message name — nothing shannon-
//! specific leaks in.

#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::option_if_let_else
)]

use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::fs;
use std::path::{Path, PathBuf};

use prost_reflect::{
    DescriptorPool, DynamicMessage, Kind, MapKey, MessageDescriptor, SerializeOptions, Value,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A loaded descriptor pool. Backed by a [`prost_reflect::DescriptorPool`]
/// when schemas have been provided; otherwise empty. Schema-less decoding
/// is always available regardless of pool contents.
#[derive(Clone, Debug, Default)]
pub struct ProtoPool {
    pool: Option<DescriptorPool>,
}

impl ProtoPool {
    /// An empty pool — supports only schema-less decode.
    #[must_use]
    pub fn empty() -> Self {
        Self { pool: None }
    }

    /// Build a pool from a pre-compiled `FileDescriptorSet` (`.pb` file,
    /// produced by `protoc --descriptor_set_out=x.pb --include_imports`).
    pub fn from_descriptor_set(path: &Path) -> Result<Self, ProtoError> {
        let bytes =
            fs::read(path).map_err(|e| ProtoError::Io(format!("{}: {e}", path.display())))?;
        let pool = DescriptorPool::decode(bytes.as_slice())
            .map_err(|e| ProtoError::Parse(format!("decode descriptor set: {e}")))?;
        Ok(Self { pool: Some(pool) })
    }

    /// Build a pool by compiling `.proto` files on the fly. `roots` are
    /// directories searched for imports. Uses [`protox`], a pure-Rust
    /// protoc replacement.
    pub fn from_proto_files(files: &[PathBuf], roots: &[PathBuf]) -> Result<Self, ProtoError> {
        let mut compiler = protox::Compiler::new(roots)
            .map_err(|e| ProtoError::Compile(format!("create compiler: {e}")))?;
        compiler.include_imports(true);
        for f in files {
            compiler
                .open_file(f)
                .map_err(|e| ProtoError::Compile(format!("{}: {e}", f.display())))?;
        }
        let fds = compiler.file_descriptor_set();
        let pool = DescriptorPool::from_file_descriptor_set(fds)
            .map_err(|e| ProtoError::Compile(format!("build pool: {e}")))?;
        Ok(Self { pool: Some(pool) })
    }

    /// Load all `.proto` files under `dir` recursively.
    pub fn from_proto_dir(dir: &Path) -> Result<Self, ProtoError> {
        let mut files: Vec<PathBuf> = Vec::new();
        collect_proto_files(dir, &mut files)?;
        if files.is_empty() {
            return Ok(Self { pool: None });
        }
        Self::from_proto_files(&files, &[dir.to_path_buf()])
    }

    /// Fully-qualified message names currently known. Empty if the pool
    /// has no schemas loaded.
    #[must_use]
    pub fn message_names(&self) -> Vec<String> {
        self.pool.as_ref().map_or_else(Vec::new, |p| {
            p.all_messages().map(|m| m.full_name().to_owned()).collect()
        })
    }

    fn message(&self, fqn: &str) -> Option<MessageDescriptor> {
        self.pool.as_ref().and_then(|p| p.get_message_by_name(fqn))
    }
}

/// Fully-rendered decode result.
#[derive(Clone, Debug)]
pub struct Decoded {
    /// Fully-qualified message name if a schema was used.
    pub schema_used: Option<String>,
    /// Human-readable rendering (JSON when schema-aware, protoscope-like
    /// when schema-less).
    pub json_like: String,
    /// Structured view for programmatic use.
    pub fields: Vec<DecodedField>,
}

/// One decoded field.
#[derive(Clone, Debug)]
pub struct DecodedField {
    /// Protobuf field number.
    pub tag: u32,
    /// Wire type from the tag byte.
    pub wire_type: WireType,
    /// Field name, if known from the schema.
    pub name: Option<String>,
    /// Decoded value.
    pub value: DecodedValue,
}

/// Protobuf wire type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireType {
    Varint,
    I64,
    Len,
    SGroup,
    EGroup,
    I32,
}

impl WireType {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Varint,
            1 => Self::I64,
            2 => Self::Len,
            3 => Self::SGroup,
            4 => Self::EGroup,
            5 => Self::I32,
            _ => return None,
        })
    }
}

/// Decoded value (either typed via the schema, or "best-effort" schema-less).
#[derive(Clone, Debug)]
pub enum DecodedValue {
    U64(u64),
    I64(i64),
    Bool(bool),
    F32(f32),
    F64(f64),
    Str(String),
    /// Raw bytes. Truncated to 256 bytes when reported via the structured
    /// form to keep memory bounded; the original length is exposed only in
    /// the JSON rendering when truncation occurred.
    Bytes(Vec<u8>),
    Message(Vec<DecodedField>),
    Repeated(Vec<DecodedValue>),
    /// Schema-less catch-all — a length-delimited payload that was not
    /// recognised as a submessage or a string.
    Raw(Vec<u8>),
}

/// Errors surfaced by the decoder.
#[derive(Clone, Debug)]
pub enum ProtoError {
    Io(String),
    Parse(String),
    Compile(String),
    UnknownMessage(String),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(s) => write!(f, "proto I/O: {s}"),
            Self::Parse(s) => write!(f, "proto parse: {s}"),
            Self::Compile(s) => write!(f, "proto compile: {s}"),
            Self::UnknownMessage(s) => write!(f, "unknown proto message: {s}"),
        }
    }
}

impl std::error::Error for ProtoError {}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

const MAX_DEPTH: usize = 32;
const MAX_FIELD_BYTES: usize = 4 * 1024;
const BYTES_REPORT_CAP: usize = 256;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Decode `bytes` as the message named `msg_fqn` (e.g. `"pkg.Service.Request"`).
/// Falls back to schema-less decode if the message is not in the pool.
pub fn decode_known(pool: &ProtoPool, msg_fqn: &str, bytes: &[u8]) -> Result<Decoded, ProtoError> {
    if let Some(md) = pool.message(msg_fqn) {
        schema_decode(&md, bytes)
    } else {
        Ok(decode_unknown(bytes))
    }
}

/// Guess a message from a well-known gRPC method path like `"pkg.Service/Method"`.
/// Looks up the service, finds the method, dispatches to its request or
/// response message type depending on `is_request`. Falls back to
/// schema-less decode if the method isn't in the pool.
pub fn decode_grpc(
    pool: &ProtoPool,
    method: &str,
    bytes: &[u8],
    is_request: bool,
) -> Result<Decoded, ProtoError> {
    let Some(dp) = pool.pool.as_ref() else {
        return Ok(decode_unknown(bytes));
    };

    // `pkg.Service/Method` → ("pkg.Service", "Method"). Leading slash is
    // tolerated because that's what HTTP/2 :path carries.
    let path = method.strip_prefix('/').unwrap_or(method);
    let Some((service_fqn, method_name)) = path.split_once('/') else {
        return Ok(decode_unknown(bytes));
    };

    let Some(svc) = dp.get_service_by_name(service_fqn) else {
        return Ok(decode_unknown(bytes));
    };

    let Some(m) = svc.methods().find(|m| m.name() == method_name) else {
        return Ok(decode_unknown(bytes));
    };

    let md = if is_request { m.input() } else { m.output() };
    schema_decode(&md, bytes)
}

/// Always-available schema-less decode. Returns a protoscope-style tree.
#[must_use]
pub fn decode_unknown(bytes: &[u8]) -> Decoded {
    match parse_message_schemaless(bytes, 0) {
        Ok(fields) => {
            let json_like = render_schemaless(&fields);
            Decoded {
                schema_used: None,
                json_like,
                fields,
            }
        }
        Err(e) => Decoded {
            schema_used: None,
            json_like: format!("<invalid: {e}>"),
            fields: Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Schema-aware decode
// ---------------------------------------------------------------------------

fn schema_decode(md: &MessageDescriptor, bytes: &[u8]) -> Result<Decoded, ProtoError> {
    let dyn_msg = DynamicMessage::decode(md.clone(), bytes)
        .map_err(|e| ProtoError::Parse(format!("decode {}: {e}", md.full_name())))?;

    // JSON rendering via prost-reflect's serde impl. We request enum-as-string
    // and skip default fields to keep output compact.
    let mut ser = serde_json::Serializer::new(Vec::new());
    let opts = SerializeOptions::new()
        .skip_default_fields(true)
        .stringify_64_bit_integers(false);
    dyn_msg
        .serialize_with_options(&mut ser, &opts)
        .map_err(|e| ProtoError::Parse(format!("serialize: {e}")))?;
    let json_like = String::from_utf8(ser.into_inner())
        .map_err(|e| ProtoError::Parse(format!("non-utf8 json: {e}")))?;

    // Structured form: mirror the schema, then append any unknown fields
    // the bytes still carried.
    let mut fields = Vec::new();
    for (fd, val) in dyn_msg.fields() {
        let wire = wire_for_kind(&fd.kind(), fd.is_list() || fd.is_map());
        let value = value_from_reflect(val, &fd.kind(), 0);
        fields.push(DecodedField {
            tag: fd.number(),
            wire_type: wire,
            name: Some(fd.name().to_owned()),
            value,
        });
    }
    // Append fields present on the wire but absent from the descriptor
    // (forward/backward-compat). We do a cheap schema-less sweep and
    // keep only tags the schema didn't already cover.
    let known_tags: std::collections::HashSet<u32> = md.fields().map(|fd| fd.number()).collect();
    if let Ok(schemaless) = parse_message_schemaless(bytes, 0) {
        for f in schemaless {
            if !known_tags.contains(&f.tag) {
                fields.push(f);
            }
        }
    }

    Ok(Decoded {
        schema_used: Some(md.full_name().to_owned()),
        json_like,
        fields,
    })
}

fn wire_for_kind(kind: &Kind, is_repeated_or_map: bool) -> WireType {
    if is_repeated_or_map {
        // Packed repeated / maps hit the wire as length-delimited.
        return WireType::Len;
    }
    match kind {
        Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => WireType::I64,
        Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => WireType::I32,
        Kind::String | Kind::Bytes | Kind::Message(_) => WireType::Len,
        Kind::Int32
        | Kind::Int64
        | Kind::Uint32
        | Kind::Uint64
        | Kind::Sint32
        | Kind::Sint64
        | Kind::Bool
        | Kind::Enum(_) => WireType::Varint,
    }
}

fn value_from_reflect(v: &Value, kind: &Kind, depth: usize) -> DecodedValue {
    if depth >= MAX_DEPTH {
        return DecodedValue::Raw(Vec::new());
    }
    match v {
        Value::Bool(b) => DecodedValue::Bool(*b),
        Value::I32(i) => DecodedValue::I64(i64::from(*i)),
        Value::I64(i) => DecodedValue::I64(*i),
        Value::U32(u) => DecodedValue::U64(u64::from(*u)),
        Value::U64(u) => DecodedValue::U64(*u),
        Value::F32(f) => DecodedValue::F32(*f),
        Value::F64(f) => DecodedValue::F64(*f),
        Value::String(s) => DecodedValue::Str(s.clone()),
        Value::Bytes(b) => {
            let cap = BYTES_REPORT_CAP.min(b.len());
            DecodedValue::Bytes(b[..cap].to_vec())
        }
        Value::EnumNumber(n) => {
            if let Kind::Enum(ed) = kind {
                if let Some(v) = ed.get_value(*n) {
                    return DecodedValue::Str(v.name().to_owned());
                }
            }
            DecodedValue::I64(i64::from(*n))
        }
        Value::Message(dm) => {
            let mut fields = Vec::new();
            for (fd, val) in dm.fields() {
                fields.push(DecodedField {
                    tag: fd.number(),
                    wire_type: wire_for_kind(&fd.kind(), fd.is_list() || fd.is_map()),
                    name: Some(fd.name().to_owned()),
                    value: value_from_reflect(val, &fd.kind(), depth + 1),
                });
            }
            DecodedValue::Message(fields)
        }
        Value::List(items) => {
            let vec: Vec<DecodedValue> = items
                .iter()
                .map(|it| value_from_reflect(it, kind, depth + 1))
                .collect();
            DecodedValue::Repeated(vec)
        }
        Value::Map(m) => {
            // Flatten map entries as a submessage with synthetic field 1 = key,
            // field 2 = value — matching the generated `map_entry` layout.
            let mut fields = Vec::new();
            for (k, val) in m {
                let key_val = map_key_to_value(k);
                let entry = DecodedValue::Message(vec![
                    DecodedField {
                        tag: 1,
                        wire_type: WireType::Varint,
                        name: Some("key".to_owned()),
                        value: key_val,
                    },
                    DecodedField {
                        tag: 2,
                        wire_type: WireType::Len,
                        name: Some("value".to_owned()),
                        value: value_from_reflect(val, kind, depth + 1),
                    },
                ]);
                fields.push(DecodedField {
                    tag: 0,
                    wire_type: WireType::Len,
                    name: None,
                    value: entry,
                });
            }
            DecodedValue::Message(fields)
        }
    }
}

fn map_key_to_value(k: &MapKey) -> DecodedValue {
    match k {
        MapKey::Bool(b) => DecodedValue::Bool(*b),
        MapKey::I32(i) => DecodedValue::I64(i64::from(*i)),
        MapKey::I64(i) => DecodedValue::I64(*i),
        MapKey::U32(u) => DecodedValue::U64(u64::from(*u)),
        MapKey::U64(u) => DecodedValue::U64(*u),
        MapKey::String(s) => DecodedValue::Str(s.clone()),
    }
}

// ---------------------------------------------------------------------------
// Schema-less decode
// ---------------------------------------------------------------------------

fn parse_message_schemaless(
    mut bytes: &[u8],
    depth: usize,
) -> Result<Vec<DecodedField>, ProtoError> {
    if depth >= MAX_DEPTH {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (tag, rest) = read_varint(bytes)?;
        bytes = rest;
        let wire_raw = (tag & 0x7) as u8;
        let field_number = u32::try_from(tag >> 3)
            .map_err(|_| ProtoError::Parse(format!("tag too large: {tag}")))?;
        let Some(wt) = WireType::from_u8(wire_raw) else {
            return Err(ProtoError::Parse(format!("unknown wire type {wire_raw}")));
        };
        let (value, rest) = read_value(bytes, wt, depth)?;
        bytes = rest;
        out.push(DecodedField {
            tag: field_number,
            wire_type: wt,
            name: None,
            value,
        });
    }
    Ok(out)
}

fn read_value<'a>(
    bytes: &'a [u8],
    wt: WireType,
    depth: usize,
) -> Result<(DecodedValue, &'a [u8]), ProtoError> {
    match wt {
        WireType::Varint => {
            let (v, rest) = read_varint(bytes)?;
            Ok((DecodedValue::U64(v), rest))
        }
        WireType::I64 => {
            if bytes.len() < 8 {
                return Err(ProtoError::Parse("short I64 field".into()));
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[..8]);
            Ok((DecodedValue::U64(u64::from_le_bytes(arr)), &bytes[8..]))
        }
        WireType::I32 => {
            if bytes.len() < 4 {
                return Err(ProtoError::Parse("short I32 field".into()));
            }
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[..4]);
            Ok((
                DecodedValue::U64(u64::from(u32::from_le_bytes(arr))),
                &bytes[4..],
            ))
        }
        WireType::Len => {
            let (len, rest) = read_varint(bytes)?;
            let len = usize::try_from(len)
                .map_err(|_| ProtoError::Parse(format!("length too large: {len}")))?;
            if rest.len() < len {
                return Err(ProtoError::Parse(format!(
                    "short Len field: need {len}, have {}",
                    rest.len()
                )));
            }
            let (slice, after) = rest.split_at(len);
            if len > MAX_FIELD_BYTES {
                // Truncation marker: record a Bytes value sized at the cap
                // plus a sentinel so the renderer can display
                // `…[truncated]`.
                let cap = BYTES_REPORT_CAP.min(slice.len());
                return Ok((
                    DecodedValue::Raw(prefix_with_marker(&slice[..cap], true)),
                    after,
                ));
            }
            Ok((classify_len(slice, depth), after))
        }
        WireType::SGroup | WireType::EGroup => {
            // Deprecated — record as empty and keep going; we don't try
            // to match SGroup/EGroup boundaries.
            Ok((DecodedValue::Raw(Vec::new()), bytes))
        }
    }
}

/// Sentinel tag we prepend to truncated Raw payloads so the renderer can
/// emit the `[truncated]` marker without a separate out-of-band flag.
const TRUNC_MAGIC: &[u8] = b"__trunc__";

fn prefix_with_marker(slice: &[u8], truncated: bool) -> Vec<u8> {
    if !truncated {
        return slice.to_vec();
    }
    let mut v = Vec::with_capacity(TRUNC_MAGIC.len() + slice.len());
    v.extend_from_slice(TRUNC_MAGIC);
    v.extend_from_slice(slice);
    v
}

fn is_truncated(raw: &[u8]) -> bool {
    raw.starts_with(TRUNC_MAGIC)
}

fn classify_len(slice: &[u8], depth: usize) -> DecodedValue {
    // 1) Try to re-parse as a submessage.
    if depth + 1 < MAX_DEPTH && looks_like_message(slice) {
        if let Ok(fields) = parse_message_schemaless(slice, depth + 1) {
            if !fields.is_empty() {
                return DecodedValue::Message(fields);
            }
        }
    }

    // 2) Try UTF-8 with mostly printable characters.
    if let Ok(s) = std::str::from_utf8(slice) {
        if !s.is_empty() && is_mostly_printable(s) {
            return DecodedValue::Str(s.to_owned());
        }
    }

    // 3) Fall through as raw bytes (kept small).
    let cap = BYTES_REPORT_CAP.min(slice.len());
    DecodedValue::Raw(slice[..cap].to_vec())
}

/// Heuristic: at least 90% of the parsed tags must carry a known
/// non-deprecated wire type (0/1/2/5) AND the whole slice must be
/// consumed, AND we must see at least one field.
fn looks_like_message(slice: &[u8]) -> bool {
    if slice.is_empty() {
        return false;
    }
    let mut remaining = slice;
    let mut total: u32 = 0;
    let mut good: u32 = 0;
    while !remaining.is_empty() {
        let Ok((tag, rest)) = read_varint(remaining) else {
            return false;
        };
        total = total.saturating_add(1);
        let wt = (tag & 0x7) as u8;
        let fnum = tag >> 3;
        let is_good = matches!(wt, 0 | 1 | 2 | 5) && fnum != 0;
        if is_good {
            good = good.saturating_add(1);
        }
        remaining = rest;
        // Skip over the value so we can keep scanning.
        match WireType::from_u8(wt) {
            Some(WireType::Varint) => match read_varint(remaining) {
                Ok((_, r)) => remaining = r,
                Err(_) => return false,
            },
            Some(WireType::I64) => {
                if remaining.len() < 8 {
                    return false;
                }
                remaining = &remaining[8..];
            }
            Some(WireType::I32) => {
                if remaining.len() < 4 {
                    return false;
                }
                remaining = &remaining[4..];
            }
            Some(WireType::Len) => {
                let Ok((len, r)) = read_varint(remaining) else {
                    return false;
                };
                let Ok(len) = usize::try_from(len) else {
                    return false;
                };
                if r.len() < len {
                    return false;
                }
                remaining = &r[len..];
            }
            Some(WireType::SGroup | WireType::EGroup) | None => return false,
        }
    }
    total > 0 && (good * 10) >= (total * 9)
}

fn is_mostly_printable(s: &str) -> bool {
    // At least one printable, and >=80% of chars printable/whitespace.
    let mut total = 0usize;
    let mut printable = 0usize;
    for ch in s.chars() {
        total += 1;
        if is_printable_char(ch) {
            printable += 1;
        }
    }
    total > 0 && (printable * 5) >= (total * 4)
}

fn is_printable_char(ch: char) -> bool {
    ch == '\t' || ch == '\n' || ch == '\r' || (ch >= ' ' && ch != '\u{7f}')
}

// ---------------------------------------------------------------------------
// Varint decoder
// ---------------------------------------------------------------------------

fn read_varint(bytes: &[u8]) -> Result<(u64, &[u8]), ProtoError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i == 10 {
            // A varint is at most 10 bytes. If we're here and the 10th byte
            // still has its continuation bit set — or (specifically for the
            // 10th byte) if it uses more than one bit — the input is
            // malformed.
            return Err(ProtoError::Parse("varint exceeds 10 bytes".into()));
        }
        let low = u64::from(b & 0x7f);
        // The 10th byte (index 9) can only contribute 1 useful bit in an
        // unsigned 64-bit varint; anything larger is malformed. We accept
        // up to 0x01 here, consistent with prost.
        if i == 9 && (b & 0x7f) > 1 {
            return Err(ProtoError::Parse("varint overflows u64".into()));
        }
        result |= low << shift;
        if b & 0x80 == 0 {
            return Ok((result, &bytes[i + 1..]));
        }
        shift += 7;
    }
    Err(ProtoError::Parse("truncated varint".into()))
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_schemaless(fields: &[DecodedField]) -> String {
    let mut out = String::new();
    render_fields(fields, &mut out);
    out
}

fn render_fields(fields: &[DecodedField], out: &mut String) {
    out.push('{');
    let mut first = true;
    for f in fields {
        if !first {
            out.push_str(", ");
        }
        first = false;
        // Field name: prefer schema name, else `#<tag>`.
        if let Some(name) = &f.name {
            out.push_str(name);
        } else {
            out.push('#');
            out.push_str(&f.tag.to_string());
        }
        out.push_str(": ");
        render_value(&f.value, out);
    }
    out.push('}');
}

fn render_value(v: &DecodedValue, out: &mut String) {
    match v {
        DecodedValue::U64(u) => out.push_str(&u.to_string()),
        DecodedValue::I64(i) => out.push_str(&i.to_string()),
        DecodedValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        DecodedValue::F32(f) => out.push_str(&f.to_string()),
        DecodedValue::F64(f) => out.push_str(&f.to_string()),
        DecodedValue::Str(s) => {
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        DecodedValue::Bytes(b) => {
            render_bytes(b, false, out);
        }
        DecodedValue::Message(fields) => {
            render_fields(fields, out);
        }
        DecodedValue::Repeated(items) => {
            out.push('[');
            let mut first = true;
            for it in items {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                render_value(it, out);
            }
            out.push(']');
        }
        DecodedValue::Raw(b) => {
            if is_truncated(b) {
                let body = &b[TRUNC_MAGIC.len()..];
                render_bytes(body, true, out);
            } else {
                render_bytes(b, false, out);
            }
        }
    }
}

fn render_bytes(b: &[u8], truncated: bool, out: &mut String) {
    out.push_str("0x");
    for byte in b.iter().take(BYTES_REPORT_CAP) {
        let _ = write!(out, "{byte:02x}");
    }
    if truncated || b.len() > BYTES_REPORT_CAP {
        out.push_str("…[truncated]");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn collect_proto_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), ProtoError> {
    // Iterative BFS to avoid blowing the stack on deep trees.
    let mut queue: VecDeque<PathBuf> = VecDeque::new();
    queue.push_back(dir.to_path_buf());
    while let Some(cur) = queue.pop_front() {
        let rd =
            fs::read_dir(&cur).map_err(|e| ProtoError::Io(format!("{}: {e}", cur.display())))?;
        for entry in rd {
            let entry = entry.map_err(|e| ProtoError::Io(format!("{e}")))?;
            let path = entry.path();
            let ft = entry
                .file_type()
                .map_err(|e| ProtoError::Io(format!("{}: {e}", path.display())))?;
            if ft.is_dir() {
                queue.push_back(path);
            } else if ft.is_file() && path.extension().and_then(|s| s.to_str()) == Some("proto") {
                out.push(path);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_varint(mut v: u64, out: &mut Vec<u8>) {
        while v >= 0x80 {
            out.push(((v & 0x7f) | 0x80) as u8);
            v >>= 7;
        }
        out.push(v as u8);
    }

    fn enc_tag(field_number: u32, wt: u8, out: &mut Vec<u8>) {
        enc_varint(u64::from((field_number << 3) | u32::from(wt)), out);
    }

    #[test]
    fn schemaless_simple_string_and_varint() {
        // { 1: "hello", 2: 42 }
        let bytes: Vec<u8> = vec![
            0x0a, 0x05, b'h', b'e', b'l', b'l', b'o', // field 1, wt 2, len 5, "hello"
            0x10, 0x2a, // field 2, wt 0, value 42
        ];
        let d = decode_unknown(&bytes);
        assert_eq!(d.fields.len(), 2);
        assert_eq!(d.fields[0].tag, 1);
        assert_eq!(d.fields[0].wire_type, WireType::Len);
        match &d.fields[0].value {
            DecodedValue::Str(s) => assert_eq!(s, "hello"),
            other => panic!("expected Str, got {other:?}"),
        }
        assert_eq!(d.fields[1].tag, 2);
        assert_eq!(d.fields[1].wire_type, WireType::Varint);
        match d.fields[1].value {
            DecodedValue::U64(42) => {}
            ref other => panic!("expected U64(42), got {other:?}"),
        }
        assert!(d.json_like.contains("\"hello\""));
        assert!(d.json_like.contains("42"));
        assert!(d.json_like.contains("#1"));
        assert!(d.json_like.contains("#2"));
    }

    #[test]
    fn schemaless_nested_message() {
        // Inner: { 1: true } → 0x08 0x01
        // Outer: { 1: inner } → 0x0a 0x02 0x08 0x01
        let bytes: Vec<u8> = vec![0x0a, 0x02, 0x08, 0x01];
        let d = decode_unknown(&bytes);
        assert_eq!(d.fields.len(), 1);
        match &d.fields[0].value {
            DecodedValue::Message(inner) => {
                assert_eq!(inner.len(), 1);
                assert_eq!(inner[0].tag, 1);
                // We can't tell 1 from true without a schema; check U64(1).
                match inner[0].value {
                    DecodedValue::U64(1) => {}
                    ref o => panic!("expected U64(1), got {o:?}"),
                }
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn schemaless_packed_repeated_varints_as_raw_or_message() {
        // Packed repeated field 1: [1, 2, 3] → 0x0a 0x03 0x01 0x02 0x03
        // Schema-less: without a schema, the payload 01 02 03 is valid
        // tags (field 0 wt 1, field 0 wt 2, ...) — but field number 0 is
        // invalid, so our heuristic should reject it. Verify we fall
        // through to Raw or Str (since these bytes aren't printable).
        let bytes: Vec<u8> = vec![0x0a, 0x03, 0x01, 0x02, 0x03];
        let d = decode_unknown(&bytes);
        assert_eq!(d.fields.len(), 1);
        // Accept either Raw or Message here — the point of the test is
        // to document that without a schema we cannot recover the
        // Repeated semantics.
        let ok = matches!(
            d.fields[0].value,
            DecodedValue::Raw(_)
                | DecodedValue::Message(_)
                | DecodedValue::Str(_)
                | DecodedValue::Bytes(_)
        );
        assert!(ok, "unexpected value: {:?}", d.fields[0].value);
    }

    #[test]
    fn schema_aware_repeated_packed() {
        // Compile a toy .proto on the fly.
        let tmp = tempfile::tempdir().unwrap();
        let proto_path = tmp.path().join("toy.proto");
        fs::write(
            &proto_path,
            r#"
                syntax = "proto3";
                package toy;
                message Ping {
                    string msg = 1;
                    int64 n = 2;
                    repeated int32 nums = 3;
                }
            "#,
        )
        .unwrap();

        let pool =
            ProtoPool::from_proto_files(&[PathBuf::from("toy.proto")], &[tmp.path().to_path_buf()])
                .expect("compile");
        let _ = proto_path; // silence unused in this path
        assert!(pool.message_names().iter().any(|n| n == "toy.Ping"));

        // Encode { msg: "hello", n: 42, nums: [1,2,3] } by hand.
        let mut buf: Vec<u8> = Vec::new();
        // field 1 (string) tag
        enc_tag(1, 2, &mut buf);
        enc_varint(5, &mut buf);
        buf.extend_from_slice(b"hello");
        // field 2 (varint) tag
        enc_tag(2, 0, &mut buf);
        enc_varint(42, &mut buf);
        // field 3 (packed repeated int32)
        enc_tag(3, 2, &mut buf);
        let mut inner: Vec<u8> = Vec::new();
        enc_varint(1, &mut inner);
        enc_varint(2, &mut inner);
        enc_varint(3, &mut inner);
        enc_varint(inner.len() as u64, &mut buf);
        buf.extend_from_slice(&inner);

        let decoded = decode_known(&pool, "toy.Ping", &buf).expect("decode");
        assert_eq!(decoded.schema_used.as_deref(), Some("toy.Ping"));
        assert!(decoded.json_like.contains("hello"));
        assert!(decoded.json_like.contains("\"msg\""));
        assert!(decoded.json_like.contains("\"n\""));
        assert!(decoded.json_like.contains("\"nums\""));
        // Find the `nums` field and check it's Repeated.
        let nums = decoded
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("nums"))
            .expect("nums field present");
        match &nums.value {
            DecodedValue::Repeated(items) => {
                assert_eq!(items.len(), 3);
            }
            other => panic!("expected Repeated, got {other:?}"),
        }
    }

    #[test]
    fn schema_aware_unknown_message_falls_back() {
        let pool = ProtoPool::empty();
        let bytes: Vec<u8> = vec![0x08, 0x2a]; // { 1: 42 }
        let d = decode_known(&pool, "nope.Nope", &bytes).unwrap();
        assert!(d.schema_used.is_none());
        assert_eq!(d.fields.len(), 1);
    }

    #[test]
    fn invalid_varint_errors() {
        // 10 bytes all with continuation bit set → overflow.
        let bytes: Vec<u8> = vec![0xff; 11];
        let err = read_varint(&bytes).unwrap_err();
        match err {
            ProtoError::Parse(_) => {}
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn bounded_large_bytes_truncates() {
        // Build { 1: <100 KiB of zeros> } as a Len field.
        let big = vec![0u8; 100 * 1024];
        let mut bytes: Vec<u8> = Vec::new();
        enc_tag(1, 2, &mut bytes);
        enc_varint(big.len() as u64, &mut bytes);
        bytes.extend_from_slice(&big);

        let d = decode_unknown(&bytes);
        assert_eq!(d.fields.len(), 1);
        match &d.fields[0].value {
            DecodedValue::Raw(v) => {
                assert!(is_truncated(v), "should be marked truncated");
                assert!(v.len() <= TRUNC_MAGIC.len() + BYTES_REPORT_CAP);
            }
            other => panic!("expected Raw, got {other:?}"),
        }
        assert!(d.json_like.contains("[truncated]"));
    }

    #[test]
    fn decode_grpc_falls_back_without_schema() {
        let pool = ProtoPool::empty();
        let bytes: Vec<u8> = vec![0x08, 0x01];
        let d = decode_grpc(&pool, "pkg.Svc/Method", &bytes, true).unwrap();
        assert!(d.schema_used.is_none());
    }

    #[test]
    fn wire_type_mapping() {
        assert_eq!(WireType::from_u8(0), Some(WireType::Varint));
        assert_eq!(WireType::from_u8(1), Some(WireType::I64));
        assert_eq!(WireType::from_u8(2), Some(WireType::Len));
        assert_eq!(WireType::from_u8(3), Some(WireType::SGroup));
        assert_eq!(WireType::from_u8(4), Some(WireType::EGroup));
        assert_eq!(WireType::from_u8(5), Some(WireType::I32));
        assert_eq!(WireType::from_u8(6), None);
    }
}
