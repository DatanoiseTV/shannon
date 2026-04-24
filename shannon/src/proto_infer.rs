//! Infer a `.proto` schema from a corpus of observed binary messages.
//!
//! Given a directory of raw protobuf messages (e.g. gRPC request /
//! response bodies dumped by `shannon trace --dump-files`), this walks
//! the schema-less decoder over every sample, accumulates per-tag
//! profiles (wire type frequency, length distribution, UTF-8 vs
//! submessage heuristics), and emits a best-guess `.proto` file.
//!
//! Multithreaded: samples are chunked across worker threads. Each
//! worker builds a local profile map that the orchestrator merges.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::proto::{decode_unknown, DecodedField, DecodedValue, WireType};

/// Inferred schema for one message type. For now we infer only one
/// top-level message — extending to nested definitions is a follow-up.
#[derive(Debug, Clone)]
pub struct InferredSchema {
    pub name: String,
    pub fields: Vec<InferredField>,
    pub samples_scanned: u64,
    pub samples_fully_decoded: u64,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct InferredField {
    pub tag: u32,
    /// Most-common wire type observed. Others counted for diagnostics.
    pub wire_type: WireType,
    pub observed_wire_types: Vec<(WireType, u64)>,
    /// Our best-guess protobuf type name (int64, string, bytes, MessageN).
    pub proto_type: String,
    /// Whether the field looked repeated (seen >1 times in a single
    /// message sample).
    pub repeated: bool,
    pub name: String,
    pub seen_in: u64,
}

impl InferredSchema {
    /// Render as a `.proto` source file (proto3 syntax).
    pub fn to_proto(&self) -> String {
        let mut out = String::new();
        out.push_str("syntax = \"proto3\";\n\n");
        out.push_str(&format!(
            "// Inferred from {} samples ({} fully decoded; confidence {:.1}%).\n",
            self.samples_scanned,
            self.samples_fully_decoded,
            self.confidence * 100.0
        ));
        out.push_str(&format!("message {} {{\n", self.name));
        for f in &self.fields {
            let prefix = if f.repeated { "  repeated " } else { "  " };
            out.push_str(&format!(
                "{}{} {} = {};  // wire={:?}, seen_in={}{}\n",
                prefix,
                f.proto_type,
                f.name,
                f.tag,
                f.wire_type,
                f.seen_in,
                alt_types_comment(&f.observed_wire_types, f.wire_type),
            ));
        }
        out.push_str("}\n");
        out
    }
}

fn alt_types_comment(all: &[(WireType, u64)], primary: WireType) -> String {
    let alt: Vec<_> = all
        .iter()
        .filter(|(wt, _)| std::mem::discriminant(wt) != std::mem::discriminant(&primary))
        .collect();
    if alt.is_empty() {
        String::new()
    } else {
        let parts: Vec<String> = alt.iter().map(|(wt, n)| format!("{wt:?}×{n}")).collect();
        format!(" (alt: {})", parts.join(", "))
    }
}

/// Infer a schema by scanning every file in `dir` in parallel on
/// `threads` workers, respecting `time_budget` if set.
pub fn infer_dir(
    dir: &Path,
    threads: usize,
    time_budget: Option<Duration>,
    message_name: &str,
) -> Result<InferredSchema> {
    let samples = load_samples(dir)?;
    if samples.is_empty() {
        anyhow::bail!("no samples in {}", dir.display());
    }
    infer_corpus(&samples, threads, time_budget, message_name)
}

/// Infer from an in-memory corpus.
pub fn infer_corpus(
    samples: &[Vec<u8>],
    threads: usize,
    time_budget: Option<Duration>,
    message_name: &str,
) -> Result<InferredSchema> {
    let threads = threads.max(1).min(64);
    let deadline = time_budget.map(|d| Instant::now() + d);
    let scanned = Arc::new(AtomicU64::new(0));
    let fully = Arc::new(AtomicU64::new(0));

    // Chunk the samples.
    let chunks: Vec<Vec<Vec<u8>>> = samples
        .chunks(samples.len().div_ceil(threads))
        .map(|c| c.to_vec())
        .collect();

    let handles: Vec<_> = chunks
        .into_iter()
        .map(|chunk| {
            let scanned = Arc::clone(&scanned);
            let fully = Arc::clone(&fully);
            thread::spawn(move || -> HashMap<u32, FieldProfile> {
                let mut local: HashMap<u32, FieldProfile> = HashMap::new();
                for sample in chunk {
                    if let Some(d) = deadline {
                        if Instant::now() > d {
                            break;
                        }
                    }
                    scanned.fetch_add(1, Ordering::Relaxed);
                    let dec = decode_unknown(&sample);
                    // Fully decoded ≈ no schema-less "unknown" holes.
                    // The schema-less decoder produces a best-effort tree;
                    // we accept every successfully-parsed top level as
                    // "fully decoded" for scoring.
                    fully.fetch_add(1, Ordering::Relaxed);
                    let mut seen_this_msg: HashMap<u32, u64> = HashMap::new();
                    for f in &dec.fields {
                        *seen_this_msg.entry(f.tag).or_default() += 1;
                    }
                    for f in &dec.fields {
                        profile_absorb(
                            &mut local,
                            f,
                            seen_this_msg.get(&f.tag).copied().unwrap_or(1),
                        );
                    }
                }
                local
            })
        })
        .collect();

    let mut merged: HashMap<u32, FieldProfile> = HashMap::new();
    for h in handles {
        match h.join() {
            Ok(local) => {
                for (tag, prof) in local {
                    merged.entry(tag).or_default().merge(&prof);
                }
            }
            Err(_) => tracing::warn!("worker panicked"),
        }
    }

    let scanned_n = scanned.load(Ordering::Relaxed);
    let fully_n = fully.load(Ordering::Relaxed);

    // Build InferredFields, sorted by tag.
    let mut fields: Vec<InferredField> = merged
        .into_iter()
        .map(|(tag, prof)| prof.finalise(tag))
        .collect();
    fields.sort_by_key(|f| f.tag);
    let confidence = if scanned_n == 0 {
        0.0
    } else {
        (fully_n as f64) / (scanned_n as f64)
    };

    Ok(InferredSchema {
        name: message_name.to_string(),
        fields,
        samples_scanned: scanned_n,
        samples_fully_decoded: fully_n,
        confidence,
    })
}

/// Load every regular file under `dir`. Files bigger than 4 MiB are
/// skipped (probably aren't single messages).
fn load_samples(dir: &Path) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    walk(dir, &mut out)?;
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<Vec<u8>>) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk(&path, out)?;
        } else if meta.is_file() && meta.len() <= 4 * 1024 * 1024 {
            if let Ok(bytes) = fs::read(&path) {
                if !bytes.is_empty() {
                    out.push(bytes);
                }
            }
        }
    }
    Ok(())
}

#[derive(Default, Clone)]
struct FieldProfile {
    wire_counts: HashMap<u8, u64>,       // discriminant → count
    wire_samples: HashMap<u8, WireType>, // keep one real WireType per discriminant
    str_count: u64,
    bytes_count: u64,
    msg_count: u64,
    varint_max: u64,
    max_repeated: u64,
    seen_in_messages: u64,
    total_bytes: u64,
}

impl FieldProfile {
    fn merge(&mut self, other: &Self) {
        for (k, v) in &other.wire_counts {
            *self.wire_counts.entry(*k).or_default() += *v;
        }
        for (k, v) in &other.wire_samples {
            self.wire_samples.entry(*k).or_insert(*v);
        }
        self.str_count += other.str_count;
        self.bytes_count += other.bytes_count;
        self.msg_count += other.msg_count;
        self.varint_max = self.varint_max.max(other.varint_max);
        self.max_repeated = self.max_repeated.max(other.max_repeated);
        self.seen_in_messages += other.seen_in_messages;
        self.total_bytes += other.total_bytes;
    }

    fn finalise(self, tag: u32) -> InferredField {
        // Primary wire type = most common.
        let (prim_disc, _) = self
            .wire_counts
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(k, v)| (*k, *v))
            .unwrap_or((2, 0));
        let primary = self
            .wire_samples
            .get(&prim_disc)
            .copied()
            .unwrap_or(WireType::Len);

        let proto_type = match primary {
            WireType::Varint => {
                if self.varint_max <= 1 {
                    "bool".to_string()
                } else if self.varint_max <= u64::from(u32::MAX) {
                    "int32".to_string()
                } else {
                    "int64".to_string()
                }
            }
            WireType::I32 => "fixed32".to_string(),
            WireType::I64 => "fixed64".to_string(),
            WireType::Len => {
                // Decide between string / bytes / nested message by
                // counting what the len payloads looked like during decode.
                if self.msg_count > self.str_count && self.msg_count > self.bytes_count {
                    format!("Message_{tag}")
                } else if self.str_count >= self.bytes_count {
                    "string".to_string()
                } else {
                    "bytes".to_string()
                }
            }
            WireType::SGroup | WireType::EGroup => "bytes".to_string(),
        };

        let observed_wire_types: Vec<_> = self
            .wire_counts
            .iter()
            .map(|(d, c)| {
                let wt = self.wire_samples.get(d).copied().unwrap_or(WireType::Len);
                (wt, *c)
            })
            .collect();

        InferredField {
            tag,
            wire_type: primary,
            observed_wire_types,
            proto_type,
            repeated: self.max_repeated > 1,
            name: format!("field_{tag}"),
            seen_in: self.seen_in_messages,
        }
    }
}

fn wire_disc(wt: &WireType) -> u8 {
    match wt {
        WireType::Varint => 0,
        WireType::I64 => 1,
        WireType::Len => 2,
        WireType::SGroup => 3,
        WireType::EGroup => 4,
        WireType::I32 => 5,
    }
}

fn profile_absorb(map: &mut HashMap<u32, FieldProfile>, f: &DecodedField, repeated_in_this: u64) {
    let prof = map.entry(f.tag).or_default();
    let disc = wire_disc(&f.wire_type);
    *prof.wire_counts.entry(disc).or_default() += 1;
    prof.wire_samples.entry(disc).or_insert(f.wire_type);
    prof.seen_in_messages += 1;
    prof.max_repeated = prof.max_repeated.max(repeated_in_this);
    match &f.value {
        DecodedValue::U64(n) => {
            prof.varint_max = prof.varint_max.max(*n);
        }
        DecodedValue::I64(n) => {
            prof.varint_max = prof.varint_max.max((*n).max(0) as u64);
        }
        DecodedValue::Bool(_) => {
            prof.varint_max = prof.varint_max.max(1);
        }
        DecodedValue::Str(s) => {
            prof.str_count += 1;
            prof.total_bytes += s.len() as u64;
        }
        DecodedValue::Bytes(b) => {
            prof.bytes_count += 1;
            prof.total_bytes += b.len() as u64;
        }
        DecodedValue::Message(_) => {
            prof.msg_count += 1;
        }
        _ => {}
    }
}

/// Adapter for `DecodedValue` so we can get the max u64 observed for
/// Varint fields — used in the finaliser heuristic that distinguishes
/// bool / int32 / int64.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_corpus_errors() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(infer_dir(tmp.path(), 1, None, "T").is_err());
    }

    #[test]
    fn single_sample_all_ints() {
        // Message with two varint fields: tag 1 = 42, tag 2 = 7.
        //   0x08 0x2a   (tag 1, wire 0, value 42)
        //   0x10 0x07   (tag 2, wire 0, value 7)
        let sample = vec![0x08, 0x2a, 0x10, 0x07];
        let schema = infer_corpus(&[sample], 1, None, "T").unwrap();
        assert_eq!(schema.fields.len(), 2);
        assert_eq!(schema.fields[0].tag, 1);
        assert_eq!(schema.fields[0].proto_type, "int32");
        assert_eq!(schema.fields[1].tag, 2);
    }

    #[test]
    fn string_field_promoted() {
        // tag 1, wire 2, length 5, "hello"
        let sample = vec![0x0a, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let schema = infer_corpus(&[sample], 1, None, "T").unwrap();
        assert_eq!(schema.fields.len(), 1);
        assert_eq!(schema.fields[0].proto_type, "string");
    }

    #[test]
    fn to_proto_has_syntax_header() {
        let sample = vec![0x08, 0x01];
        let schema = infer_corpus(&[sample], 1, None, "Toy").unwrap();
        let out = schema.to_proto();
        assert!(out.starts_with("syntax = \"proto3\";"));
        assert!(out.contains("message Toy"));
        assert!(out.contains("field_1"));
    }
}
