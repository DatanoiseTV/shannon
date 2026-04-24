//! API catalog — ingest observed HTTP/gRPC records and maintain a
//! de-duplicated, self-describing inventory of endpoints.
//!
//! The module is deliberately self-contained: it consumes plain-data
//! *facts* (`Http1Fact` / `Http2Fact`) rather than parser types, so it
//! can be unit-tested without pulling the rest of the parser graph in.
//!
//! What it maintains per endpoint:
//!
//! * a URL template with inferred path parameters (`/users/{id}`)
//! * per-key query / header parameter info (type + example + required)
//! * per-status call counts
//! * fold-merged JSON schemas for request and response bodies
//! * P² online quantile estimators for p50/p99 latency
//! * byte-count averages
//!
//! Persists to JSON (versioned envelope, atomic rename on save) and can
//! export a hand-rolled `OpenAPI` 3.0.0 YAML document.

// The module deliberately accepts a short list of pedantic/nursery
// lints that produce mostly-stylistic noise for code that mixes
// long-lived mutex guards with fallible IO and many small helper
// functions.
#![allow(
    clippy::significant_drop_tightening,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::use_self,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_markdown,
    clippy::suboptimal_flops,
    clippy::manual_midpoint,
    clippy::redundant_clone,
    clippy::collapsible_if,
    clippy::explicit_iter_loop,
    clippy::unnecessary_map_or,
    clippy::if_same_then_else,
    clippy::uninlined_format_args,
    clippy::match_same_arms,
    clippy::ptr_arg
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Public error type
// ---------------------------------------------------------------------------

/// All errors surfaced by the catalog.
#[derive(Debug)]
pub enum CatalogError {
    Io(String),
    Parse(String),
    Serialize(String),
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "api-catalog io: {m}"),
            Self::Parse(m) => write!(f, "api-catalog parse: {m}"),
            Self::Serialize(m) => write!(f, "api-catalog serialize: {m}"),
        }
    }
}

impl std::error::Error for CatalogError {}

impl From<std::io::Error> for CatalogError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<serde_json::Error> for CatalogError {
    fn from(value: serde_json::Error) -> Self {
        Self::Parse(value.to_string())
    }
}

// ---------------------------------------------------------------------------
// Input facts — decoupled from parser types
// ---------------------------------------------------------------------------

/// HTTP/1 fact handed to the catalog. Holds both request and response
/// shapes; for a request, `status` is `None` and `method`/`path` are
/// populated. For a response, `status` is set and `method`/`path`
/// typically mirror the request's.
#[derive(Debug, Clone)]
pub struct Http1Fact {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub status: Option<u16>,
}

/// HTTP/2 fact, carrying either a request side (`method`+`path` set) or
/// response side (`status` set), or a gRPC surface (`grpc_service` /
/// `grpc_method` populated).
#[derive(Debug, Clone)]
pub struct Http2Fact {
    pub stream_id: u32,
    pub method: Option<String>,
    pub path: Option<String>,
    pub authority: Option<String>,
    pub content_type: Option<String>,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub grpc_service: Option<String>,
    pub grpc_method: Option<String>,
    pub grpc_status: Option<u32>,
    pub body: Vec<u8>,
    pub end_stream: bool,
}

// ---------------------------------------------------------------------------
// Public snapshot types
// ---------------------------------------------------------------------------

/// Inferred parameter type — shared between path/query/header params and
/// JSON body schema leaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamType {
    Integer,
    Number,
    Boolean,
    Uuid,
    String,
    Array(Box<ParamType>),
    Object,
    Unknown,
}

/// One inferred parameter (path segment, query key or header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamInfo {
    pub name: String,
    pub inferred_type: ParamType,
    pub example: Option<String>,
    pub sample_count: u64,
    pub distinct_values_seen: u64,
    pub required: bool,
}

/// Minimal inferred JSON schema node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSchema {
    pub ty: ParamType,
    pub properties: Vec<(String, JsonSchema)>,
    pub items: Option<Box<JsonSchema>>,
    pub required: Vec<String>,
    pub enum_values: Vec<String>,
    pub example: Option<String>,
}

/// Public read-only summary of a catalog endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSummary {
    pub key: String,
    pub host: Option<String>,
    pub method: String,
    pub template: String,
    pub grpc: Option<(String, String)>,
    pub call_count: u64,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub status_counts: Vec<(u16, u64)>,
    pub path_params: Vec<ParamInfo>,
    pub query_params: Vec<ParamInfo>,
    pub header_params: Vec<ParamInfo>,
    pub request_schema: Option<JsonSchema>,
    pub response_schema: Option<JsonSchema>,
    pub latency_ms_p50: Option<f64>,
    pub latency_ms_p99: Option<f64>,
    pub avg_request_bytes: u64,
    pub avg_response_bytes: u64,
}

// ---------------------------------------------------------------------------
// Internal book-keeping types
// ---------------------------------------------------------------------------

const MAX_EXAMPLES_PER_SEGMENT: usize = 16;
const MAX_SCHEMA_DEPTH: usize = 8;
const MAX_OBJ_PROPS: usize = 64;
const MAX_ARRAY_ITEMS: usize = 32;
const MAX_DISTINCT_STRINGS: usize = 64;
const ENUM_MAX_CARDINALITY: usize = 20;
const ENUM_MIN_OBSERVATIONS: u64 = 5;
const MAX_PAIR_BUFFER: usize = 512;

/// Per-path-position state used to decide when a segment should become a
/// `{placeholder}`.
#[derive(Debug, Clone, Default)]
struct SegmentStat {
    /// Recent concrete values seen (bounded).
    examples: Vec<String>,
    /// True once we've seen ≥2 distinct values all of the same detected
    /// class.
    collapsed: bool,
    /// The placeholder chosen on collapse (e.g. `{id}`, `{uuid}`).
    placeholder: Option<String>,
    /// Classification tag of the *last* observed class; used to detect
    /// all-same-class across the current examples.
    observed_class: Option<SegClass>,
    /// Total number of observations.
    seen: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegClass {
    Integer,
    Uuid,
    Ulid,
    Opaque,
    Hash,
    Literal,
}

impl SegClass {
    fn placeholder(self) -> &'static str {
        match self {
            Self::Integer => "{id}",
            Self::Uuid => "{uuid}",
            Self::Ulid => "{ulid}",
            Self::Opaque => "{opaque}",
            Self::Hash => "{hash}",
            Self::Literal => "",
        }
    }

    fn param_name(self) -> &'static str {
        match self {
            Self::Integer => "id",
            Self::Uuid => "uuid",
            Self::Ulid => "ulid",
            Self::Opaque => "opaque",
            Self::Hash => "hash",
            Self::Literal => "literal",
        }
    }

    fn param_type(self) -> ParamType {
        match self {
            Self::Integer => ParamType::Integer,
            Self::Uuid => ParamType::Uuid,
            _ => ParamType::String,
        }
    }
}

/// Accumulator for a single query-string key.
#[derive(Debug, Clone, Default)]
struct ParamAcc {
    examples: Vec<String>,
    /// Observations of this key.
    sample_count: u64,
    distinct: std::collections::BTreeSet<String>,
    /// Number of surrounding requests — used together with `sample_count`
    /// to decide whether the param is required.
    opportunity_count: u64,
    /// Collapsed set of distinct values, bounded so we don't unbounded-grow.
    overflow: bool,
    /// Whether this value should be redacted when surfacing examples.
    redact: bool,
}

/// P² quantile estimator (Jain & Chlamtac, 1985).
///
/// Maintains five markers representing the min, p, mid, (1+p)/2, max
/// heights and their positions. Supports single-quantile estimation; we
/// run two of these per endpoint (one for p=0.5, one for p=0.99).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct P2 {
    p: f64,
    n: [f64; 5],
    np: [f64; 5],
    dn: [f64; 5],
    q: [f64; 5],
    count: u64,
}

impl P2 {
    fn new(p: f64) -> Self {
        Self {
            p,
            n: [1.0, 2.0, 3.0, 4.0, 5.0],
            np: [1.0, 1.0 + 2.0 * p, 1.0 + 4.0 * p, 3.0 + 2.0 * p, 5.0],
            dn: [0.0, p / 2.0, p, (1.0 + p) / 2.0, 1.0],
            q: [0.0; 5],
            count: 0,
        }
    }

    fn observe(&mut self, x: f64) {
        self.count += 1;
        if self.count <= 5 {
            self.q[(self.count - 1) as usize] = x;
            if self.count == 5 {
                // bootstrap: sort markers
                let mut tmp = self.q;
                tmp.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                self.q = tmp;
            }
            return;
        }
        // Find cell k: 0..4
        let k = if x < self.q[0] {
            self.q[0] = x;
            0
        } else if x >= self.q[4] {
            self.q[4] = x;
            3
        } else {
            let mut k = 0;
            for i in 0..4 {
                if self.q[i] <= x && x < self.q[i + 1] {
                    k = i;
                    break;
                }
            }
            k
        };
        // Increment positions
        for i in (k + 1)..5 {
            self.n[i] += 1.0;
        }
        for i in 0..5 {
            self.np[i] += self.dn[i];
        }
        // Adjust inner markers
        for i in 1..4 {
            let d = self.np[i] - self.n[i];
            if (d >= 1.0 && self.n[i + 1] - self.n[i] > 1.0)
                || (d <= -1.0 && self.n[i - 1] - self.n[i] < -1.0)
            {
                let ds = d.signum();
                let parabolic = self.parabolic(i, ds);
                let new_q = if self.q[i - 1] < parabolic && parabolic < self.q[i + 1] {
                    parabolic
                } else {
                    self.linear(i, ds)
                };
                self.q[i] = new_q;
                self.n[i] += ds;
            }
        }
    }

    fn parabolic(&self, i: usize, d: f64) -> f64 {
        let num1 = d / (self.n[i + 1] - self.n[i - 1]);
        let t1 = (self.n[i] - self.n[i - 1] + d) * (self.q[i + 1] - self.q[i])
            / (self.n[i + 1] - self.n[i]);
        let t2 = (self.n[i + 1] - self.n[i] - d) * (self.q[i] - self.q[i - 1])
            / (self.n[i] - self.n[i - 1]);
        self.q[i] + num1 * (t1 + t2)
    }

    fn linear(&self, i: usize, d: f64) -> f64 {
        let j = if d > 0.0 { i + 1 } else { i - 1 };
        self.q[i] + d * (self.q[j] - self.q[i]) / (self.n[j] - self.n[i])
    }

    fn quantile(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else if self.count < 5 {
            // Fallback: direct quantile from stored samples.
            let mut samples: Vec<f64> = self.q[..(self.count as usize)].to_vec();
            samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let idx = (((samples.len() - 1) as f64) * self.p).round() as usize;
            Some(samples[idx])
        } else {
            Some(self.q[2])
        }
    }
}

/// Folded JSON schema accumulator. Tracks counts so that we can emit a
/// final schema with accurate `required` fields after N samples.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SchemaAcc {
    ty_votes: BTreeMap<String, u64>,
    /// For Object nodes: property name → (accumulator, how many object
    /// samples it appeared in).
    props: Vec<(String, Box<SchemaAcc>, u64)>,
    /// For Array nodes: merged item accumulator.
    items: Option<Box<SchemaAcc>>,
    /// For String nodes: distinct values observed (capped).
    distinct: std::collections::BTreeSet<String>,
    /// True once `distinct.len()` exceeds `MAX_DISTINCT_STRINGS`.
    distinct_overflow: bool,
    /// Total number of samples folded into this node.
    samples: u64,
    /// Total number of *object* samples at this node — drives required
    /// field detection.
    object_samples: u64,
    /// Last observed scrubbed example.
    example: Option<String>,
}

/// Per-endpoint mutable state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Endpoint {
    host: Option<String>,
    method: String,
    /// Literal original segments, bookkeeping for template derivation.
    #[serde(default)]
    segments: Vec<SegmentStatSerde>,
    #[serde(default)]
    grpc: Option<(String, String)>,
    call_count: u64,
    first_seen_unix: u64,
    last_seen_unix: u64,
    status_counts: BTreeMap<u16, u64>,
    query: BTreeMap<String, ParamAccSerde>,
    headers: BTreeMap<String, ParamAccSerde>,
    request_schema: Option<SchemaAcc>,
    response_schema: Option<SchemaAcc>,
    p50: P2,
    p99: P2,
    total_request_bytes: u64,
    total_response_bytes: u64,
    request_byte_samples: u64,
    response_byte_samples: u64,
}

/// Serde-friendly mirror of [`SegmentStat`]. `observed_class` is encoded
/// as a tag string.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SegmentStatSerde {
    examples: Vec<String>,
    collapsed: bool,
    placeholder: Option<String>,
    observed_class: Option<String>,
    seen: u64,
}

impl From<&SegmentStat> for SegmentStatSerde {
    fn from(s: &SegmentStat) -> Self {
        Self {
            examples: s.examples.clone(),
            collapsed: s.collapsed,
            placeholder: s.placeholder.clone(),
            observed_class: s.observed_class.map(|c| class_tag(c).to_string()),
            seen: s.seen,
        }
    }
}

impl From<&SegmentStatSerde> for SegmentStat {
    fn from(s: &SegmentStatSerde) -> Self {
        Self {
            examples: s.examples.clone(),
            collapsed: s.collapsed,
            placeholder: s.placeholder.clone(),
            observed_class: s.observed_class.as_deref().and_then(class_from_tag),
            seen: s.seen,
        }
    }
}

fn class_tag(c: SegClass) -> &'static str {
    match c {
        SegClass::Integer => "int",
        SegClass::Uuid => "uuid",
        SegClass::Ulid => "ulid",
        SegClass::Opaque => "opaque",
        SegClass::Hash => "hash",
        SegClass::Literal => "literal",
    }
}

fn class_from_tag(t: &str) -> Option<SegClass> {
    Some(match t {
        "int" => SegClass::Integer,
        "uuid" => SegClass::Uuid,
        "ulid" => SegClass::Ulid,
        "opaque" => SegClass::Opaque,
        "hash" => SegClass::Hash,
        "literal" => SegClass::Literal,
        _ => return None,
    })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ParamAccSerde {
    examples: Vec<String>,
    sample_count: u64,
    distinct: Vec<String>,
    opportunity_count: u64,
    overflow: bool,
    redact: bool,
}

impl From<&ParamAcc> for ParamAccSerde {
    fn from(p: &ParamAcc) -> Self {
        Self {
            examples: p.examples.clone(),
            sample_count: p.sample_count,
            distinct: p.distinct.iter().cloned().collect(),
            opportunity_count: p.opportunity_count,
            overflow: p.overflow,
            redact: p.redact,
        }
    }
}

impl From<&ParamAccSerde> for ParamAcc {
    fn from(p: &ParamAccSerde) -> Self {
        Self {
            examples: p.examples.clone(),
            sample_count: p.sample_count,
            distinct: p.distinct.iter().cloned().collect(),
            opportunity_count: p.opportunity_count,
            overflow: p.overflow,
            redact: p.redact,
        }
    }
}

impl Default for P2 {
    fn default() -> Self {
        Self::new(0.5)
    }
}

// ---------------------------------------------------------------------------
// Main catalog
// ---------------------------------------------------------------------------

/// Thread-safe API catalog; every mutating method takes `&self`.
#[derive(Debug, Default)]
pub struct ApiCatalog {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// `endpoint_key → endpoint state`.
    endpoints: BTreeMap<String, EndpointState>,
    /// Pending in-flight requests waiting for their response. Keyed by
    /// `(peer, stream_id)` for HTTP/2 and `(peer, "")` for HTTP/1 (one
    /// at a time per TCP connection is a reasonable approximation).
    pending: BTreeMap<(String, u32), PendingRequest>,
    /// Bounded FIFO ordering of pending keys for bounded memory.
    pending_order: std::collections::VecDeque<(String, u32)>,
}

#[derive(Debug)]
struct PendingRequest {
    endpoint_key: String,
    ts: SystemTime,
    req_bytes: usize,
}

/// The fully runtime representation of an endpoint (non-serde
/// `SegmentStat` uses our rich enum).
#[derive(Debug, Default)]
struct EndpointState {
    host: Option<String>,
    method: String,
    segments: Vec<SegmentStat>,
    grpc: Option<(String, String)>,
    call_count: u64,
    first_seen_unix: u64,
    last_seen_unix: u64,
    status_counts: BTreeMap<u16, u64>,
    query: BTreeMap<String, ParamAcc>,
    headers: BTreeMap<String, ParamAcc>,
    request_schema: Option<SchemaAcc>,
    response_schema: Option<SchemaAcc>,
    p50: P2,
    p99: P2,
    total_request_bytes: u64,
    total_response_bytes: u64,
    request_byte_samples: u64,
    response_byte_samples: u64,
}

impl EndpointState {
    fn to_serde(&self) -> Endpoint {
        Endpoint {
            host: self.host.clone(),
            method: self.method.clone(),
            segments: self.segments.iter().map(SegmentStatSerde::from).collect(),
            grpc: self.grpc.clone(),
            call_count: self.call_count,
            first_seen_unix: self.first_seen_unix,
            last_seen_unix: self.last_seen_unix,
            status_counts: self.status_counts.clone(),
            query: self
                .query
                .iter()
                .map(|(k, v)| (k.clone(), ParamAccSerde::from(v)))
                .collect(),
            headers: self
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), ParamAccSerde::from(v)))
                .collect(),
            request_schema: self.request_schema.clone(),
            response_schema: self.response_schema.clone(),
            p50: self.p50.clone(),
            p99: self.p99.clone(),
            total_request_bytes: self.total_request_bytes,
            total_response_bytes: self.total_response_bytes,
            request_byte_samples: self.request_byte_samples,
            response_byte_samples: self.response_byte_samples,
        }
    }

    fn from_serde(e: &Endpoint) -> Self {
        Self {
            host: e.host.clone(),
            method: e.method.clone(),
            segments: e.segments.iter().map(SegmentStat::from).collect(),
            grpc: e.grpc.clone(),
            call_count: e.call_count,
            first_seen_unix: e.first_seen_unix,
            last_seen_unix: e.last_seen_unix,
            status_counts: e.status_counts.clone(),
            query: e
                .query
                .iter()
                .map(|(k, v)| (k.clone(), ParamAcc::from(v)))
                .collect(),
            headers: e
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), ParamAcc::from(v)))
                .collect(),
            request_schema: e.request_schema.clone(),
            response_schema: e.response_schema.clone(),
            p50: e.p50.clone(),
            p99: e.p99.clone(),
            total_request_bytes: e.total_request_bytes,
            total_response_bytes: e.total_response_bytes,
            request_byte_samples: e.request_byte_samples,
            response_byte_samples: e.response_byte_samples,
        }
    }
}

/// On-disk envelope.
#[derive(Debug, Serialize, Deserialize)]
struct CatalogFile {
    version: u32,
    generated_unix: u64,
    endpoints: BTreeMap<String, Endpoint>,
}

impl ApiCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a previously saved catalog. If the file does not exist, an
    /// empty catalog is returned (convenient for first-run behaviour).
    pub fn load(path: &Path) -> Result<Self, CatalogError> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => return Err(CatalogError::Io(e.to_string())),
        };
        let file: CatalogFile =
            serde_json::from_slice(&bytes).map_err(|e| CatalogError::Parse(e.to_string()))?;
        let mut inner = Inner::default();
        for (k, v) in &file.endpoints {
            inner
                .endpoints
                .insert(k.clone(), EndpointState::from_serde(v));
        }
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Atomically persist the catalog as JSON.
    pub fn save(&self, path: &Path) -> Result<(), CatalogError> {
        let inner = self.inner.lock();
        let file = CatalogFile {
            version: 1,
            generated_unix: now_unix(),
            endpoints: inner
                .endpoints
                .iter()
                .map(|(k, v)| (k.clone(), v.to_serde()))
                .collect(),
        };
        let bytes =
            serde_json::to_vec_pretty(&file).map_err(|e| CatalogError::Serialize(e.to_string()))?;
        drop(inner);
        let tmp: PathBuf = {
            let mut p = path.as_os_str().to_owned();
            p.push(".tmp");
            PathBuf::from(p)
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(CatalogError::from)?;
            }
        }
        {
            let mut f = fs::File::create(&tmp).map_err(CatalogError::from)?;
            f.write_all(&bytes).map_err(CatalogError::from)?;
            f.sync_all().map_err(CatalogError::from)?;
        }
        fs::rename(&tmp, path).map_err(CatalogError::from)?;
        Ok(())
    }

    /// Export the catalog as OpenAPI 3.0.0 YAML.
    pub fn export_openapi(&self, path: &Path, title: &str) -> Result<(), CatalogError> {
        let snap = self.snapshot();
        let yaml = render_openapi(&snap, title);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(CatalogError::from)?;
            }
        }
        fs::write(path, yaml).map_err(CatalogError::from)?;
        Ok(())
    }

    /// Ingest a paired HTTP/1 request + optional response.
    pub fn record_http1(&self, req: &Http1Fact, resp: Option<&Http1Fact>, peer: &str) {
        let (path_only, query) = split_path_query(&req.path);
        let host = header_value(&req.headers, "host");
        let now = SystemTime::now();
        let mut guard = self.inner.lock();
        let (ep_key, ep) = ensure_endpoint(
            &mut guard.endpoints,
            host.as_deref(),
            &req.method,
            path_only,
            None,
        );
        ep.touch(now);
        ep.call_count += 1;
        apply_path_segments(ep, path_only);
        apply_query(ep, &query);
        apply_headers(ep, &req.headers);
        apply_body(ep, &req.headers, &req.body, true);
        ep.total_request_bytes += req.body.len() as u64;
        ep.request_byte_samples += 1;
        let ep_key = ep_key.clone();
        if let Some(resp) = resp {
            if let Some(st) = resp.status {
                *ep.status_counts.entry(st).or_default() += 1;
            }
            apply_body(ep, &resp.headers, &resp.body, false);
            ep.total_response_bytes += resp.body.len() as u64;
            ep.response_byte_samples += 1;
        } else {
            // Record as pending so a later explicit response call can
            // pair. HTTP/1 has no stream ID so we use 0.
            enqueue_pending(&mut guard, peer, 0, ep_key, now, req.body.len());
        }
    }

    /// Ingest a single HTTP/2 record (request or response fragment).
    pub fn record_http2(&self, rec: &Http2Fact, peer: &str) {
        let now = SystemTime::now();
        // gRPC path: method + path headers include /service/method.
        if rec.grpc_service.is_some() || rec.grpc_method.is_some() {
            let svc = rec.grpc_service.clone().unwrap_or_default();
            let method = rec.grpc_method.clone().unwrap_or_default();
            let st = rec.grpc_status;
            let req_bytes = if rec.status.is_none() && rec.method.is_some() {
                rec.body.len()
            } else {
                0
            };
            let resp_bytes = if rec.status.is_some() || rec.grpc_status.is_some() {
                rec.body.len()
            } else {
                0
            };
            drop_guard_and_record_grpc(self, &svc, &method, st, req_bytes, resp_bytes, peer);
            return;
        }

        let mut guard = self.inner.lock();
        // Request side.
        if let (Some(method), Some(path)) = (rec.method.clone(), rec.path.clone()) {
            let (path_only, query) = split_path_query(&path);
            let (ep_key, ep) = ensure_endpoint(
                &mut guard.endpoints,
                rec.authority.as_deref(),
                &method,
                path_only,
                None,
            );
            ep.touch(now);
            ep.call_count += 1;
            apply_path_segments(ep, path_only);
            apply_query(ep, &query);
            apply_headers(ep, &rec.headers);
            apply_body(ep, &rec.headers, &rec.body, true);
            ep.total_request_bytes += rec.body.len() as u64;
            ep.request_byte_samples += 1;
            let ep_key = ep_key.clone();
            enqueue_pending(&mut guard, peer, rec.stream_id, ep_key, now, rec.body.len());
            return;
        }

        // Response side: try to match pending by (peer, stream_id).
        if let Some(status) = rec.status {
            let k = (peer.to_string(), rec.stream_id);
            if let Some(pending) = guard.pending.remove(&k) {
                guard.pending_order.retain(|x| x != &k);
                let ep_key = pending.endpoint_key.clone();
                if let Some(ep) = guard.endpoints.get_mut(&ep_key) {
                    *ep.status_counts.entry(status).or_default() += 1;
                    apply_body(ep, &rec.headers, &rec.body, false);
                    ep.total_response_bytes += rec.body.len() as u64;
                    ep.response_byte_samples += 1;
                    if let Ok(elapsed) = now.duration_since(pending.ts) {
                        let ms = elapsed.as_secs_f64() * 1000.0;
                        ep.p50.observe(ms);
                        ep.p99.observe(ms);
                    }
                }
            }
        }
    }

    /// Record a gRPC fact directly (useful for the gRPC-on-HTTP/2 case
    /// where the caller has already parsed the service/method).
    pub fn record_grpc(
        &self,
        svc: &str,
        method: &str,
        status: Option<u32>,
        req_bytes: usize,
        resp_bytes: usize,
        peer: &str,
    ) {
        let now = SystemTime::now();
        let key = format!("gRPC {svc}/{method}");
        let mut guard = self.inner.lock();
        let ep = guard
            .endpoints
            .entry(key.clone())
            .or_insert_with(|| EndpointState {
                method: "gRPC".into(),
                grpc: Some((svc.to_string(), method.to_string())),
                first_seen_unix: now_unix(),
                ..EndpointState::default()
            });
        ep.touch(now);
        ep.call_count += 1;
        if let Some(st) = status {
            let code = u16::try_from(st).unwrap_or(u16::MAX);
            *ep.status_counts.entry(code).or_default() += 1;
        }
        if req_bytes > 0 {
            ep.total_request_bytes += req_bytes as u64;
            ep.request_byte_samples += 1;
        }
        if resp_bytes > 0 {
            ep.total_response_bytes += resp_bytes as u64;
            ep.response_byte_samples += 1;
        }
        let _ = peer; // peer is not load-bearing for gRPC de-duplication.
    }

    pub fn len(&self) -> usize {
        self.inner.lock().endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().endpoints.is_empty()
    }

    /// Materialise a snapshot of every endpoint.
    pub fn snapshot(&self) -> Vec<EndpointSummary> {
        let guard = self.inner.lock();
        guard
            .endpoints
            .iter()
            .map(|(key, ep)| summarise(key, ep))
            .collect()
    }
}

fn drop_guard_and_record_grpc(
    cat: &ApiCatalog,
    svc: &str,
    method: &str,
    st: Option<u32>,
    req_bytes: usize,
    resp_bytes: usize,
    peer: &str,
) {
    cat.record_grpc(svc, method, st, req_bytes, resp_bytes, peer);
}

// ---------------------------------------------------------------------------
// Endpoint-mutation helpers
// ---------------------------------------------------------------------------

impl EndpointState {
    fn touch(&mut self, now: SystemTime) {
        let t = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if self.first_seen_unix == 0 {
            self.first_seen_unix = t;
        }
        self.last_seen_unix = t;
        if self.p50.p == 0.0 {
            self.p50 = P2::new(0.5);
        }
        if self.p99.p == 0.0 {
            self.p99 = P2::new(0.99);
        }
    }
}

fn ensure_endpoint<'a>(
    map: &'a mut BTreeMap<String, EndpointState>,
    host: Option<&str>,
    method: &str,
    path: &str,
    grpc: Option<(String, String)>,
) -> (String, &'a mut EndpointState) {
    // The *template* (normalised form) is derived after segments are
    // folded. For keying we use host + method + path-signature, where
    // the path-signature is the best-effort current template (if the
    // endpoint was already seen before) or the concrete path (first
    // time). Since we're keyed by normalised template, we need to
    // locate a template-compatible endpoint.
    let host_s = host.unwrap_or("-").to_string();
    let incoming_segments: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    // Try to match any existing endpoint of same host+method with
    // compatible segment template.
    let mut chosen: Option<String> = None;
    for (k, ep) in map.iter() {
        if ep.method != method || ep.host.as_deref() != host {
            continue;
        }
        if ep.segments.len() != incoming_segments.len() {
            continue;
        }
        let compatible = ep
            .segments
            .iter()
            .zip(&incoming_segments)
            .all(|(stat, seg)| segment_compatible(stat, seg));
        if compatible {
            chosen = Some(k.clone());
            break;
        }
    }
    let key = chosen.unwrap_or_else(|| format!("{method} {host_s} {path}"));
    let entry = map.entry(key.clone()).or_insert_with(|| EndpointState {
        host: host.map(str::to_string),
        method: method.to_string(),
        segments: incoming_segments
            .iter()
            .map(|s| SegmentStat {
                examples: vec![(*s).to_string()],
                ..SegmentStat::default()
            })
            .collect(),
        grpc,
        first_seen_unix: now_unix(),
        ..EndpointState::default()
    });
    (key, entry)
}

fn segment_compatible(stat: &SegmentStat, seg: &str) -> bool {
    if stat.collapsed {
        // If already collapsed, the new segment must match the class.
        let c = classify_segment(seg);
        stat.observed_class.is_some_and(|oc| oc == c)
    } else {
        // Not yet collapsed. Either the literal matches one of the
        // existing examples, OR all examples share a common class with
        // this seg (which would collapse on next apply).
        if stat.examples.iter().any(|e| e == seg) {
            return true;
        }
        let c = classify_segment(seg);
        stat.examples.iter().all(|e| classify_segment(e) == c) && c != SegClass::Literal
    }
}

fn apply_path_segments(ep: &mut EndpointState, path: &str) {
    let segs: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if segs.len() != ep.segments.len() {
        // Path shape changed mid-flight; skip fold rather than scramble
        // templates. A separate endpoint would be created on the next
        // call via ensure_endpoint's compatibility check.
        return;
    }
    for (stat, seg) in ep.segments.iter_mut().zip(&segs) {
        stat.seen += 1;
        if stat.collapsed {
            if stat.examples.len() < MAX_EXAMPLES_PER_SEGMENT {
                if !stat.examples.iter().any(|e| e == *seg) {
                    stat.examples.push((*seg).to_string());
                }
            }
            continue;
        }
        if !stat.examples.iter().any(|e| e == *seg) {
            if stat.examples.len() < MAX_EXAMPLES_PER_SEGMENT {
                stat.examples.push((*seg).to_string());
            }
        }
        let classes: Vec<SegClass> = stat.examples.iter().map(|e| classify_segment(e)).collect();
        stat.observed_class = classes.last().copied();
        if stat.examples.len() >= 2 && !classes.is_empty() {
            let c0 = classes[0];
            if c0 != SegClass::Literal && classes.iter().all(|c| *c == c0) {
                stat.collapsed = true;
                stat.placeholder = Some(c0.placeholder().to_string());
                stat.observed_class = Some(c0);
            }
        }
    }
}

fn apply_query(ep: &mut EndpointState, query: &str) {
    let mut seen_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if !query.is_empty() {
        for kv in query.split('&') {
            if kv.is_empty() {
                continue;
            }
            let (k, v) = match kv.find('=') {
                Some(i) => (&kv[..i], &kv[i + 1..]),
                None => (kv, ""),
            };
            let key = url_decode(k);
            let val = url_decode(v);
            let redact = key_is_secret(&key);
            let acc = ep.query.entry(key.clone()).or_insert_with(|| ParamAcc {
                redact,
                ..ParamAcc::default()
            });
            acc.redact = acc.redact || redact;
            acc.sample_count += 1;
            let shown = if acc.redact {
                "<redacted>".to_string()
            } else {
                val.clone()
            };
            push_example(&mut acc.examples, &shown);
            if acc.distinct.len() < MAX_DISTINCT_STRINGS {
                acc.distinct.insert(val);
            } else {
                acc.overflow = true;
            }
            seen_keys.insert(key);
        }
    }
    for (k, acc) in ep.query.iter_mut() {
        acc.opportunity_count += 1;
        let _ = k;
    }
    // keys not seen this round simply don't get their sample_count bumped.
    let _ = seen_keys;
}

fn apply_headers(ep: &mut EndpointState, headers: &[(String, String)]) {
    for (name, value) in headers {
        let lname = name.to_ascii_lowercase();
        if is_standard_header(&lname) {
            continue;
        }
        let redact = header_always_redact(&lname) || key_is_secret(&lname);
        let acc = ep.headers.entry(lname.clone()).or_insert_with(|| ParamAcc {
            redact,
            ..ParamAcc::default()
        });
        acc.redact = acc.redact || redact;
        acc.sample_count += 1;
        acc.opportunity_count += 1;
        let shown = if acc.redact {
            "<redacted>".to_string()
        } else {
            value.clone()
        };
        push_example(&mut acc.examples, &shown);
        if acc.distinct.len() < MAX_DISTINCT_STRINGS {
            acc.distinct.insert(value.clone());
        } else {
            acc.overflow = true;
        }
    }
}

fn apply_body(ep: &mut EndpointState, headers: &[(String, String)], body: &[u8], is_request: bool) {
    if body.is_empty() {
        return;
    }
    let ct = header_value(headers, "content-type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let looks_json = ct.contains("application/json")
        || ct.contains("+json")
        || body.first().map_or(false, |b| *b == b'{' || *b == b'[');
    if !looks_json {
        return;
    }
    let Ok(val) = serde_json::from_slice::<Value>(body) else {
        return;
    };
    let slot = if is_request {
        &mut ep.request_schema
    } else {
        &mut ep.response_schema
    };
    let acc = slot.get_or_insert_with(SchemaAcc::default);
    fold_into(acc, &val, 0);
}

fn fold_into(acc: &mut SchemaAcc, val: &Value, depth: usize) {
    if depth >= MAX_SCHEMA_DEPTH {
        return;
    }
    acc.samples += 1;
    let ty = json_value_type(val);
    *acc.ty_votes
        .entry(param_type_tag(&ty).to_string())
        .or_default() += 1;
    match val {
        Value::Null => {}
        Value::Bool(b) => {
            acc.example = Some(b.to_string());
        }
        Value::Number(n) => {
            acc.example = Some(n.to_string());
        }
        Value::String(s) => {
            let s_redacted = scrub_string_example(s);
            acc.example = Some(truncate(&s_redacted, 64));
            if !acc.distinct_overflow {
                if acc.distinct.len() < MAX_DISTINCT_STRINGS {
                    acc.distinct.insert(s.clone());
                } else {
                    acc.distinct_overflow = true;
                }
            }
        }
        Value::Array(items) => {
            let items_acc = acc
                .items
                .get_or_insert_with(|| Box::new(SchemaAcc::default()));
            for (i, item) in items.iter().enumerate() {
                if i >= MAX_ARRAY_ITEMS {
                    break;
                }
                fold_into(items_acc, item, depth + 1);
            }
        }
        Value::Object(map) => {
            acc.object_samples += 1;
            for (k, v) in map.iter().take(MAX_OBJ_PROPS) {
                if key_is_secret(k) {
                    // Still fold the shape, but redact the example.
                    let sub = find_or_insert_prop(&mut acc.props, k);
                    sub.samples += 1;
                    *sub.ty_votes.entry("string".into()).or_default() += 1;
                    sub.example = Some("<redacted>".into());
                    let entry = find_prop_count_mut(&mut acc.props, k);
                    *entry += 1;
                    continue;
                }
                let sub = find_or_insert_prop(&mut acc.props, k);
                fold_into(sub, v, depth + 1);
                let entry = find_prop_count_mut(&mut acc.props, k);
                *entry += 1;
            }
        }
    }
}

fn find_or_insert_prop<'a>(
    props: &'a mut Vec<(String, Box<SchemaAcc>, u64)>,
    name: &str,
) -> &'a mut SchemaAcc {
    if let Some(idx) = props.iter().position(|(n, _, _)| n == name) {
        return &mut props[idx].1;
    }
    if props.len() < MAX_OBJ_PROPS {
        props.push((name.to_string(), Box::new(SchemaAcc::default()), 0));
        let last = props.len() - 1;
        return &mut props[last].1;
    }
    // Map into existing first prop to avoid panic; in practice
    // MAX_OBJ_PROPS is large.
    &mut props[0].1
}

fn find_prop_count_mut<'a>(
    props: &'a mut Vec<(String, Box<SchemaAcc>, u64)>,
    name: &str,
) -> &'a mut u64 {
    let idx = props.iter().position(|(n, _, _)| n == name).unwrap_or(0);
    &mut props[idx].2
}

// ---------------------------------------------------------------------------
// Pending request bookkeeping
// ---------------------------------------------------------------------------

fn enqueue_pending(
    inner: &mut Inner,
    peer: &str,
    stream: u32,
    ep_key: String,
    now: SystemTime,
    req_bytes: usize,
) {
    let k = (peer.to_string(), stream);
    if inner.pending.len() >= MAX_PAIR_BUFFER {
        if let Some(old) = inner.pending_order.pop_front() {
            inner.pending.remove(&old);
        }
    }
    inner.pending.insert(
        k.clone(),
        PendingRequest {
            endpoint_key: ep_key,
            ts: now,
            req_bytes,
        },
    );
    inner.pending_order.push_back(k);
}

// ---------------------------------------------------------------------------
// Classification + inference
// ---------------------------------------------------------------------------

fn classify_segment(s: &str) -> SegClass {
    if s.is_empty() {
        return SegClass::Literal;
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return SegClass::Integer;
    }
    if uuid_regex().is_match(s) {
        return SegClass::Uuid;
    }
    if s.len() == 26 && s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return SegClass::Ulid;
    }
    if s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return SegClass::Hash;
    }
    if s.len() >= 20 && s.chars().all(is_base64url) {
        return SegClass::Opaque;
    }
    SegClass::Literal
}

fn is_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn uuid_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .expect("valid uuid regex")
    })
}

fn secret_key_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(token|password|secret|api[_-]?key|authorization|cookie|credit|cc[-_]?num|ssn)",
        )
        .expect("valid secret regex")
    })
}

fn key_is_secret(name: &str) -> bool {
    secret_key_regex().is_match(name)
}

fn header_always_redact(lname: &str) -> bool {
    matches!(
        lname,
        "authorization" | "cookie" | "set-cookie" | "proxy-authorization"
    )
}

fn is_standard_header(lname: &str) -> bool {
    matches!(
        lname,
        "host"
            | "user-agent"
            | "accept"
            | "accept-encoding"
            | "accept-language"
            | "cache-control"
            | "connection"
            | "content-length"
            | "content-type"
            | "content-encoding"
            | "date"
            | "etag"
            | "expect"
            | "expires"
            | "if-match"
            | "if-none-match"
            | "if-modified-since"
            | "last-modified"
            | "pragma"
            | "referer"
            | "server"
            | "transfer-encoding"
            | "upgrade"
            | "vary"
            | "via"
            | ":method"
            | ":path"
            | ":scheme"
            | ":authority"
            | ":status"
    )
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(name) {
            return Some(v.clone());
        }
    }
    None
}

fn split_path_query(path_and_query: &str) -> (&str, String) {
    match path_and_query.find('?') {
        Some(i) => (&path_and_query[..i], path_and_query[i + 1..].to_string()),
        None => (path_and_query, String::new()),
    }
}

fn url_decode(s: &str) -> String {
    // Minimal percent-decoder plus `+` → ' '.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'+' {
            out.push(b' ');
            i += 1;
        } else if c == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
            } else {
                out.push(c);
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn push_example(examples: &mut Vec<String>, v: &str) {
    if examples.len() >= MAX_EXAMPLES_PER_SEGMENT {
        examples.remove(0);
    }
    examples.push(v.to_string());
}

fn json_value_type(v: &Value) -> ParamType {
    match v {
        Value::Null => ParamType::Unknown,
        Value::Bool(_) => ParamType::Boolean,
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                ParamType::Integer
            } else {
                ParamType::Number
            }
        }
        Value::String(s) => {
            if uuid_regex().is_match(s) {
                ParamType::Uuid
            } else {
                ParamType::String
            }
        }
        Value::Array(_) => ParamType::Array(Box::new(ParamType::Unknown)),
        Value::Object(_) => ParamType::Object,
    }
}

fn param_type_tag(t: &ParamType) -> &'static str {
    match t {
        ParamType::Integer => "integer",
        ParamType::Number => "number",
        ParamType::Boolean => "boolean",
        ParamType::Uuid => "uuid",
        ParamType::String => "string",
        ParamType::Array(_) => "array",
        ParamType::Object => "object",
        ParamType::Unknown => "unknown",
    }
}

fn scrub_string_example(s: &str) -> String {
    // If the *value* itself looks like an obvious token (very long
    // alnum, JWT shape), replace wholesale.
    let trimmed = s.trim();
    if trimmed.len() > 64
        && trimmed
            .chars()
            .all(|c| is_base64url(c) || c == '.' || c == '=')
    {
        return "<redacted>".into();
    }
    s.to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut out = s[..max.min(s.len())].to_string();
        out.push('…');
        out
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Value-type inference for query strings
// ---------------------------------------------------------------------------

fn infer_value_type<'a, I: Iterator<Item = &'a String>>(iter: I) -> ParamType {
    let mut all_int = true;
    let mut all_number = true;
    let mut all_bool = true;
    let mut all_uuid = true;
    let mut any = false;
    for v in iter {
        any = true;
        if v.parse::<i64>().is_err() {
            all_int = false;
        }
        if v.parse::<f64>().is_err() {
            all_number = false;
        }
        if !matches!(
            v.to_ascii_lowercase().as_str(),
            "true" | "false" | "1" | "0" | "yes" | "no" | "on" | "off"
        ) {
            all_bool = false;
        }
        if !uuid_regex().is_match(v) {
            all_uuid = false;
        }
    }
    if !any {
        return ParamType::Unknown;
    }
    if all_int {
        ParamType::Integer
    } else if all_number {
        ParamType::Number
    } else if all_bool {
        ParamType::Boolean
    } else if all_uuid {
        ParamType::Uuid
    } else {
        ParamType::String
    }
}

// ---------------------------------------------------------------------------
// Summarisation
// ---------------------------------------------------------------------------

fn template_from_segments(segs: &[SegmentStat]) -> String {
    let mut out = String::new();
    out.push('/');
    let mut first = true;
    for s in segs {
        if !first {
            out.push('/');
        }
        first = false;
        if s.collapsed {
            if let Some(p) = &s.placeholder {
                out.push_str(p);
            } else {
                out.push_str("{param}");
            }
        } else {
            // Pick first example if only one, else {param}.
            if s.examples.len() == 1 {
                out.push_str(&s.examples[0]);
            } else if s.examples.is_empty() {
                out.push_str("{param}");
            } else {
                out.push_str(&s.examples[0]);
            }
        }
    }
    out
}

fn summarise(key: &str, ep: &EndpointState) -> EndpointSummary {
    let template = if ep.segments.is_empty() {
        "/".to_string()
    } else {
        template_from_segments(&ep.segments)
    };
    // Rebuild a stable key keyed by method + host + template.
    let key_out = ep.grpc.as_ref().map_or_else(
        || {
            format!(
                "{} {} {}",
                ep.method,
                ep.host.as_deref().unwrap_or("-"),
                template
            )
        },
        |(s, m)| format!("gRPC {s}/{m}"),
    );

    let status_counts: Vec<(u16, u64)> = ep.status_counts.iter().map(|(k, v)| (*k, *v)).collect();

    let path_params: Vec<ParamInfo> = ep
        .segments
        .iter()
        .filter(|s| s.collapsed)
        .map(|s| {
            let class = s.observed_class.unwrap_or(SegClass::Literal);
            let example = s.examples.last().cloned();
            let distinct = s.examples.len() as u64;
            ParamInfo {
                name: class.param_name().to_string(),
                inferred_type: class.param_type(),
                example,
                sample_count: s.seen,
                distinct_values_seen: distinct,
                required: true,
            }
        })
        .collect();

    let mut query_params: Vec<ParamInfo> = ep
        .query
        .iter()
        .map(|(k, acc)| {
            let ty = infer_value_type(acc.distinct.iter());
            let example = acc.examples.last().cloned();
            let total_requests = ep.call_count.max(1);
            let required = acc.sample_count >= total_requests;
            ParamInfo {
                name: k.clone(),
                inferred_type: ty,
                example,
                sample_count: acc.sample_count,
                distinct_values_seen: acc.distinct.len() as u64,
                required,
            }
        })
        .collect();
    query_params.sort_by(|a, b| a.name.cmp(&b.name));

    let mut header_params: Vec<ParamInfo> = ep
        .headers
        .iter()
        .map(|(k, acc)| {
            let ty = infer_value_type(acc.distinct.iter());
            let example = acc.examples.last().cloned();
            let total_requests = ep.call_count.max(1);
            let required = acc.sample_count >= total_requests;
            ParamInfo {
                name: k.clone(),
                inferred_type: ty,
                example,
                sample_count: acc.sample_count,
                distinct_values_seen: acc.distinct.len() as u64,
                required,
            }
        })
        .collect();
    header_params.sort_by(|a, b| a.name.cmp(&b.name));

    let request_schema = ep.request_schema.as_ref().map(finalise_schema);
    let response_schema = ep.response_schema.as_ref().map(finalise_schema);

    let latency_ms_p50 = ep.p50.quantile();
    let latency_ms_p99 = ep.p99.quantile();

    let avg_request_bytes = if ep.request_byte_samples > 0 {
        ep.total_request_bytes / ep.request_byte_samples
    } else {
        0
    };
    let avg_response_bytes = if ep.response_byte_samples > 0 {
        ep.total_response_bytes / ep.response_byte_samples
    } else {
        0
    };

    let _ = key;
    EndpointSummary {
        key: key_out,
        host: ep.host.clone(),
        method: ep.method.clone(),
        template,
        grpc: ep.grpc.clone(),
        call_count: ep.call_count,
        first_seen_unix: ep.first_seen_unix,
        last_seen_unix: ep.last_seen_unix,
        status_counts,
        path_params,
        query_params,
        header_params,
        request_schema,
        response_schema,
        latency_ms_p50,
        latency_ms_p99,
        avg_request_bytes,
        avg_response_bytes,
    }
}

fn finalise_schema(acc: &SchemaAcc) -> JsonSchema {
    let ty = dominant_type(&acc.ty_votes);
    let mut required: Vec<String> = Vec::new();
    let mut properties: Vec<(String, JsonSchema)> = Vec::new();
    if matches!(ty, ParamType::Object) && acc.object_samples > 0 {
        for (name, sub, count) in &acc.props {
            let child = finalise_schema(sub);
            if *count >= acc.object_samples {
                required.push(name.clone());
            }
            properties.push((name.clone(), child));
        }
    }
    let items = acc.items.as_ref().map(|it| Box::new(finalise_schema(it)));
    let enum_values: Vec<String> = if matches!(ty, ParamType::String)
        && !acc.distinct_overflow
        && acc.samples >= ENUM_MIN_OBSERVATIONS
        && acc.distinct.len() <= ENUM_MAX_CARDINALITY
        && acc.distinct.len() > 1
    {
        let mut v: Vec<String> = acc.distinct.iter().cloned().collect();
        v.sort();
        v
    } else {
        Vec::new()
    };
    JsonSchema {
        ty,
        properties,
        items,
        required,
        enum_values,
        example: acc.example.clone(),
    }
}

fn dominant_type(votes: &BTreeMap<String, u64>) -> ParamType {
    let mut best: Option<(&String, u64)> = None;
    for (k, v) in votes {
        if k == "unknown" {
            continue;
        }
        if best.as_ref().is_none_or(|(_, bv)| *v > *bv) {
            best = Some((k, *v));
        }
    }
    match best.map(|(k, _)| k.as_str()) {
        Some("integer") => ParamType::Integer,
        Some("number") => ParamType::Number,
        Some("boolean") => ParamType::Boolean,
        Some("uuid") => ParamType::Uuid,
        Some("string") => ParamType::String,
        Some("array") => ParamType::Array(Box::new(ParamType::Unknown)),
        Some("object") => ParamType::Object,
        _ => ParamType::Unknown,
    }
}

// ---------------------------------------------------------------------------
// OpenAPI emission
// ---------------------------------------------------------------------------

fn render_openapi(endpoints: &[EndpointSummary], title: &str) -> String {
    let mut out = String::new();
    writeln!(out, "openapi: 3.0.0").unwrap();
    writeln!(out, "info:").unwrap();
    writeln!(out, "  title: {}", yaml_escape(title)).unwrap();
    writeln!(out, "  version: \"1.0.0\"").unwrap();
    writeln!(out, "paths:").unwrap();

    // Group endpoints by template so each path holds one or more
    // method entries.
    let mut by_template: BTreeMap<String, Vec<&EndpointSummary>> = BTreeMap::new();
    for ep in endpoints {
        if ep.grpc.is_some() {
            // gRPC endpoints are emitted separately as x-grpc.
            continue;
        }
        by_template.entry(ep.template.clone()).or_default().push(ep);
    }
    for (template, group) in &by_template {
        writeln!(out, "  {}:", yaml_path(template)).unwrap();
        for ep in group {
            let method_l = ep.method.to_ascii_lowercase();
            writeln!(out, "    {method_l}:").unwrap();
            writeln!(
                out,
                "      summary: \"{} {} ({} calls)\"",
                yaml_escape_inner(&ep.method),
                yaml_escape_inner(&ep.template),
                ep.call_count
            )
            .unwrap();
            writeln!(
                out,
                "      description: \"auto-generated from observed traffic\""
            )
            .unwrap();
            writeln!(out, "      x-call-count: {}", ep.call_count).unwrap();
            writeln!(out, "      x-first-seen: {}", ep.first_seen_unix).unwrap();
            writeln!(out, "      x-last-seen: {}", ep.last_seen_unix).unwrap();
            if let Some(p50) = ep.latency_ms_p50 {
                writeln!(out, "      x-latency-p50-ms: {p50:.3}").unwrap();
            }
            if let Some(p99) = ep.latency_ms_p99 {
                writeln!(out, "      x-latency-p99-ms: {p99:.3}").unwrap();
            }
            if !ep.path_params.is_empty()
                || !ep.query_params.is_empty()
                || !ep.header_params.is_empty()
            {
                writeln!(out, "      parameters:").unwrap();
                for p in &ep.path_params {
                    emit_param(&mut out, p, "path", true);
                }
                for p in &ep.query_params {
                    emit_param(&mut out, p, "query", p.required);
                }
                for p in &ep.header_params {
                    emit_param(&mut out, p, "header", p.required);
                }
            }
            if let Some(rs) = &ep.request_schema {
                writeln!(out, "      requestBody:").unwrap();
                writeln!(out, "        required: true").unwrap();
                writeln!(out, "        content:").unwrap();
                writeln!(out, "          application/json:").unwrap();
                writeln!(out, "            schema:").unwrap();
                emit_schema(&mut out, rs, 14);
            }
            writeln!(out, "      responses:").unwrap();
            if ep.status_counts.is_empty() {
                writeln!(out, "        default:").unwrap();
                writeln!(out, "          description: \"observed\"").unwrap();
            } else {
                for (st, ct) in &ep.status_counts {
                    writeln!(out, "        \"{st}\":").unwrap();
                    writeln!(out, "          description: \"observed {ct} times\"").unwrap();
                    if let Some(rs) = &ep.response_schema {
                        writeln!(out, "          content:").unwrap();
                        writeln!(out, "            application/json:").unwrap();
                        writeln!(out, "              schema:").unwrap();
                        emit_schema(&mut out, rs, 16);
                    }
                }
            }
        }
    }
    // gRPC listing as vendor extension.
    let grpc: Vec<&EndpointSummary> = endpoints.iter().filter(|e| e.grpc.is_some()).collect();
    if !grpc.is_empty() {
        writeln!(out, "x-grpc-services:").unwrap();
        for ep in grpc {
            if let Some((s, m)) = &ep.grpc {
                writeln!(out, "  - service: {}", yaml_escape(s)).unwrap();
                writeln!(out, "    method: {}", yaml_escape(m)).unwrap();
                writeln!(out, "    x-call-count: {}", ep.call_count).unwrap();
            }
        }
    }
    out
}

fn emit_param(out: &mut String, p: &ParamInfo, r#in: &str, required: bool) {
    writeln!(out, "        - name: {}", yaml_escape(&p.name)).unwrap();
    writeln!(out, "          in: {}", r#in).unwrap();
    writeln!(out, "          required: {required}").unwrap();
    writeln!(out, "          schema:").unwrap();
    writeln!(out, "            type: {}", openapi_type(&p.inferred_type)).unwrap();
    if matches!(p.inferred_type, ParamType::Uuid) {
        writeln!(out, "            format: uuid").unwrap();
    }
    if let Some(ex) = &p.example {
        writeln!(out, "          example: {}", yaml_escape(ex)).unwrap();
    }
}

fn emit_schema(out: &mut String, schema: &JsonSchema, indent: usize) {
    let pad = " ".repeat(indent);
    writeln!(out, "{pad}type: {}", openapi_type(&schema.ty)).unwrap();
    if matches!(schema.ty, ParamType::Uuid) {
        writeln!(out, "{pad}format: uuid").unwrap();
    }
    if !schema.enum_values.is_empty() {
        writeln!(out, "{pad}enum:").unwrap();
        for v in &schema.enum_values {
            writeln!(out, "{pad}  - {}", yaml_escape(v)).unwrap();
        }
    }
    if matches!(schema.ty, ParamType::Object) && !schema.properties.is_empty() {
        if !schema.required.is_empty() {
            writeln!(out, "{pad}required:").unwrap();
            for r in &schema.required {
                writeln!(out, "{pad}  - {}", yaml_escape(r)).unwrap();
            }
        }
        writeln!(out, "{pad}properties:").unwrap();
        for (n, sub) in &schema.properties {
            writeln!(out, "{pad}  {}:", yaml_escape(n)).unwrap();
            emit_schema(out, sub, indent + 4);
        }
    }
    if let Some(items) = &schema.items {
        writeln!(out, "{pad}items:").unwrap();
        emit_schema(out, items, indent + 2);
    }
    if let Some(ex) = &schema.example {
        writeln!(out, "{pad}example: {}", yaml_escape(ex)).unwrap();
    }
}

fn openapi_type(t: &ParamType) -> &'static str {
    match t {
        ParamType::Integer => "integer",
        ParamType::Number => "number",
        ParamType::Boolean => "boolean",
        ParamType::Uuid | ParamType::String => "string",
        ParamType::Array(_) => "array",
        ParamType::Object => "object",
        ParamType::Unknown => "string",
    }
}

fn yaml_escape(s: &str) -> String {
    // Quote + escape control chars + quotes.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
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
    out
}

fn yaml_escape_inner(s: &str) -> String {
    // Used inside a string already quoted with '"'; escape the inner '"'.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn yaml_path(p: &str) -> String {
    // YAML keys starting with '/' are fine unquoted, but we quote for
    // safety when the path has colons or other specials.
    if p.chars()
        .any(|c| matches!(c, ':' | '#' | '&' | '*' | '!' | '|' | '>' | '%' | '@' | '`'))
    {
        yaml_escape(p)
    } else {
        format!("\"{p}\"")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn mk_req(method: &str, path: &str) -> Http1Fact {
        Http1Fact {
            method: method.into(),
            path: path.into(),
            headers: vec![("Host".into(), "api.example.com".into())],
            body: Vec::new(),
            status: None,
        }
    }

    fn mk_req_body(method: &str, path: &str, body: &[u8]) -> Http1Fact {
        Http1Fact {
            method: method.into(),
            path: path.into(),
            headers: vec![
                ("Host".into(), "api.example.com".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: body.to_vec(),
            status: None,
        }
    }

    #[test]
    fn integer_path_collapses_to_id() {
        let c = ApiCatalog::new();
        c.record_http1(&mk_req("GET", "/users/1"), None, "p1");
        c.record_http1(&mk_req("GET", "/users/42"), None, "p1");
        let snap = c.snapshot();
        assert_eq!(snap.len(), 1, "snap={snap:?}");
        let ep = &snap[0];
        assert_eq!(ep.template, "/users/{id}");
        assert_eq!(ep.path_params.len(), 1);
        assert_eq!(ep.path_params[0].inferred_type, ParamType::Integer);
        assert_eq!(ep.call_count, 2);
    }

    #[test]
    fn uuid_path_collapses_to_uuid() {
        let c = ApiCatalog::new();
        c.record_http1(
            &mk_req("GET", "/orders/7b9f92f8-1234-4abc-8def-0123456789ab"),
            None,
            "p",
        );
        c.record_http1(
            &mk_req("GET", "/orders/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
            None,
            "p",
        );
        let snap = c.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].template, "/orders/{uuid}");
        assert_eq!(snap[0].path_params[0].inferred_type, ParamType::Uuid);
    }

    #[test]
    fn query_param_with_two_values_required_and_string_typed() {
        let c = ApiCatalog::new();
        c.record_http1(&mk_req("GET", "/feed?tab=recent"), None, "p");
        c.record_http1(&mk_req("GET", "/feed?tab=starred"), None, "p");
        let snap = c.snapshot();
        assert_eq!(snap.len(), 1);
        let ep = &snap[0];
        assert_eq!(ep.query_params.len(), 1);
        let q = &ep.query_params[0];
        assert_eq!(q.name, "tab");
        assert_eq!(q.inferred_type, ParamType::String);
        assert_eq!(q.distinct_values_seen, 2);
        assert!(q.required);
    }

    #[test]
    fn json_body_required_fields_and_types() {
        let c = ApiCatalog::new();
        c.record_http1(
            &mk_req_body("POST", "/widgets", br#"{"name":"a","age":1}"#),
            None,
            "p",
        );
        c.record_http1(
            &mk_req_body("POST", "/widgets", br#"{"name":"b","age":2,"admin":true}"#),
            None,
            "p",
        );
        let snap = c.snapshot();
        let ep = &snap[0];
        let rs = ep.request_schema.as_ref().expect("request schema");
        assert_eq!(rs.ty, ParamType::Object);
        let mut names: Vec<String> = rs.properties.iter().map(|(n, _)| n.clone()).collect();
        names.sort();
        assert_eq!(names, vec!["admin", "age", "name"]);
        let required: std::collections::BTreeSet<String> = rs.required.iter().cloned().collect();
        assert!(required.contains("name"));
        assert!(required.contains("age"));
        assert!(!required.contains("admin"));
        for (n, sub) in &rs.properties {
            match n.as_str() {
                "name" => assert_eq!(sub.ty, ParamType::String),
                "age" => assert_eq!(sub.ty, ParamType::Integer),
                "admin" => assert_eq!(sub.ty, ParamType::Boolean),
                _ => {}
            }
        }
    }

    #[test]
    fn authorization_header_redacted() {
        let c = ApiCatalog::new();
        let mut r = mk_req("GET", "/me");
        r.headers
            .push(("Authorization".into(), "Bearer xyz".into()));
        c.record_http1(&r, None, "p");
        let snap = c.snapshot();
        let ep = &snap[0];
        let h = ep
            .header_params
            .iter()
            .find(|p| p.name == "authorization")
            .expect("authorization header");
        assert_eq!(h.example.as_deref(), Some("<redacted>"));
    }

    #[test]
    fn enum_values_detected_for_role() {
        let c = ApiCatalog::new();
        let bodies: [&[u8]; 6] = [
            br#"{"role":"admin"}"#,
            br#"{"role":"user"}"#,
            br#"{"role":"guest"}"#,
            br#"{"role":"admin"}"#,
            br#"{"role":"user"}"#,
            br#"{"role":"guest"}"#,
        ];
        for b in bodies {
            c.record_http1(&mk_req_body("POST", "/auth", b), None, "p");
        }
        let snap = c.snapshot();
        let rs = snap[0].request_schema.as_ref().unwrap();
        let role = rs.properties.iter().find(|(n, _)| n == "role").unwrap();
        let mut ev = role.1.enum_values.clone();
        ev.sort();
        assert_eq!(ev, vec!["admin".to_string(), "guest".into(), "user".into()]);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("catalog.json");
        let c = ApiCatalog::new();
        c.record_http1(&mk_req("GET", "/users/1"), None, "p");
        c.record_http1(&mk_req("GET", "/users/2"), None, "p");
        c.save(&p).unwrap();
        let mut bytes = Vec::new();
        fs::File::open(&p).unwrap().read_to_end(&mut bytes).unwrap();
        assert!(!bytes.is_empty());
        let c2 = ApiCatalog::load(&p).unwrap();
        let s1 = c.snapshot();
        let s2 = c2.snapshot();
        assert_eq!(s1.len(), s2.len());
        assert_eq!(s1[0].template, s2[0].template);
        assert_eq!(s1[0].call_count, s2[0].call_count);
    }

    #[test]
    fn openapi_contains_expected_keys() {
        let c = ApiCatalog::new();
        let mut r = mk_req("GET", "/users/1?active=true");
        r.headers.push(("X-Tenant".into(), "acme".into()));
        c.record_http1(&r, None, "p");
        let mut r2 = mk_req("GET", "/users/2?active=false");
        r2.headers.push(("X-Tenant".into(), "acme".into()));
        c.record_http1(&r2, None, "p");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.yaml");
        c.export_openapi(&path, "test-svc").unwrap();
        let s = fs::read_to_string(&path).unwrap();
        assert!(s.contains("openapi: 3.0.0"), "yaml={s}");
        assert!(s.contains("paths:"));
        assert!(s.contains("parameters:"));
        assert!(s.contains("in: path"));
        assert!(s.contains("in: query"));
        assert!(s.contains("x-call-count"));
    }

    #[test]
    fn http2_request_response_pairs_by_stream() {
        let c = ApiCatalog::new();
        let req = Http2Fact {
            stream_id: 1,
            method: Some("GET".into()),
            path: Some("/v1/ping".into()),
            authority: Some("svc".into()),
            content_type: None,
            status: None,
            headers: vec![],
            grpc_service: None,
            grpc_method: None,
            grpc_status: None,
            body: vec![],
            end_stream: false,
        };
        c.record_http2(&req, "peerA");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let resp = Http2Fact {
            stream_id: 1,
            method: None,
            path: None,
            authority: Some("svc".into()),
            content_type: None,
            status: Some(200),
            headers: vec![],
            grpc_service: None,
            grpc_method: None,
            grpc_status: None,
            body: vec![],
            end_stream: true,
        };
        c.record_http2(&resp, "peerA");
        let snap = c.snapshot();
        assert_eq!(snap.len(), 1);
        let ep = &snap[0];
        assert_eq!(ep.status_counts, vec![(200, 1)]);
        assert!(ep.latency_ms_p50.is_some());
    }

    #[test]
    fn grpc_records_accumulate() {
        let c = ApiCatalog::new();
        c.record_grpc("my.Svc", "DoThing", Some(0), 12, 34, "peer");
        c.record_grpc("my.Svc", "DoThing", Some(0), 8, 20, "peer");
        let snap = c.snapshot();
        assert_eq!(snap.len(), 1);
        let ep = &snap[0];
        assert_eq!(ep.method, "gRPC");
        assert_eq!(ep.grpc.as_ref().unwrap().0, "my.Svc");
        assert_eq!(ep.call_count, 2);
    }

    #[test]
    fn p2_quantile_reasonable() {
        let mut p = P2::new(0.5);
        for i in 1..=1000u64 {
            p.observe(i as f64);
        }
        let med = p.quantile().unwrap();
        assert!((450.0..=550.0).contains(&med), "median was {med}");
    }
}
