//! Tools exposed to the LLM in `shannon ask`.
//!
//! Each tool is a function the model can call via the OpenAI tool-use
//! protocol. Tools are read-only queries against a loaded catalog and
//! an optional events NDJSON file — the LLM can't mutate shannon state.
//!
//! Tool discovery: the [`ToolSpec`]s describe the schema; [`dispatch`]
//! routes a `ToolCall` to its handler and returns the textual payload
//! the model will receive back.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::api_catalog::{ApiCatalog, EndpointSummary};
use crate::llm_client::{ToolCall, ToolSpec};

pub struct AskState {
    pub catalog: ApiCatalog,
    pub events_path: Option<PathBuf>,
}

impl AskState {
    pub fn new(catalog: ApiCatalog, events_path: Option<PathBuf>) -> Self {
        Self {
            catalog,
            events_path,
        }
    }

    pub fn available_tools() -> Vec<ToolSpec> {
        vec![
            ToolSpec::function(
                "list_endpoints",
                "List observed HTTP / gRPC endpoints with call counts and latency percentiles. Sort by 'calls' (default), 'p50', 'p99', or 'bytes'. Limit defaults to 20.",
                json!({
                    "type": "object",
                    "properties": {
                        "sort": { "type": "string", "enum": ["calls", "p50", "p99", "bytes"] },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 200 }
                    },
                    "additionalProperties": false
                }),
            ),
            ToolSpec::function(
                "get_endpoint",
                "Return full details (params, response status distribution, example values) for a single endpoint by its template, e.g. 'GET /users/{id}'.",
                json!({
                    "type": "object",
                    "properties": {
                        "template": { "type": "string" }
                    },
                    "required": ["template"],
                    "additionalProperties": false
                }),
            ),
            ToolSpec::function(
                "catalog_stats",
                "Return overall catalog statistics: total endpoint count, distinct hosts, total call count, fastest and slowest p99.",
                json!({
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }),
            ),
            ToolSpec::function(
                "search_events",
                "Grep through the events JSONL file for lines matching a pattern. Returns up to 'limit' (default 50) matching lines. Pattern is a plain-text substring match (case-sensitive).",
                json!({
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 500 }
                    },
                    "required": ["pattern"],
                    "additionalProperties": false
                }),
            ),
        ]
    }
}

/// Dispatch a tool call to its handler. Returns a plain-text result the
/// model will see as a `tool` message.
pub fn dispatch(state: &AskState, call: &ToolCall) -> Result<String> {
    let name = call.function.name.as_str();
    let args = call.parsed_args().unwrap_or(Value::Null);
    match name {
        "list_endpoints" => list_endpoints(state, &args),
        "get_endpoint" => get_endpoint(state, &args),
        "catalog_stats" => catalog_stats(state),
        "search_events" => search_events(state, &args),
        _ => Ok(format!("error: unknown tool '{name}'")),
    }
}

fn list_endpoints(state: &AskState, args: &Value) -> Result<String> {
    let sort = args.get("sort").and_then(|v| v.as_str()).unwrap_or("calls");
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(20)
        .min(200) as usize;

    let mut snap = state.catalog.snapshot();
    match sort {
        "p50" => snap.sort_by(|a, b| {
            b.latency_ms_p50
                .unwrap_or(0.0)
                .partial_cmp(&a.latency_ms_p50.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        "p99" => snap.sort_by(|a, b| {
            b.latency_ms_p99
                .unwrap_or(0.0)
                .partial_cmp(&a.latency_ms_p99.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        "bytes" => snap.sort_by(|a, b| {
            let ab = a.avg_request_bytes + a.avg_response_bytes;
            let bb = b.avg_request_bytes + b.avg_response_bytes;
            bb.cmp(&ab)
        }),
        _ => snap.sort_by(|a, b| b.call_count.cmp(&a.call_count)),
    }
    snap.truncate(limit);
    let rows: Vec<Value> = snap
        .iter()
        .map(|e| {
            json!({
                "key": e.key,
                "host": e.host,
                "method": e.method,
                "template": e.template,
                "call_count": e.call_count,
                "p50_ms": e.latency_ms_p50,
                "p99_ms": e.latency_ms_p99,
                "avg_req_bytes": e.avg_request_bytes,
                "avg_resp_bytes": e.avg_response_bytes,
            })
        })
        .collect();
    Ok(serde_json::to_string_pretty(&Value::Array(rows))?)
}

fn get_endpoint(state: &AskState, args: &Value) -> Result<String> {
    let template = args
        .get("template")
        .and_then(|v| v.as_str())
        .context("tool requires 'template' argument")?;
    let snap = state.catalog.snapshot();
    let hit = snap
        .iter()
        .find(|e| e.key == template || e.template == template);
    match hit {
        Some(e) => Ok(serde_json::to_string_pretty(&endpoint_detail(e))?),
        None => Ok(format!("no endpoint matching '{template}' in catalog")),
    }
}

fn endpoint_detail(e: &EndpointSummary) -> Value {
    let params = |p: &crate::api_catalog::ParamInfo| {
        json!({
            "name": p.name,
            "type": format!("{:?}", p.inferred_type),
            "example": p.example,
            "required": p.required,
            "sample_count": p.sample_count,
        })
    };
    json!({
        "key": e.key,
        "host": e.host,
        "method": e.method,
        "template": e.template,
        "call_count": e.call_count,
        "first_seen_unix": e.first_seen_unix,
        "last_seen_unix": e.last_seen_unix,
        "p50_ms": e.latency_ms_p50,
        "p99_ms": e.latency_ms_p99,
        "status_counts": e.status_counts,
        "path_params": e.path_params.iter().map(params).collect::<Vec<_>>(),
        "query_params": e.query_params.iter().map(params).collect::<Vec<_>>(),
        "header_params": e.header_params.iter().map(params).collect::<Vec<_>>(),
    })
}

fn catalog_stats(state: &AskState) -> Result<String> {
    let snap = state.catalog.snapshot();
    let total_calls: u64 = snap.iter().map(|e| e.call_count).sum();
    let mut hosts = HashMap::<String, u64>::new();
    for e in &snap {
        if let Some(h) = &e.host {
            *hosts.entry(h.clone()).or_default() += e.call_count;
        }
    }
    let mut p99_vec: Vec<f64> = snap.iter().filter_map(|e| e.latency_ms_p99).collect();
    p99_vec.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let result = json!({
        "endpoints": snap.len(),
        "distinct_hosts": hosts.len(),
        "total_calls": total_calls,
        "fastest_p99_ms": p99_vec.first(),
        "slowest_p99_ms": p99_vec.last(),
        "top_hosts": top_n(&hosts, 10),
    });
    Ok(serde_json::to_string_pretty(&result)?)
}

fn top_n(map: &HashMap<String, u64>, n: usize) -> Value {
    let mut v: Vec<(&String, &u64)> = map.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1));
    v.truncate(n);
    Value::Array(
        v.iter()
            .map(|(k, c)| json!({"host": k, "calls": c}))
            .collect(),
    )
}

fn search_events(state: &AskState, args: &Value) -> Result<String> {
    let pattern = args
        .get("pattern")
        .and_then(|v| v.as_str())
        .context("tool requires 'pattern' argument")?;
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(50)
        .min(500) as usize;
    let Some(path) = state.events_path.as_ref() else {
        return Ok("no events file configured; rerun shannon ask with --events PATH".into());
    };
    let matches = scan_file(path, pattern, limit)?;
    if matches.is_empty() {
        Ok("no matches".into())
    } else {
        Ok(matches.join("\n"))
    }
}

fn scan_file(path: &Path, pattern: &str, limit: usize) -> Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    f.seek(SeekFrom::Start(0))?;
    let reader: Box<dyn BufRead> = if n >= 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Box::new(BufReader::new(zstd::stream::Decoder::new(f)?))
    } else if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        Box::new(BufReader::new(flate2::read::GzDecoder::new(f)))
    } else {
        Box::new(BufReader::new(f))
    };
    let mut out = Vec::with_capacity(limit);
    for line in reader.lines().map_while(Result::ok) {
        if line.contains(pattern) {
            out.push(line);
            if out.len() >= limit {
                break;
            }
        }
    }
    Ok(out)
}
