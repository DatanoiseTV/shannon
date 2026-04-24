//! Config file support. Every flag works without a config; the file exists
//! only to persist defaults across invocations.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

/// On-disk configuration. All fields are optional so an empty file is valid.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Default redaction mode (`auto` | `strict` | `off`).
    pub redact: Option<String>,
    /// Default maximum body size in bytes for `trace` output.
    pub max_body: Option<u32>,
    /// Default theme for `watch`.
    pub theme: Option<String>,
    /// Additional cgroup paths to always include.
    #[serde(default)]
    pub always_include_cgroups: Vec<PathBuf>,
    /// PIDs to always exclude.
    #[serde(default)]
    pub always_exclude_pids: Vec<u32>,
    /// comm globs to always exclude.
    #[serde(default)]
    pub always_exclude_comms: Vec<String>,
}

impl Config {
    /// Load from `path`, or return `Config::default()` if the file does not
    /// exist. Parse errors are reported.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(body) => toml::from_str(&body)
                .with_context(|| format!("parsing config {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
        }
    }

    /// Default on-disk path, resolved at runtime from `$XDG_CONFIG_HOME` or
    /// `$HOME/.config`.
    pub fn default_path() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("shannon").join("config.toml"))
    }
}

// Local, minimal TOML parser — we don't need the full `toml` crate here for
// three optional strings plus a few vectors. Using `toml_edit` would pull in
// ~100KB of extra compile time; a small home-rolled parser is fine for a
// flat schema.
mod toml {
    use std::collections::BTreeMap;

    /// Parse a toml string into our config. Only supports the subset we need:
    /// top-level string/number/bool values and arrays of strings/numbers. No
    /// tables, no nested structures.
    pub fn from_str<T: for<'de> serde::Deserialize<'de>>(s: &str) -> anyhow::Result<T> {
        let mut map: BTreeMap<String, Value> = BTreeMap::new();
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                anyhow::bail!("malformed line: {line}");
            };
            map.insert(k.trim().to_string(), Value::parse(v.trim())?);
        }
        let json = serde_json::to_value(&map)?;
        Ok(serde_json::from_value(json)?)
    }

    #[derive(Debug, serde::Serialize)]
    #[serde(untagged)]
    enum Value {
        String(String),
        Int(i64),
        Bool(bool),
        Array(Vec<Value>),
    }

    impl Value {
        fn parse(s: &str) -> anyhow::Result<Self> {
            if s.starts_with('[') && s.ends_with(']') {
                let inner = &s[1..s.len() - 1];
                let mut out = Vec::new();
                for part in split_commas(inner) {
                    out.push(Value::parse(part.trim())?);
                }
                return Ok(Value::Array(out));
            }
            if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))
            {
                return Ok(Value::String(s[1..s.len() - 1].to_string()));
            }
            if s == "true" {
                return Ok(Value::Bool(true));
            }
            if s == "false" {
                return Ok(Value::Bool(false));
            }
            if let Ok(n) = s.parse::<i64>() {
                return Ok(Value::Int(n));
            }
            anyhow::bail!("unknown value: {s}");
        }
    }

    fn split_commas(s: &str) -> impl Iterator<Item = &str> {
        let mut depth = 0i32;
        let mut in_str = false;
        let mut last = 0;
        let bytes = s.as_bytes();
        let len = bytes.len();
        (0..=len).filter_map(move |i| {
            if i == len {
                let slice = &s[last..];
                return (!slice.is_empty()).then_some(slice);
            }
            let b = bytes[i];
            if b == b'"' {
                in_str = !in_str;
            } else if !in_str {
                if b == b'[' {
                    depth += 1;
                } else if b == b']' {
                    depth -= 1;
                } else if b == b',' && depth == 0 {
                    let slice = &s[last..i];
                    last = i + 1;
                    return (!slice.is_empty()).then_some(slice);
                }
            }
            None
        })
    }
}
