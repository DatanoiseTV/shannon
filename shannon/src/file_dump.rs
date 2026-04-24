//! Dump parsed HTTP bodies to disk.
//!
//! Wired into `shannon trace --dump-files DIR` and the TUI. For every
//! completed HTTP/1 request/response (and eventually HTTP/2 DATA streams)
//! we decompress the body if `Content-Encoding` declares a codec we know
//! (`gzip`, `deflate`, `zstd`), pick a sensible filename, and drop the
//! result into `DIR`.
//!
//! The reassembly for chunked transfer-encoding already happens in the
//! HTTP parser — by the time we see a `ParsedRecord`, `body` is the full
//! decoded message body (bounded to 4 KiB in the parser; larger bodies
//! are truncated and flagged via `body_complete=false`).
//!
//! Auto-filename algorithm:
//!
//!   <YYYYMMDDTHHMMSS>_<method>_<host-or-pid>_<path-fingerprint>.<ext>
//!
//! where `path-fingerprint` is the URL path with slashes replaced by `_`,
//! truncated to 64 chars, then suffixed with the first 8 hex chars of an
//! FNV-1a digest of the full original path so collisions don't clobber.
//! Extension is guessed from `Content-Type` (fallback `.bin`).

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::parsers::http1::{ParsedRecord, RecordKind};

/// Bytes of body we'll drop to disk per record. Matches the parser cap
/// so we never over-promise what's captured.
const MAX_DUMP_BYTES: usize = 4096;

pub struct FileDumper {
    dir: PathBuf,
    written: u64,
}

impl FileDumper {
    /// Create (or use) a directory and return a ready dumper.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self { dir, written: 0 })
    }

    pub fn count(&self) -> u64 {
        self.written
    }

    /// Write an HTTP/1 response body to disk. Returns `None` if the record
    /// isn't a response or has an empty body.
    pub fn write_http1(&mut self, r: &ParsedRecord, request_method: Option<&str>, request_path: Option<&str>, host: Option<&str>) -> Option<PathBuf> {
        if !matches!(r.kind, RecordKind::Response) {
            return None;
        }
        if r.body.is_empty() {
            return None;
        }
        let encoding = header_value(&r.headers, "content-encoding").unwrap_or_default();
        let content_type = header_value(&r.headers, "content-type").unwrap_or_default();
        let decoded = decompress(&r.body, &encoding).unwrap_or_else(|_| r.body.clone());

        let ext = guess_extension(&content_type);
        let method = request_method.unwrap_or("GET");
        let path = request_path.unwrap_or("/");
        let name = make_filename(method, host.unwrap_or("unknown"), path, ext);
        let path = self.dir.join(&name);

        match File::create(&path).and_then(|mut f| f.write_all(&decoded)) {
            Ok(()) => {
                self.written += 1;
                Some(path)
            }
            Err(err) => {
                tracing::warn!(%err, path = %path.display(), "writing dumped body");
                None
            }
        }
    }

    /// Write arbitrary bytes to a named file inside the dump dir.
    pub fn write_named(&mut self, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = self.dir.join(name);
        let mut f = File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        f.write_all(bytes).with_context(|| format!("writing {}", path.display()))?;
        self.written += 1;
        Ok(path)
    }
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn decompress(body: &[u8], encoding: &str) -> Result<Vec<u8>> {
    let enc = encoding.trim().to_ascii_lowercase();
    match enc.as_str() {
        "" | "identity" => Ok(body.to_vec()),
        "gzip" | "x-gzip" => {
            use std::io::Read;
            let mut out = Vec::with_capacity(body.len() * 3);
            flate2::read::GzDecoder::new(body)
                .read_to_end(&mut out)
                .context("gzip decode")?;
            Ok(out)
        }
        "deflate" => {
            use std::io::Read;
            let mut out = Vec::with_capacity(body.len() * 3);
            flate2::read::ZlibDecoder::new(body)
                .read_to_end(&mut out)
                .context("deflate decode")?;
            Ok(out)
        }
        "zstd" => {
            let decoded =
                zstd::stream::decode_all(body).context("zstd decode")?;
            Ok(decoded)
        }
        other => {
            tracing::debug!(encoding = %other, "unknown Content-Encoding; keeping bytes verbatim");
            Ok(body.to_vec())
        }
    }
}

fn guess_extension(content_type: &str) -> &'static str {
    let ct = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match ct.as_str() {
        "text/html" | "application/xhtml+xml" => "html",
        "text/plain" => "txt",
        "text/css" => "css",
        "text/javascript" | "application/javascript" | "application/ecmascript" => "js",
        "application/json" | "application/problem+json" => "json",
        "application/xml" | "text/xml" | "application/rss+xml" | "application/atom+xml" => "xml",
        "application/yaml" | "text/yaml" | "application/x-yaml" => "yaml",
        "image/png" => "png",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "image/avif" => "avif",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "audio/mpeg" => "mp3",
        "audio/ogg" => "ogg",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "application/x-tar" | "application/tar" => "tar",
        "application/gzip" | "application/x-gzip" => "gz",
        "application/octet-stream" | "" => "bin",
        "application/wasm" => "wasm",
        "application/grpc" | "application/grpc+proto" => "grpc",
        "application/protobuf" | "application/x-protobuf" => "pb",
        "text/event-stream" => "sse",
        _ => "bin",
    }
}

fn make_filename(method: &str, host: &str, path: &str, ext: &str) -> String {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let path_slug = path_slug(path, 64);
    let fp = fnv1a8hex(path.as_bytes());
    let safe_host = host.chars().map(sanitise).collect::<String>();
    let safe_method = method.chars().map(sanitise).collect::<String>();
    format!("{ts:013}_{safe_method}_{safe_host}_{path_slug}_{fp}.{ext}")
}

fn path_slug(path: &str, max: usize) -> String {
    let mut s = String::with_capacity(path.len());
    for c in path.chars() {
        s.push(match c {
            '/' => '_',
            '?' | '#' => break,
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' => c,
            _ => '-',
        });
    }
    if s.len() > max {
        s.truncate(max);
    }
    if s.is_empty() {
        "root".to_string()
    } else {
        s
    }
}

fn sanitise(c: char) -> char {
    if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' {
        c
    } else {
        '-'
    }
}

fn fnv1a8hex(bytes: &[u8]) -> String {
    // 64-bit FNV-1a, take first 8 hex chars.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    let s = format!("{h:016x}");
    s[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_guessed() {
        assert_eq!(guess_extension("text/html; charset=utf-8"), "html");
        assert_eq!(guess_extension("application/json"), "json");
        assert_eq!(guess_extension("image/png"), "png");
        assert_eq!(guess_extension("application/octet-stream"), "bin");
        assert_eq!(guess_extension(""), "bin");
    }

    #[test]
    fn filename_is_reasonable() {
        let f = make_filename("GET", "example.com", "/a/b/c?q=1", "html");
        assert!(f.ends_with(".html"));
        assert!(f.contains("GET"));
        assert!(f.contains("example.com"));
        assert!(f.contains("_a_b_c_")); // pre-'?' path segments
    }

    #[test]
    fn decompress_identity() {
        assert_eq!(decompress(b"hello", "").unwrap(), b"hello");
        assert_eq!(decompress(b"hello", "identity").unwrap(), b"hello");
    }

    #[test]
    fn decompress_gzip_roundtrip() {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"the quick brown fox").unwrap();
        let compressed = encoder.finish().unwrap();
        let out = decompress(&compressed, "gzip").unwrap();
        assert_eq!(out, b"the quick brown fox");
    }
}
