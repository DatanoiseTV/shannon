//! LLM API shape recognition.
//!
//! Classifies observed HTTP paths / bodies as calls to common LLM APIs
//! and extracts a compact summary: provider, model, endpoint type,
//! approximate token counts if the request is JSON and the fields are
//! present. We don't do full JSON parsing — a targeted scan for a handful
//! of key fields is enough for the observability surface.
//!
//! Supported shapes:
//!
//! - OpenAI: `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`
//! - Anthropic: `/v1/messages`
//! - Google Gemini: `/v1beta/models/*:generateContent`, `*:streamGenerateContent`
//! - Ollama: `/api/generate`, `/api/chat`, `/api/embed`, `/api/embeddings`
//! - LM Studio: exposes the OpenAI shape — falls through to OpenAI
//! - vLLM / TGI / LiteLLM: typically OpenAI-compatible — falls through
//! - Azure OpenAI: `/openai/deployments/*/chat/completions?...`
//! - AWS Bedrock: `/model/*/invoke`, `/model/*/invoke-with-response-stream`

use std::fmt;

/// A recognised LLM call.
#[derive(Debug, Clone)]
pub struct LlmCall {
    pub provider: Provider,
    pub endpoint: Endpoint,
    pub model: Option<String>,
    pub streaming: bool,
    /// Rough prompt-size hint (bytes of `prompt` / `messages` / `input`).
    pub prompt_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    OpenAi,
    Anthropic,
    Gemini,
    Ollama,
    AzureOpenAi,
    Bedrock,
    OpenAiCompatible, // self-hosted (LM Studio, vLLM, TGI, llama.cpp)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Chat,
    Completion,
    Embedding,
    Other,
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
            Self::Ollama => "ollama",
            Self::AzureOpenAi => "azure-openai",
            Self::Bedrock => "bedrock",
            Self::OpenAiCompatible => "openai-compat",
        })
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Chat => "chat",
            Self::Completion => "completion",
            Self::Embedding => "embedding",
            Self::Other => "other",
        })
    }
}

impl LlmCall {
    pub fn display_line(&self) -> String {
        let model = self.model.as_deref().unwrap_or("?");
        format!(
            "llm {}/{} model={} stream={} prompt={}B",
            self.provider, self.endpoint, model, self.streaming, self.prompt_bytes
        )
    }
}

/// Classify a captured HTTP request. Returns `None` for non-LLM traffic.
pub fn classify_http_request(method: &str, path: &str, host: Option<&str>, body: &[u8]) -> Option<LlmCall> {
    if method.eq_ignore_ascii_case("GET") {
        return None;
    }
    let host_lc = host.map(str::to_ascii_lowercase);
    let host_ref = host_lc.as_deref().unwrap_or("");
    let (provider, endpoint) = match detect_endpoint(path, host_ref) {
        Some(v) => v,
        None => return None,
    };
    let model = extract_model(body);
    let streaming = body_has_key(body, b"\"stream\"") && body_has_value(body, b"true");
    let prompt_bytes = estimate_prompt_bytes(body);
    Some(LlmCall { provider, endpoint, model, streaming, prompt_bytes })
}

fn detect_endpoint(path: &str, host: &str) -> Option<(Provider, Endpoint)> {
    let p = path;
    // Strip query string for path classification.
    let p = p.split('?').next().unwrap_or(p);

    // Anthropic Messages API.
    if host.contains("anthropic.com") || p.ends_with("/v1/messages") {
        if p.ends_with("/v1/messages") {
            return Some((Provider::Anthropic, Endpoint::Chat));
        }
    }

    // Google Gemini.
    if host.contains("googleapis.com") || host.contains("generativelanguage") {
        if p.contains(":generateContent") || p.contains(":streamGenerateContent") {
            return Some((Provider::Gemini, Endpoint::Chat));
        }
        if p.contains(":embedContent") {
            return Some((Provider::Gemini, Endpoint::Embedding));
        }
    }

    // Azure OpenAI: /openai/deployments/<name>/chat/completions?api-version=...
    if p.starts_with("/openai/deployments/") {
        if p.contains("/chat/completions") {
            return Some((Provider::AzureOpenAi, Endpoint::Chat));
        }
        if p.contains("/completions") {
            return Some((Provider::AzureOpenAi, Endpoint::Completion));
        }
        if p.contains("/embeddings") {
            return Some((Provider::AzureOpenAi, Endpoint::Embedding));
        }
    }

    // AWS Bedrock runtime.
    if host.contains("bedrock-runtime") || host.contains("bedrock.") {
        if p.contains("/invoke") {
            return Some((Provider::Bedrock, Endpoint::Chat));
        }
    }

    // Ollama local API.
    if p == "/api/chat" {
        return Some((Provider::Ollama, Endpoint::Chat));
    }
    if p == "/api/generate" {
        return Some((Provider::Ollama, Endpoint::Completion));
    }
    if p == "/api/embed" || p == "/api/embeddings" {
        return Some((Provider::Ollama, Endpoint::Embedding));
    }

    // OpenAI (canonical + compatible).
    if p.ends_with("/v1/chat/completions") {
        return Some((classify_openai(host), Endpoint::Chat));
    }
    if p.ends_with("/v1/completions") {
        return Some((classify_openai(host), Endpoint::Completion));
    }
    if p.ends_with("/v1/embeddings") {
        return Some((classify_openai(host), Endpoint::Embedding));
    }
    None
}

fn classify_openai(host: &str) -> Provider {
    if host.contains("openai.com") {
        Provider::OpenAi
    } else {
        Provider::OpenAiCompatible
    }
}

fn extract_model(body: &[u8]) -> Option<String> {
    extract_json_string(body, b"\"model\"")
}

fn extract_json_string(body: &[u8], needle: &[u8]) -> Option<String> {
    let i = find_subslice(body, needle)?;
    let mut p = i + needle.len();
    while p < body.len() && body[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= body.len() || body[p] != b':' {
        return None;
    }
    p += 1;
    while p < body.len() && body[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= body.len() || body[p] != b'"' {
        return None;
    }
    p += 1;
    let start = p;
    while p < body.len() && body[p] != b'"' {
        // Handle \" escapes.
        if body[p] == b'\\' && p + 1 < body.len() {
            p += 2;
            continue;
        }
        p += 1;
    }
    if p > body.len() {
        return None;
    }
    let val = &body[start..p];
    Some(String::from_utf8_lossy(val).into_owned())
}

fn body_has_key(body: &[u8], key: &[u8]) -> bool {
    find_subslice(body, key).is_some()
}

fn body_has_value(body: &[u8], value: &[u8]) -> bool {
    find_subslice(body, value).is_some()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    memchr::memmem::find(haystack, needle)
}

fn estimate_prompt_bytes(body: &[u8]) -> u64 {
    // Best-effort: add up the byte-length of any "content" / "prompt" /
    // "input" / "messages" fields we can find. Approximate — we're just
    // giving operators a "how much did this request send" signal.
    let mut total = 0u64;
    for key in [
        &b"\"prompt\""[..],
        b"\"input\"",
        b"\"inputs\"",
        b"\"content\"",
        b"\"messages\"",
    ] {
        if let Some(i) = find_subslice(body, key) {
            total += field_byte_span(body, i + key.len());
        }
    }
    total
}

fn field_byte_span(body: &[u8], mut p: usize) -> u64 {
    while p < body.len() && body[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= body.len() || body[p] != b':' {
        return 0;
    }
    p += 1;
    while p < body.len() && body[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= body.len() {
        return 0;
    }
    let start = p;
    let mut depth = 0i32;
    let mut in_string = false;
    while p < body.len() {
        let b = body[p];
        if in_string {
            if b == b'\\' && p + 1 < body.len() {
                p += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'[' | b'{' => depth += 1,
                b']' | b'}' => {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                b',' if depth == 0 => break,
                _ => {}
            }
        }
        p += 1;
    }
    (p - start) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_openai_chat() {
        let body = b"{\"model\":\"gpt-4o\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}";
        let c = classify_http_request("POST", "/v1/chat/completions", Some("api.openai.com"), body)
            .expect("classified");
        assert_eq!(c.provider, Provider::OpenAi);
        assert_eq!(c.endpoint, Endpoint::Chat);
        assert_eq!(c.model.as_deref(), Some("gpt-4o"));
        assert!(c.streaming);
        assert!(c.prompt_bytes > 0);
    }

    #[test]
    fn detects_anthropic_messages() {
        let body = b"{\"model\":\"claude-sonnet-4\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}";
        let c = classify_http_request("POST", "/v1/messages", Some("api.anthropic.com"), body)
            .expect("classified");
        assert_eq!(c.provider, Provider::Anthropic);
    }

    #[test]
    fn detects_ollama_chat() {
        let body = b"{\"model\":\"llama3.2\",\"messages\":[]}";
        let c = classify_http_request("POST", "/api/chat", Some("localhost"), body).expect("");
        assert_eq!(c.provider, Provider::Ollama);
        assert_eq!(c.endpoint, Endpoint::Chat);
    }

    #[test]
    fn detects_gemini_generate() {
        let body = b"{\"contents\":[]}";
        let c = classify_http_request(
            "POST",
            "/v1beta/models/gemini-2.0-flash:generateContent",
            Some("generativelanguage.googleapis.com"),
            body,
        )
        .expect("classified");
        assert_eq!(c.provider, Provider::Gemini);
    }

    #[test]
    fn detects_azure() {
        let c = classify_http_request(
            "POST",
            "/openai/deployments/gpt4/chat/completions?api-version=2024-02-15",
            Some("myaoai.openai.azure.com"),
            b"{\"model\":\"gpt4\"}",
        )
        .expect("classified");
        assert_eq!(c.provider, Provider::AzureOpenAi);
    }

    #[test]
    fn non_llm_returns_none() {
        assert!(classify_http_request("GET", "/", Some("example.com"), b"").is_none());
        assert!(classify_http_request("POST", "/api/users", Some("example.com"), b"").is_none());
    }
}
