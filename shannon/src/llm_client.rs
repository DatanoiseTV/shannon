//! OpenAI-compatible chat client with tool-use.
//!
//! Works against any endpoint that speaks the OpenAI `/v1/chat/completions`
//! shape — which includes:
//!
//! - [Ollama](https://ollama.com) (default base: `http://localhost:11434/v1`)
//! - [LM Studio](https://lmstudio.ai) (default base: `http://localhost:1234/v1`)
//! - vLLM, TGI, LiteLLM, llama.cpp's built-in server, LocalAI
//! - Real OpenAI / Azure OpenAI (with an API key)
//!
//! Tool-use is the OpenAI function-calling protocol. We define tools in
//! Rust as [`ToolSpec`]s, ship them to the model, and loop on any
//! `tool_calls` the model returns until it emits a final text message.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Default Ollama OpenAI-compatible endpoint.
pub const OLLAMA_DEFAULT: &str = "http://localhost:11434/v1";
/// Default LM Studio OpenAI-compatible endpoint.
pub const LMSTUDIO_DEFAULT: &str = "http://localhost:1234/v1";

/// A discovered local LLM backend — the auto-probe found a listener
/// that speaks the OpenAI-compatible chat API.
#[derive(Debug, Clone)]
pub struct Discovered {
    pub kind: &'static str, // "ollama" | "lmstudio" | "openai-compat"
    pub base_url: String,
    /// First model the backend lists; used as a sane default when the
    /// user doesn't specify --model.
    pub first_model: Option<String>,
}

/// Probe common localhost ports for an OpenAI-compatible LLM service.
/// Returns every backend found. Ordered by preference (Ollama first,
/// LM Studio second, then any generic server on the well-known vLLM /
/// LocalAI / llama.cpp ports).
#[must_use]
pub fn autodiscover() -> Vec<Discovered> {
    const CANDIDATES: &[(&str, &str)] = &[
        ("ollama", OLLAMA_DEFAULT),
        ("lmstudio", LMSTUDIO_DEFAULT),
        ("openai-compat", "http://localhost:8000/v1"), // vLLM / LocalAI default
        ("openai-compat", "http://localhost:8080/v1"), // llama.cpp / TGI default
        ("openai-compat", "http://localhost:11435/v1"), // LiteLLM default
        ("openai-compat", "http://localhost:4000/v1"), // LiteLLM proxy default
    ];
    let mut out = Vec::new();
    for (kind, base) in CANDIDATES {
        if let Some(first_model) = probe(base) {
            out.push(Discovered {
                kind,
                base_url: (*base).to_string(),
                first_model: Some(first_model),
            });
        }
    }
    out
}

fn probe(base: &str) -> Option<String> {
    // GET /models — the OpenAI-compat spec requires it, every backend
    // implements it. Short timeout: we're only probing.
    let url = format!("{}/models", base.trim_end_matches('/'));
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(400))
        .build();
    let resp = agent.get(&url).call().ok()?;
    let text = resp.into_string().ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    // Standard shape: { "data": [ {"id": "...", ...}, ... ] }
    v.get("data")
        .and_then(|d| d.as_array())
        .and_then(|a| a.first())
        .and_then(|m| m.get("id"))
        .and_then(|id| id.as_str())
        .map(str::to_string)
}

pub struct LlmClient {
    base_url: String,
    model: String,
    api_key: Option<String>,
    timeout: Duration,
}

impl LlmClient {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            api_key: None,
            timeout: Duration::from_secs(120),
        }
    }

    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Make one `chat/completions` request. Returns the raw assistant
    /// message (which may include `tool_calls`).
    pub fn chat(&self, messages: &[ChatMessage], tools: &[ToolSpec]) -> Result<ChatMessage> {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "stream": false,
        });
        if !tools.is_empty() {
            body["tools"] = serde_json::to_value(tools)?;
            body["tool_choice"] = serde_json::json!("auto");
        }

        let agent = ureq::AgentBuilder::new().timeout(self.timeout).build();
        let mut req = agent.post(&url).set("Content-Type", "application/json");
        if let Some(ref key) = self.api_key {
            req = req.set("Authorization", &format!("Bearer {key}"));
        }
        let resp = req
            .send_json(body)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .with_context(|| format!("POST {url}"))?;
        let text = resp.into_string().context("reading response")?;
        let parsed: ChatResponse = serde_json::from_str(&text)
            .with_context(|| format!("parsing response body: {text}"))?;
        let choice = parsed
            .choices
            .into_iter()
            .next()
            .context("no choices in response")?;
        Ok(choice.message)
    }
}

// -- Messages + tools --------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// When role=="tool", the id of the tool_call this reply is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    pub fn system(text: impl Into<String>) -> Self {
        Self::plain("system", text)
    }
    pub fn user(text: impl Into<String>) -> Self {
        Self::plain("user", text)
    }
    pub fn assistant_text(text: impl Into<String>) -> Self {
        Self::plain("assistant", text)
    }
    pub fn tool(call_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            role: "tool".into(),
            content: Some(text.into()),
            name: None,
            tool_calls: Vec::new(),
            tool_call_id: Some(call_id.into()),
        }
    }
    fn plain(role: &str, text: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: Some(text.into()),
            name: None,
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(default, rename = "type")]
    pub ty: String,
    pub function: ToolCallFunction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolCallFunction {
    pub name: String,
    pub arguments: String, // JSON-encoded
}

impl ToolCall {
    pub fn parsed_args(&self) -> Result<Value> {
        serde_json::from_str(&self.function.arguments)
            .with_context(|| format!("parsing tool args for {}", self.function.name))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolSpec {
    #[serde(rename = "type")]
    pub ty: &'static str,
    pub function: ToolFunction,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolFunction {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

impl ToolSpec {
    pub fn function(
        name: impl Into<String>,
        description: impl Into<String>,
        parameters: Value,
    ) -> Self {
        Self {
            ty: "function",
            function: ToolFunction {
                name: name.into(),
                description: description.into(),
                parameters,
            },
        }
    }
}

// -- Response shape ----------------------------------------------------------

#[derive(Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChatMessage,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_message_serialises() {
        let m = ChatMessage::user("hi");
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"role\":\"user\""));
        assert!(s.contains("\"content\":\"hi\""));
    }

    #[test]
    fn tool_message_has_call_id() {
        let m = ChatMessage::tool("call_42", "result");
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"tool_call_id\":\"call_42\""));
        assert!(s.contains("\"role\":\"tool\""));
    }

    #[test]
    fn tool_spec_serialises_as_function() {
        let t = ToolSpec::function(
            "list_endpoints",
            "List observed endpoints",
            serde_json::json!({"type": "object", "properties": {}}),
        );
        let s = serde_json::to_string(&t).unwrap();
        assert!(s.contains("\"type\":\"function\""));
        assert!(s.contains("list_endpoints"));
    }
}
