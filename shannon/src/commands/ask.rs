//! `shannon ask` — answer natural-language questions about observed
//! traffic using a local LLM with tool-use.
//!
//! Default endpoint is Ollama at `http://localhost:11434/v1`. LM Studio
//! at `http://localhost:1234/v1`, or any OpenAI-compatible server, can
//! be selected via `--endpoint`.
//!
//! The tool-use loop runs up to 8 rounds: send messages, receive either
//! a final text answer or more `tool_calls`, execute each, append
//! `tool` messages, repeat. Stops early on the first assistant message
//! that has text content and no more tool calls.

use std::io::Write;

use anyhow::Result;

use crate::api_catalog::ApiCatalog;
use crate::ask_tools::{dispatch, AskState};
use crate::cli::{AskArgs, Cli};
use crate::llm_client::{autodiscover, ChatMessage, LlmClient, LMSTUDIO_DEFAULT, OLLAMA_DEFAULT};

const MAX_TOOL_ROUNDS: usize = 8;

const SYSTEM_PROMPT: &str = "You are shannon-ask, an observability assistant attached to a live catalog of HTTP / gRPC endpoints observed on a Linux host. Use the tools provided to look up endpoints, get details, compute stats, or grep through the events log. Prefer calling tools over guessing. When you have enough information, answer concisely and directly. If a tool returns no matches, say so honestly instead of inventing details.";

pub fn run(_cli: &Cli, args: AskArgs) -> Result<()> {
    let (endpoint, model, kind) = match args.endpoint.as_deref() {
        Some("ollama") => (OLLAMA_DEFAULT.to_string(), args.model.clone(), "ollama"),
        Some("lmstudio" | "lm-studio") => (LMSTUDIO_DEFAULT.to_string(), args.model.clone(), "lmstudio"),
        Some("auto") | None => {
            // Probe common local listeners and pick the first that answers.
            let found = autodiscover();
            if let Some(first) = found.first() {
                eprintln!(
                    "shannon: autodiscovered {} at {}",
                    first.kind, first.base_url
                );
                let picked_model = first.first_model.clone().unwrap_or_else(|| args.model.clone());
                (first.base_url.clone(), picked_model, first.kind)
            } else {
                anyhow::bail!(
                    "no LLM backend found on localhost. Start Ollama (`ollama serve`) or LM Studio, or pass --endpoint <url>"
                );
            }
        }
        Some(url) => (url.to_string(), args.model.clone(), "openai-compat"),
    };
    let mut client = LlmClient::new(&endpoint, &model);
    if let Some(key) = args.api_key.clone() {
        client = client.with_api_key(key);
    }
    let _ = kind;

    let catalog = args
        .catalog
        .as_deref()
        .map(ApiCatalog::load)
        .transpose()
        .map_err(|e| anyhow::anyhow!("loading catalog: {e}"))?
        .unwrap_or_else(ApiCatalog::new);
    if catalog.is_empty() && args.events.is_none() {
        eprintln!(
            "shannon: warning — catalog is empty and no --events file given; tools will return nothing useful"
        );
    }
    let state = AskState::new(catalog, args.events.clone());
    let tools = AskState::available_tools();

    let mut messages = vec![ChatMessage::system(SYSTEM_PROMPT)];

    eprintln!("shannon: asking {} via {endpoint}", model);
    if args.interactive {
        return interactive_loop(&client, &state, &tools, &mut messages);
    }
    messages.push(ChatMessage::user(args.question.clone()));
    for round in 0..MAX_TOOL_ROUNDS {
        let reply = client.chat(&messages, &tools)?;
        if !reply.tool_calls.is_empty() {
            // Record the assistant's tool-call message before appending
            // the tool results — the protocol requires this exact order.
            messages.push(ChatMessage {
                role: "assistant".into(),
                content: reply.content.clone(),
                name: None,
                tool_calls: reply.tool_calls.clone(),
                tool_call_id: None,
            });
            for call in &reply.tool_calls {
                let result = dispatch(&state, call).unwrap_or_else(|e| format!("error: {e}"));
                eprintln!(
                    "shannon:   tool {} called (round {}) -> {} bytes",
                    call.function.name,
                    round + 1,
                    result.len()
                );
                messages.push(ChatMessage::tool(call.id.clone(), result));
            }
            continue;
        }
        // Final text answer.
        let text = reply.content.unwrap_or_default();
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{text}")?;
        return Ok(());
    }
    anyhow::bail!("hit the tool-use round limit ({MAX_TOOL_ROUNDS}); the model kept calling tools without concluding")
}

/// Multi-turn REPL. Read a user line from stdin, run the same tool-use
/// loop, echo the answer, repeat. Empty line or Ctrl-D quits.
fn interactive_loop(
    client: &LlmClient,
    state: &AskState,
    tools: &[crate::llm_client::ToolSpec],
    messages: &mut Vec<ChatMessage>,
) -> Result<()> {
    use std::io::{BufRead, Write as IoWrite};
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    loop {
        write!(stdout, "\nshannon> ")?;
        stdout.flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            writeln!(stdout)?;
            return Ok(());
        }
        let q = line.trim();
        if q.is_empty() {
            return Ok(());
        }
        messages.push(ChatMessage::user(q.to_string()));
        let answered = run_one_turn(client, state, tools, messages)?;
        writeln!(stdout, "{answered}")?;
    }
}

fn run_one_turn(
    client: &LlmClient,
    state: &AskState,
    tools: &[crate::llm_client::ToolSpec],
    messages: &mut Vec<ChatMessage>,
) -> Result<String> {
    for _ in 0..MAX_TOOL_ROUNDS {
        let reply = client.chat(messages, tools)?;
        if !reply.tool_calls.is_empty() {
            messages.push(ChatMessage {
                role: "assistant".into(),
                content: reply.content.clone(),
                name: None,
                tool_calls: reply.tool_calls.clone(),
                tool_call_id: None,
            });
            for call in &reply.tool_calls {
                let result = dispatch(state, call).unwrap_or_else(|e| format!("error: {e}"));
                messages.push(ChatMessage::tool(call.id.clone(), result));
            }
            continue;
        }
        let text = reply.content.unwrap_or_default();
        messages.push(ChatMessage::assistant_text(text.clone()));
        return Ok(text);
    }
    Ok("(tool-use round limit reached)".into())
}
