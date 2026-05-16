//! Kiro CodeWhisperer handler.
//!
//! Pipeline:
//! 1. Parse Kiro request body (`conversationState` + tool definitions).
//! 2. Convert to OpenAI `messages[]` + `tools[]` format.
//! 3. Forward to `${router}/v1/chat/completions` (OpenAI SSE).
//! 4. Re-encode the SSE stream as AWS EventStream binary frames.
//!
//! Ported from `9router/src/mitm/handlers/kiro.js`.

use crate::upstream::Upstream;
use agbridge_eventstream::events;
use anyhow::Result;
use bytes::Bytes;
use futures::StreamExt;
use http::HeaderMap;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, warn};

pub struct KiroHandler {
    pub model_map: HashMap<String, String>,
}

impl KiroHandler {
    /// Returns a streaming body of binary EventStream frames.
    pub async fn intercept(
        &self,
        body: Bytes,
        headers: &HeaderMap,
        upstream: &Upstream,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>> {
        let req_body: Value = serde_json::from_slice(&body)
            .map_err(|e| anyhow::anyhow!("invalid Kiro JSON body: {e}"))?;

        let messages = code_whisperer_to_messages(&req_body);
        if messages.is_empty() {
            anyhow::bail!("Kiro request produced 0 messages");
        }
        let tools = extract_tools(&req_body);

        // Resolve upstream model name
        let raw_model = req_body
            .pointer("/conversationState/currentMessage/userInputMessage/modelId")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string();
        let upstream_model = self
            .model_map
            .get(&raw_model)
            .cloned()
            .unwrap_or_else(|| raw_model.clone());

        let mut openai_body = json!({
            "model": upstream_model,
            "messages": messages,
            "stream": true,
        });
        if !tools.is_empty() {
            openai_body["tools"] = Value::Array(tools);
            openai_body["tool_choice"] = json!("auto");
        }

        let res = upstream.post_json("/v1/chat/completions", &openai_body, headers).await?;
        let stream = res.bytes_stream();

        // Channel-driven re-encode worker.
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(64);
        tokio::spawn(reencode_loop(stream, tx));

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }
}

/// Drive the OpenAI SSE → EventStream conversion loop.
async fn reencode_loop<S>(mut stream: S, tx: mpsc::Sender<std::io::Result<Bytes>>)
where
    S: futures::Stream<Item = reqwest::Result<Bytes>> + Unpin,
{
    let mut buf = String::new();
    let mut tool_calls: HashMap<u64, ToolCallAccum> = HashMap::new();
    let mut stop_sent = false;

    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                warn!("upstream stream error: {e}");
                break;
            }
        };
        buf.push_str(&String::from_utf8_lossy(&chunk));

        // Drain complete SSE lines (LF-terminated)
        loop {
            let Some(idx) = buf.find('\n') else { break };
            let line: String = buf.drain(..=idx).collect();
            let trimmed = line.trim();
            if !trimmed.starts_with("data:") {
                continue;
            }
            let raw = trimmed[5..].trim();
            if raw == "[DONE]" {
                if !stop_sent {
                    let _ = tx.send(Ok(events::message_stop())).await;
                    stop_sent = true;
                }
                continue;
            }
            let Ok(json) = serde_json::from_str::<Value>(raw) else { continue };
            let Some(delta) = json.pointer("/choices/0/delta") else { continue };

            if let Some(text) = delta.get("content").and_then(|v| v.as_str()) {
                if !text.is_empty() {
                    let _ = tx.send(Ok(events::assistant_text(text))).await;
                }
            }

            if let Some(arr) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                for tc in arr {
                    let idx = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                    let acc = tool_calls.entry(idx).or_default();
                    if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                        if !id.is_empty() { acc.id = id.to_string(); }
                    }
                    if let Some(f) = tc.get("function") {
                        if let Some(name) = f.get("name").and_then(|v| v.as_str()) {
                            acc.name.push_str(name);
                        }
                        if let Some(args) = f.get("arguments") {
                            acc.args.push_str(&safe_args_str(args));
                        }
                    }
                }
            }

            if let Some(reason) = json.pointer("/choices/0/finish_reason").and_then(|v| v.as_str()) {
                debug!(?reason, count = tool_calls.len(), "kiro: finish");
                if reason == "tool_calls" {
                    for acc in tool_calls.values() {
                        let input = if acc.args.is_empty() { "{}".to_string() } else { acc.args.clone() };
                        let _ = tx.send(Ok(events::tool_use(&acc.id, &acc.name, &input))).await;
                    }
                }
                if !stop_sent {
                    let _ = tx.send(Ok(events::message_stop())).await;
                    stop_sent = true;
                }
            }
        }
    }
    if !stop_sent {
        let _ = tx.send(Ok(events::message_stop())).await;
    }
}

#[derive(Default)]
struct ToolCallAccum {
    id: String,
    name: String,
    args: String,
}

fn safe_args_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "{}".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "{}".to_string()),
    }
}

fn code_whisperer_to_messages(body: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let cs = match body.get("conversationState") { Some(v) => v, None => return out };
    if let Some(history) = cs.get("history").and_then(|v| v.as_array()) {
        for item in history {
            if let Some(uim) = item.get("userInputMessage") {
                out.extend(convert_user_input(uim));
            } else if let Some(arm) = item.get("assistantResponseMessage") {
                out.push(convert_assistant_response(arm));
            }
        }
    }
    if let Some(uim) = cs.pointer("/currentMessage/userInputMessage") {
        out.extend(convert_user_input(uim));
    }
    out
}

fn convert_user_input(uim: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let tool_results = uim
        .pointer("/userInputMessageContext/toolResults")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let has_tool_results = !tool_results.is_empty();
    for tr in &tool_results {
        let id = tr.get("toolUseId").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let text = tr
            .get("content")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| c.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        out.push(json!({ "role": "tool", "tool_call_id": id, "content": text }));
    }
    let text = uim.get("content").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !text.is_empty() || !has_tool_results {
        out.push(json!({ "role": "user", "content": text }));
    }
    out
}

fn convert_assistant_response(arm: &Value) -> Value {
    let tool_uses = arm.get("toolUses").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if !tool_uses.is_empty() {
        let calls: Vec<Value> = tool_uses
            .iter()
            .map(|tu| {
                let id = tu.get("toolUseId").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let name = tu.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let args = tu.get("input").map(safe_args_str).unwrap_or_else(|| "{}".to_string());
                json!({
                    "id": id,
                    "type": "function",
                    "function": { "name": name, "arguments": args },
                })
            })
            .collect();
        let content = arm.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
        json!({ "role": "assistant", "content": content, "tool_calls": calls })
    } else {
        let content = arm.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
        json!({ "role": "assistant", "content": content })
    }
}

fn extract_tools(body: &Value) -> Vec<Value> {
    let cs = match body.get("conversationState") { Some(v) => v, None => return vec![] };
    let mut tools = cs
        .pointer("/currentMessage/userInputMessage/userInputMessageContext/tools")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if tools.is_empty() {
        if let Some(history) = cs.get("history").and_then(|v| v.as_array()) {
            for item in history {
                if let Some(arr) = item
                    .pointer("/userInputMessage/userInputMessageContext/tools")
                    .and_then(|v| v.as_array())
                {
                    tools = arr.clone();
                    break;
                }
            }
        }
    }
    tools
        .into_iter()
        .map(|t| {
            let spec = t.get("toolSpecification").cloned().unwrap_or(t);
            let name = spec.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let desc = spec
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| format!("Tool: {name}"));
            let params = spec
                .pointer("/inputSchema/json")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object", "properties": {}, "required": [] }));
            json!({
                "type": "function",
                "function": { "name": name, "description": desc, "parameters": params },
            })
        })
        .collect()
}

// Pull in tokio-stream from handlers Cargo.toml? No — declare here.
mod tokio_stream {
    pub mod wrappers {
        pub use ::tokio_stream::wrappers::ReceiverStream;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_input_with_text_only() {
        let m = code_whisperer_to_messages(&json!({
            "conversationState": {
                "currentMessage": {
                    "userInputMessage": { "content": "hello" }
                }
            }
        }));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["role"], "user");
        assert_eq!(m[0]["content"], "hello");
    }
}
