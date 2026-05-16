//! Antigravity intercept.
//!
//! Forwards the Gemini-formatted body to `${router}/v1/chat/completions`,
//! optionally rewriting `body.model` according to the configured model map.
//! 9router on the VPS auto-detects this format via `userAgent==="antigravity"`
//! and runs its own translator chain.

use crate::upstream::Upstream;
use anyhow::Result;
use bytes::Bytes;
use http::HeaderMap;
use std::collections::HashMap;
use tracing::debug;

pub struct AntigravityHandler {
    pub model_map: HashMap<String, String>,
}

impl AntigravityHandler {
    pub async fn intercept(
        &self,
        url: &str,
        body: Bytes,
        headers: &HeaderMap,
        upstream: &Upstream,
    ) -> Result<reqwest::Response> {
        let mut json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        let extracted = extract_model(url, &json);
        if let Some(model) = extracted.as_deref() {
            if let Some(target) = self.model_map.get(model) {
                if let Some(obj) = json.as_object_mut() {
                    obj.insert("model".into(), serde_json::Value::String(target.clone()));
                }
                debug!(from = model, to = target, "antigravity: model rewritten");
            }
        }
        upstream.post_json("/v1/chat/completions", &json, headers).await
    }
}

/// Extract the model id from the URL path (Gemini style `/models/<id>:method`)
/// or the JSON body as a fallback.
fn extract_model(url: &str, json: &serde_json::Value) -> Option<String> {
    if let Some(start) = url.find("/models/") {
        let rest = &url[start + "/models/".len()..];
        let end = rest.find(['/', ':']).unwrap_or(rest.len());
        if end > 0 {
            return Some(rest[..end].to_string());
        }
    }
    json.get("model").and_then(|v| v.as_str()).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_from_path() {
        let m = extract_model(
            "/v1beta/models/gemini-3-flash:generateContent",
            &json!({}),
        );
        assert_eq!(m.unwrap(), "gemini-3-flash");
    }

    #[test]
    fn extract_from_body() {
        let m = extract_model("/foo", &json!({ "model": "abc" }));
        assert_eq!(m.unwrap(), "abc");
    }
}
