//! GitHub Copilot intercept. Maps Copilot endpoints to 9router endpoints.

use crate::upstream::Upstream;
use anyhow::Result;
use bytes::Bytes;
use http::HeaderMap;
use std::collections::HashMap;

pub struct CopilotHandler {
    pub model_map: HashMap<String, String>,
}

impl CopilotHandler {
    pub async fn intercept(
        &self,
        url: &str,
        body: Bytes,
        headers: &HeaderMap,
        upstream: &Upstream,
    ) -> Result<reqwest::Response> {
        let router_path = resolve_path(url);
        let mut json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);

        if let Some(model) = json.get("model").and_then(|v| v.as_str()).map(str::to_string) {
            if let Some(target) = self.model_map.get(&model) {
                if let Some(obj) = json.as_object_mut() {
                    obj.insert("model".into(), serde_json::Value::String(target.clone()));
                }
            }
        }

        upstream.post_json(router_path, &json, headers).await
    }
}

fn resolve_path(req_url: &str) -> &'static str {
    if req_url.contains("/v1/messages") {
        "/v1/messages"
    } else if req_url.contains("/responses") {
        "/v1/responses"
    } else {
        "/v1/chat/completions"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_mapping() {
        assert_eq!(resolve_path("/chat/completions"), "/v1/chat/completions");
        assert_eq!(resolve_path("/v1/messages"), "/v1/messages");
        assert_eq!(resolve_path("/responses"), "/v1/responses");
    }
}
