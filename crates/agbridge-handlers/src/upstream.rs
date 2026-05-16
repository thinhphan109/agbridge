//! Upstream HTTP client.
//!
//! Single shared `reqwest::Client` that sends the rewritten body to the
//! configured 9router VPS, attaching the bearer API key. Hop-by-hop headers
//! and the original Authorization are stripped so we never leak credentials
//! intended for the original endpoint.

use anyhow::Result;
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

const STRIP_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "content-type",
    "authorization",
    // proxy / forwarding chain
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
];

#[derive(Clone)]
pub struct Upstream {
    inner: Arc<UpstreamInner>,
}

struct UpstreamInner {
    client: Client,
    base_url: String,
    api_key: String,
}

impl Upstream {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .user_agent(concat!("agbridge/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            inner: Arc::new(UpstreamInner {
                client,
                base_url: base_url.into().trim_end_matches('/').to_owned(),
                api_key: api_key.into(),
            }),
        })
    }

    /// POST a JSON body to the given upstream sub-path. The response is
    /// returned as a streaming `reqwest::Response`.
    pub async fn post_json(
        &self,
        path: &str,
        body: &Value,
        forward_headers: &HeaderMap,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.inner.base_url, path);
        let mut req = self
            .inner
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .bearer_auth(&self.inner.api_key)
            .json(body);

        for (k, v) in forward_headers.iter() {
            if !STRIP_HEADERS.iter().any(|s| s.eq_ignore_ascii_case(k.as_str())) {
                req = req.header(k.clone(), v.clone());
            }
        }
        // Mark as MITM-originated so the upstream MITM layer (if any) doesn't
        // re-intercept its own traffic.
        req = req.header(
            HeaderName::from_static("x-request-source"),
            HeaderValue::from_static("local"),
        );

        debug!(url = %url, "upstream POST");
        let res = req.send().await?;
        Ok(res)
    }

    /// Same as `post_json` but accepts an arbitrary byte body (used by
    /// Antigravity which forwards the original Gemini wire-format).
    pub async fn post_bytes(
        &self,
        path: &str,
        body: Bytes,
        forward_headers: &HeaderMap,
        content_type: &str,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.inner.base_url, path);
        let mut req = self
            .inner
            .client
            .post(&url)
            .header("Content-Type", content_type)
            .bearer_auth(&self.inner.api_key)
            .body(body);

        for (k, v) in forward_headers.iter() {
            if !STRIP_HEADERS.iter().any(|s| s.eq_ignore_ascii_case(k.as_str())) {
                req = req.header(k.clone(), v.clone());
            }
        }
        req = req.header(
            HeaderName::from_static("x-request-source"),
            HeaderValue::from_static("local"),
        );
        let res = req.send().await?;
        Ok(res)
    }
}
