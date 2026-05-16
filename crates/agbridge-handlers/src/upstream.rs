//! Upstream HTTP client.
//!
//! Single shared `reqwest::Client` that sends the rewritten body to the
//! configured 9router VPS, attaching the bearer API key. Hop-by-hop headers
//! and the original Authorization are stripped so we never leak credentials
//! intended for the original endpoint.
//!
//! Egress lock: every outbound request URL is validated to belong to the
//! configured `base_url` host. This is a defense-in-depth check so a future
//! handler that accidentally builds a wrong URL cannot exfiltrate data to a
//! third-party host.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use reqwest::Url;
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
    base_host: String,
    api_key: String,
}

impl Upstream {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self> {
        let base_url: String = base_url.into().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&base_url).map_err(|e| anyhow!("invalid router_url: {e}"))?;
        let base_host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("router_url has no host"))?
            .to_string();
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .user_agent(concat!("agbridge/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            inner: Arc::new(UpstreamInner {
                client,
                base_url,
                base_host,
                api_key: api_key.into(),
            }),
        })
    }

    /// Resolve `path` against `base_url` and assert the result still points to
    /// the configured upstream host. Returns the validated URL.
    fn resolve(&self, path: &str) -> Result<Url> {
        let candidate = if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else {
            format!("{}{}", self.inner.base_url, path)
        };
        let url = Url::parse(&candidate).map_err(|e| anyhow!("invalid upstream path `{path}`: {e}"))?;
        match url.host_str() {
            Some(h) if h.eq_ignore_ascii_case(&self.inner.base_host) => Ok(url),
            other => Err(anyhow!(
                "egress denied: refusing to call host {:?}, only {} is allowed",
                other,
                self.inner.base_host
            )),
        }
    }

    /// POST a JSON body to the given upstream sub-path. The response is
    /// returned as a streaming `reqwest::Response`.
    pub async fn post_json(
        &self,
        path: &str,
        body: &Value,
        forward_headers: &HeaderMap,
    ) -> Result<reqwest::Response> {
        let url = self.resolve(path)?;
        let mut req = self
            .inner
            .client
            .post(url.clone())
            .header("Content-Type", "application/json")
            .bearer_auth(&self.inner.api_key)
            .json(body);

        for (k, v) in forward_headers.iter() {
            if !STRIP_HEADERS.iter().any(|s| s.eq_ignore_ascii_case(k.as_str())) {
                req = req.header(k.clone(), v.clone());
            }
        }
        req = req.header(
            HeaderName::from_static("x-request-source"),
            HeaderValue::from_static("local"),
        );

        debug!(url = %url, "upstream POST");
        let res = req.send().await?;
        Ok(res)
    }

    /// Same as `post_json` but accepts an arbitrary byte body.
    pub async fn post_bytes(
        &self,
        path: &str,
        body: Bytes,
        forward_headers: &HeaderMap,
        content_type: &str,
    ) -> Result<reqwest::Response> {
        let url = self.resolve(path)?;
        let mut req = self
            .inner
            .client
            .post(url.clone())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fake() -> Upstream {
        Upstream::new("https://router.example.com", "test").unwrap()
    }

    #[test]
    fn resolve_relative_path_keeps_host() {
        let url = fake().resolve("/v1/chat/completions").unwrap();
        assert_eq!(url.host_str(), Some("router.example.com"));
        assert_eq!(url.path(), "/v1/chat/completions");
    }

    #[test]
    fn resolve_rejects_absolute_url_to_other_host() {
        let err = fake().resolve("https://attacker.example.org/foo").unwrap_err();
        assert!(err.to_string().contains("egress denied"), "got: {err}");
    }

    #[test]
    fn resolve_accepts_absolute_url_to_same_host() {
        let url = fake().resolve("https://router.example.com/v1/x").unwrap();
        assert_eq!(url.path(), "/v1/x");
    }

    #[test]
    fn rejects_garbage_path() {
        assert!(fake().resolve("ht!tp://broken").is_err());
    }
}

