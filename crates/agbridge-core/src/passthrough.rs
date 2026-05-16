//! Passthrough.
//!
//! When a hostname is in our hosts hijack list but the URL path is NOT one we
//! intercept (telemetry, OAuth refresh, model list, etc.), we must forward the
//! request to the real upstream so the IDE keeps working.
//!
//! Strategy:
//! 1. Resolve the original hostname via a public DNS resolver (Cloudflare),
//!    bypassing the `127.0.0.1` line we wrote into the hosts file.
//! 2. Build a `reqwest::Client` per host that has `resolve()` set so reqwest
//!    uses the public-DNS IP, not the local hosts file.
//! 3. Forward the buffered request and stream the response back unmodified.
//!
//! Mirrors `passthrough()` in `9router/src/mitm/server.js`.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use parking_lot::RwLock;
use reqwest::Client;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

const CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// `cloudcode-pa` returns 429 in production; the daily-* dev endpoint accepts
/// the same payload. Same trick as the JS impl.
fn host_rewrite(input: &str) -> &str {
    match input {
        "cloudcode-pa.googleapis.com" => "daily-cloudcode-pa.googleapis.com",
        other => other,
    }
}

#[derive(Clone)]
pub struct Passthrough {
    inner: Arc<Inner>,
}

struct Inner {
    resolver: TokioAsyncResolver,
    /// host → (IP, expires_at)
    dns_cache: RwLock<HashMap<String, (IpAddr, Instant)>>,
    /// host → reqwest client with DNS override locked in
    clients: RwLock<HashMap<String, Client>>,
}

impl Passthrough {
    pub fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
        Ok(Self {
            inner: Arc::new(Inner {
                resolver,
                dns_cache: RwLock::new(HashMap::new()),
                clients: RwLock::new(HashMap::new()),
            }),
        })
    }

    async fn resolve(&self, host: &str) -> Result<IpAddr> {
        if let Some((ip, ts)) = self.inner.dns_cache.read().get(host).copied() {
            if ts.elapsed() < CACHE_TTL { return Ok(ip); }
        }
        let lookup = self.inner.resolver.lookup_ip(host).await
            .with_context(|| format!("public DNS lookup failed for {host}"))?;
        let ip = lookup.iter().next()
            .ok_or_else(|| anyhow!("no IP found for {host}"))?;
        self.inner.dns_cache.write().insert(host.to_string(), (ip, Instant::now()));
        Ok(ip)
    }

    /// Build (or fetch) a reqwest client whose DNS for `host` is pinned to
    /// `ip`. This is the mechanism that lets us bypass the hosts file: the
    /// URL still uses `host` (so SNI and cert hostname match), but the TCP
    /// connection goes to the real `ip`.
    async fn client_for(&self, host: &str) -> Result<Client> {
        if let Some(c) = self.inner.clients.read().get(host).cloned() {
            return Ok(c);
        }
        let ip = self.resolve(host).await?;
        let addr = SocketAddr::new(ip, 443);
        let client = Client::builder()
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .connect_timeout(Duration::from_secs(8))
            .resolve(host, addr)
            .user_agent(concat!("agbridge-passthrough/", env!("CARGO_PKG_VERSION")))
            .build()?;
        self.inner.clients.write().insert(host.to_string(), client.clone());
        Ok(client)
    }

    /// Forward to the real upstream and return a streaming hyper response.
    pub async fn forward(
        &self,
        original_host: &str,
        method: hyper::Method,
        uri: hyper::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<hyper::Response<crate::BoxedBody>> {
        let original_host = original_host.split(':').next().unwrap_or(original_host);
        let target_host = host_rewrite(original_host).to_string();

        let path = uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        let url = format!("https://{}{}", target_host, path);

        let client = self.client_for(&target_host).await?;
        let mut builder = client.request(method, &url);
        for (k, v) in headers.iter() {
            if k.as_str().eq_ignore_ascii_case("host") {
                builder = builder.header("host", &target_host);
            } else {
                builder = builder.header(k.clone(), v.clone());
            }
        }
        if !body.is_empty() {
            builder = builder.body(body);
        }
        debug!(%target_host, %url, "passthrough forward");

        let resp = builder.send().await.with_context(|| format!("passthrough to {target_host}"))?;
        let status = resp.status().as_u16();
        let mut hyper_builder = hyper::Response::builder().status(status);
        for (k, v) in resp.headers().iter() {
            if !is_hop_by_hop(k.as_str()) {
                hyper_builder = hyper_builder.header(k.clone(), v.clone());
            }
        }
        let stream = resp.bytes_stream().map(|r| match r {
            Ok(b) => Ok(Frame::data(b)),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        });
        let body = StreamBody::new(stream);
        let boxed = body.map_err(|e| anyhow::anyhow!("{e}")).boxed_unsync();
        Ok(hyper_builder.body(boxed)?)
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "te" | "trailer" | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_rewrite_known() {
        assert_eq!(host_rewrite("cloudcode-pa.googleapis.com"), "daily-cloudcode-pa.googleapis.com");
        assert_eq!(host_rewrite("api.github.com"), "api.github.com");
    }
}
