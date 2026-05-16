//! TLS MITM server.
//!
//! Listens on `config.listen_addr`, terminates TLS using a per-host leaf cert
//! signed by the agbridge Root CA, then dispatches each request to the
//! appropriate tool handler. Non-target hosts and non-intercepted paths fall
//! through to [`passthrough::Passthrough`] which forwards them unmodified to
//! the real upstream (DNS bypass via Cloudflare).

pub mod passthrough;
use passthrough::Passthrough;

use agbridge_cert::CertManager;
use agbridge_config::Config;
use agbridge_handlers::{antigravity::AntigravityHandler, copilot::CopilotHandler, cursor::CursorHandler, kiro::KiroHandler, upstream::Upstream};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

pub struct Server {
    config: Arc<Config>,
    cert: CertManager,
    upstream: Upstream,
    passthrough: Passthrough,
}

impl Server {
    pub fn new(config: Config, cert: CertManager) -> Result<Self> {
        let upstream = Upstream::new(&config.router_url, config.api_key.expose())?;
        let passthrough = Passthrough::new()?;
        Ok(Self {
            config: Arc::new(config),
            cert,
            upstream,
            passthrough,
        })
    }

    pub async fn run(self) -> Result<()> {
        let resolver = Arc::new(SniResolver { cert: self.cert.clone() });
        let mut server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .with_context(|| format!("bind {}", self.config.listen_addr))?;
        info!(addr = %self.config.listen_addr, "agbridge TLS server listening");

        let state = Arc::new(SharedState {
            antigravity: AntigravityHandler { model_map: self.config.tools.antigravity.model_map.clone() },
            copilot: CopilotHandler { model_map: self.config.tools.copilot.model_map.clone() },
            kiro: KiroHandler { model_map: self.config.tools.kiro.model_map.clone() },
            cursor: CursorHandler,
            cursor_enabled: self.config.tools.cursor.enabled,
            upstream: self.upstream.clone(),
            passthrough: self.passthrough.clone(),
        });

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => { warn!("accept error: {e}"); continue; }
            };
            let acceptor = acceptor.clone();
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_conn(acceptor, stream, state).await {
                    debug!(%peer, "connection ended: {e}");
                }
            });
        }
    }
}

struct SharedState {
    antigravity: AntigravityHandler,
    copilot: CopilotHandler,
    kiro: KiroHandler,
    cursor: CursorHandler,
    cursor_enabled: bool,
    upstream: Upstream,
    passthrough: Passthrough,
}

async fn serve_conn(
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    state: Arc<SharedState>,
) -> Result<()> {
    let tls = acceptor.accept(stream).await?;
    let io = TokioIo::new(tls);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let state = state.clone();
                async move { dispatch(req, state).await }
            }),
        )
        .await?;
    Ok(())
}

async fn dispatch(
    req: Request<Incoming>,
    state: Arc<SharedState>,
) -> Result<Response<BoxedBody>> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let url = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
    debug!(%host, %url, "incoming");

    if url == "/_mitm_health" {
        return Ok(json_response(200, br#"{"ok":true,"agbridge":true}"#));
    }

    let (parts, incoming) = req.into_parts();
    let body = incoming.collect().await?.to_bytes();
    let headers_h = parts.headers.clone();
    let method = parts.method.clone();
    let uri = parts.uri.clone();

    let pass = || async {
        state.passthrough.forward(&host, method.clone(), uri.clone(), &headers_h, body.clone()).await
    };

    let Some(tool) = agbridge_handlers::tool_for_host(&host) else {
        return pass().await;
    };
    if !agbridge_handlers::is_intercepted_path(tool, &url) {
        return pass().await;
    }
    if matches!(tool, agbridge_handlers::Tool::Cursor) && !state.cursor_enabled {
        return pass().await;
    }

    let res = match tool {
        agbridge_handlers::Tool::Antigravity => {
            let res = state.antigravity.intercept(&url, body, &headers_h, &state.upstream).await?;
            forward_response(res).await?
        }
        agbridge_handlers::Tool::Copilot => {
            let res = state.copilot.intercept(&url, body, &headers_h, &state.upstream).await?;
            forward_response(res).await?
        }
        agbridge_handlers::Tool::Kiro => {
            let stream = state.kiro.intercept(body, &headers_h, &state.upstream).await?;
            stream_response_eventstream(stream)?
        }
        agbridge_handlers::Tool::Cursor => {
            let r = state.cursor.intercept(&url, body).await?;
            stub_to_response(r)?
        }
    };
    Ok(res)
}

/// Forward a `reqwest::Response` body as-is back to the caller.
async fn forward_response(res: reqwest::Response) -> Result<Response<BoxedBody>> {
    let status = res.status().as_u16();
    let mut builder = Response::builder().status(status);
    for (k, v) in res.headers().iter() {
        if !is_hop_by_hop(k.as_str()) {
            builder = builder.header(k.clone(), v.clone());
        }
    }
    let stream = res.bytes_stream().map(|r| match r {
        Ok(b) => Ok(Frame::data(b)),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    });
    let body = StreamBody::new(stream);
    let boxed: BoxedBody = body.map_err(io_to_anyhow).boxed_unsync();
    Ok(builder.body(boxed)?)
}

/// Wrap a stream of EventStream frames into the HTTP response.
fn stream_response_eventstream(
    stream: futures::stream::BoxStream<'static, std::io::Result<Bytes>>,
) -> Result<Response<BoxedBody>> {
    let body = StreamBody::new(stream.map(|r| r.map(Frame::data)));
    let boxed: BoxedBody = body.map_err(io_to_anyhow).boxed_unsync();
    let res = Response::builder()
        .status(200)
        .header("content-type", "application/vnd.amazon.eventstream")
        .header("transfer-encoding", "chunked")
        .body(boxed)?;
    Ok(res)
}

fn stub_to_response(r: agbridge_handlers::InterceptResult) -> Result<Response<BoxedBody>> {
    let mut b = Response::builder().status(r.status);
    for (k, v) in r.headers.iter() {
        b = b.header(k.clone(), v.clone());
    }
    let bytes = match r.body {
        agbridge_handlers::BodyOut::Bytes(b) => b,
        _ => Bytes::new(),
    };
    Ok(b.body(Full::new(bytes).map_err(io_to_anyhow).boxed_unsync())?)
}

fn json_response(status: u16, body: &'static [u8]) -> Response<BoxedBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(body)).map_err(io_to_anyhow).boxed_unsync())
        .unwrap()
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "te" | "trailer" | "upgrade"
    )
}

pub type BoxedBody = http_body_util::combinators::UnsyncBoxBody<Bytes, anyhow::Error>;

fn io_to_anyhow(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

/// SNI resolver — issues per-domain leaf certs lazily.
#[derive(Debug)]
struct SniResolver {
    cert: CertManager,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?.to_string();
        let leaf = self.cert.leaf_for(&sni).ok()?;
        let cert_chain = parse_pem_certs(&leaf.cert_pem)?;
        let key = parse_pem_key(&leaf.key_pem)?;
        Some(Arc::new(CertifiedKey::new(cert_chain, key)))
    }
}

fn parse_pem_certs(pem: &str) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut reader = pem.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).filter_map(|r| r.ok()).collect();
    if certs.is_empty() { None } else { Some(certs) }
}

fn parse_pem_key(pem: &str) -> Option<Arc<dyn rustls::sign::SigningKey>> {
    let mut reader = pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut reader).ok().flatten()?;
    rustls::crypto::ring::sign::any_supported_type(&key).ok()
}
