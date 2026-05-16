//! Per-tool MITM intercept logic.
//!
//! Every handler reads a request body, optionally rewrites the model field,
//! forwards to the upstream 9router, and pipes the streamed response back to
//! the caller in the format the calling IDE expects.

pub mod antigravity;
pub mod copilot;
pub mod cursor;
pub mod kiro;
pub mod upstream;

use bytes::Bytes;
use http::HeaderMap;

/// Outcome returned by each handler. The core server takes this and writes
/// it to the underlying TLS stream.
pub struct InterceptResult {
    pub status: u16,
    pub headers: HeaderMap,
    /// Either a buffered body or a streaming SSE/EventStream body.
    pub body: BodyOut,
}

pub enum BodyOut {
    Bytes(Bytes),
    /// Boxed stream of byte chunks. Driven by tokio.
    Stream(futures::stream::BoxStream<'static, std::io::Result<Bytes>>),
}

/// Identify the tool a hostname belongs to. Returns `None` for hosts we
/// passthrough.
pub fn tool_for_host(host: &str) -> Option<Tool> {
    let h = host.split(':').next().unwrap_or(host);
    match h {
        "cloudcode-pa.googleapis.com" | "daily-cloudcode-pa.googleapis.com" => Some(Tool::Antigravity),
        "api.individual.githubcopilot.com" => Some(Tool::Copilot),
        "q.us-east-1.amazonaws.com" | "codewhisperer.us-east-1.amazonaws.com" => Some(Tool::Kiro),
        "api2.cursor.sh" => Some(Tool::Cursor),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Antigravity,
    Copilot,
    Kiro,
    Cursor,
}

/// Whether the URL path is a chat/completion endpoint we want to intercept.
pub fn is_intercepted_path(tool: Tool, path: &str) -> bool {
    match tool {
        Tool::Antigravity => path.contains(":generateContent") || path.contains(":streamGenerateContent"),
        Tool::Copilot => {
            path.contains("/chat/completions") || path.contains("/v1/messages") || path.contains("/responses")
        }
        Tool::Kiro => path.contains("/generateAssistantResponse"),
        Tool::Cursor => path.contains("/Run") || path.contains("/RunSSE") || path.contains("/RunPoll") || path.contains("/BidiAppend"),
    }
}

// re-export http for downstream modules
pub use http;
