//! Redaction-aware tracing helpers.
//!
//! Wraps any text emitted via `tracing` with a regex-based scrubber so leaked
//! tokens never end up in stdout/stderr, log files, or service event logs.
//!
//! Usage:
//! ```no_run
//! agbridge_logging::init("info");
//! tracing::info!(token = "sk-live-abcdef", "this is fine");
//! // → "this is fine token=\"[REDACTED]\""
//! ```

use std::sync::OnceLock;

use regex::Regex;
use tracing_subscriber::fmt::format::{DefaultFields, Writer};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Patterns that should be replaced with `[REDACTED]` in any log output.
fn patterns() -> &'static [Regex] {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            // Authorization: Bearer xxx
            Regex::new(r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+").unwrap(),
            // Generic API keys (OpenAI / Anthropic / generic sk-)
            Regex::new(r"sk-(?:ant-|live-|proj-|test-)?[A-Za-z0-9_\-]{12,}").unwrap(),
            // x-api-key: xxx
            Regex::new(r"(?i)(x-api-key\s*[:=]\s*)\S+").unwrap(),
            // bearer token in url query (?token=...)
            Regex::new(r"(?i)([?&](api_?key|token)=)[^&\s]+").unwrap(),
        ]
    })
}

pub fn redact(input: &str) -> String {
    let mut out = input.to_string();
    for re in patterns() {
        out = re.replace_all(&out, |caps: &regex::Captures| {
            // If the pattern has a capture group it represents the prefix to keep.
            if caps.len() > 1 {
                format!("{}[REDACTED]", &caps[1])
            } else {
                "[REDACTED]".to_string()
            }
        }).into_owned();
    }
    out
}

/// Initialise the global subscriber with redaction enabled.
pub fn init(directives: &str) {
    let filter = EnvFilter::try_new(directives).unwrap_or_else(|_| EnvFilter::new("info"));
    let layer = fmt::layer()
        .with_timer(SystemTime)
        .fmt_fields(RedactingFields::default());
    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .init();
}

#[derive(Default)]
struct RedactingFields {
    inner: DefaultFields,
}

impl<'w> FormatFields<'w> for RedactingFields {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        mut writer: Writer<'w>,
        fields: R,
    ) -> std::fmt::Result {
        let mut buf = String::new();
        let inner_writer = Writer::new(&mut buf);
        self.inner.format_fields(inner_writer, fields)?;
        let scrubbed = redact(&buf);
        writer.write_str(&scrubbed)
    }
}

// Re-export so binaries can do `use agbridge_logging::*` if they want.
pub use tracing;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_bearer() {
        let s = "Authorization: Bearer abc123def456ghi789";
        assert!(redact(s).contains("[REDACTED]"));
        assert!(!redact(s).contains("abc123"));
    }

    #[test]
    fn redacts_anthropic_key() {
        let s = "key=sk-ant-api03-AAAAbbbCCCCddddEEEE";
        let out = redact(s);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("AAAAbbbCCCC"));
    }

    #[test]
    fn redacts_openai_key() {
        let s = "OPENAI_API_KEY=sk-proj-abcdefghijklmnop";
        let out = redact(s);
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn keeps_safe_text() {
        let s = "starting agbridge on port 443";
        assert_eq!(redact(s), s);
    }

    #[test]
    fn redacts_url_query_token() {
        let s = "GET /v1/foo?api_key=secretvalue&x=1";
        let out = redact(s);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("secretvalue"));
    }

    #[test]
    fn redacts_x_api_key() {
        let s = "x-api-key: sk-1234567890abcdefg";
        let out = redact(s);
        assert!(out.contains("[REDACTED]"));
    }
}
