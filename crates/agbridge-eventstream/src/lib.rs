//! AWS EventStream binary frame encoder.
//!
//! Wire format (big-endian):
//!
//! ```text
//! [totalLen 4B] [headersLen 4B] [preludeCRC 4B]
//! [headers ...] [payload bytes ...] [messageCRC 4B]
//! ```
//!
//! Each header is `[nameLen 1B][name UTF-8][type 1B][...]`. Type 7 (string) is
//! the only one we emit. The Smithy SDK that Kiro uses requires three system
//! headers per frame: `:message-type`, `:event-type`, `:content-type`.
//!
//! Ported from `9router/src/mitm/handlers/kiro.js`.

use bytes::{BufMut, Bytes, BytesMut};

const HEADER_TYPE_STRING: u8 = 7;

/// Build a single event-type frame carrying a JSON payload.
pub fn build_frame(event_type: &str, payload: &[u8]) -> Bytes {
    let mut headers = BytesMut::new();
    encode_string_header(&mut headers, ":message-type", "event");
    encode_string_header(&mut headers, ":event-type", event_type);
    encode_string_header(&mut headers, ":content-type", "application/json");

    let headers_len = headers.len() as u32;
    let total_len = 4 + 4 + 4 + headers_len + payload.len() as u32 + 4;

    let mut frame = BytesMut::with_capacity(total_len as usize);
    frame.put_u32(total_len);
    frame.put_u32(headers_len);
    let prelude_crc = crc32fast::hash(&frame[..8]);
    frame.put_u32(prelude_crc);
    frame.extend_from_slice(&headers);
    frame.extend_from_slice(payload);
    let message_crc = crc32fast::hash(&frame);
    frame.put_u32(message_crc);

    frame.freeze()
}

fn encode_string_header(buf: &mut BytesMut, name: &str, value: &str) {
    let name_bytes = name.as_bytes();
    let value_bytes = value.as_bytes();
    debug_assert!(name_bytes.len() <= u8::MAX as usize, "header name too long");
    debug_assert!(value_bytes.len() <= u16::MAX as usize, "header value too long");

    buf.put_u8(name_bytes.len() as u8);
    buf.extend_from_slice(name_bytes);
    buf.put_u8(HEADER_TYPE_STRING);
    buf.put_u16(value_bytes.len() as u16);
    buf.extend_from_slice(value_bytes);
}

/// Convenience helpers used by the Kiro handler.
pub mod events {
    use super::build_frame;
    use bytes::Bytes;
    use serde_json::json;

    pub fn assistant_text(text: &str) -> Bytes {
        let payload = serde_json::to_vec(&json!({ "content": text })).unwrap();
        build_frame("assistantResponseEvent", &payload)
    }

    pub fn tool_use(tool_use_id: &str, name: &str, input_json_str: &str) -> Bytes {
        // Note: `input` MUST be a JSON STRING, not an object. Kiro's internal
        // tool dispatcher does `JSON.parse(input)`; sending a parsed object
        // turns into "[object Object]" on its side.
        let payload = serde_json::to_vec(&json!({
            "toolUseId": tool_use_id,
            "name": name,
            "input": input_json_str,
        }))
        .unwrap();
        build_frame("toolUseEvent", &payload)
    }

    pub fn message_stop() -> Bytes {
        build_frame("messageStopEvent", b"{}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout_is_correct() {
        let f = build_frame("assistantResponseEvent", br#"{"content":"hi"}"#);
        let total_len = u32::from_be_bytes(f[0..4].try_into().unwrap());
        assert_eq!(total_len as usize, f.len());
        let headers_len = u32::from_be_bytes(f[4..8].try_into().unwrap());
        let prelude_crc = u32::from_be_bytes(f[8..12].try_into().unwrap());
        assert_eq!(prelude_crc, crc32fast::hash(&f[..8]));
        let body_end = f.len() - 4;
        let msg_crc = u32::from_be_bytes(f[body_end..].try_into().unwrap());
        assert_eq!(msg_crc, crc32fast::hash(&f[..body_end]));
        assert!(headers_len > 0);
    }

    #[test]
    fn message_stop_payload_is_empty_object() {
        let f = events::message_stop();
        let body = String::from_utf8_lossy(&f[12..(f.len() - 4)]);
        assert!(body.contains("{}"));
    }
}
