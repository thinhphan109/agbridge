//! Cursor stub. The real wire format is protobuf; reverse-engineering it is
//! out of scope for v1. Returning 501 lets us keep the host listed in the
//! hosts file (so the IDE doesn't fall back to its real endpoint with a
//! broken DNS) while making the failure mode loud and obvious.

use anyhow::Result;
use bytes::Bytes;

pub struct CursorHandler;

impl CursorHandler {
    pub async fn intercept(&self, _url: &str, _body: Bytes) -> Result<crate::InterceptResult> {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "application/json".parse()?);
        Ok(crate::InterceptResult {
            status: 501,
            headers,
            body: crate::BodyOut::Bytes(Bytes::from_static(
                br#"{"error":{"message":"Cursor is not implemented in agbridge v1","type":"not_implemented"}}"#,
            )),
        })
    }
}
