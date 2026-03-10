use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Request payload sent from the TypeScript guest to the Rust backend via IPC.
///
/// All URL parsing and validation happens exclusively in Rust to avoid
/// JS/Rust URL parsing differentials.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchRequest {
   pub url: String,
   pub method: Option<String>,
   pub headers: Option<HashMap<String, String>>,
   pub body: Option<String>,
   pub body_encoding: Option<String>,
   pub timeout_ms: Option<u64>,
   pub request_id: Option<String>,
}

/// Response payload sent from the Rust backend to the TypeScript guest via IPC.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchResponse {
   pub status: u16,
   pub status_text: String,
   pub headers: HashMap<String, Vec<String>>,
   pub body: String,
   pub body_encoding: String,
   pub url: String,
   pub redirected: bool,
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn test_fetch_request_deserializes_camel_case() {
      let json = serde_json::json!({
         "url": "https://example.com",
         "method": "POST",
         "headers": {"content-type": "application/json"},
         "body": "hello",
         "bodyEncoding": "utf8",
         "timeoutMs": 5000,
         "requestId": "req-1"
      });

      let req: FetchRequest = serde_json::from_value(json).unwrap();

      assert_eq!(req.url, "https://example.com");
      assert_eq!(req.method.as_deref(), Some("POST"));
      assert_eq!(
         req.headers.as_ref().unwrap().get("content-type").unwrap(),
         "application/json"
      );
      assert_eq!(req.body.as_deref(), Some("hello"));
      assert_eq!(req.body_encoding.as_deref(), Some("utf8"));
      assert_eq!(req.timeout_ms, Some(5000));
      assert_eq!(req.request_id.as_deref(), Some("req-1"));
   }

   #[test]
   fn test_fetch_request_minimal() {
      let json = serde_json::json!({"url": "https://example.com"});
      let req: FetchRequest = serde_json::from_value(json).unwrap();

      assert_eq!(req.url, "https://example.com");
      assert!(req.method.is_none());
      assert!(req.headers.is_none());
      assert!(req.body.is_none());
      assert!(req.body_encoding.is_none());
      assert!(req.timeout_ms.is_none());
      assert!(req.request_id.is_none());
   }

   #[test]
   fn test_fetch_response_serializes_camel_case() {
      let resp = FetchResponse {
         status: 200,
         status_text: "OK".to_string(),
         headers: HashMap::from([("content-type".to_string(), vec!["text/html".to_string()])]),
         body: "hello".to_string(),
         body_encoding: "utf8".to_string(),
         url: "https://example.com".to_string(),
         redirected: false,
      };

      let json = serde_json::to_value(&resp).unwrap();

      assert_eq!(json["status"], 200);
      assert_eq!(json["statusText"], "OK");
      assert_eq!(json["body"], "hello");
      assert_eq!(json["bodyEncoding"], "utf8");
      assert_eq!(json["url"], "https://example.com");
      assert_eq!(json["redirected"], false);
      assert!(json["headers"]["content-type"].is_array());
   }
}
