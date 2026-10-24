use tauri::{AppHandle, Runtime, State};

use crate::client::{HttpClientState, InFlightRequests};
use crate::error::Result;
use crate::types::{ExecuteResult, FetchRequest};

/// Executes an HTTP request through the plugin's security and execution pipeline.
///
/// This is the primary IPC command invoked by the TypeScript guest.
///
/// Returns `tauri::ipc::Response` using binary framing:
/// `[4-byte BE metadata length][metadata JSON][body bytes]` sent as
/// `InvokeResponseBody::Raw`, delivered to the TypeScript guest as an
/// `ArrayBuffer`.
#[tauri::command]
pub(crate) async fn fetch<R: Runtime>(
   _app: AppHandle<R>,
   state: State<'_, HttpClientState>,
   in_flight: State<'_, InFlightRequests>,
   request: FetchRequest,
) -> Result<tauri::ipc::Response> {
   let request_id = request.request_id.clone();

   if let Some(ref id) = request_id {
      // Spawn as a trackable task for abort support.
      // NOTE: There is a race between spawn and register — the task could
      // complete before register() is called. The double-remove below
      // mitigates this by ensuring cleanup even if the spawned task's
      // internal remove races with register.
      let state_ref = state.inner().clone();
      let id_clone = id.clone();
      let in_flight_clone = in_flight.inner().clone();

      let handle = tokio::spawn(async move {
         let result = state_ref.execute(request).await;

         // Clean up tracking regardless of outcome
         in_flight_clone.remove(&id_clone).await;

         result
      });

      in_flight.register(id.clone(), handle.abort_handle()).await;

      let result = match handle.await {
         Ok(result) => result,
         Err(e) if e.is_cancelled() => Err(crate::error::Error::Aborted),
         Err(e) => Err(crate::error::Error::Other(format!("task panicked: {e}"))),
      };

      // Ensure cleanup even if spawn's internal remove raced with register
      in_flight.remove(id).await;

      result.and_then(pack_ipc_response)
   } else {
      state.execute(request).await.and_then(pack_ipc_response)
   }
}

/// Cancels an in-flight request by its request ID.
///
/// Returns `true` if a matching request was found and aborted,
/// `false` if no request with the given ID was in flight.
#[tauri::command]
pub(crate) async fn abort_request<R: Runtime>(
   _app: AppHandle<R>,
   in_flight: State<'_, InFlightRequests>,
   request_id: String,
) -> Result<bool> {
   Ok(HttpClientState::abort(&in_flight, &request_id).await)
}

/// Packs an `ExecuteResult` into a binary-framed IPC response.
///
/// Frame format: `[4-byte BE metadata length][metadata JSON][body bytes]`
/// sent as `InvokeResponseBody::Raw`.
fn pack_ipc_response(result: ExecuteResult) -> Result<tauri::ipc::Response> {
   let metadata_json = serde_json::to_vec(&result.metadata)
      .map_err(|e| crate::error::Error::Other(format!("metadata serialization failed: {e}")))?;

   let meta_len = u32::try_from(metadata_json.len())
      .map_err(|_| crate::error::Error::Other("metadata too large for IPC frame".into()))?;
   let mut buf = Vec::with_capacity(4 + metadata_json.len() + result.body.len());

   buf.extend_from_slice(&meta_len.to_be_bytes());
   buf.extend_from_slice(&metadata_json);
   buf.extend_from_slice(&result.body);

   Ok(tauri::ipc::Response::new(buf))
}

#[cfg(test)]
mod tests {
   use super::*;
   use crate::types::FetchResponseMetadata;
   use rstest::rstest;
   use std::collections::HashMap;

   #[test]
   fn test_pack_ipc_response_binary_framing_structure() {
      let result = ExecuteResult {
         metadata: FetchResponseMetadata {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::from([(
               "content-type".to_string(),
               vec!["application/json".to_string()],
            )]),
            url: "https://example.com".to_string(),
            redirected: false,
            retry_count: 0,
         },
         body: b"hello world".to_vec(),
      };

      let resp = pack_ipc_response(result).unwrap();
      let buf = extract_raw_bytes(resp);

      // First 4 bytes are big-endian metadata length
      let meta_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

      assert!(meta_len > 0, "metadata length should be non-zero");
      assert_eq!(buf.len(), 4 + meta_len + b"hello world".len());

      // Metadata should be valid JSON
      let meta_json: serde_json::Value = serde_json::from_slice(&buf[4..4 + meta_len]).unwrap();

      assert_eq!(meta_json["status"], 200);
      assert_eq!(meta_json["statusText"], "OK");
      assert_eq!(meta_json["url"], "https://example.com");
      assert_eq!(meta_json["redirected"], false);
      assert_eq!(meta_json["retryCount"], 0);

      // Body bytes follow metadata
      assert_eq!(&buf[4 + meta_len..], b"hello world");
   }

   #[rstest]
   // No body bytes after metadata
   #[case::empty(Vec::new())]
   // PNG signature: binary bytes must come through unchanged
   #[case::binary(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])]
   // Larger than u8::MAX: every body byte must still follow the metadata
   #[case::larger_than_u8_max(vec![0xAB; 1024])]
   fn test_pack_ipc_response_body_preserved(#[case] body: Vec<u8>) {
      let result = ExecuteResult {
         metadata: FetchResponseMetadata {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            url: "https://example.com".to_string(),
            redirected: false,
            retry_count: 0,
         },
         body: body.clone(),
      };

      let resp = pack_ipc_response(result).unwrap();
      let buf = extract_raw_bytes(resp);

      let meta_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

      // Exactly the body bytes follow the metadata
      assert_eq!(&buf[4 + meta_len..], body.as_slice());
   }

   #[test]
   fn test_pack_ipc_response_retry_count_in_metadata() {
      let result = ExecuteResult {
         metadata: FetchResponseMetadata {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            url: "https://example.com".to_string(),
            redirected: false,
            retry_count: 3,
         },
         body: b"ok".to_vec(),
      };

      let resp = pack_ipc_response(result).unwrap();
      let buf = extract_raw_bytes(resp);

      let meta_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
      let meta_json: serde_json::Value = serde_json::from_slice(&buf[4..4 + meta_len]).unwrap();

      assert_eq!(meta_json["retryCount"], 3);
   }

   #[test]
   fn test_pack_ipc_response_redirected_flag_in_metadata() {
      let result = ExecuteResult {
         metadata: FetchResponseMetadata {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            url: "https://example.com/final".to_string(),
            redirected: true,
            retry_count: 0,
         },
         body: b"redirected".to_vec(),
      };

      let resp = pack_ipc_response(result).unwrap();
      let buf = extract_raw_bytes(resp);

      let meta_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
      let meta_json: serde_json::Value = serde_json::from_slice(&buf[4..4 + meta_len]).unwrap();

      assert_eq!(meta_json["redirected"], true);
   }

   #[test]
   fn test_pack_ipc_response_headers_in_metadata() {
      let result = ExecuteResult {
         metadata: FetchResponseMetadata {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::from([
               (
                  "content-type".to_string(),
                  vec!["application/json".to_string()],
               ),
               ("x-request-id".to_string(), vec!["abc-123".to_string()]),
            ]),
            url: "https://example.com".to_string(),
            redirected: false,
            retry_count: 0,
         },
         body: b"{}".to_vec(),
      };

      let resp = pack_ipc_response(result).unwrap();
      let buf = extract_raw_bytes(resp);

      let meta_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
      let meta_json: serde_json::Value = serde_json::from_slice(&buf[4..4 + meta_len]).unwrap();

      assert!(meta_json["headers"]["content-type"].is_array());
      assert_eq!(meta_json["headers"]["content-type"][0], "application/json");
      assert_eq!(meta_json["headers"]["x-request-id"][0], "abc-123");
   }

   #[test]
   fn test_pack_ipc_response_metadata_camel_case() {
      let result = ExecuteResult {
         metadata: FetchResponseMetadata {
            status: 404,
            status_text: "Not Found".to_string(),
            headers: HashMap::new(),
            url: "https://example.com/missing".to_string(),
            redirected: false,
            retry_count: 1,
         },
         body: b"not found".to_vec(),
      };

      let resp = pack_ipc_response(result).unwrap();
      let buf = extract_raw_bytes(resp);

      let meta_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
      let meta_json: serde_json::Value = serde_json::from_slice(&buf[4..4 + meta_len]).unwrap();

      // Verify camelCase field names
      assert!(meta_json.get("statusText").is_some());
      assert!(meta_json.get("retryCount").is_some());
      // Verify no snake_case field names
      assert!(meta_json.get("status_text").is_none());
      assert!(meta_json.get("retry_count").is_none());
   }

   /// Extracts the raw bytes from a `tauri::ipc::Response` for test assertions.
   ///
   /// Uses the `IpcResponse` trait to get the `InvokeResponseBody`, then
   /// matches on the `Raw` variant. Panics if the response is JSON (which
   /// would indicate a bug in the desktop `pack_ipc_response`).
   fn extract_raw_bytes(resp: tauri::ipc::Response) -> Vec<u8> {
      use tauri::ipc::IpcResponse;

      match resp.body().expect("response body should be Ok") {
         tauri::ipc::InvokeResponseBody::Raw(bytes) => bytes,
         tauri::ipc::InvokeResponseBody::Json(json) => {
            panic!("expected Raw bytes, got Json: {json}")
         }
      }
   }
}
