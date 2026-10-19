//! Builder for backend (non-IPC) HTTP requests.
//!
//! Provides a fluent API for constructing requests that go through the full
//! plugin security pipeline (domain allowlist, private IP blocking, redirect
//! validation, streaming body limits, retry).
//!
//! Created by [`HttpClientState::get`](crate::client::HttpClientState::get),
//! [`HttpClientState::post`](crate::client::HttpClientState::post),
//! [`HttpClientState::head`](crate::client::HttpClientState::head), or
//! [`HttpClientState::request`](crate::client::HttpClientState::request).
//!
//! # Examples
//!
//! ```no_run
//! use tauri_plugin_http_client::client::HttpClientState;
//!
//! async fn example(http: &HttpClientState) {
//!    let response = http.get("https://api.example.com/data")
//!       .header("Accept", "application/json")
//!       .send()
//!       .await
//!       .unwrap();
//!
//!    let status = response.status();
//!    let body = response.text().unwrap();
//! }
//! ```

use std::time::Duration;

use crate::client::HttpClientState;
use crate::error::Result;
use crate::response::Response;

/// Fluent builder for Rust-side HTTP requests through the plugin security pipeline.
///
/// Created by [`HttpClientState::get`](crate::client::HttpClientState::get),
/// [`HttpClientState::post`](crate::client::HttpClientState::post),
/// [`HttpClientState::head`](crate::client::HttpClientState::head), or
/// [`HttpClientState::request`](crate::client::HttpClientState::request).
/// Call [`send`](RequestBuilder::send) to execute the request.
///
/// All requests go through the same security pipeline as IPC-initiated requests:
/// domain allowlist validation, private IP blocking, redirect policy enforcement,
/// streaming body limits, and configurable retry.
pub struct RequestBuilder<'a> {
   state: &'a HttpClientState,
   url: String,
   method: reqwest::Method,
   headers: Vec<(String, String)>,
   body: Option<Vec<u8>>,
   timeout: Option<Duration>,
   max_retries: Option<u32>,
}

impl<'a> RequestBuilder<'a> {
   pub(crate) fn new(state: &'a HttpClientState, method: reqwest::Method, url: String) -> Self {
      Self {
         state,
         url,
         method,
         headers: Vec::new(),
         body: None,
         timeout: None,
         max_retries: None,
      }
   }

   /// Adds a header to the request.
   ///
   /// Per-request headers override default headers configured at plugin init.
   /// Forbidden headers (e.g., `Host`, `Connection`) are rejected at send time.
   pub fn header(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
      self.headers.push((key.into(), val.into()));
      self
   }

   /// Sets the request body.
   pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
      self.body = Some(body.into());
      self
   }

   /// Sets a per-request timeout, overriding the plugin's default timeout.
   pub fn timeout(mut self, timeout: Duration) -> Self {
      self.timeout = Some(timeout);
      self
   }

   /// Sets the maximum number of retries for this request.
   ///
   /// Capped at the plugin-level `RetryConfig::max_retries` ceiling.
   /// `Some(0)` disables retry for this request.
   pub fn max_retries(mut self, n: u32) -> Self {
      self.max_retries = Some(n);
      self
   }

   /// Execute the request through the full security pipeline.
   ///
   /// Validates the URL against the domain allowlist, applies private IP
   /// blocking, enforces redirect policy, streams the response body with
   /// size limits, and retries on transient failures.
   pub async fn send(self) -> Result<Response> {
      self
         .state
         .execute_backend(
            &self.url,
            self.method,
            &self.headers,
            self.body.as_deref(),
            self.timeout,
            self.max_retries,
         )
         .await
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use rstest::rstest;

   fn test_state() -> HttpClientState {
      HttpClientState::for_testing()
   }

   #[test]
   fn test_builder_defaults() {
      let state = test_state();
      let builder = RequestBuilder::new(&state, reqwest::Method::GET, "https://example.com".into());

      assert_eq!(builder.url, "https://example.com");
      assert_eq!(builder.method, reqwest::Method::GET);
      assert!(builder.headers.is_empty());
      assert!(builder.body.is_none());
      assert!(builder.timeout.is_none());
      assert!(builder.max_retries.is_none());
   }

   #[test]
   fn test_header_accumulates() {
      let state = test_state();
      let builder = state
         .get("https://example.com")
         .header("Accept", "application/json")
         .header("X-Custom", "value");

      assert_eq!(builder.headers.len(), 2);
      assert_eq!(
         builder.headers[0],
         ("Accept".to_string(), "application/json".to_string())
      );
      assert_eq!(
         builder.headers[1],
         ("X-Custom".to_string(), "value".to_string())
      );
   }

   #[test]
   fn test_body_set() {
      let state = test_state();
      let builder = state.post("https://example.com").body(b"payload".to_vec());

      assert_eq!(builder.body.as_deref(), Some(b"payload".as_slice()));
   }

   #[test]
   fn test_body_from_string() {
      let state = test_state();
      let builder = state
         .post("https://example.com")
         .body(String::from("text payload"));

      assert_eq!(builder.body.as_deref(), Some(b"text payload".as_slice()));
   }

   #[test]
   fn test_timeout_set() {
      let state = test_state();
      let builder = state
         .get("https://example.com")
         .timeout(Duration::from_secs(5));

      assert_eq!(builder.timeout, Some(Duration::from_secs(5)));
   }

   #[rstest]
   #[case::custom_count(3)]
   #[case::zero_disables(0)]
   fn test_max_retries_stores_value(#[case] retries: u32) {
      let state = test_state();
      let builder = state.get("https://example.com").max_retries(retries);

      assert_eq!(builder.max_retries, Some(retries));
   }

   #[test]
   fn test_method_preserved() {
      let state = test_state();

      let get = state.get("https://example.com");

      assert_eq!(get.method, reqwest::Method::GET);

      let post = state.post("https://example.com");

      assert_eq!(post.method, reqwest::Method::POST);

      let head = state.head("https://example.com");

      assert_eq!(head.method, reqwest::Method::HEAD);

      let put = state.request(reqwest::Method::PUT, "https://example.com");

      assert_eq!(put.method, reqwest::Method::PUT);
   }

   #[test]
   fn test_chaining() {
      let state = test_state();
      let builder = state
         .post("https://example.com")
         .header("Content-Type", "application/json")
         .body(b"{\"key\":\"value\"}".to_vec())
         .timeout(Duration::from_secs(30))
         .max_retries(2);

      assert_eq!(builder.url, "https://example.com");
      assert_eq!(builder.method, reqwest::Method::POST);
      assert_eq!(builder.headers.len(), 1);
      assert!(builder.body.is_some());
      assert_eq!(builder.timeout, Some(Duration::from_secs(30)));
      assert_eq!(builder.max_retries, Some(2));
   }

   #[tokio::test]
   async fn test_send_happy_path() {
      let server = wiremock::MockServer::start().await;

      wiremock::Mock::given(wiremock::matchers::method("GET"))
         .and(wiremock::matchers::path("/test"))
         .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = test_state();
      let resp = state
         .get(format!("{}/test", server.uri()))
         .send()
         .await
         .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::OK);
      assert_eq!(resp.text().unwrap(), "ok");
   }

   #[tokio::test]
   async fn test_send_post_with_body_and_headers() {
      let server = wiremock::MockServer::start().await;

      wiremock::Mock::given(wiremock::matchers::method("POST"))
         .and(wiremock::matchers::path("/submit"))
         .and(wiremock::matchers::header(
            "content-type",
            "application/json",
         ))
         .respond_with(wiremock::ResponseTemplate::new(201).set_body_string("created"))
         .mount(&server)
         .await;

      let state = test_state();
      let resp = state
         .post(format!("{}/submit", server.uri()))
         .header("content-type", "application/json")
         .body(b"{\"name\":\"test\"}".to_vec())
         .send()
         .await
         .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
      assert_eq!(resp.text().unwrap(), "created");
   }

   #[tokio::test]
   async fn test_send_head_request() {
      let server = wiremock::MockServer::start().await;

      wiremock::Mock::given(wiremock::matchers::method("HEAD"))
         .and(wiremock::matchers::path("/resource"))
         .respond_with(wiremock::ResponseTemplate::new(200).insert_header("content-length", "1024"))
         .mount(&server)
         .await;

      let state = test_state();
      let resp = state
         .head(format!("{}/resource", server.uri()))
         .send()
         .await
         .unwrap();

      assert_eq!(resp.status(), reqwest::StatusCode::OK);
      assert_eq!(resp.headers().get("content-length").unwrap(), "1024");
      assert!(resp.body().is_empty());
   }

   #[tokio::test]
   async fn test_send_forbidden_header_rejected() {
      let state = test_state();
      let result = state
         .get("http://127.0.0.1:1234")
         .header("host", "evil.com")
         .send()
         .await;

      assert!(result.is_err());
      let err = result.unwrap_err();

      assert!(matches!(err, crate::error::Error::ForbiddenHeader(_)));
   }
}
