use std::collections::HashMap;
use std::time::Duration;

/// Configuration for the HTTP client plugin, set during plugin initialization.
///
/// All fields have sensible defaults. The configuration is immutable after
/// plugin setup.
pub struct HttpClientConfig {
   pub default_timeout: Option<Duration>,
   pub max_redirects: usize,
   pub max_response_body_size: usize,
   pub max_allowlist_size: usize,
   pub user_agent: Option<String>,
   pub default_headers: HashMap<String, String>,
   pub retry: RetryConfig,
   /// Disables the DNS rebinding check (private IP rejection after resolution).
   ///
   /// When `true`, requests and redirects to private IPs (127.0.0.1, etc.)
   /// are allowed. Only intended for integration tests where the test server
   /// resolves to localhost.
   ///
   /// **Default: `false`.** Do not enable in production — the DNS rebinding
   /// check is a defense-in-depth layer against SSRF.
   pub(crate) allow_private_ip: bool,
}

impl Default for HttpClientConfig {
   fn default() -> Self {
      Self {
         default_timeout: None,
         max_redirects: 10,
         max_response_body_size: 10 * 1024 * 1024, // 10MB
         max_allowlist_size: 128,
         user_agent: None,
         default_headers: HashMap::new(),
         retry: RetryConfig::disabled(),
         allow_private_ip: false,
      }
   }
}

/// Configuration for automatic request retries.
///
/// Disabled by default (`max_retries: 0`). Enable via
/// [`Builder::retry`](crate::Builder::retry) or
/// [`Builder::max_retries`](crate::Builder::max_retries).
///
/// When enabled, only transient errors (connection failures, timeouts) and
/// configurable status codes trigger retries. Security errors are never
/// retried.
///
/// Timeout is per-attempt: a request with `max_retries: 3` and a 10s timeout
/// could take up to ~43s (4 attempts + backoff delays).
#[derive(Debug, Clone)]
pub struct RetryConfig {
   /// Maximum retry attempts (not counting the initial request). 0 = disabled.
   pub max_retries: u32,
   /// Base delay before the first retry. Default: 200ms.
   /// Subsequent retries use exponential backoff: `initial_backoff * 2^(attempt-1)`.
   pub initial_backoff: Duration,
   /// Maximum backoff duration (caps exponential growth). Default: 10s.
   pub max_backoff: Duration,
   /// HTTP status codes that trigger a retry. Default: `[408, 429, 500, 502, 503, 504]`.
   ///
   /// - **408 Request Timeout**: Server closed an idle connection (RFC 9110 §15.5.9).
   ///   Explicitly transient — the server is inviting the client to retry.
   /// - **429 Too Many Requests**: Rate limited (RFC 6585). Retried with
   ///   `Retry-After` header support when present.
   /// - **500 Internal Server Error**: Often transient in practice (OOM, database
   ///   pool exhaustion, deployment blips). Safe to retry for idempotent methods;
   ///   the `retryable_methods` guard prevents duplicate side effects on mutations.
   /// - **502 Bad Gateway**: Upstream sent an invalid response. Classic transient
   ///   infrastructure failure in load-balanced environments.
   /// - **503 Service Unavailable**: Server explicitly overloaded or in maintenance
   ///   (RFC 9110 §15.6.4). The most unambiguously retriable status code.
   /// - **504 Gateway Timeout**: Upstream didn't respond in time. Transient by nature.
   ///
   /// Notably excluded: **501** (server doesn't support the method — permanent),
   /// **505** (HTTP version not supported — permanent), **511** (captive portal).
   pub retryable_status_codes: Vec<u16>,
   /// Maximum duration to wait when honoring a `Retry-After` header.
   /// Values exceeding this cap are clamped. Default: 60s.
   pub max_retry_after: Duration,
   /// HTTP methods eligible for retry. Default: `["GET", "HEAD", "PUT", "DELETE", "OPTIONS"]`
   /// — the idempotent methods defined by RFC 9110 §9.2.2.
   ///
   /// PUT and DELETE are idempotent: repeating them produces the same server
   /// state as a single execution. POST and PATCH are excluded because they
   /// are not idempotent — retrying them risks duplicate side effects (e.g.,
   /// creating duplicate resources or applying a patch twice).
   ///
   /// Set to `None` to retry all methods regardless of idempotency. Only do
   /// this if you know all endpoints handle duplicate requests safely (e.g.,
   /// via idempotency keys).
   pub retryable_methods: Option<Vec<String>>,
}

impl RetryConfig {
   /// Returns a `RetryConfig` with retry disabled (`max_retries: 0`).
   pub fn disabled() -> Self {
      Self {
         max_retries: 0,
         ..Self::default()
      }
   }

   /// Returns `true` if the given status code is in the retryable set.
   pub fn is_retryable_status(&self, status: u16) -> bool {
      self.retryable_status_codes.contains(&status)
   }

   /// Returns `true` if the given HTTP method is eligible for retry.
   pub fn is_retryable_method(&self, method: &str) -> bool {
      match &self.retryable_methods {
         None => true,
         Some(methods) => methods.iter().any(|m| m.eq_ignore_ascii_case(method)),
      }
   }
}

impl Default for RetryConfig {
   fn default() -> Self {
      Self {
         max_retries: 3,
         initial_backoff: Duration::from_millis(200),
         max_backoff: Duration::from_secs(10),
         retryable_status_codes: vec![408, 429, 500, 502, 503, 504],
         max_retry_after: Duration::from_secs(60),
         retryable_methods: Some(vec![
            "GET".to_string(),
            "HEAD".to_string(),
            "PUT".to_string(),
            "DELETE".to_string(),
            "OPTIONS".to_string(),
         ]),
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn test_config_default_values_correct() {
      let config = HttpClientConfig::default();

      assert!(config.default_timeout.is_none());
      assert_eq!(config.max_redirects, 10);
      assert_eq!(config.max_allowlist_size, 128);
      assert!(config.user_agent.is_none());
      assert!(config.default_headers.is_empty());
   }

   #[test]
   fn test_config_default_max_response_body_size_is_10mb() {
      let config = HttpClientConfig::default();

      assert_eq!(config.max_response_body_size, 10 * 1024 * 1024);
   }

   #[test]
   fn test_config_default_retry_is_disabled() {
      let config = HttpClientConfig::default();

      assert_eq!(config.retry.max_retries, 0);
   }

   #[test]
   fn test_retry_config_default_values() {
      let config = RetryConfig::default();

      assert_eq!(config.max_retries, 3);
      assert_eq!(config.initial_backoff, Duration::from_millis(200));
      assert_eq!(config.max_backoff, Duration::from_secs(10));
      assert_eq!(
         config.retryable_status_codes,
         vec![408, 429, 500, 502, 503, 504]
      );
      assert_eq!(config.max_retry_after, Duration::from_secs(60));
      assert_eq!(
         config.retryable_methods,
         Some(vec![
            "GET".to_string(),
            "HEAD".to_string(),
            "PUT".to_string(),
            "DELETE".to_string(),
            "OPTIONS".to_string()
         ])
      );
   }

   #[test]
   fn test_retry_config_disabled() {
      let config = RetryConfig::disabled();

      assert_eq!(config.max_retries, 0);
      // Other fields inherit defaults
      assert_eq!(config.initial_backoff, Duration::from_millis(200));
   }

   #[test]
   fn test_is_retryable_status() {
      let config = RetryConfig::default();

      assert!(config.is_retryable_status(408));
      assert!(config.is_retryable_status(429));
      assert!(config.is_retryable_status(500));
      assert!(config.is_retryable_status(502));
      assert!(config.is_retryable_status(503));
      assert!(config.is_retryable_status(504));
      assert!(!config.is_retryable_status(200));
      assert!(!config.is_retryable_status(400));
      assert!(!config.is_retryable_status(401));
      assert!(!config.is_retryable_status(403));
      assert!(!config.is_retryable_status(404));
      assert!(!config.is_retryable_status(501));
   }

   /// 408 Request Timeout is retried because it represents a server-side idle
   /// connection timeout (RFC 9110 §15.5.9) — the server is explicitly inviting
   /// the client to resend the request.
   #[test]
   fn test_is_retryable_status_408_request_timeout() {
      let config = RetryConfig::default();

      assert!(config.is_retryable_status(408));
   }

   #[test]
   fn test_is_retryable_method_default() {
      let config = RetryConfig::default();

      assert!(config.is_retryable_method("GET"));
      assert!(config.is_retryable_method("HEAD"));
      assert!(config.is_retryable_method("PUT"));
      assert!(config.is_retryable_method("DELETE"));
      assert!(config.is_retryable_method("OPTIONS"));
      assert!(config.is_retryable_method("get")); // case-insensitive
      assert!(config.is_retryable_method("put")); // case-insensitive
      assert!(config.is_retryable_method("delete")); // case-insensitive
      assert!(!config.is_retryable_method("POST"));
      assert!(!config.is_retryable_method("PATCH"));
   }

   /// POST and PATCH are not idempotent (RFC 9110 §9.2.2) — retrying them
   /// risks duplicate side effects (e.g., creating duplicate resources or
   /// applying a patch twice). They are excluded from retries by default.
   #[test]
   fn test_non_idempotent_methods_not_retried_by_default() {
      let config = RetryConfig::default();

      assert!(!config.is_retryable_method("POST"));
      assert!(!config.is_retryable_method("PATCH"));
   }

   #[test]
   fn test_is_retryable_method_none_allows_all() {
      let config = RetryConfig {
         retryable_methods: None,
         ..RetryConfig::default()
      };

      assert!(config.is_retryable_method("GET"));
      assert!(config.is_retryable_method("POST"));
      assert!(config.is_retryable_method("PUT"));
      assert!(config.is_retryable_method("DELETE"));
      assert!(config.is_retryable_method("PATCH"));
   }

   #[test]
   fn test_is_retryable_status_empty_list() {
      let config = RetryConfig {
         retryable_status_codes: vec![],
         ..RetryConfig::default()
      };

      assert!(!config.is_retryable_status(429));
      assert!(!config.is_retryable_status(503));
   }

   #[test]
   fn test_is_retryable_method_empty_list() {
      let config = RetryConfig {
         retryable_methods: Some(vec![]),
         ..RetryConfig::default()
      };

      assert!(!config.is_retryable_method("GET"));
      assert!(!config.is_retryable_method("POST"));
   }

   #[test]
   fn test_custom_retryable_status_codes() {
      let config = RetryConfig {
         retryable_status_codes: vec![418, 503],
         ..RetryConfig::default()
      };

      assert!(config.is_retryable_status(418));
      assert!(config.is_retryable_status(503));
      assert!(!config.is_retryable_status(500)); // Not in custom list
      assert!(!config.is_retryable_status(429)); // Not in custom list
   }
}
