use std::error::Error as StdError;

use serde::{Serialize, ser::Serializer};

pub type Result<T> = std::result::Result<T, Error>;

/// Structured error response sent to the TypeScript guest via IPC.
///
/// Follows the `{code, message}` pattern used by `tauri-plugin-sqlite`.
#[derive(Serialize)]
struct ErrorResponse {
   code: String,
   message: String,
}

/// All error types that can occur during HTTP client operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
   #[error("domain not allowed: {0}")]
   DomainNotAllowed(String),

   #[error("url scheme not allowed: {0}")]
   SchemeNotAllowed(String),

   #[error("ip addresses not allowed in urls")]
   IpAddressNotAllowed,

   #[error("invalid url: {0}")]
   InvalidUrl(String),

   #[error("request error: {0}")]
   Request(reqwest::Error),

   #[error("request aborted")]
   Aborted,

   #[error("response too large: {size} bytes exceeds limit of {limit} bytes")]
   ResponseTooLarge { size: usize, limit: usize },

   #[error("redirect to disallowed domain: {0}")]
   RedirectBlocked(String),

   #[error("url must not contain userinfo")]
   UserinfoNotAllowed,

   #[error("allowlist size exceeded: {count} patterns exceeds limit of {limit}")]
   AllowlistSizeExceeded { count: usize, limit: usize },

   #[error("wildcard patterns not allowed at runtime: {0}")]
   WildcardNotAllowedAtRuntime(String),

   #[error("invalid domain pattern: {0}")]
   InvalidDomainPattern(String),

   #[error("forbidden header: {0}")]
   ForbiddenHeader(String),

   #[error("{0}")]
   Other(String),
}

impl From<reqwest::Error> for Error {
   fn from(e: reqwest::Error) -> Self {
      if e.is_redirect() {
         // Walk the error source chain to find our RedirectBlockedError
         let mut source = StdError::source(&e);

         while let Some(err) = source {
            if let Some(blocked) = err.downcast_ref::<crate::client::RedirectBlockedError>() {
               return Error::RedirectBlocked(blocked.0.clone());
            }
            source = err.source();
         }
      }

      Error::Request(e)
   }
}

impl Error {
   /// Returns `true` if this error represents a transient failure that may
   /// succeed on retry (connection errors and timeouts).
   ///
   /// Security errors (`DomainNotAllowed`, `IpAddressNotAllowed`, etc.) are
   /// never retryable — they indicate policy violations that will not change
   /// between attempts.
   pub fn is_retryable(&self) -> bool {
      matches!(self, Error::Request(e) if e.is_timeout() || e.is_connect())
   }

   fn code(&self) -> &str {
      match self {
         Error::DomainNotAllowed(_) => "DOMAIN_NOT_ALLOWED",
         Error::SchemeNotAllowed(_) => "SCHEME_NOT_ALLOWED",
         Error::IpAddressNotAllowed => "IP_ADDRESS_NOT_ALLOWED",
         Error::InvalidUrl(_) => "INVALID_URL",
         Error::Request(e) => {
            if e.is_timeout() {
               "TIMEOUT"
            } else if e.is_connect() {
               "CONNECTION_ERROR"
            } else {
               "REQUEST_ERROR"
            }
         }
         Error::Aborted => "ABORTED",
         Error::ResponseTooLarge { .. } => "RESPONSE_TOO_LARGE",
         Error::RedirectBlocked(_) => "REDIRECT_BLOCKED",
         // Surfaced as INVALID_URL to avoid leaking internal validation details
         Error::UserinfoNotAllowed => "INVALID_URL",
         Error::AllowlistSizeExceeded { .. } => "ALLOWLIST_SIZE_EXCEEDED",
         Error::WildcardNotAllowedAtRuntime(_) => "WILDCARD_NOT_ALLOWED_AT_RUNTIME",
         Error::InvalidDomainPattern(_) => "INVALID_DOMAIN_PATTERN",
         Error::ForbiddenHeader(_) => "FORBIDDEN_HEADER",
         Error::Other(_) => "ERROR",
      }
   }
}

impl Serialize for Error {
   fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
   where
      S: Serializer,
   {
      let resp = ErrorResponse {
         code: self.code().to_string(),
         message: self.to_string(),
      };

      resp.serialize(serializer)
   }
}

#[cfg(test)]
mod tests {
   use std::time::Duration;

   use wiremock::matchers::method;
   use wiremock::{Mock, MockServer, ResponseTemplate};

   use super::*;
   use rstest::rstest;

   #[rstest]
   #[case::domain_not_allowed(
      Error::DomainNotAllowed("evil.com".to_string()),
      "DOMAIN_NOT_ALLOWED",
      "domain not allowed: evil.com"
   )]
   #[case::scheme_not_allowed(
      Error::SchemeNotAllowed("ftp".to_string()),
      "SCHEME_NOT_ALLOWED",
      "url scheme not allowed: ftp"
   )]
   #[case::ip_address_not_allowed(
      Error::IpAddressNotAllowed,
      "IP_ADDRESS_NOT_ALLOWED",
      "ip addresses not allowed in urls"
   )]
   #[case::invalid_url(
      Error::InvalidUrl("not a url".to_string()),
      "INVALID_URL",
      "invalid url: not a url"
   )]
   #[case::aborted(Error::Aborted, "ABORTED", "request aborted")]
   #[case::response_too_large(
      Error::ResponseTooLarge {
         size: 20_000_000,
         limit: 10_000_000,
      },
      "RESPONSE_TOO_LARGE",
      "response too large: 20000000 bytes exceeds limit of 10000000 bytes"
   )]
   #[case::redirect_blocked(
      Error::RedirectBlocked("evil.com".to_string()),
      "REDIRECT_BLOCKED",
      "redirect to disallowed domain: evil.com"
   )]
   #[case::userinfo_not_allowed(
      Error::UserinfoNotAllowed,
      "INVALID_URL",
      "url must not contain userinfo"
   )]
   #[case::allowlist_size_exceeded(
      Error::AllowlistSizeExceeded {
         count: 150,
         limit: 128,
      },
      "ALLOWLIST_SIZE_EXCEEDED",
      "allowlist size exceeded: 150 patterns exceeds limit of 128"
   )]
   #[case::wildcard_not_allowed_at_runtime(
      Error::WildcardNotAllowedAtRuntime("*.evil.com".to_string()),
      "WILDCARD_NOT_ALLOWED_AT_RUNTIME",
      "wildcard patterns not allowed at runtime: *.evil.com"
   )]
   #[case::invalid_domain_pattern(
      Error::InvalidDomainPattern("pattern contains invalid characters".to_string()),
      "INVALID_DOMAIN_PATTERN",
      "invalid domain pattern: pattern contains invalid characters"
   )]
   #[case::forbidden_header(
      Error::ForbiddenHeader("host".to_string()),
      "FORBIDDEN_HEADER",
      "forbidden header: host"
   )]
   #[case::other(
      Error::Other("something went wrong".to_string()),
      "ERROR",
      "something went wrong"
   )]
   fn test_error_serialization_code_and_message(
      #[case] error: Error,
      #[case] code: &str,
      #[case] message: &str,
   ) {
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], code);
      assert_eq!(json["message"], message);
   }

   #[rstest]
   #[case::domain_not_allowed(Error::DomainNotAllowed("evil.com".to_string()))]
   #[case::scheme_not_allowed(Error::SchemeNotAllowed("ftp".to_string()))]
   #[case::ip_address_not_allowed(Error::IpAddressNotAllowed)]
   #[case::invalid_url(Error::InvalidUrl("bad".to_string()))]
   #[case::aborted(Error::Aborted)]
   #[case::redirect_blocked(Error::RedirectBlocked("evil.com".to_string()))]
   #[case::userinfo_not_allowed(Error::UserinfoNotAllowed)]
   #[case::allowlist_size_exceeded(Error::AllowlistSizeExceeded {
      count: 200,
      limit: 128,
   })]
   #[case::wildcard_not_allowed_at_runtime(Error::WildcardNotAllowedAtRuntime(
      "*.evil.com".to_string()
   ))]
   #[case::invalid_domain_pattern(Error::InvalidDomainPattern("bad".to_string()))]
   #[case::forbidden_header(Error::ForbiddenHeader("host".to_string()))]
   #[case::other(Error::Other("fail".to_string()))]
   #[case::response_too_large(Error::ResponseTooLarge {
      size: 20_000_000,
      limit: 10_000_000,
   })]
   fn test_is_retryable_non_request_errors_never_retryable(#[case] error: Error) {
      assert!(!error.is_retryable());
   }

   // --- Error::Request classification ---
   //
   // reqwest::Error has no public constructor, so each test provokes a real
   // failure locally (no external network).

   /// Request to a local port with nothing listening, yielding a connect error.
   async fn connect_error() -> reqwest::Error {
      // Bind to reserve a free port, then drop so nothing is listening
      let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
      let port = listener.local_addr().unwrap().port();

      drop(listener);

      reqwest::Client::new()
         .get(format!("http://127.0.0.1:{port}/"))
         .send()
         .await
         .unwrap_err()
   }

   /// Request against a server that replies far slower than the client timeout.
   async fn timeout_error() -> reqwest::Error {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
         .mount(&server)
         .await;

      reqwest::Client::builder()
         .timeout(Duration::from_millis(50))
         .build()
         .unwrap()
         .get(server.uri())
         .send()
         .await
         .unwrap_err()
   }

   /// Request with an unparsable URL, yielding a builder error that is
   /// neither a timeout nor a connect error.
   async fn builder_error() -> reqwest::Error {
      reqwest::Client::new()
         .get("not a url")
         .send()
         .await
         .unwrap_err()
   }

   #[tokio::test]
   async fn test_error_request_timeout_code_and_retryable() {
      let source = timeout_error().await;

      assert!(source.is_timeout());

      let error = Error::from(source);
      let json = serde_json::to_value(&error).unwrap();

      assert!(matches!(error, Error::Request(_)));
      assert_eq!(json["code"], "TIMEOUT");
      assert!(
         json["message"]
            .as_str()
            .unwrap()
            .starts_with("request error:")
      );
      assert!(error.is_retryable());
   }

   #[tokio::test]
   async fn test_error_request_connect_code_and_retryable() {
      let source = connect_error().await;

      assert!(source.is_connect());
      assert!(!source.is_timeout());

      let error = Error::from(source);
      let json = serde_json::to_value(&error).unwrap();

      assert!(matches!(error, Error::Request(_)));
      assert_eq!(json["code"], "CONNECTION_ERROR");
      assert!(
         json["message"]
            .as_str()
            .unwrap()
            .starts_with("request error:")
      );
      assert!(error.is_retryable());
   }

   #[tokio::test]
   async fn test_error_request_other_code_not_retryable() {
      let source = builder_error().await;

      assert!(!source.is_timeout());
      assert!(!source.is_connect());

      let error = Error::from(source);
      let json = serde_json::to_value(&error).unwrap();

      assert!(matches!(error, Error::Request(_)));
      assert_eq!(json["code"], "REQUEST_ERROR");
      assert!(
         json["message"]
            .as_str()
            .unwrap()
            .starts_with("request error:")
      );
      assert!(!error.is_retryable());
   }
}
