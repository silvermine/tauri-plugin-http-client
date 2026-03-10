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
   Request(#[from] reqwest::Error),

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

   #[error("{0}")]
   Other(String),
}

impl Error {
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
   use super::*;

   #[test]
   fn test_error_serialization_domain_not_allowed() {
      let error = Error::DomainNotAllowed("evil.com".to_string());
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "DOMAIN_NOT_ALLOWED");
      assert_eq!(json["message"], "domain not allowed: evil.com");
   }

   #[test]
   fn test_error_serialization_scheme_not_allowed() {
      let error = Error::SchemeNotAllowed("ftp".to_string());
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "SCHEME_NOT_ALLOWED");
      assert_eq!(json["message"], "url scheme not allowed: ftp");
   }

   #[test]
   fn test_error_serialization_ip_address_not_allowed() {
      let error = Error::IpAddressNotAllowed;
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "IP_ADDRESS_NOT_ALLOWED");
   }

   #[test]
   fn test_error_serialization_invalid_url() {
      let error = Error::InvalidUrl("not a url".to_string());
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "INVALID_URL");
   }

   #[test]
   fn test_error_serialization_aborted() {
      let error = Error::Aborted;
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "ABORTED");
      assert_eq!(json["message"], "request aborted");
   }

   #[test]
   fn test_error_serialization_response_too_large() {
      let error = Error::ResponseTooLarge {
         size: 20_000_000,
         limit: 10_000_000,
      };
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "RESPONSE_TOO_LARGE");
      assert!(
         json["message"]
            .as_str()
            .unwrap()
            .contains("20000000 bytes exceeds limit of 10000000 bytes")
      );
   }

   #[test]
   fn test_error_serialization_redirect_blocked() {
      let error = Error::RedirectBlocked("evil.com".to_string());
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "REDIRECT_BLOCKED");
   }

   #[test]
   fn test_error_serialization_userinfo_not_allowed() {
      let error = Error::UserinfoNotAllowed;
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "INVALID_URL");
   }

   #[test]
   fn test_error_serialization_allowlist_size_exceeded() {
      let error = Error::AllowlistSizeExceeded {
         count: 150,
         limit: 128,
      };
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "ALLOWLIST_SIZE_EXCEEDED");
      assert!(
         json["message"]
            .as_str()
            .unwrap()
            .contains("150 patterns exceeds limit of 128")
      );
   }

   #[test]
   fn test_error_serialization_wildcard_not_allowed_at_runtime() {
      let error = Error::WildcardNotAllowedAtRuntime("*.evil.com".to_string());
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "WILDCARD_NOT_ALLOWED_AT_RUNTIME");
      assert!(json["message"].as_str().unwrap().contains("*.evil.com"));
   }

   #[test]
   fn test_error_serialization_invalid_domain_pattern() {
      let error = Error::InvalidDomainPattern("pattern contains invalid characters".to_string());
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "INVALID_DOMAIN_PATTERN");
      assert!(
         json["message"]
            .as_str()
            .unwrap()
            .contains("pattern contains invalid characters")
      );
   }

   #[test]
   fn test_error_serialization_other() {
      let error = Error::Other("something went wrong".to_string());
      let json = serde_json::to_value(&error).unwrap();

      assert_eq!(json["code"], "ERROR");
      assert_eq!(json["message"], "something went wrong");
   }
}
