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
}
