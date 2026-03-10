//! Tauri plugin providing HTTP request capabilities with a domain allowlist
//! for security.
//!
//! # Overview
//!
//! This plugin exposes a `request(url, options)` API to the Tauri webview,
//! backed by Rust's `reqwest` crate. Every request is validated against a
//! domain allowlist that can be configured at plugin initialization and
//! modified at runtime from Rust via [`HttpClientExt`], preventing
//! unauthorized network access from the frontend.
//!
//! # Usage
//!
//! ```no_run
//! use std::time::Duration;
//!
//! tauri::Builder::default()
//!    .plugin(
//!       tauri_plugin_http_client::Builder::new()
//!          .allowed_domains(vec![
//!             "api.example.com".into(),
//!             "*.cdn.example.com".into(),
//!          ])
//!          .default_timeout(Duration::from_secs(30))
//!          .build()
//!    );
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tauri::{
   Manager, Runtime,
   plugin::{self, TauriPlugin},
};

pub mod allowlist;
pub mod client;
mod commands;
pub mod config;
pub mod error;
pub mod types;

use allowlist::DomainAllowlist;
use client::{HttpClientState, InFlightRequests, build_redirect_policy};
use config::{HttpClientConfig, RetryConfig};

/// Plugin builder for configuring the HTTP client before initialization.
///
/// # Examples
///
/// ```ignore
/// use std::time::Duration;
///
/// let plugin = tauri_plugin_http_client::Builder::new()
///    .allowed_domains(vec!["api.example.com".into()])
///    .default_timeout(Duration::from_secs(30))
///    .max_redirects(5)
///    .build();
/// ```
pub struct Builder {
   allowed_domains: Vec<String>,
   default_timeout: Option<Duration>,
   max_redirects: Option<usize>,
   max_response_body_size: Option<usize>,
   max_allowlist_size: Option<usize>,
   user_agent: Option<String>,
   default_headers: Option<HashMap<String, String>>,
   retry: Option<RetryConfig>,
}

impl Builder {
   /// Creates a new builder with no allowed domains (blocks all requests).
   pub fn new() -> Self {
      Self {
         allowed_domains: Vec::new(),
         default_timeout: None,
         max_redirects: None,
         max_response_body_size: None,
         max_allowlist_size: None,
         user_agent: None,
         default_headers: None,
         retry: None,
      }
   }

   /// Sets the list of allowed domain patterns.
   ///
   /// Supported formats:
   /// - `"api.example.com"` - exact match
   /// - `"*.example.com"` - any subdomain of `example.com`
   ///
   /// An empty list blocks all requests (secure by default).
   pub fn allowed_domains(mut self, domains: Vec<String>) -> Self {
      self.allowed_domains = domains;
      self
   }

   /// Sets the default request timeout. Can be overridden per-request.
   pub fn default_timeout(mut self, timeout: Duration) -> Self {
      self.default_timeout = Some(timeout);
      self
   }

   /// Sets the maximum number of redirects to follow (default: 10).
   pub fn max_redirects(mut self, max: usize) -> Self {
      self.max_redirects = Some(max);
      self
   }

   /// Sets the maximum response body size in bytes (default: 10MB).
   pub fn max_response_body_size(mut self, max: usize) -> Self {
      self.max_response_body_size = Some(max);
      self
   }

   /// Sets the maximum total number of patterns in the allowlist (default: 128).
   ///
   /// This cap applies to all patterns, including those set at init time and
   /// those added at runtime. It prevents runaway additions from buggy code.
   pub fn max_allowlist_size(mut self, max: usize) -> Self {
      self.max_allowlist_size = Some(max);
      self
   }

   /// Sets a custom User-Agent header for all requests.
   pub fn user_agent(mut self, ua: String) -> Self {
      self.user_agent = Some(ua);
      self
   }

   /// Sets default headers applied to all requests.
   ///
   /// Per-request headers override these defaults.
   pub fn default_headers(mut self, headers: HashMap<String, String>) -> Self {
      self.default_headers = Some(headers);
      self
   }

   /// Enables automatic retry with the provided configuration.
   ///
   /// By default, retry is disabled. Pass [`RetryConfig::default()`] for
   /// sensible defaults (3 retries, 200ms initial backoff, exponential
   /// backoff with jitter, only idempotent methods).
   ///
   /// # Examples
   ///
   /// ```no_run
   /// use tauri_plugin_http_client::config::RetryConfig;
   ///
   /// let plugin = tauri_plugin_http_client::Builder::new()
   ///    .allowed_domains(vec!["api.example.com".into()])
   ///    .retry(RetryConfig::default())
   ///    .build();
   /// ```
   pub fn retry(mut self, config: RetryConfig) -> Self {
      self.retry = Some(config);
      self
   }

   /// Convenience method to enable retry with a specific max retry count
   /// and default settings for all other retry parameters.
   ///
   /// Equivalent to `retry(RetryConfig { max_retries: n, ..Default::default() })`.
   pub fn max_retries(mut self, n: u32) -> Self {
      self.retry = Some(RetryConfig {
         max_retries: n,
         ..RetryConfig::default()
      });
      self
   }

   /// Builds the Tauri plugin with the configured settings.
   pub fn build<R: Runtime>(self) -> TauriPlugin<R> {
      let allowed_domains = self.allowed_domains;
      let default_timeout = self.default_timeout;
      let max_redirects = self.max_redirects.unwrap_or(10);
      let max_response_body_size = self.max_response_body_size.unwrap_or(10 * 1024 * 1024);
      let max_allowlist_size = self.max_allowlist_size.unwrap_or(128);
      let user_agent = self.user_agent;
      let default_headers = self.default_headers.unwrap_or_default();
      let retry = self.retry.unwrap_or_else(RetryConfig::disabled);

      plugin::Builder::new("http-client")
         .invoke_handler(tauri::generate_handler![
            commands::fetch,
            commands::abort_request,
         ])
         .setup(move |app, _api| {
            // Create shared allowlist: same Arc used by both HttpClientState
            // and the redirect policy closure.
            let allowlist = Arc::new(RwLock::new(
               DomainAllowlist::new(allowed_domains).map_err(|e| e.to_string())?,
            ));

            let redirect_policy = build_redirect_policy(Arc::clone(&allowlist), max_redirects);

            let mut client_builder = reqwest::Client::builder().redirect(redirect_policy);

            if let Some(ref ua) = user_agent {
               client_builder = client_builder.user_agent(ua.clone());
            }

            let client = client_builder.build().map_err(|e| e.to_string())?;

            let config = HttpClientConfig {
               default_timeout,
               max_redirects,
               max_response_body_size,
               max_allowlist_size,
               user_agent,
               default_headers,
               retry,
            };

            let state = HttpClientState::new(client, allowlist, config);

            app.manage(state);
            app.manage(InFlightRequests::new());

            Ok(())
         })
         .build()
   }
}

impl Default for Builder {
   fn default() -> Self {
      Self::new()
   }
}

/// Convenience function that creates a plugin with default settings.
///
/// The default configuration has an empty allowlist, which blocks all requests.
/// Use [`Builder`] for custom configuration.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
   Builder::new().build()
}

/// Extension trait providing access to the HTTP client state from any Tauri manager.
///
/// # Examples
///
/// ```no_run
/// use tauri::Manager;
/// use tauri_plugin_http_client::HttpClientExt;
///
/// // In a Tauri command or setup hook:
/// // let state = app.http_client();
/// // app.add_allowed_domains(vec!["new-api.example.com".into()]).unwrap();
/// ```
pub trait HttpClientExt<R: Runtime> {
   /// Returns a reference to the HTTP client state.
   fn http_client(&self) -> &HttpClientState;

   /// Adds a single domain pattern to the allowlist at runtime.
   ///
   /// See [`HttpClientState::add_allowed_domain`] for details.
   fn add_allowed_domain(&self, domain: impl Into<String>) -> error::Result<()>;

   /// Adds multiple domain patterns to the allowlist at runtime.
   ///
   /// See [`HttpClientState::add_allowed_domains`] for details.
   fn add_allowed_domains(&self, domains: Vec<String>) -> error::Result<()>;

   /// Removes a single domain from the runtime allowlist.
   ///
   /// See [`HttpClientState::remove_allowed_domain`] for details.
   fn remove_allowed_domain(&self, domain: impl Into<String>) -> error::Result<bool>;

   /// Removes multiple domains from the runtime allowlist.
   ///
   /// See [`HttpClientState::remove_allowed_domains`] for details.
   fn remove_allowed_domains(&self, domains: Vec<String>) -> error::Result<usize>;

   /// Removes all runtime-added domains, preserving config-time domains.
   ///
   /// See [`HttpClientState::remove_all_runtime_domains`] for details.
   fn remove_all_runtime_domains(&self) -> usize;
}

impl<R: Runtime, T: Manager<R>> HttpClientExt<R> for T {
   fn http_client(&self) -> &HttpClientState {
      self.state::<HttpClientState>().inner()
   }

   fn add_allowed_domain(&self, domain: impl Into<String>) -> error::Result<()> {
      self.http_client().add_allowed_domain(domain)
   }

   fn add_allowed_domains(&self, domains: Vec<String>) -> error::Result<()> {
      self.http_client().add_allowed_domains(domains)
   }

   fn remove_allowed_domain(&self, domain: impl Into<String>) -> error::Result<bool> {
      self.http_client().remove_allowed_domain(domain)
   }

   fn remove_allowed_domains(&self, domains: Vec<String>) -> error::Result<usize> {
      self.http_client().remove_allowed_domains(domains)
   }

   fn remove_all_runtime_domains(&self) -> usize {
      self.http_client().remove_all_runtime_domains()
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn test_builder_default_has_empty_allowlist() {
      let builder = Builder::new();

      assert!(builder.allowed_domains.is_empty());
      assert!(builder.default_timeout.is_none());
      assert!(builder.max_redirects.is_none());
      assert!(builder.max_response_body_size.is_none());
      assert!(builder.max_allowlist_size.is_none());
      assert!(builder.user_agent.is_none());
      assert!(builder.default_headers.is_none());
      assert!(builder.retry.is_none());
   }

   #[test]
   fn test_builder_default_impl_matches_new() {
      let from_new = Builder::new();
      let from_default = Builder::default();

      assert_eq!(from_new.allowed_domains, from_default.allowed_domains);
      assert_eq!(from_new.default_timeout, from_default.default_timeout);
      assert_eq!(from_new.max_redirects, from_default.max_redirects);
      assert_eq!(
         from_new.max_response_body_size,
         from_default.max_response_body_size
      );
      assert_eq!(from_new.max_allowlist_size, from_default.max_allowlist_size);
      assert_eq!(from_new.user_agent, from_default.user_agent);
      assert_eq!(from_new.default_headers, from_default.default_headers);
      assert!(from_new.retry.is_none());
      assert!(from_default.retry.is_none());
   }

   #[test]
   fn test_builder_setters() {
      let builder = Builder::new()
         .allowed_domains(vec!["example.com".into()])
         .default_timeout(Duration::from_secs(30))
         .max_redirects(5)
         .max_response_body_size(1024)
         .max_allowlist_size(64)
         .user_agent("test-agent".into())
         .default_headers(HashMap::from([("x-key".into(), "val".into())]));

      assert_eq!(builder.allowed_domains, vec!["example.com"]);
      assert_eq!(builder.default_timeout, Some(Duration::from_secs(30)));
      assert_eq!(builder.max_redirects, Some(5));
      assert_eq!(builder.max_response_body_size, Some(1024));
      assert_eq!(builder.max_allowlist_size, Some(64));
      assert_eq!(builder.user_agent, Some("test-agent".to_string()));
      assert_eq!(
         builder.default_headers,
         Some(HashMap::from([("x-key".into(), "val".into())]))
      );
   }

   #[test]
   fn test_builder_retry_setter() {
      let builder = Builder::new().retry(RetryConfig::default());

      assert!(builder.retry.is_some());
      assert_eq!(builder.retry.as_ref().unwrap().max_retries, 3);
   }

   #[test]
   fn test_builder_max_retries_convenience() {
      let builder = Builder::new().max_retries(5);

      assert!(builder.retry.is_some());
      assert_eq!(builder.retry.as_ref().unwrap().max_retries, 5);
      // Other fields should be defaults
      assert_eq!(
         builder.retry.as_ref().unwrap().initial_backoff,
         Duration::from_millis(200)
      );
   }
}
