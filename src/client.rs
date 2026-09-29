use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use futures_util::StreamExt;
use parking_lot::RwLock;
use reqwest::redirect;

use reqwest::header::HeaderMap;

use crate::allowlist::{DomainAllowlist, is_private_ip};
use crate::config::{HttpClientConfig, RetryConfig};
use crate::error::{Error, Result};
use crate::types::{BodyEncoding, ExecuteResult, FetchRequest, FetchResponseMetadata};

/// Headers that are always forbidden in per-request and default headers.
///
/// - `host`: Prevents virtual-host routing attacks that bypass the domain allowlist.
/// - `connection`, `keep-alive`, `upgrade`: Hop-by-hop headers managed by reqwest;
///   caller-supplied values interfere with connection pooling and HTTP/2 multiplexing.
/// - `transfer-encoding`, `te`, `trailer`: Body framing headers managed by reqwest;
///   caller-supplied values enable request smuggling attacks.
///
/// Cookie/Authorization headers are intentionally excluded — this plugin's security
/// model is domain restriction, not credential management. Applications legitimately
/// need to set these for session-based APIs and auth tokens.
const FORBIDDEN_HEADERS: &[&str] = &[
   "host",
   "connection",
   "keep-alive",
   "transfer-encoding",
   "te",
   "upgrade",
   "trailer",
];

/// Header name prefixes that are always forbidden.
///
/// - `sec-`: Browser-set security headers (`Sec-Fetch-*`, `Sec-CH-*`).
///   Setting these from Rust/JS would misrepresent the request context.
/// - `proxy-`: Proxy control headers (`Proxy-Authorization`, `Proxy-Connection`).
///   These affect proxy routing in ways outside the plugin's security model.
const FORBIDDEN_HEADER_PREFIXES: &[&str] = &["sec-", "proxy-"];

/// Internal response type shared between the IPC and backend paths.
///
/// Carries native `reqwest` types so that each path can convert to its own
/// public type without intermediate re-encoding.
struct RawResponse {
   status: reqwest::StatusCode,
   headers: HeaderMap,
   url: url::Url,
   redirected: bool,
   body: Vec<u8>,
}

impl RawResponse {
   /// Converts to the IPC-oriented [`ExecuteResult`] (string headers,
   /// numeric status).
   fn into_execute_result(self, retry_count: u32) -> ExecuteResult {
      let mut response_headers: HashMap<String, Vec<String>> = HashMap::new();

      for (name, value) in &self.headers {
         let name = name.as_str().to_string();

         if let Ok(v) = value.to_str() {
            response_headers
               .entry(name)
               .or_default()
               .push(v.to_string());
         }
      }

      ExecuteResult {
         metadata: FetchResponseMetadata {
            status: self.status.as_u16(),
            status_text: self.status.canonical_reason().unwrap_or("").to_string(),
            headers: response_headers,
            url: self.url.to_string(),
            redirected: self.redirected,
            retry_count,
         },
         body: self.body,
      }
   }

   /// Converts to the backend-oriented [`Response`](crate::response::Response)
   /// (native `reqwest` types).
   fn into_response(self, retry_count: u32) -> crate::response::Response {
      crate::response::Response::new(
         self.status,
         self.headers,
         self.url,
         self.redirected,
         self.body,
         retry_count,
      )
   }
}

/// Validates that a header name is not in the forbidden list.
///
/// Returns `Err(Error::ForbiddenHeader)` if the name matches any entry in
/// [`FORBIDDEN_HEADERS`] (case-insensitive exact match) or any prefix in
/// [`FORBIDDEN_HEADER_PREFIXES`] (case-insensitive starts-with).
pub(crate) fn validate_header_name(name: &str) -> Result<()> {
   let lower = name.to_ascii_lowercase();

   if FORBIDDEN_HEADERS.contains(&lower.as_str()) {
      return Err(Error::ForbiddenHeader(lower));
   }

   for prefix in FORBIDDEN_HEADER_PREFIXES {
      if lower.starts_with(prefix) {
         return Err(Error::ForbiddenHeader(lower));
      }
   }

   Ok(())
}

/// Core HTTP client state shared across all requests.
///
/// Uses `Arc` internally so cloning is cheap. `reqwest::Client` also
/// uses internal `Arc`, making this safe to share as Tauri managed state.
///
/// The allowlist is wrapped in `Arc<RwLock<DomainAllowlist>>` to support
/// runtime mutations via [`add_allowed_domain`](Self::add_allowed_domain),
/// [`add_allowed_domains`](Self::add_allowed_domains),
/// [`remove_allowed_domain`](Self::remove_allowed_domain),
/// [`remove_allowed_domains`](Self::remove_allowed_domains), and
/// [`remove_all_runtime_domains`](Self::remove_all_runtime_domains).
/// The same `Arc` is shared with the redirect policy closure, ensuring
/// both always see the current allowlist state.
#[derive(Clone)]
pub struct HttpClientState {
   client: reqwest::Client,
   allowlist: Arc<RwLock<DomainAllowlist>>,
   config: Arc<HttpClientConfig>,
}

/// Tracks in-flight requests for abort support.
///
/// Maps request IDs to their `AbortHandle`, allowing cancellation from
/// the TypeScript guest via the `abort_request` command.
#[derive(Clone)]
pub struct InFlightRequests(Arc<tokio::sync::RwLock<HashMap<String, tokio::task::AbortHandle>>>);

impl Default for InFlightRequests {
   fn default() -> Self {
      Self(Arc::new(tokio::sync::RwLock::new(HashMap::new())))
   }
}

impl InFlightRequests {
   pub fn new() -> Self {
      Self::default()
   }

   /// Registers an abort handle for a request ID.
   pub async fn register(&self, request_id: String, handle: tokio::task::AbortHandle) {
      self.0.write().await.insert(request_id, handle);
   }

   /// Removes a request ID from tracking (called on completion).
   pub async fn remove(&self, request_id: &str) {
      self.0.write().await.remove(request_id);
   }
}

impl HttpClientState {
   /// Builds a new `HttpClientState` with a shared allowlist, reqwest client, and config.
   ///
   /// The `allowlist` Arc should be the same instance passed to
   /// [`build_redirect_policy`], ensuring both the request validation path
   /// and the redirect policy always read the same allowlist state.
   pub fn new(
      client: reqwest::Client,
      allowlist: Arc<RwLock<DomainAllowlist>>,
      config: HttpClientConfig,
   ) -> Self {
      Self {
         client,
         allowlist,
         config: Arc::new(config),
      }
   }

   /// Validates a URL against the current allowlist.
   pub fn validate_url(&self, url: &str) -> Result<url::Url> {
      self.allowlist.read().validate_url(url)
   }

   /// Returns `true` if the allowlist has no patterns (blocks all requests).
   pub fn is_allowlist_empty(&self) -> bool {
      self.allowlist.read().is_empty()
   }

   /// Adds a single domain pattern to the allowlist at runtime.
   ///
   /// This is a convenience wrapper around [`add_allowed_domains`](Self::add_allowed_domains).
   pub fn add_allowed_domain(&self, domain: impl Into<String>) -> Result<()> {
      self.add_allowed_domains(vec![domain.into()])
   }

   /// Adds domain patterns to the allowlist at runtime.
   ///
   /// # Errors
   ///
   /// Returns [`Error::AllowlistSizeExceeded`] if adding the domains would
   /// exceed the configured `max_allowlist_size` cap.
   ///
   /// Returns [`Error::WildcardNotAllowedAtRuntime`] if any pattern starts
   /// with `*.`. Wildcard patterns should be configured at build time.
   /// No patterns are added if any pattern is invalid (atomic operation).
   pub fn add_allowed_domains(
      &self,
      domains: impl IntoIterator<Item = impl Into<String>>,
   ) -> Result<()> {
      let domains: Vec<String> = domains.into_iter().map(Into::into).collect();
      let mut al = self.allowlist.write();
      let current = al.pattern_count();
      let limit = self.config.max_allowlist_size;

      if current + domains.len() > limit {
         return Err(Error::AllowlistSizeExceeded {
            count: current + domains.len(),
            limit,
         });
      }

      tracing::info!(
         patterns = ?domains,
         "adding domains to allowlist"
      );

      al.add_patterns(domains)?;

      Ok(())
   }

   /// Removes a single domain pattern from the runtime allowlist.
   ///
   /// Returns `true` if the domain was found and removed, `false` if it was
   /// not present in the runtime allowlist (config-time domains are not affected).
   ///
   /// This is a convenience wrapper around [`remove_allowed_domains`](Self::remove_allowed_domains).
   pub fn remove_allowed_domain(&self, domain: impl Into<String>) -> Result<bool> {
      let count = self.remove_allowed_domains(vec![domain.into()])?;

      Ok(count > 0)
   }

   /// Removes domain patterns from the runtime allowlist.
   ///
   /// Only runtime-added patterns are affected. Config-time patterns (set via
   /// [`Builder::allowed_domains`](crate::Builder::allowed_domains)) cannot be
   /// removed — attempts to remove them are silently ignored.
   ///
   /// Returns the number of patterns actually removed.
   ///
   /// # Allowlist Consistency
   ///
   /// Removal uses eventual consistency: in-flight requests may complete their
   /// current hop, but the redirect policy will block subsequent hops to the
   /// removed domain. The failure mode is always "fail secure" — a removed
   /// domain produces `DomainNotAllowed`, never silent access.
   ///
   /// # Errors
   ///
   /// Returns [`Error::WildcardNotAllowedAtRuntime`] if any pattern starts
   /// with `*.`. No patterns are removed if any pattern is invalid (atomic operation).
   pub fn remove_allowed_domains(
      &self,
      domains: impl IntoIterator<Item = impl Into<String>>,
   ) -> Result<usize> {
      let domains: Vec<String> = domains.into_iter().map(Into::into).collect();
      let mut al = self.allowlist.write();

      let removed = al.remove_patterns(&domains)?;

      if removed > 0 {
         tracing::info!(
            patterns = ?domains,
            removed,
            remaining = al.pattern_count(),
            "removed domains from allowlist"
         );
      }

      Ok(removed)
   }

   /// Removes all runtime-added domain patterns, preserving config-time patterns.
   ///
   /// Returns the number of patterns removed. Useful for revoking all
   /// session-scoped domain grants (e.g., on user logout).
   pub fn remove_all_runtime_domains(&self) -> usize {
      let mut al = self.allowlist.write();
      let removed = al.remove_all_runtime_patterns();

      if removed > 0 {
         tracing::info!(
            removed,
            remaining = al.pattern_count(),
            "removed all runtime domains from allowlist"
         );
      }

      removed
   }

   /// Executes an HTTP request through the full validation and execution pipeline,
   /// with optional automatic retry on transient failures.
   ///
   /// # Pipeline (per attempt)
   ///
   /// 1. Validate URL through allowlist security checks
   /// 2. Build the reqwest request (method, headers, body, timeout)
   /// 3. Execute with custom redirect policy
   /// 4. Read response body with size limit enforcement
   /// 5. Return structured response
   ///
   /// # Retry Behavior
   ///
   /// When retry is enabled (`RetryConfig::max_retries > 0`), transient errors
   /// (connection failures, timeouts) and retryable status codes (default:
   /// 429, 500, 502, 503, 504) trigger automatic retries with exponential
   /// backoff and jitter. Security errors are never retried.
   ///
   /// The URL is re-validated against the allowlist on every attempt. If the
   /// allowlist changes between retries (e.g., a domain is removed), the
   /// subsequent attempt fails with `DomainNotAllowed` (fail-secure).
   ///
   /// Timeout is per-attempt: a request with `max_retries: 3` and a 10s
   /// timeout could take up to ~43s (4 attempts + backoff delays).
   ///
   /// When retries are exhausted, the last response is returned (including
   /// 5xx responses — these are valid HTTP responses, not transport errors).
   /// Intermediate retryable responses are fully read and discarded; the
   /// caller only sees the final attempt's response body.
   pub(crate) async fn execute(&self, req: FetchRequest) -> Result<ExecuteResult> {
      #[cfg(target_os = "android")]
      crate::android::ensure_tls_ready()
         .await
         .map_err(Error::Other)?;

      let method = parse_method(req.method.as_deref().unwrap_or("GET"))?;
      let body_bytes = match req.body {
         Some(ref b) => Some(decode_request_body(b, req.body_encoding.as_ref())?),
         None => None,
      };
      let timeout = req
         .timeout_ms
         .map(Duration::from_millis)
         .or(self.config.default_timeout);
      let max_retries = self.resolve_max_retries(&req);

      // Parse and validate URL once before the retry loop. The URL string
      // doesn't change between retries, so re-parsing is unnecessary.
      let url = self.allowlist.read().validate_url(&req.url)?;

      // Build a merged HeaderMap: default headers first, then per-request
      // headers (which override defaults). Validates forbidden headers.
      let merged_headers = self.build_ipc_header_map(&req.headers)?;

      let (raw, attempt) = self
         .execute_with_retry(
            &url,
            &method,
            &merged_headers,
            body_bytes.as_deref(),
            timeout,
            max_retries,
         )
         .await?;

      Ok(raw.into_execute_result(attempt))
   }

   /// Executes an HTTP request from Rust backend code, returning a native
   /// [`Response`](crate::response::Response) with `reqwest` types.
   ///
   /// This is the backend counterpart to [`execute`](Self::execute) (which
   /// serves the IPC/frontend path). It follows the same security pipeline:
   /// domain allowlist, private IP blocking, redirect validation, streaming
   /// body limits, and retry.
   ///
   /// Called by [`RequestBuilder::send`](crate::request::RequestBuilder::send).
   pub(crate) async fn execute_backend(
      &self,
      url: &str,
      method: reqwest::Method,
      headers: &[(String, String)],
      body: Option<&[u8]>,
      timeout: Option<Duration>,
      max_retries: Option<u32>,
   ) -> Result<crate::response::Response> {
      #[cfg(target_os = "android")]
      crate::android::ensure_tls_ready()
         .await
         .map_err(Error::Other)?;

      let timeout = timeout.or(self.config.default_timeout);
      let max_retries = match max_retries {
         Some(n) => n.min(self.config.retry.max_retries),
         None => self.config.retry.max_retries,
      };

      // Build a merged HeaderMap: default headers first, then per-request
      // headers (which override defaults). Validates forbidden headers.
      let merged_headers = self.build_backend_header_map(headers)?;

      let url = self.validate_url_for_request(url)?;

      let (raw, attempt) = self
         .execute_with_retry(&url, &method, &merged_headers, body, timeout, max_retries)
         .await?;

      Ok(raw.into_response(attempt))
   }

   /// Shared retry loop used by both [`execute`](Self::execute) (IPC path)
   /// and [`execute_backend`](Self::execute_backend) (Rust backend path).
   ///
   /// Expects the URL to be pre-validated and headers pre-merged by the
   /// caller. Returns the final [`RawResponse`] and the attempt count
   /// (0 = succeeded on first try, 1+ = number of retries performed).
   ///
   /// # Retry Behavior
   ///
   /// When retry is enabled (`max_retries > 0`), transient errors
   /// (connection failures, timeouts) and retryable status codes trigger
   /// automatic retries with exponential backoff and jitter. Security
   /// errors are never retried.
   ///
   /// The URL is re-validated against the allowlist on every retry attempt.
   /// If the allowlist changes between retries (e.g., a domain is removed),
   /// the subsequent attempt fails with `DomainNotAllowed` (fail-secure).
   async fn execute_with_retry(
      &self,
      url: &url::Url,
      method: &reqwest::Method,
      headers: &HeaderMap,
      body: Option<&[u8]>,
      timeout: Option<Duration>,
      max_retries: u32,
   ) -> Result<(RawResponse, u32)> {
      let max_attempts = max_retries + 1;
      let retry_config = &self.config.retry;
      let method_retryable = retry_config.is_retryable_method(method.as_str());

      let mut last_result: Option<Result<RawResponse>> = None;
      let mut attempt: u32 = 0;

      // Bounded: returns when attempt + 1 >= max_attempts (should_retry = false)
      loop {
         if attempt >= max_attempts {
            // Invariant: structurally unreachable — should_retry prevents
            // attempt from reaching max_attempts. This is a defensive
            // check against an impossible condition, not normal error
            // handling. If triggered, the retry loop has a logic bug.
            tracing::error!(
               attempt,
               max_attempts,
               url = %url,
               "retry loop exceeded max_attempts; this is a bug"
            );
            return Err(Error::Other(format!(
               "retry loop exceeded max_attempts ({max_attempts}); this is a bug"
            )));
         }

         if attempt > 0 {
            let backoff = calculate_backoff(retry_config, attempt, last_result.as_ref());

            tracing::debug!(
               attempt,
               max_attempts,
               backoff_ms = backoff.as_millis() as u64,
               url = %url,
               "retrying request"
            );

            tokio::time::sleep(backoff).await;

            // SECURITY: Re-validate the parsed URL on every retry attempt.
            // The allowlist is mutable at runtime — a domain removed between
            // retries must cause immediate failure (fail-secure). We use
            // validate_parsed_url (not validate_url) to avoid redundant
            // string parsing since the URL itself hasn't changed.
            self.revalidate_parsed_url(url)?;
         }

         let result = self.execute_once(url, method, headers, body, timeout).await;

         let should_retry = attempt + 1 < max_attempts && method_retryable;

         match result {
            Ok(ref resp)
               if should_retry && retry_config.is_retryable_status(resp.status.as_u16()) =>
            {
               last_result = Some(result);
               attempt += 1;
            }
            Err(e) if should_retry && e.is_retryable() => {
               last_result = Some(Err(e));
               attempt += 1;
            }
            Ok(raw) => return Ok((raw, attempt)),
            Err(e) => return Err(e),
         }
      }
   }

   /// Validates a URL string against the domain allowlist, returning a parsed
   /// [`Url`](url::Url).
   ///
   /// In `#[cfg(test)]` builds with `skip_url_validation` enabled, performs
   /// only basic URL parsing without allowlist or scheme checks.
   fn validate_url_for_request(&self, url: &str) -> Result<url::Url> {
      #[cfg(test)]
      if self.config.skip_url_validation {
         return url::Url::parse(url).map_err(|e| Error::InvalidUrl(e.to_string()));
      }

      self.allowlist.read().validate_url(url)
   }

   /// Re-validates an already-parsed URL against the domain allowlist.
   ///
   /// Used on retry attempts to enforce fail-secure behavior when the
   /// allowlist changes between retries. Skips validation in
   /// `#[cfg(test)]` builds with `skip_url_validation` enabled.
   fn revalidate_parsed_url(&self, url: &url::Url) -> Result<()> {
      #[cfg(test)]
      if self.config.skip_url_validation {
         return Ok(());
      }

      self.allowlist.read().validate_parsed_url(url)
   }

   /// Builds a merged [`HeaderMap`] from the plugin's default headers and
   /// per-request backend headers (slice of tuples).
   ///
   /// Default headers are applied first; per-request headers override them.
   /// All header names are validated against the forbidden-header list.
   fn build_backend_header_map(&self, request_headers: &[(String, String)]) -> Result<HeaderMap> {
      merge_headers(
         &self.config.default_headers,
         request_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
      )
   }

   /// Starts building a GET request through the plugin's security pipeline.
   ///
   /// Returns a [`RequestBuilder`](crate::request::RequestBuilder) that can
   /// be customized with headers, timeout, and retry settings before sending.
   pub fn get(&self, url: impl Into<String>) -> crate::request::RequestBuilder<'_> {
      crate::request::RequestBuilder::new(self, reqwest::Method::GET, url.into())
   }

   /// Starts building a POST request through the plugin's security pipeline.
   pub fn post(&self, url: impl Into<String>) -> crate::request::RequestBuilder<'_> {
      crate::request::RequestBuilder::new(self, reqwest::Method::POST, url.into())
   }

   /// Starts building a HEAD request through the plugin's security pipeline.
   ///
   /// Returns a [`RequestBuilder`](crate::request::RequestBuilder) that can
   /// be customized with headers, timeout, and retry settings before sending.
   pub fn head(&self, url: impl Into<String>) -> crate::request::RequestBuilder<'_> {
      crate::request::RequestBuilder::new(self, reqwest::Method::HEAD, url.into())
   }

   /// Starts building a request with an arbitrary HTTP method.
   pub fn request(
      &self,
      method: reqwest::Method,
      url: impl Into<String>,
   ) -> crate::request::RequestBuilder<'_> {
      crate::request::RequestBuilder::new(self, method, url.into())
   }

   /// Executes a single HTTP request attempt through the full pipeline.
   ///
   /// This is the inner implementation called by [`execute`](Self::execute)
   /// and [`execute_backend`](Self::execute_backend) on each attempt. It
   /// assumes URL validation has already been performed and headers have
   /// been pre-validated and merged into a [`HeaderMap`].
   ///
   /// Returns a [`RawResponse`] carrying native `reqwest` types. Conversion
   /// to the caller's public type (`ExecuteResult` for IPC, `Response` for
   /// backend) happens after the retry loop.
   async fn execute_once(
      &self,
      url: &url::Url,
      method: &reqwest::Method,
      headers: &HeaderMap,
      body: Option<&[u8]>,
      timeout: Option<Duration>,
   ) -> Result<RawResponse> {
      let mut builder = self.client.request(method.clone(), url.clone());

      // Clone required: reqwest's builder.headers() takes HeaderMap by value.
      builder = builder.headers(headers.clone());

      if let Some(body) = body {
         builder = builder.body(body.to_vec());
      }

      if let Some(t) = timeout {
         builder = builder.timeout(t);
      }

      let response = builder.send().await?;

      // Track if we were redirected
      let final_url = response.url().clone();
      let redirected = final_url.as_str() != url.as_str();

      // Anti-DNS-rebinding: verify the resolved address is not private.
      // NOTE: remote_addr() returns None through proxies, neutralizing this
      // check. This is acceptable — proxy environments provide their own
      // network-layer protections. The domain allowlist remains the primary
      // security boundary.
      if !self.config.allow_private_ip {
         if let Some(remote_addr) = response.remote_addr() {
            let ip = remote_addr.ip();

            if is_private_ip(&ip) {
               return Err(Error::DomainNotAllowed(format!(
                  "resolved to private ip address: {ip}"
               )));
            }
         } else {
            tracing::warn!(
               url = %final_url,
               "remote_addr() returned None; DNS rebinding check skipped"
            );
         }
      }

      let status = response.status();
      let resp_headers = response.headers().clone();
      // HEAD responses have no body per RFC 9110 §9.3.2. The Content-Length
      // header advertises the would-be GET body size, so passing through
      // read_body_with_limit would spuriously reject HEADs against resources
      // larger than max_response_body_size.
      let body_bytes = if method == reqwest::Method::HEAD {
         Vec::new()
      } else {
         self.read_body_with_limit(response).await?
      };

      Ok(RawResponse {
         status,
         headers: resp_headers,
         url: final_url,
         redirected,
         body: body_bytes,
      })
   }

   /// Reads the response body as a stream, enforcing the configured size limit.
   ///
   /// Unlike buffering the entire body before checking, this aborts as soon as
   /// accumulated bytes exceed the limit, preventing memory exhaustion.
   async fn read_body_with_limit(&self, response: reqwest::Response) -> Result<Vec<u8>> {
      let limit = self.config.max_response_body_size;

      if let Some(len) = response.content_length()
         && len > limit as u64
      {
         return Err(Error::ResponseTooLarge {
            size: len.try_into().unwrap_or(usize::MAX),
            limit,
         });
      }

      // Pre-allocate using the (already validated) Content-Length when available.
      // This is safe because we rejected values exceeding the limit above.
      let capacity = response.content_length().unwrap_or(0) as usize;
      let mut body = Vec::with_capacity(capacity);
      let mut stream = response.bytes_stream();

      while let Some(chunk) = stream.next().await {
         let chunk = chunk.map_err(Error::Request)?;

         body.extend_from_slice(&chunk);

         if body.len() > limit {
            return Err(Error::ResponseTooLarge {
               size: body.len(),
               limit,
            });
         }
      }

      Ok(body)
   }

   /// Resolves the effective max retries for a request, capping per-request
   /// overrides at the plugin-level configuration ceiling.
   fn resolve_max_retries(&self, req: &FetchRequest) -> u32 {
      match req.max_retries {
         Some(n) => n.min(self.config.retry.max_retries),
         None => self.config.retry.max_retries,
      }
   }

   /// Builds a merged [`HeaderMap`] from the plugin's default headers and
   /// optional per-request IPC headers.
   ///
   /// Default headers are applied first; per-request headers override them.
   /// All header names are validated against the forbidden-header list.
   fn build_ipc_header_map(
      &self,
      request_headers: &Option<HashMap<String, String>>,
   ) -> Result<HeaderMap> {
      let empty = HashMap::new();
      let headers = request_headers.as_ref().unwrap_or(&empty);

      merge_headers(
         &self.config.default_headers,
         headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
      )
   }

   /// Aborts an in-flight request by ID.
   ///
   /// Returns `true` if a request with the given ID was found and aborted,
   /// `false` if no matching request was in flight.
   pub async fn abort(in_flight: &InFlightRequests, request_id: &str) -> bool {
      // Drop the write lock before aborting to avoid holding it during task cancellation
      let handle = {
         let mut map = in_flight.0.write().await;

         map.remove(request_id)
      };

      if let Some(handle) = handle {
         handle.abort();
         true
      } else {
         false
      }
   }
}

/// Test-only constructor for `HttpClientState`.
///
/// Bypasses domain allowlist validation and private IP checks, allowing
/// tests to use local mock servers on `127.0.0.1`.
///
/// **Only available in `#[cfg(test)]` builds.**
///
/// # Testing downstream crates
///
/// `for_testing()` is `#[cfg(test)]`-gated and is not available to downstream
/// consumers. Downstream crates that use the backend API (`get`, `post`,
/// `request`) via [`tauri::State<HttpClientState>`] should test against a real
/// `HttpClientState` registered by the plugin. Set up the plugin with
/// `Builder::new().allowed_domains(["localhost"]).build()` and start your mock
/// server on `localhost` (or a DNS-resolvable hostname that is allowlisted).
///
/// If your mock server binds to `127.0.0.1` rather than `localhost`, configure
/// it to also listen on `localhost` so the domain allowlist check passes.
#[cfg(test)]
impl HttpClientState {
   /// Creates an `HttpClientState` suitable for unit/integration tests with
   /// local mock servers.
   ///
   /// Skips all URL validation (scheme, IP-literal, domain allowlist) and
   /// allows requests to private/loopback IP addresses. This enables tests
   /// using any local mock server bound to `127.0.0.1`.
   ///
   /// # Behavioral differences from production
   ///
   /// - **No redirect validation**: Uses reqwest's default redirect policy
   ///   (follow up to 10 hops) instead of [`build_redirect_policy`] — redirects
   ///   are not validated against the domain allowlist.
   /// - **No default header validation**: Default headers are not checked
   ///   against the forbidden-header list at construction time (they are still
   ///   validated per-request via [`merge_headers`]).
   /// - **No custom redirect limit**: Uses reqwest's default (10) instead of
   ///   `HttpClientConfig::max_redirects`.
   pub fn for_testing() -> Self {
      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(Vec::<String>::new()).expect("empty allowlist is always valid"),
      ));
      let client = reqwest::Client::builder()
         .build()
         .expect("default reqwest client should build");
      let config = HttpClientConfig {
         allow_private_ip: true,
         #[cfg(test)]
         skip_url_validation: true,
         ..HttpClientConfig::default()
      };

      Self::new(client, allowlist, config)
   }
}

/// Builds a merged [`HeaderMap`] from default headers and per-request headers.
///
/// Default headers are applied first; per-request headers override defaults
/// with the same name. All per-request header names are validated against the
/// forbidden-header list.
fn merge_headers<'a>(
   defaults: &HashMap<String, String>,
   per_request: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<HeaderMap> {
   let mut map = HeaderMap::new();

   for (key, value) in defaults {
      map.insert(
         reqwest::header::HeaderName::from_bytes(key.as_bytes())
            .map_err(|e| Error::Other(format!("invalid default header name '{key}': {e}")))?,
         reqwest::header::HeaderValue::from_str(value)
            .map_err(|e| Error::Other(format!("invalid default header value for '{key}': {e}")))?,
      );
   }

   for (key, value) in per_request {
      validate_header_name(key)?;
      map.insert(
         reqwest::header::HeaderName::from_bytes(key.as_bytes())
            .map_err(|e| Error::Other(format!("invalid header name '{key}': {e}")))?,
         reqwest::header::HeaderValue::from_str(value)
            .map_err(|e| Error::Other(format!("invalid header value for '{key}': {e}")))?,
      );
   }

   Ok(map)
}

fn parse_method(method: &str) -> Result<reqwest::Method> {
   match method.to_uppercase().as_str() {
      "GET" => Ok(reqwest::Method::GET),
      "POST" => Ok(reqwest::Method::POST),
      "PUT" => Ok(reqwest::Method::PUT),
      "DELETE" => Ok(reqwest::Method::DELETE),
      "PATCH" => Ok(reqwest::Method::PATCH),
      "HEAD" => Ok(reqwest::Method::HEAD),
      "OPTIONS" => Ok(reqwest::Method::OPTIONS),
      other => Err(Error::Other(format!("unsupported http method: {other}"))),
   }
}

fn decode_request_body(body: &str, encoding: Option<&BodyEncoding>) -> Result<Vec<u8>> {
   match encoding.unwrap_or(&BodyEncoding::Utf8) {
      BodyEncoding::Utf8 => Ok(body.as_bytes().to_vec()),
      BodyEncoding::Base64 => base64::engine::general_purpose::STANDARD
         .decode(body)
         .map_err(|e| Error::Other(format!("invalid base64 body: {e}"))),
   }
}

/// Calculates the backoff duration for a retry attempt using exponential
/// backoff with jitter.
///
/// For responses with `Retry-After` headers, the header value is used instead
/// of the calculated backoff (capped at `max_retry_after`).
///
/// Jitter uses "equal jitter": `base/2 + random(0, base/2)`, which provides
/// decorrelation without excessive variance.
fn calculate_backoff(
   config: &RetryConfig,
   attempt: u32,
   last_result: Option<&Result<RawResponse>>,
) -> Duration {
   // Check for Retry-After header on the last response
   if let Some(Ok(resp)) = last_result
      && let Some(retry_after) = parse_retry_after_from_response(resp)
   {
      return retry_after.min(config.max_retry_after);
   }

   // Exponential backoff: initial * 2^(attempt-1)
   let exponent = (attempt - 1).min(31); // prevent overflow
   let base_ms = config.initial_backoff.as_millis() as u64;
   let calculated_ms = base_ms.saturating_mul(1u64 << exponent);
   let capped_ms = calculated_ms.min(config.max_backoff.as_millis() as u64);

   // Equal jitter: base/2 + random(0, base/2)
   let half = capped_ms / 2;
   let jitter = if half > 0 {
      let nanos = std::time::SystemTime::now()
         .duration_since(std::time::UNIX_EPOCH)
         .unwrap_or_default()
         .subsec_nanos() as u64;

      nanos % half
   } else {
      0
   };

   Duration::from_millis(half + jitter)
}

/// Extracts a `Retry-After` duration from a response's headers.
///
/// Supports both delta-seconds format (`Retry-After: 120`) and ignores
/// HTTP-date format (too complex to parse without a date library).
fn parse_retry_after_from_response(resp: &RawResponse) -> Option<Duration> {
   let value = resp.headers.get("retry-after")?;

   value
      .to_str()
      .ok()?
      .trim()
      .parse::<u64>()
      .ok()
      .map(Duration::from_secs)
}

/// Builds a custom redirect policy that validates each redirect hop against the allowlist.
///
/// This is the #1 security requirement: prevents SSRF via open redirects.
///
/// The `allowlist` Arc should be the same instance used by `HttpClientState`,
/// ensuring the redirect policy always reads the current allowlist (including
/// any domains added at runtime via [`HttpClientState::add_allowed_domains`]).
pub fn build_redirect_policy(
   allowlist: Arc<RwLock<DomainAllowlist>>,
   max_redirects: usize,
) -> redirect::Policy {
   build_redirect_policy_inner(allowlist, max_redirects, false)
}

/// Inner implementation shared by [`build_redirect_policy`] and test helpers.
///
/// When `allow_private_ip` is `true`, the DNS rebinding check on redirect
/// targets is skipped. This is only used in integration tests where the test
/// server resolves to localhost.
fn build_redirect_policy_inner(
   allowlist: Arc<RwLock<DomainAllowlist>>,
   max_redirects: usize,
   allow_private_ip: bool,
) -> redirect::Policy {
   redirect::Policy::custom(move |attempt| {
      if attempt.previous().len() >= max_redirects {
         // stop() returns the last redirect response as a non-error result,
         // so the caller sees a 3xx status rather than a reqwest error.
         return attempt.stop();
      }

      let url = attempt.url().clone();

      // Validate each redirect hop against the current allowlist
      if let Err(_e) = allowlist.read().validate_parsed_url(&url) {
         return attempt.error(RedirectBlockedError(url.to_string()));
      }

      // Check for private IP in redirect target.
      // If DNS resolution fails (Err), we skip the private IP check. This is
      // safe because: (1) the allowlist domain check above is the primary guard,
      // and (2) the actual connection will fail downstream on DNS failure.
      if !allow_private_ip && let Ok(addrs) = url.socket_addrs(|| None) {
         for addr in &addrs {
            if is_private_ip(&addr.ip()) {
               return attempt.error(RedirectBlockedError(format!(
                  "redirect to private ip: {}",
                  addr.ip()
               )));
            }
         }
      }

      attempt.follow()
   })
}

/// Custom error type for redirect policy violations.
#[derive(Debug)]
pub(crate) struct RedirectBlockedError(pub(crate) String);

impl std::fmt::Display for RedirectBlockedError {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "redirect to disallowed domain: {}", self.0)
   }
}

impl std::error::Error for RedirectBlockedError {}

#[cfg(test)]
mod tests {
   use super::*;

   /// Helper to build a `RawResponse` for tests that need to exercise
   /// `calculate_backoff` and `parse_retry_after_from_response`.
   fn raw_response_with_headers(headers: HeaderMap) -> RawResponse {
      RawResponse {
         status: reqwest::StatusCode::TOO_MANY_REQUESTS,
         headers,
         url: url::Url::parse("https://example.com").unwrap(),
         redirected: false,
         body: Vec::new(),
      }
   }

   #[test]
   fn test_parse_method() {
      assert_eq!(parse_method("GET").unwrap(), reqwest::Method::GET);
      assert_eq!(parse_method("post").unwrap(), reqwest::Method::POST);
      assert_eq!(parse_method("Put").unwrap(), reqwest::Method::PUT);
      assert_eq!(parse_method("DELETE").unwrap(), reqwest::Method::DELETE);
      assert_eq!(parse_method("PATCH").unwrap(), reqwest::Method::PATCH);
      assert_eq!(parse_method("HEAD").unwrap(), reqwest::Method::HEAD);
      assert_eq!(parse_method("OPTIONS").unwrap(), reqwest::Method::OPTIONS);
      assert!(parse_method("INVALID").is_err());
   }

   #[test]
   fn test_decode_request_body_utf8() {
      let body = decode_request_body("hello", Some(&BodyEncoding::Utf8)).unwrap();

      assert_eq!(body, b"hello");
   }

   #[test]
   fn test_decode_request_body_base64() {
      let body = decode_request_body("aGVsbG8=", Some(&BodyEncoding::Base64)).unwrap();

      assert_eq!(body, b"hello");
   }

   #[test]
   fn test_decode_request_body_invalid_base64() {
      assert!(decode_request_body("not valid base64!!!", Some(&BodyEncoding::Base64)).is_err());
   }

   #[test]
   fn test_decode_request_body_default_encoding() {
      let body = decode_request_body("hello", None).unwrap();

      assert_eq!(body, b"hello");
   }

   #[test]
   fn test_parse_method_case_insensitive() {
      assert_eq!(parse_method("get").unwrap(), reqwest::Method::GET);
      assert_eq!(parse_method("Get").unwrap(), reqwest::Method::GET);
      assert_eq!(parse_method("gEt").unwrap(), reqwest::Method::GET);
   }

   #[test]
   fn test_parse_method_unsupported_returns_error_with_method_name() {
      let err = parse_method("TRACE").unwrap_err();
      let msg = err.to_string();

      assert!(
         msg.contains("TRACE"),
         "error should contain method name: {msg}"
      );
   }

   // --- InFlightRequests / abort tests ---

   #[tokio::test]
   async fn test_in_flight_register_and_remove() {
      let in_flight = InFlightRequests::new();
      let handle = tokio::spawn(async { 42 });

      in_flight
         .register("req-1".to_string(), handle.abort_handle())
         .await;
      in_flight.remove("req-1").await;

      // After removal, the map should be empty
      let map = in_flight.0.read().await;

      assert!(map.is_empty());
   }

   #[tokio::test]
   async fn test_in_flight_remove_nonexistent_is_noop() {
      let in_flight = InFlightRequests::new();

      // Should not panic
      in_flight.remove("nonexistent").await;
   }

   #[tokio::test]
   async fn test_abort_registered_request_returns_true() {
      let in_flight = InFlightRequests::new();

      let handle = tokio::spawn(async {
         tokio::time::sleep(Duration::from_secs(60)).await;
      });

      in_flight
         .register("req-1".to_string(), handle.abort_handle())
         .await;

      let aborted = HttpClientState::abort(&in_flight, "req-1").await;

      assert!(aborted);
      assert!(handle.await.is_err());
   }

   #[tokio::test]
   async fn test_abort_unknown_request_returns_false() {
      let in_flight = InFlightRequests::new();

      let aborted = HttpClientState::abort(&in_flight, "nonexistent").await;

      assert!(!aborted);
   }

   #[tokio::test]
   async fn test_abort_then_abort_again_returns_false() {
      let in_flight = InFlightRequests::new();

      let handle = tokio::spawn(async {
         tokio::time::sleep(Duration::from_secs(60)).await;
      });

      in_flight
         .register("req-1".to_string(), handle.abort_handle())
         .await;
      HttpClientState::abort(&in_flight, "req-1").await;

      let aborted_again = HttpClientState::abort(&in_flight, "req-1").await;

      assert!(!aborted_again);
   }

   #[tokio::test]
   async fn test_concurrent_register_and_abort_no_deadlock() {
      let in_flight = InFlightRequests::new();

      // Register multiple requests and abort them concurrently
      for i in 0..10 {
         let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
         });

         in_flight
            .register(format!("req-{i}"), handle.abort_handle())
            .await;
      }

      let in_flight_clone = in_flight.clone();
      let abort_handles: Vec<_> = (0..10)
         .map(|i| {
            let inf = in_flight_clone.clone();

            tokio::spawn(async move { HttpClientState::abort(&inf, &format!("req-{i}")).await })
         })
         .collect();

      for handle in abort_handles {
         let result = handle.await.unwrap();

         assert!(result);
      }
   }

   #[test]
   fn test_redirect_blocked_error_display() {
      let err = RedirectBlockedError("https://evil.com".to_string());

      assert_eq!(
         err.to_string(),
         "redirect to disallowed domain: https://evil.com"
      );
   }

   #[test]
   fn test_http_client_state_accessors() {
      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(vec!["example.com".to_string()]).unwrap(),
      ));
      let client = reqwest::Client::new();
      let config = HttpClientConfig::default();

      let state = HttpClientState::new(client, allowlist, config);

      assert!(state.validate_url("https://example.com").is_ok());
      assert!(state.validate_url("https://evil.com").is_err());
      assert!(!state.is_allowlist_empty());
   }

   #[test]
   fn test_in_flight_requests_default() {
      let in_flight = InFlightRequests::default();
      let in_flight2 = InFlightRequests::new();

      assert!(!std::ptr::eq(&in_flight, &in_flight2));
   }

   // --- Wiremock-based integration tests ---

   use wiremock::matchers::{method, path};
   use wiremock::{Mock, MockServer, ResponseTemplate};

   /// Helper to build an HttpClientState with a given allowlist and custom config,
   /// using the redirect policy. Does NOT allow private IPs (for testing the
   /// DNS rebinding check itself).
   fn build_test_state(
      domains: &[&str],
      max_redirects: usize,
      max_body_size: usize,
   ) -> HttpClientState {
      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(domains.iter().map(|s| s.to_string()).collect()).unwrap(),
      ));
      let policy = build_redirect_policy(Arc::clone(&allowlist), max_redirects);
      let client = reqwest::Client::builder().redirect(policy).build().unwrap();
      let config = HttpClientConfig {
         max_redirects,
         max_response_body_size: max_body_size,
         ..Default::default()
      };

      HttpClientState::new(client, allowlist, config)
   }

   /// Helper to build an HttpClientState for integration tests using wiremock
   /// on localhost. Bypasses the DNS rebinding check since wiremock resolves
   /// to 127.0.0.1 (a private IP). The domain allowlist remains enforced.
   fn build_localhost_test_state(max_redirects: usize, max_body_size: usize) -> HttpClientState {
      build_localhost_test_state_with_config(HttpClientConfig {
         max_redirects,
         max_response_body_size: max_body_size,
         allow_private_ip: true,
         ..Default::default()
      })
   }

   fn build_localhost_test_state_with_config(config: HttpClientConfig) -> HttpClientState {
      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(vec!["localhost".to_string()]).unwrap(),
      ));
      let policy = build_redirect_policy_inner(
         Arc::clone(&allowlist),
         config.max_redirects,
         config.allow_private_ip,
      );
      let client = reqwest::Client::builder().redirect(policy).build().unwrap();

      HttpClientState::new(client, allowlist, config)
   }

   /// Converts a wiremock server URI (http://127.0.0.1:PORT) to use localhost
   /// so the URL passes domain allowlist validation.
   fn localhost_url(server: &MockServer, path: &str) -> String {
      let uri = server.uri();
      let port = uri.rsplit(':').next().unwrap();

      format!("http://localhost:{port}{path}")
   }

   fn make_request(url: &str) -> FetchRequest {
      FetchRequest {
         url: url.to_string(),
         method: None,
         headers: None,
         body: None,
         body_encoding: None,
         timeout_ms: None,
         request_id: None,
         max_retries: None,
      }
   }

   // --- Redirect policy tests ---
   //
   // These tests use build_redirect_policy (or build_redirect_policy_inner)
   // to test the actual plugin redirect logic, not reqwest's default policy.
   // Tests that go through execute() use localhost_url() and
   // build_localhost_test_state() to bypass the IP-address URL validation
   // while still exercising the full pipeline.

   #[tokio::test]
   async fn test_redirect_to_allowed_domain_succeeds() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/a"))
         .respond_with(
            ResponseTemplate::new(302).insert_header("Location", localhost_url(&server, "/b")),
         )
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/b"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/a"));
      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
      assert!(resp.metadata.redirected);
      assert_eq!(resp.body, b"ok");
   }

   #[tokio::test]
   async fn test_redirect_to_disallowed_domain_blocked() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/redirect"))
         .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "https://evil.example.com/pwned"),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/redirect"));
      let result = state.execute(req).await;

      assert!(result.is_err());
      assert!(
         matches!(result.unwrap_err(), Error::RedirectBlocked(_)),
         "should block redirect to disallowed domain"
      );
   }

   #[tokio::test]
   async fn test_redirect_chain_exceeds_max_hops() {
      let server = MockServer::start().await;

      // Create a chain of 4 redirects (max is 3)
      for i in 0..4 {
         Mock::given(method("GET"))
            .and(path(format!("/hop{i}")))
            .respond_with(ResponseTemplate::new(302).insert_header(
               "Location",
               localhost_url(&server, &format!("/hop{}", i + 1)),
            ))
            .mount(&server)
            .await;
      }

      Mock::given(method("GET"))
         .and(path("/hop4"))
         .respond_with(ResponseTemplate::new(200).set_body_string("final"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state(3, 10_000_000);
      let req = make_request(&localhost_url(&server, "/hop0"));
      let resp = state.execute(req).await.unwrap();

      // With max_redirects=3, the 4th redirect is stopped and the 3xx is returned
      assert!(
         resp.metadata.status >= 300 && resp.metadata.status < 400,
         "should return redirect status when max hops exceeded, got: {}",
         resp.metadata.status
      );
   }

   #[tokio::test]
   async fn test_redirect_within_same_domain_succeeds() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/start"))
         .respond_with(
            ResponseTemplate::new(302).insert_header("Location", localhost_url(&server, "/end")),
         )
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/end"))
         .respond_with(ResponseTemplate::new(200).set_body_string("final"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/start"));
      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
      assert_eq!(resp.body, b"final");
      assert!(resp.metadata.redirected);
   }

   #[tokio::test]
   async fn test_zero_max_redirects_blocks_all() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/start"))
         .respond_with(
            ResponseTemplate::new(302).insert_header("Location", localhost_url(&server, "/end")),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(0, 10_000_000);
      let req = make_request(&localhost_url(&server, "/start"));
      let resp = state.execute(req).await.unwrap();

      // With max_redirects=0, the redirect is not followed
      assert!(resp.metadata.status >= 300 && resp.metadata.status < 400);
      assert!(!resp.metadata.redirected);
   }

   // --- Body size limit tests ---

   #[tokio::test]
   async fn test_body_within_limit_succeeds() {
      let server = MockServer::start().await;
      let body = "x".repeat(100);

      Mock::given(method("GET"))
         .and(path("/small"))
         .respond_with(ResponseTemplate::new(200).set_body_string(&body))
         .mount(&server)
         .await;

      // Use 1000 byte limit, bypass allowlist by constructing state carefully
      let state = build_test_state(&["localhost"], 10, 1000);
      let client = reqwest::Client::new();
      let resp = client
         .get(format!("{}/small", server.uri()))
         .send()
         .await
         .unwrap();
      let result = state.read_body_with_limit(resp).await;

      assert!(result.is_ok());
      assert_eq!(result.unwrap().len(), 100);
   }

   #[tokio::test]
   async fn test_content_length_exceeds_limit_early_reject() {
      let server = MockServer::start().await;
      let body = "x".repeat(2000);

      Mock::given(method("GET"))
         .and(path("/big"))
         .respond_with(ResponseTemplate::new(200).set_body_string(&body))
         .mount(&server)
         .await;

      let state = build_test_state(&["localhost"], 10, 100);
      let client = reqwest::Client::new();
      let resp = client
         .get(format!("{}/big", server.uri()))
         .send()
         .await
         .unwrap();
      let result = state.read_body_with_limit(resp).await;

      assert!(result.is_err());
      let err = result.unwrap_err();

      assert!(
         matches!(err, Error::ResponseTooLarge { .. }),
         "expected ResponseTooLarge, got: {err:?}"
      );
   }

   #[tokio::test]
   async fn test_chunked_body_exceeds_limit_aborts_midstream() {
      let server = MockServer::start().await;

      // wiremock sends the body; with a small limit, streaming read will abort
      let body = "x".repeat(500);

      Mock::given(method("GET"))
         .and(path("/chunked"))
         .respond_with(ResponseTemplate::new(200).set_body_string(&body))
         .mount(&server)
         .await;

      let state = build_test_state(&["localhost"], 10, 100);
      let client = reqwest::Client::new();
      let resp = client
         .get(format!("{}/chunked", server.uri()))
         .send()
         .await
         .unwrap();
      let result = state.read_body_with_limit(resp).await;

      assert!(result.is_err());
      assert!(matches!(
         result.unwrap_err(),
         Error::ResponseTooLarge { .. }
      ));
   }

   #[tokio::test]
   async fn test_body_exactly_at_limit_succeeds() {
      let server = MockServer::start().await;
      let body = "x".repeat(100);

      Mock::given(method("GET"))
         .and(path("/exact"))
         .respond_with(ResponseTemplate::new(200).set_body_string(&body))
         .mount(&server)
         .await;

      let state = build_test_state(&["localhost"], 10, 100);
      let client = reqwest::Client::new();
      let resp = client
         .get(format!("{}/exact", server.uri()))
         .send()
         .await
         .unwrap();
      let result = state.read_body_with_limit(resp).await;

      assert!(result.is_ok());
      assert_eq!(result.unwrap().len(), 100);
   }

   #[tokio::test]
   async fn test_empty_body_succeeds() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/empty"))
         .respond_with(ResponseTemplate::new(200))
         .mount(&server)
         .await;

      let state = build_test_state(&["localhost"], 10, 100);
      let client = reqwest::Client::new();
      let resp = client
         .get(format!("{}/empty", server.uri()))
         .send()
         .await
         .unwrap();
      let result = state.read_body_with_limit(resp).await;

      assert!(result.is_ok());
      assert!(result.unwrap().is_empty());
   }

   // --- HEAD request tests ---

   #[tokio::test]
   async fn test_head_succeeds_when_content_length_exceeds_body_limit() {
      let server = MockServer::start().await;

      // HEAD response with Content-Length advertising a large would-be body.
      // wiremock sends no body for the HEAD response (correct per spec).
      Mock::given(method("HEAD"))
         .and(path("/big"))
         .respond_with(ResponseTemplate::new(200).insert_header("Content-Length", "100000000"))
         .mount(&server)
         .await;

      // Body limit (100 bytes) is far smaller than advertised Content-Length.
      let state = build_localhost_test_state(10, 100);
      let mut req = make_request(&localhost_url(&server, "/big"));
      req.method = Some("HEAD".to_string());

      let resp = state.execute(req).await.expect("HEAD must not be rejected");

      assert_eq!(resp.metadata.status, 200);
      assert!(resp.body.is_empty(), "HEAD body must be empty");
   }

   #[tokio::test]
   async fn test_head_preserves_response_headers() {
      let server = MockServer::start().await;

      Mock::given(method("HEAD"))
         .and(path("/resource"))
         .respond_with(
            ResponseTemplate::new(200)
               .insert_header("Content-Length", "50000000")
               .insert_header("Content-Type", "application/octet-stream")
               .insert_header("ETag", "\"abc123\""),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 100);
      let mut req = make_request(&localhost_url(&server, "/resource"));
      req.method = Some("HEAD".to_string());

      let resp = state.execute(req).await.unwrap();

      let headers = &resp.metadata.headers;
      let get_header = |name: &str| {
         headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.first().map(String::as_str))
      };

      assert_eq!(get_header("content-length"), Some("50000000"));
      assert_eq!(get_header("content-type"), Some("application/octet-stream"));
      assert_eq!(get_header("etag"), Some("\"abc123\""));
   }

   #[tokio::test]
   async fn test_get_still_rejects_oversized_content_length() {
      // Regression guard: HEAD bypass must not weaken the GET-path body limit.
      let server = MockServer::start().await;
      let body = "x".repeat(2000);

      Mock::given(method("GET"))
         .and(path("/big"))
         .respond_with(ResponseTemplate::new(200).set_body_string(&body))
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 100);
      let req = make_request(&localhost_url(&server, "/big"));
      let err = state.execute(req).await.unwrap_err();

      assert!(
         matches!(err, Error::ResponseTooLarge { .. }),
         "expected ResponseTooLarge, got: {err:?}"
      );
   }

   // --- DNS rebinding tests ---

   #[tokio::test]
   async fn test_execute_rejects_ip_address_in_url() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/data"))
         .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
         .mount(&server)
         .await;

      // wiremock serves on 127.0.0.1, which is an IP literal in the URL.
      // validate_url rejects IP addresses before the request is even sent,
      // so the DNS rebinding check never runs. This test verifies that the
      // IP address guard works at the URL validation layer.
      let state = build_test_state(&["localhost"], 10, 10_000_000);
      let req = make_request(&format!("{}/data", server.uri()));
      let result = state.execute(req).await;

      assert!(result.is_err());
      assert!(
         matches!(result.unwrap_err(), Error::IpAddressNotAllowed),
         "should reject IP address in URL before sending request"
      );
   }

   #[tokio::test]
   async fn test_dns_rebinding_rejects_localhost_when_private_ip_check_enabled() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/data"))
         .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
         .mount(&server)
         .await;

      // Use the non-localhost state (private IP check enabled).
      // localhost resolves to 127.0.0.1 which should be rejected.
      let state = build_test_state(&["localhost"], 10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/data"));
      let result = state.execute(req).await;

      assert!(result.is_err());
      let err = result.unwrap_err();

      assert!(
         matches!(err, Error::DomainNotAllowed(ref msg) if msg.contains("private ip")),
         "should reject private IP from DNS resolution, got: {err:?}"
      );
   }

   // --- Dynamic allowlist tests ---

   #[test]
   fn test_add_allowed_domain_validates_new_url() {
      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(vec!["api.example.com".to_string()]).unwrap(),
      ));
      let client = reqwest::Client::new();
      let config = HttpClientConfig::default();
      let state = HttpClientState::new(client, allowlist, config);

      assert!(state.validate_url("https://new.example.com").is_err());

      state.add_allowed_domain("new.example.com").unwrap();

      assert!(state.validate_url("https://new.example.com").is_ok());
      assert!(state.validate_url("https://api.example.com").is_ok());
   }

   #[test]
   fn test_add_allowed_domains_batch() {
      let allowlist = Arc::new(RwLock::new(DomainAllowlist::new(vec![]).unwrap()));
      let client = reqwest::Client::new();
      let config = HttpClientConfig::default();
      let state = HttpClientState::new(client, allowlist, config);

      assert!(state.is_allowlist_empty());

      state
         .add_allowed_domains(["a.example.com", "b.example.com"])
         .unwrap();

      assert!(!state.is_allowlist_empty());
      assert!(state.validate_url("https://a.example.com").is_ok());
      assert!(state.validate_url("https://b.example.com").is_ok());
   }

   #[test]
   fn test_add_allowed_domains_cap_exceeded() {
      let allowlist = Arc::new(RwLock::new(DomainAllowlist::new(vec![]).unwrap()));
      let client = reqwest::Client::new();
      let config = HttpClientConfig {
         max_allowlist_size: 2,
         ..Default::default()
      };
      let state = HttpClientState::new(client, allowlist, config);

      state.add_allowed_domains(["a.com", "b.com"]).unwrap();

      let result = state.add_allowed_domain("c.com");

      assert!(result.is_err());
      assert!(matches!(
         result.unwrap_err(),
         Error::AllowlistSizeExceeded { count: 3, limit: 2 }
      ));
   }

   #[test]
   fn test_redirect_policy_sees_dynamically_added_domain() {
      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(vec!["initial.example.com".to_string()]).unwrap(),
      ));
      let policy_allowlist = Arc::clone(&allowlist);

      // Before adding: validate_parsed_url should fail for the new domain
      let new_url = url::Url::parse("https://added.example.com/path").unwrap();

      assert!(allowlist.read().validate_parsed_url(&new_url).is_err());

      // Add domain through the shared allowlist
      allowlist
         .write()
         .add_patterns(vec!["added.example.com".to_string()])
         .unwrap();

      // The same Arc (as redirect policy would use) now sees the new domain
      assert!(
         policy_allowlist
            .read()
            .validate_parsed_url(&new_url)
            .is_ok()
      );
   }

   // --- Dynamic allowlist removal tests ---

   #[test]
   fn test_remove_allowed_domain_blocks_url() {
      let allowlist = Arc::new(RwLock::new(DomainAllowlist::new(vec![]).unwrap()));
      let client = reqwest::Client::new();
      let config = HttpClientConfig::default();
      let state = HttpClientState::new(client, allowlist, config);

      state.add_allowed_domain("api.example.com").unwrap();
      assert!(state.validate_url("https://api.example.com").is_ok());

      let removed = state.remove_allowed_domain("api.example.com").unwrap();

      assert!(removed);
      assert!(state.validate_url("https://api.example.com").is_err());
   }

   #[test]
   fn test_remove_allowed_domains_batch() {
      let allowlist = Arc::new(RwLock::new(DomainAllowlist::new(vec![]).unwrap()));
      let client = reqwest::Client::new();
      let config = HttpClientConfig::default();
      let state = HttpClientState::new(client, allowlist, config);

      state
         .add_allowed_domains(["a.example.com", "b.example.com", "c.example.com"])
         .unwrap();

      let removed = state
         .remove_allowed_domains(["a.example.com", "c.example.com"])
         .unwrap();

      assert_eq!(removed, 2);
      assert!(state.validate_url("https://a.example.com").is_err());
      assert!(state.validate_url("https://b.example.com").is_ok());
      assert!(state.validate_url("https://c.example.com").is_err());
   }

   #[test]
   fn test_remove_all_runtime_domains() {
      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(vec!["init.example.com".to_string()]).unwrap(),
      ));
      let client = reqwest::Client::new();
      let config = HttpClientConfig::default();
      let state = HttpClientState::new(client, allowlist, config);

      state
         .add_allowed_domains(["a.example.com", "b.example.com"])
         .unwrap();

      let removed = state.remove_all_runtime_domains();

      assert_eq!(removed, 2);
      assert!(state.validate_url("https://a.example.com").is_err());
      assert!(state.validate_url("https://b.example.com").is_err());
      // Config-time domain preserved
      assert!(state.validate_url("https://init.example.com").is_ok());
   }

   #[test]
   fn test_redirect_policy_sees_removal() {
      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(vec!["init.example.com".to_string()]).unwrap(),
      ));
      let policy_allowlist = Arc::clone(&allowlist);

      // Add a runtime domain
      allowlist
         .write()
         .add_patterns(vec!["dynamic.example.com".to_string()])
         .unwrap();

      let dynamic_url = url::Url::parse("https://dynamic.example.com/path").unwrap();

      assert!(
         policy_allowlist
            .read()
            .validate_parsed_url(&dynamic_url)
            .is_ok()
      );

      // Remove the runtime domain
      allowlist
         .write()
         .remove_patterns(&["dynamic.example.com".to_string()])
         .unwrap();

      // The same Arc (as redirect policy would use) now rejects the domain
      assert!(
         policy_allowlist
            .read()
            .validate_parsed_url(&dynamic_url)
            .is_err()
      );
   }

   // --- Retry logic tests ---

   #[test]
   fn test_resolve_max_retries_uses_config_default() {
      let state = build_test_state_with_retry(
         &["example.com"],
         RetryConfig {
            max_retries: 3,
            ..RetryConfig::default()
         },
      );
      let req = make_request("https://example.com");

      assert_eq!(state.resolve_max_retries(&req), 3);
   }

   #[test]
   fn test_resolve_max_retries_per_request_override() {
      let state = build_test_state_with_retry(
         &["example.com"],
         RetryConfig {
            max_retries: 5,
            ..RetryConfig::default()
         },
      );
      let mut req = make_request("https://example.com");

      req.max_retries = Some(2);

      assert_eq!(state.resolve_max_retries(&req), 2);
   }

   #[test]
   fn test_resolve_max_retries_per_request_capped_at_config() {
      let state = build_test_state_with_retry(
         &["example.com"],
         RetryConfig {
            max_retries: 3,
            ..RetryConfig::default()
         },
      );
      let mut req = make_request("https://example.com");

      req.max_retries = Some(10);

      assert_eq!(state.resolve_max_retries(&req), 3);
   }

   #[test]
   fn test_resolve_max_retries_per_request_zero_disables() {
      let state = build_test_state_with_retry(
         &["example.com"],
         RetryConfig {
            max_retries: 3,
            ..RetryConfig::default()
         },
      );
      let mut req = make_request("https://example.com");

      req.max_retries = Some(0);

      assert_eq!(state.resolve_max_retries(&req), 0);
   }

   fn build_test_state_with_retry(domains: &[&str], retry: RetryConfig) -> HttpClientState {
      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(domains.iter().map(|s| s.to_string()).collect()).unwrap(),
      ));
      let client = reqwest::Client::new();
      let config = HttpClientConfig {
         retry,
         ..Default::default()
      };

      HttpClientState::new(client, allowlist, config)
   }

   #[test]
   fn test_calculate_backoff_first_retry() {
      let config = RetryConfig {
         initial_backoff: Duration::from_millis(200),
         max_backoff: Duration::from_secs(10),
         ..RetryConfig::default()
      };

      let backoff = calculate_backoff(&config, 1, None);

      // Equal jitter: result should be between 0 and 200ms
      assert!(backoff <= Duration::from_millis(200));
   }

   #[test]
   fn test_calculate_backoff_exponential_growth() {
      let config = RetryConfig {
         initial_backoff: Duration::from_millis(200),
         max_backoff: Duration::from_secs(60),
         ..RetryConfig::default()
      };

      // attempt=1: base=200ms, attempt=2: base=400ms, attempt=3: base=800ms
      let b1 = calculate_backoff(&config, 1, None);
      let b3 = calculate_backoff(&config, 3, None);

      // b3 should have a higher ceiling (800ms) than b1 (200ms)
      // Due to jitter, we can only check the ceiling
      assert!(b1 <= Duration::from_millis(200));
      assert!(b3 <= Duration::from_millis(800));
   }

   #[test]
   fn test_calculate_backoff_capped_at_max() {
      let config = RetryConfig {
         initial_backoff: Duration::from_millis(1000),
         max_backoff: Duration::from_millis(2000),
         ..RetryConfig::default()
      };

      // attempt=5: 1000 * 2^4 = 16000ms, capped to 2000ms
      let backoff = calculate_backoff(&config, 5, None);

      assert!(backoff <= Duration::from_millis(2000));
   }

   #[test]
   fn test_calculate_backoff_with_retry_after_header() {
      let config = RetryConfig::default();
      let mut headers = HeaderMap::new();
      headers.insert("retry-after", "5".parse().unwrap());
      let resp = raw_response_with_headers(headers);

      let backoff = calculate_backoff(&config, 1, Some(&Ok(resp)));

      assert_eq!(backoff, Duration::from_secs(5));
   }

   #[test]
   fn test_calculate_backoff_retry_after_capped() {
      let config = RetryConfig {
         max_retry_after: Duration::from_secs(10),
         ..RetryConfig::default()
      };
      let mut headers = HeaderMap::new();
      headers.insert("retry-after", "999".parse().unwrap());
      let resp = raw_response_with_headers(headers);

      let backoff = calculate_backoff(&config, 1, Some(&Ok(resp)));

      assert_eq!(backoff, Duration::from_secs(10));
   }

   #[test]
   fn test_parse_retry_after_valid_seconds() {
      let mut headers = HeaderMap::new();
      headers.insert("retry-after", "120".parse().unwrap());
      let resp = raw_response_with_headers(headers);

      assert_eq!(
         parse_retry_after_from_response(&resp),
         Some(Duration::from_secs(120))
      );
   }

   #[test]
   fn test_parse_retry_after_missing_header() {
      let resp = raw_response_with_headers(HeaderMap::new());

      assert_eq!(parse_retry_after_from_response(&resp), None);
   }

   #[test]
   fn test_parse_retry_after_non_numeric_ignored() {
      let mut headers = HeaderMap::new();
      headers.insert(
         "retry-after",
         "Wed, 21 Oct 2025 07:28:00 GMT".parse().unwrap(),
      );
      let resp = raw_response_with_headers(headers);

      assert_eq!(parse_retry_after_from_response(&resp), None);
   }

   #[test]
   fn test_parse_retry_after_zero_seconds() {
      let mut headers = HeaderMap::new();
      headers.insert("retry-after", "0".parse().unwrap());
      let resp = raw_response_with_headers(headers);

      assert_eq!(
         parse_retry_after_from_response(&resp),
         Some(Duration::from_secs(0))
      );
   }

   #[test]
   fn test_calculate_backoff_with_retry_after_zero() {
      let config = RetryConfig::default();
      let mut headers = HeaderMap::new();
      headers.insert("retry-after", "0".parse().unwrap());
      let resp = raw_response_with_headers(headers);

      let backoff = calculate_backoff(&config, 1, Some(&Ok(resp)));

      assert_eq!(backoff, Duration::from_secs(0));
   }

   #[test]
   fn test_calculate_backoff_no_overflow_on_high_attempt() {
      let config = RetryConfig {
         initial_backoff: Duration::from_millis(200),
         max_backoff: Duration::from_secs(10),
         ..RetryConfig::default()
      };

      // Very high attempt number should not panic
      let backoff = calculate_backoff(&config, 100, None);

      assert!(backoff <= Duration::from_secs(10));
   }

   #[tokio::test]
   async fn test_retry_on_500_then_success() {
      let server = MockServer::start().await;

      // First call returns 500, second returns 200
      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(500).set_body_string("error"))
         .up_to_n_times(1)
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state_with_config(HttpClientConfig {
         retry: RetryConfig {
            max_retries: 2,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            retryable_methods: None,
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      });
      let req = make_request(&localhost_url(&server, "/api"));

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
      assert_eq!(resp.body, b"ok");
      assert_eq!(resp.metadata.retry_count, 1);
   }

   #[tokio::test]
   async fn test_retry_exhausted_returns_last_response() {
      let server = MockServer::start().await;

      // All calls return 503
      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
         .expect(3) // initial + 2 retries
         .mount(&server)
         .await;

      let state = build_localhost_test_state_with_config(HttpClientConfig {
         retry: RetryConfig {
            max_retries: 2,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      });
      let req = make_request(&localhost_url(&server, "/api"));

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 503);
      assert_eq!(resp.metadata.retry_count, 2);
   }

   #[tokio::test]
   async fn test_post_not_retried_by_default() {
      let server = MockServer::start().await;

      Mock::given(method("POST"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(500).set_body_string("error"))
         .expect(1) // Should only be called once (POST not retryable)
         .mount(&server)
         .await;

      let state = build_localhost_test_state_with_config(HttpClientConfig {
         retry: RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      });
      let mut req = make_request(&localhost_url(&server, "/api"));

      req.method = Some("POST".to_string());

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 500);
      assert_eq!(resp.metadata.retry_count, 0);
   }

   #[tokio::test]
   async fn test_retry_disabled_by_default() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
         .expect(1) // Should only be called once (no retry, default is disabled)
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/api"));

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 503);
      assert_eq!(resp.metadata.retry_count, 0);
   }

   // --- Full execute() pipeline tests ---
   //
   // These tests exercise the complete request pipeline through execute(),
   // verifying behavior that was previously untestable due to the IP
   // validation blocking wiremock requests.

   #[tokio::test]
   async fn test_execute_happy_path_get() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/data"))
         .respond_with(
            ResponseTemplate::new(200)
               .set_body_string(r#"{"hello":"world"}"#)
               .insert_header("Content-Type", "application/json"),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/data"));
      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
      assert_eq!(resp.metadata.status_text, "OK");
      assert_eq!(resp.body, br#"{"hello":"world"}"#);
      assert!(!resp.metadata.redirected);
      assert_eq!(resp.metadata.retry_count, 0);
   }

   #[tokio::test]
   async fn test_execute_with_request_headers() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/api"))
         .and(wiremock::matchers::header("X-Custom", "test-value"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let mut req = make_request(&localhost_url(&server, "/api"));

      req.headers = Some(HashMap::from([(
         "X-Custom".to_string(),
         "test-value".to_string(),
      )]));

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
   }

   #[tokio::test]
   async fn test_execute_rejects_host_header() {
      let state = build_localhost_test_state(10, 10_000_000);
      let server = MockServer::start().await;
      let mut req = make_request(&localhost_url(&server, "/api"));

      req.headers = Some(HashMap::from([(
         "Host".to_string(),
         "evil.com".to_string(),
      )]));

      let err = state.execute(req).await.unwrap_err();

      assert!(matches!(err, Error::ForbiddenHeader(_)));
   }

   #[tokio::test]
   async fn test_execute_rejects_host_header_case_insensitive() {
      let state = build_localhost_test_state(10, 10_000_000);
      let server = MockServer::start().await;
      let mut req = make_request(&localhost_url(&server, "/api"));

      req.headers = Some(HashMap::from([(
         "hOsT".to_string(),
         "evil.com".to_string(),
      )]));

      let err = state.execute(req).await.unwrap_err();

      assert!(matches!(err, Error::ForbiddenHeader(_)));
   }

   #[tokio::test]
   async fn test_execute_default_headers_applied() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/api"))
         .and(wiremock::matchers::header("X-Default", "default-value"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state_with_config(HttpClientConfig {
         default_headers: HashMap::from([("X-Default".to_string(), "default-value".to_string())]),
         allow_private_ip: true,
         ..Default::default()
      });
      let req = make_request(&localhost_url(&server, "/api"));
      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
   }

   #[tokio::test]
   async fn test_execute_per_request_headers_supplement_defaults() {
      let server = MockServer::start().await;

      // reqwest appends per-request headers rather than replacing defaults,
      // so both default and per-request headers are sent. Verify both arrive.
      Mock::given(method("GET"))
         .and(path("/api"))
         .and(wiremock::matchers::header("X-Default", "default-value"))
         .and(wiremock::matchers::header("X-Request", "request-value"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state_with_config(HttpClientConfig {
         default_headers: HashMap::from([("X-Default".to_string(), "default-value".to_string())]),
         allow_private_ip: true,
         ..Default::default()
      });
      let mut req = make_request(&localhost_url(&server, "/api"));

      req.headers = Some(HashMap::from([(
         "X-Request".to_string(),
         "request-value".to_string(),
      )]));

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
   }

   #[tokio::test]
   async fn test_execute_text_body_encoding() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/text"))
         .respond_with(
            ResponseTemplate::new(200)
               .set_body_string("plain text response")
               .insert_header("Content-Type", "text/plain"),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/text"));
      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.body, b"plain text response");
   }

   #[tokio::test]
   async fn test_execute_binary_body_encoding() {
      let server = MockServer::start().await;
      let binary_data: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47]; // PNG header bytes

      Mock::given(method("GET"))
         .and(path("/image"))
         .respond_with(
            ResponseTemplate::new(200)
               .set_body_bytes(binary_data.clone())
               .insert_header("Content-Type", "image/png"),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/image"));
      let resp = state.execute(req).await.unwrap();

      // Body is now raw bytes (no base64 encoding at the execute layer)
      assert_eq!(resp.body, binary_data);
   }

   #[tokio::test]
   async fn test_execute_post_with_body() {
      let server = MockServer::start().await;

      Mock::given(method("POST"))
         .and(path("/submit"))
         .and(wiremock::matchers::body_string(r#"{"key":"value"}"#))
         .respond_with(ResponseTemplate::new(201).set_body_string("created"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let mut req = make_request(&localhost_url(&server, "/submit"));

      req.method = Some("POST".to_string());
      req.body = Some(r#"{"key":"value"}"#.to_string());
      req.body_encoding = Some(BodyEncoding::Utf8);

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 201);
      assert_eq!(resp.body, b"created");
   }

   #[tokio::test]
   async fn test_execute_response_headers_collected() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/headers"))
         .respond_with(
            ResponseTemplate::new(200)
               .set_body_string("ok")
               .insert_header("X-Custom-Response", "header-value"),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/headers"));
      let resp = state.execute(req).await.unwrap();

      let custom_header = resp.metadata.headers.get("x-custom-response").unwrap();

      assert_eq!(custom_header, &vec!["header-value".to_string()]);
   }

   #[tokio::test]
   async fn test_execute_domain_not_allowed_rejected() {
      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request("https://evil.com/steal");
      let result = state.execute(req).await;

      assert!(result.is_err());
      assert!(matches!(result.unwrap_err(), Error::DomainNotAllowed(_)));
   }

   #[tokio::test]
   async fn test_execute_body_size_limit_through_pipeline() {
      let server = MockServer::start().await;
      let body = "x".repeat(200);

      Mock::given(method("GET"))
         .and(path("/big"))
         .respond_with(
            ResponseTemplate::new(200)
               .set_body_string(&body)
               .insert_header("Content-Type", "text/plain"),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 100); // 100 byte limit
      let req = make_request(&localhost_url(&server, "/big"));
      let result = state.execute(req).await;

      assert!(result.is_err());
      assert!(matches!(
         result.unwrap_err(),
         Error::ResponseTooLarge { .. }
      ));
   }

   #[tokio::test]
   async fn test_execute_redirect_sets_redirected_flag() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/a"))
         .respond_with(
            ResponseTemplate::new(301).insert_header("Location", localhost_url(&server, "/b")),
         )
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/b"))
         .respond_with(ResponseTemplate::new(200).set_body_string("final"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/a"));
      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
      assert!(resp.metadata.redirected);
      assert!(resp.metadata.url.contains("/b"));
   }

   #[tokio::test]
   async fn test_execute_non_redirected_request_has_false_flag() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/direct"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/direct"));
      let resp = state.execute(req).await.unwrap();

      assert!(!resp.metadata.redirected);
   }

   #[tokio::test]
   async fn test_execute_empty_string_body() {
      let server = MockServer::start().await;

      Mock::given(method("POST"))
         .and(path("/empty"))
         .and(wiremock::matchers::body_string(""))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let mut req = make_request(&localhost_url(&server, "/empty"));

      req.method = Some("POST".to_string());
      req.body = Some(String::new());
      req.body_encoding = Some(BodyEncoding::Utf8);

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
   }

   #[tokio::test]
   async fn test_execute_returns_raw_bytes_for_invalid_utf8() {
      let server = MockServer::start().await;

      // Send binary data (invalid UTF-8) with text/plain content type
      let binary_body: Vec<u8> = vec![0x48, 0x65, 0x6C, 0xFF, 0x6F]; // "Hel\xFFo"

      Mock::given(method("GET"))
         .and(path("/lossy"))
         .respond_with(
            ResponseTemplate::new(200)
               .set_body_bytes(binary_body.clone())
               .insert_header("Content-Type", "text/plain"),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/lossy"));
      let resp = state.execute(req).await.unwrap();

      // Body is raw bytes — no lossy UTF-8 conversion at the execute layer
      assert_eq!(resp.body, binary_body);
   }

   #[tokio::test]
   async fn test_execute_timeout_is_retryable() {
      let server = MockServer::start().await;

      // First request times out (delay > timeout), second succeeds
      Mock::given(method("GET"))
         .and(path("/slow"))
         .respond_with(
            ResponseTemplate::new(200)
               .set_body_string("slow")
               .set_delay(Duration::from_secs(5)),
         )
         .up_to_n_times(1)
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/slow"))
         .respond_with(ResponseTemplate::new(200).set_body_string("fast"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state_with_config(HttpClientConfig {
         retry: RetryConfig {
            max_retries: 1,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      });

      let mut req = make_request(&localhost_url(&server, "/slow"));

      req.timeout_ms = Some(100); // 100ms timeout

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
      assert_eq!(resp.body, b"fast");
      assert_eq!(resp.metadata.retry_count, 1);
   }

   #[tokio::test]
   async fn test_retry_with_custom_retryable_status_codes() {
      let server = MockServer::start().await;

      // First returns 418, second returns 200
      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(418).set_body_string("teapot"))
         .up_to_n_times(1)
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state_with_config(HttpClientConfig {
         retry: RetryConfig {
            max_retries: 1,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            retryable_status_codes: vec![418], // Custom: retry on 418
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      });
      let req = make_request(&localhost_url(&server, "/api"));

      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
      assert_eq!(resp.metadata.retry_count, 1);
   }

   #[tokio::test]
   async fn test_retry_revalidates_allowlist_between_attempts() {
      let server = MockServer::start().await;

      // First call returns 500 (triggers retry), second would return 200
      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(500).set_body_string("error"))
         .up_to_n_times(1)
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let allowlist = Arc::new(RwLock::new(
         DomainAllowlist::new(vec!["localhost".to_string()]).unwrap(),
      ));

      // Add a runtime domain that we'll remove to test revalidation
      allowlist
         .write()
         .add_patterns(vec!["localhost".to_string()])
         .unwrap();

      let policy = build_redirect_policy_inner(Arc::clone(&allowlist), 10, true);
      let client = reqwest::Client::builder().redirect(policy).build().unwrap();
      let config = HttpClientConfig {
         retry: RetryConfig {
            max_retries: 2,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            retryable_methods: None,
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      };
      let state = HttpClientState::new(client, allowlist, config);

      // The request should succeed because "localhost" is an init_pattern
      // (cannot be removed). This test verifies the revalidation path runs
      // without error when the allowlist hasn't changed.
      let req = make_request(&localhost_url(&server, "/api"));
      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
      assert_eq!(resp.metadata.retry_count, 1);
   }

   // --- Redirect to IP address (integration) ---

   #[tokio::test]
   async fn test_execute_redirect_to_ip_address_blocked() {
      let server = MockServer::start().await;

      // Redirect to an IP address URL — should be blocked by validate_parsed_url
      Mock::given(method("GET"))
         .and(path("/redir"))
         .respond_with(
            ResponseTemplate::new(301).insert_header("Location", "http://127.0.0.1:9999/evil"),
         )
         .mount(&server)
         .await;

      let state = build_localhost_test_state(10, 10_000_000);
      let req = make_request(&localhost_url(&server, "/redir"));
      let result = state.execute(req).await;

      assert!(result.is_err());
      assert!(matches!(result.unwrap_err(), Error::RedirectBlocked(_)));
   }

   // --- max_redirects stop behavior ---

   #[tokio::test]
   async fn test_execute_max_redirects_returns_3xx_not_error() {
      let server = MockServer::start().await;

      // Set up a redirect chain longer than max_redirects
      Mock::given(method("GET"))
         .and(path("/a"))
         .respond_with(
            ResponseTemplate::new(301).insert_header("Location", localhost_url(&server, "/b")),
         )
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/b"))
         .respond_with(
            ResponseTemplate::new(302).insert_header("Location", localhost_url(&server, "/c")),
         )
         .mount(&server)
         .await;

      // /c would redirect again, but max_redirects=2 should stop at /b's response
      Mock::given(method("GET"))
         .and(path("/c"))
         .respond_with(
            ResponseTemplate::new(301).insert_header("Location", localhost_url(&server, "/d")),
         )
         .mount(&server)
         .await;

      // max_redirects=2: follows /a -> /b -> /c, stops at /c's 301
      let state = build_localhost_test_state(2, 10_000_000);
      let req = make_request(&localhost_url(&server, "/a"));
      let resp = state.execute(req).await.unwrap();

      // Should get the 3xx response (stop behavior), not an error
      assert!(
         resp.metadata.status >= 300 && resp.metadata.status < 400,
         "expected 3xx status from stop(), got {}",
         resp.metadata.status
      );
      assert!(resp.metadata.redirected);
   }

   // --- Retry-After end-to-end ---

   #[tokio::test]
   async fn test_retry_honors_retry_after_header_end_to_end() {
      let server = MockServer::start().await;

      // First returns 429 with Retry-After, second returns 200
      Mock::given(method("GET"))
         .and(path("/rate-limited"))
         .respond_with(
            ResponseTemplate::new(429)
               .set_body_string("rate limited")
               .insert_header("Retry-After", "1"),
         )
         .up_to_n_times(1)
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/rate-limited"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      let state = build_localhost_test_state_with_config(HttpClientConfig {
         retry: RetryConfig {
            max_retries: 1,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_secs(5),
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      });
      let req = make_request(&localhost_url(&server, "/rate-limited"));
      let resp = state.execute(req).await.unwrap();

      assert_eq!(resp.metadata.status, 200);
      assert_eq!(resp.metadata.retry_count, 1);
   }

   // --- Per-request max_retries override ---

   #[tokio::test]
   async fn test_per_request_max_retries_override_through_execute() {
      let server = MockServer::start().await;

      // Returns 500 twice, then 200
      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(500).set_body_string("error"))
         .up_to_n_times(2)
         .mount(&server)
         .await;

      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .mount(&server)
         .await;

      // Config allows up to 5 retries, but request asks for only 1
      let state = build_localhost_test_state_with_config(HttpClientConfig {
         retry: RetryConfig {
            max_retries: 5,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      });
      let mut req = make_request(&localhost_url(&server, "/api"));

      req.max_retries = Some(1);

      let resp = state.execute(req).await.unwrap();

      // With max_retries=1, we get 2 attempts: first returns 500, second returns 500.
      // Since retries are exhausted, we get the last 500 response.
      assert_eq!(resp.metadata.status, 500);
      assert_eq!(resp.metadata.retry_count, 1);
   }

   // --- Security errors skip retry loop ---

   #[tokio::test]
   async fn test_security_error_not_retried() {
      // DomainNotAllowed should fail immediately, not be retried
      let state = build_localhost_test_state_with_config(HttpClientConfig {
         retry: RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      });

      let req = make_request("https://evil.com/steal");
      let result = state.execute(req).await;

      assert!(result.is_err());
      assert!(matches!(result.unwrap_err(), Error::DomainNotAllowed(_)));
      // If it were retried, this test would take noticeable time due to backoff.
      // The near-instant completion proves the retry loop was bypassed.
   }

   #[tokio::test]
   async fn test_forbidden_header_error_not_retried() {
      let server = MockServer::start().await;

      Mock::given(method("GET"))
         .and(path("/api"))
         .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
         .expect(0) // Should never reach the server
         .mount(&server)
         .await;

      let state = build_localhost_test_state_with_config(HttpClientConfig {
         retry: RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            ..RetryConfig::default()
         },
         allow_private_ip: true,
         ..Default::default()
      });
      let mut req = make_request(&localhost_url(&server, "/api"));

      req.headers = Some(HashMap::from([(
         "Host".to_string(),
         "evil.com".to_string(),
      )]));

      let result = state.execute(req).await;

      assert!(result.is_err());
      assert!(matches!(result.unwrap_err(), Error::ForbiddenHeader(_)));
   }

   // --- validate_header_name tests ---

   #[test]
   fn test_validate_header_name_allows_normal_headers() {
      assert!(validate_header_name("authorization").is_ok());
      assert!(validate_header_name("content-type").is_ok());
      assert!(validate_header_name("accept").is_ok());
      assert!(validate_header_name("x-custom-header").is_ok());
      assert!(validate_header_name("user-agent").is_ok());
      assert!(validate_header_name("accept-encoding").is_ok());
      assert!(validate_header_name("cookie").is_ok());
   }

   #[test]
   fn test_validate_header_name_blocks_host() {
      let result = validate_header_name("host");

      assert!(matches!(result, Err(Error::ForbiddenHeader(ref h)) if h == "host"));
   }

   #[test]
   fn test_validate_header_name_blocks_host_case_insensitive() {
      assert!(validate_header_name("HOST").is_err());
      assert!(validate_header_name("Host").is_err());
      assert!(validate_header_name("hOsT").is_err());
   }

   #[test]
   fn test_validate_header_name_blocks_connection() {
      assert!(validate_header_name("connection").is_err());
      assert!(validate_header_name("Connection").is_err());
   }

   #[test]
   fn test_validate_header_name_blocks_keep_alive() {
      assert!(validate_header_name("keep-alive").is_err());
      assert!(validate_header_name("Keep-Alive").is_err());
   }

   #[test]
   fn test_validate_header_name_blocks_transfer_encoding() {
      assert!(validate_header_name("transfer-encoding").is_err());
      assert!(validate_header_name("Transfer-Encoding").is_err());
   }

   #[test]
   fn test_validate_header_name_blocks_te() {
      assert!(validate_header_name("te").is_err());
      assert!(validate_header_name("TE").is_err());
   }

   #[test]
   fn test_validate_header_name_blocks_upgrade() {
      assert!(validate_header_name("upgrade").is_err());
      assert!(validate_header_name("Upgrade").is_err());
   }

   #[test]
   fn test_validate_header_name_blocks_trailer() {
      assert!(validate_header_name("trailer").is_err());
      assert!(validate_header_name("Trailer").is_err());
   }

   #[test]
   fn test_validate_header_name_allows_x_forwarded_headers() {
      // X-Forwarded-* headers are application-layer, not transport-layer.
      // Blocking them would break legitimate use cases (e.g., proxy context
      // forwarding). The risk requires specific server misconfiguration.
      assert!(validate_header_name("x-forwarded-for").is_ok());
      assert!(validate_header_name("X-Forwarded-For").is_ok());
      assert!(validate_header_name("x-forwarded-host").is_ok());
      assert!(validate_header_name("x-real-ip").is_ok());
   }

   #[test]
   fn test_validate_header_name_blocks_sec_prefix() {
      assert!(validate_header_name("sec-fetch-site").is_err());
      assert!(validate_header_name("sec-fetch-mode").is_err());
      assert!(validate_header_name("sec-ch-ua").is_err());
      assert!(validate_header_name("Sec-Fetch-Dest").is_err());
   }

   #[test]
   fn test_validate_header_name_blocks_proxy_prefix() {
      assert!(validate_header_name("proxy-authorization").is_err());
      assert!(validate_header_name("proxy-connection").is_err());
      assert!(validate_header_name("Proxy-Authenticate").is_err());
   }

   #[test]
   fn test_validate_header_name_error_contains_lowercased_name() {
      let result = validate_header_name("Transfer-Encoding");

      match result {
         Err(Error::ForbiddenHeader(name)) => assert_eq!(name, "transfer-encoding"),
         _ => panic!("expected ForbiddenHeader error"),
      }
   }

   #[test]
   fn test_validate_header_name_sec_prefix_not_blocked_without_dash() {
      // "sec" alone is not in FORBIDDEN_HEADERS and doesn't start with "sec-"
      assert!(validate_header_name("sec").is_ok());
   }

   // --- merge_headers tests ---

   #[test]
   fn test_merge_headers_empty_defaults_empty_request() {
      let defaults = HashMap::new();
      let map = merge_headers(&defaults, std::iter::empty()).unwrap();

      assert!(map.is_empty());
   }

   #[test]
   fn test_merge_headers_defaults_only() {
      let defaults = HashMap::from([("x-app".to_string(), "myapp".to_string())]);
      let map = merge_headers(&defaults, std::iter::empty()).unwrap();

      assert_eq!(map.get("x-app").unwrap(), "myapp");
   }

   #[test]
   fn test_merge_headers_request_only() {
      let defaults = HashMap::new();
      let map = merge_headers(&defaults, vec![("accept", "application/json")].into_iter()).unwrap();

      assert_eq!(map.get("accept").unwrap(), "application/json");
   }

   #[test]
   fn test_merge_headers_request_overrides_default() {
      let defaults = HashMap::from([("accept".to_string(), "text/html".to_string())]);
      let map = merge_headers(&defaults, vec![("accept", "application/json")].into_iter()).unwrap();

      assert_eq!(map.get("accept").unwrap(), "application/json");
   }

   #[test]
   fn test_merge_headers_forbidden_header_rejected() {
      let defaults = HashMap::new();
      let result = merge_headers(&defaults, vec![("host", "evil.com")].into_iter());

      assert!(result.is_err());
   }

   #[test]
   fn test_merge_headers_defaults_not_validated_against_forbidden() {
      // Default headers are validated at plugin init, not in merge_headers.
      // merge_headers only validates per-request headers.
      let defaults = HashMap::from([("x-custom".to_string(), "value".to_string())]);
      let map = merge_headers(&defaults, std::iter::empty()).unwrap();

      assert_eq!(map.get("x-custom").unwrap(), "value");
   }

   #[test]
   fn test_merge_headers_multiple_request_headers() {
      let defaults = HashMap::new();
      let map = merge_headers(
         &defaults,
         vec![
            ("accept", "application/json"),
            ("authorization", "Bearer token"),
         ]
         .into_iter(),
      )
      .unwrap();

      assert_eq!(map.get("accept").unwrap(), "application/json");
      assert_eq!(map.get("authorization").unwrap(), "Bearer token");
   }

   // --- for_testing tests ---

   #[test]
   fn test_for_testing_creates_valid_state() {
      let state = HttpClientState::for_testing();

      assert!(state.config.allow_private_ip);
      assert!(state.config.skip_url_validation);
      assert!(state.is_allowlist_empty());
   }

   // --- validate_url_for_request / revalidate_parsed_url tests ---

   #[test]
   fn test_validate_url_for_request_skips_allowlist_in_test() {
      let state = HttpClientState::for_testing();
      let url = state.validate_url_for_request("http://127.0.0.1:8080/test");

      assert!(url.is_ok());
      assert_eq!(url.unwrap().as_str(), "http://127.0.0.1:8080/test");
   }

   #[test]
   fn test_validate_url_for_request_rejects_invalid_url() {
      let state = HttpClientState::for_testing();
      let result = state.validate_url_for_request("not a url");

      assert!(result.is_err());
   }

   #[test]
   fn test_revalidate_parsed_url_skips_in_test() {
      let state = HttpClientState::for_testing();
      let url = url::Url::parse("http://127.0.0.1:8080/test").unwrap();

      assert!(state.revalidate_parsed_url(&url).is_ok());
   }
}
