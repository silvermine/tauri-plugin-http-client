use std::collections::HashSet;
use std::net::IpAddr;

use url::Url;

use crate::error::{Error, Result};

/// A parsed domain pattern for allowlist matching.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DomainPattern {
   /// Matches an exact domain (e.g. `api.example.com`).
   Exact(String),
   /// Matches any subdomain of the base (e.g. `*.example.com` matches
   /// `api.example.com` and `deep.sub.example.com`, but not `example.com`).
   WildcardSubdomain(String),
}

impl DomainPattern {
   fn parse(pattern: &str) -> Self {
      let normalized = pattern.to_lowercase();

      if let Some(base) = normalized.strip_prefix("*.") {
         DomainPattern::WildcardSubdomain(base.to_string())
      } else {
         DomainPattern::Exact(normalized)
      }
   }

   fn matches(&self, host: &str) -> bool {
      match self {
         DomainPattern::Exact(domain) => host == domain,
         DomainPattern::WildcardSubdomain(base) => {
            // The byte check ensures "notexample.com" doesn't match "*.example.com":
            // the character immediately before the suffix must be a dot separator.
            host.ends_with(base)
               && host.len() > base.len()
               && host.as_bytes()[host.len() - base.len() - 1] == b'.'
         }
      }
   }
}

/// Domain allowlist that validates URLs against configured domain patterns.
///
/// An empty allowlist blocks all requests (secure by default).
///
/// The allowlist uses a two-tier storage model:
///
/// - **Config-time patterns** (`init_patterns`): Set at construction via
///   [`new`](Self::new). Immutable after creation. Supports both exact and
///   wildcard patterns.
/// - **Runtime patterns** (`runtime_patterns`): Added and removed at runtime
///   via [`add_patterns`](Self::add_patterns) and [`remove_patterns`](Self::remove_patterns).
///   Exact domains only (wildcards rejected). Stored as normalized lowercase
///   strings in a `HashSet` for O(1) operations and natural deduplication.
///
/// Config-time patterns cannot be removed — they represent the app developer's
/// security policy and are structurally immutable.
#[derive(Debug, Clone)]
pub struct DomainAllowlist {
   /// Config-time patterns: immutable after construction, supports wildcards.
   init_patterns: Vec<DomainPattern>,
   /// Runtime patterns: mutable (add/remove), exact domains only.
   runtime_patterns: HashSet<String>,
}

impl DomainAllowlist {
   /// Creates a new allowlist from raw domain pattern strings.
   ///
   /// These patterns become config-time patterns and cannot be removed at
   /// runtime. Both exact and wildcard patterns are supported.
   ///
   /// Supported pattern formats:
   /// - `"api.example.com"` - exact domain match
   /// - `"*.example.com"` - any subdomain of `example.com`
   ///
   /// # Errors
   ///
   /// Returns [`Error::InvalidDomainPattern`] if any pattern is empty,
   /// contains control characters, URL-reserved characters, or is a bare `*`.
   pub fn new(raw_patterns: Vec<String>) -> Result<Self> {
      for pattern in &raw_patterns {
         // For wildcard patterns, validate the base domain after the `*.` prefix
         if let Some(base) = pattern.strip_prefix("*.") {
            validate_domain_pattern(base)?;
         } else {
            validate_domain_pattern(pattern)?;
         }
      }

      let init_patterns = raw_patterns
         .iter()
         .map(|p| DomainPattern::parse(p))
         .collect();

      Ok(Self {
         init_patterns,
         runtime_patterns: HashSet::new(),
      })
   }

   /// Validates a URL string through the full security pipeline.
   ///
   /// # Validation Steps
   ///
   /// 1. Parse URL
   /// 2. Reject non-HTTP(S) schemes
   /// 3. Reject URLs with userinfo
   /// 4. Reject backslash in authority
   /// 5. Reject IP addresses
   /// 6. Normalize host and match against allowlist
   pub fn validate_url(&self, url_str: &str) -> Result<Url> {
      // Reject backslash in URL before parsing (parser may normalize it)
      if url_str.contains('\\') {
         return Err(Error::InvalidUrl(
            "backslash not allowed in url".to_string(),
         ));
      }

      let url = Url::parse(url_str).map_err(|e| Error::InvalidUrl(e.to_string()))?;

      self.validate_parsed_url(&url)?;

      Ok(url)
   }

   /// Validates an already-parsed URL (used for redirect hop validation).
   pub fn validate_parsed_url(&self, url: &Url) -> Result<()> {
      match url.scheme() {
         "http" | "https" => {}
         scheme => {
            return Err(Error::SchemeNotAllowed(scheme.to_string()));
         }
      }

      if !url.username().is_empty() || url.password().is_some() {
         return Err(Error::UserinfoNotAllowed);
      }

      let host = url
         .host_str()
         .ok_or_else(|| Error::InvalidUrl("missing host".to_string()))?;

      // Check the parsed Host enum for definitive IPv4/IPv6 detection
      if let Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) = url.host() {
         return Err(Error::IpAddressNotAllowed);
      }

      // The url crate's Host enum doesn't catch decimal, octal, or hex
      // IP representations — those parse as domain strings. Catch them here.
      if host.parse::<IpAddr>().is_ok() || is_ip_like(host) {
         return Err(Error::IpAddressNotAllowed);
      }

      let normalized_host = host.to_lowercase();
      let normalized_host = normalized_host.trim_end_matches('.');

      if !self.is_domain_allowed(normalized_host) {
         return Err(Error::DomainNotAllowed(normalized_host.to_string()));
      }

      Ok(())
   }

   fn is_domain_allowed(&self, host: &str) -> bool {
      self.init_patterns.iter().any(|p| p.matches(host)) || self.runtime_patterns.contains(host)
   }

   /// Adds exact domain patterns to the runtime allowlist.
   ///
   /// Only exact domain patterns are accepted (e.g. `"api.example.com"`).
   /// Wildcard patterns (`"*.example.com"`) are rejected to limit the blast
   /// radius of runtime mutations. Wildcards should be configured at build
   /// time via [`Builder::allowed_domains`](crate::Builder::allowed_domains).
   ///
   /// Duplicate patterns are silently accepted (the `HashSet` deduplicates).
   ///
   /// # Errors
   ///
   /// Returns [`Error::WildcardNotAllowedAtRuntime`] if any pattern starts with `*.`.
   /// No patterns are added if any pattern is invalid (atomic operation).
   pub(crate) fn add_patterns(&mut self, raw_patterns: Vec<String>) -> Result<()> {
      // Validate all patterns before mutating (atomic batch)
      for pattern in &raw_patterns {
         validate_domain_pattern(pattern)?;

         if pattern.starts_with("*.") {
            return Err(Error::WildcardNotAllowedAtRuntime(pattern.clone()));
         }
      }

      for pattern in &raw_patterns {
         self.runtime_patterns.insert(pattern.to_lowercase());
      }

      Ok(())
   }

   /// Removes exact domain patterns from the runtime allowlist.
   ///
   /// Only runtime-added patterns can be removed. Config-time patterns
   /// (set via [`new`](Self::new)) are structurally immutable and cannot
   /// be removed — attempts to remove them are silently ignored (idempotent).
   ///
   /// Note: if a config-time wildcard pattern (e.g. `*.example.com`) covers
   /// a runtime domain being removed, the domain will still be allowed via
   /// the config-time pattern. Use [`is_runtime_domain`](Self::is_runtime_domain)
   /// to inspect runtime membership.
   ///
   /// # Errors
   ///
   /// Returns [`Error::WildcardNotAllowedAtRuntime`] if any pattern starts with `*.`.
   /// No patterns are removed if any pattern is invalid (atomic operation).
   pub(crate) fn remove_patterns(&mut self, raw_patterns: &[String]) -> Result<usize> {
      for pattern in raw_patterns {
         if pattern.starts_with("*.") {
            return Err(Error::WildcardNotAllowedAtRuntime(pattern.clone()));
         }
      }

      let mut removed = 0;

      for pattern in raw_patterns {
         if self.runtime_patterns.remove(&pattern.to_lowercase()) {
            removed += 1;
         }
      }

      Ok(removed)
   }

   /// Removes all runtime-added patterns, preserving config-time patterns.
   ///
   /// Returns the number of patterns removed.
   pub(crate) fn remove_all_runtime_patterns(&mut self) -> usize {
      let count = self.runtime_patterns.len();

      self.runtime_patterns.clear();
      count
   }

   /// Returns `true` if the given domain is in the runtime allowlist.
   ///
   /// Config-time patterns are not checked. This is useful for inspecting
   /// whether a domain was dynamically added at runtime.
   pub fn is_runtime_domain(&self, domain: &str) -> bool {
      self.runtime_patterns.contains(&domain.to_lowercase())
   }

   /// Returns the number of runtime-added patterns.
   pub fn runtime_pattern_count(&self) -> usize {
      self.runtime_patterns.len()
   }

   /// Returns the number of config-time patterns.
   pub fn config_pattern_count(&self) -> usize {
      self.init_patterns.len()
   }

   /// Returns `true` if the allowlist has no patterns (blocks all requests).
   pub fn is_empty(&self) -> bool {
      self.init_patterns.is_empty() && self.runtime_patterns.is_empty()
   }

   /// Returns the total number of patterns in the allowlist (config + runtime).
   pub fn pattern_count(&self) -> usize {
      self.init_patterns.len() + self.runtime_patterns.len()
   }
}

/// Detects IP-like hostnames that might bypass simple `IpAddr` parsing.
///
/// Catches decimal IPs (e.g. `2130706433` for `127.0.0.1`), octal notation
/// (e.g. `0177.0.0.1`), hex notation (e.g. `0x7f.0.0.1`), and bracket-wrapped IPv6.
fn is_ip_like(host: &str) -> bool {
   let host = host.trim_start_matches('[').trim_end_matches(']');

   // Pure numeric (decimal IP encoding)
   if host.chars().all(|c| c.is_ascii_digit()) && !host.is_empty() {
      return true;
   }

   if host.starts_with("0x") || host.starts_with("0X") {
      return true;
   }

   // Dotted segments that look like octal or hex
   let segments: Vec<&str> = host.split('.').collect();

   if segments.len() >= 2
      && segments.iter().all(|s| {
         !s.is_empty()
            && (s.chars().all(|c| c.is_ascii_digit()) || s.starts_with("0x") || s.starts_with("0X"))
      })
   {
      return true;
   }

   false
}

/// Checks if a resolved IP address is in a private/reserved range.
///
/// Used for anti-DNS-rebinding protection after DNS resolution.
pub fn is_private_ip(ip: &IpAddr) -> bool {
   match ip {
      IpAddr::V4(v4) => {
         v4.is_loopback()            // 127.0.0.0/8
            || v4.is_private()       // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_link_local()    // 169.254.0.0/16
            || v4.is_unspecified()   // 0.0.0.0
            || v4.is_broadcast() // 255.255.255.255
      }
      IpAddr::V6(v6) => {
         v6.is_loopback()            // ::1
            || v6.is_unspecified()   // ::
            || is_ipv6_unique_local(v6)  // fc00::/7
            || is_ipv6_link_local(v6)    // fe80::/10
            || is_ipv4_mapped_private(v6)
      }
   }
}

/// fc00::/7 — top 7 bits must be `1111110`. Mask with 0xfe00 (7 ones +
/// 9 zeros in a 16-bit segment) and compare against 0xfc00.
fn is_ipv6_unique_local(v6: &std::net::Ipv6Addr) -> bool {
   (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// fe80::/10 — top 10 bits must be `1111111010`. Mask with 0xffc0 (10 ones +
/// 6 zeros) and compare against 0xfe80.
fn is_ipv6_link_local(v6: &std::net::Ipv6Addr) -> bool {
   (v6.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv4_mapped_private(v6: &std::net::Ipv6Addr) -> bool {
   if let Some(v4) = v6.to_ipv4_mapped() {
      is_private_ip(&IpAddr::V4(v4))
   } else {
      false
   }
}

/// Validates that a domain pattern string is well-formed.
///
/// Rejects:
/// - Empty or whitespace-only strings
/// - Patterns containing control characters (`\n`, `\r`, `\t`, etc.)
/// - Patterns longer than 253 characters (DNS max)
/// - Patterns containing URL-reserved characters (`:/?#@`)
///
/// This does NOT check whether the pattern is a wildcard — that is handled
/// separately in [`DomainAllowlist::add_patterns`].
pub fn validate_domain_pattern(pattern: &str) -> Result<()> {
   if pattern != pattern.trim() {
      return Err(Error::InvalidDomainPattern(
         "pattern must not have leading or trailing whitespace".to_string(),
      ));
   }

   if pattern.is_empty() {
      return Err(Error::InvalidDomainPattern(
         "pattern must not be empty or whitespace-only".to_string(),
      ));
   }

   if pattern == "*" {
      return Err(Error::InvalidDomainPattern(
         "bare '*' is not supported; use '*.domain.com' for subdomain wildcards".to_string(),
      ));
   }

   if pattern.chars().any(|c| c.is_control()) {
      return Err(Error::InvalidDomainPattern(
         "pattern must not contain control characters".to_string(),
      ));
   }

   if pattern.len() > 253 {
      return Err(Error::InvalidDomainPattern(format!(
         "pattern length {} exceeds maximum of 253 characters",
         pattern.len(),
      )));
   }

   const RESERVED: &[char] = &[':', '/', '?', '#', '@'];

   if pattern.contains(RESERVED) {
      return Err(Error::InvalidDomainPattern(
         "pattern must not contain URL-reserved characters (:/?#@)".to_string(),
      ));
   }

   Ok(())
}

/// Convenience function: creates patterns for both `domain` and `*.domain`.
pub fn allow_domain_with_subdomains(domain: &str) -> Vec<String> {
   vec![domain.to_string(), format!("*.{domain}")]
}

/// Returns a closure that matches a domain if it equals `base_domain` or is a
/// subdomain of it (e.g. `api.example.com` for base `example.com`).
///
/// The returned closure is `Send + Sync + 'static`, suitable for use in custom
/// validation logic or middleware.
///
/// # Examples
///
/// ```no_run
/// use tauri_plugin_http_client::allowlist::subdomain_validator;
///
/// let matches = subdomain_validator("example.com");
/// assert!(matches("example.com"));
/// assert!(matches("api.example.com"));
/// assert!(!matches("notexample.com"));
/// ```
pub fn subdomain_validator(base_domain: &str) -> impl Fn(&str) -> bool + Send + Sync + 'static {
   let base = base_domain.to_lowercase();

   move |domain: &str| {
      let d = domain.to_lowercase();

      if d == base {
         return true;
      }

      d.ends_with(&base) && d.len() > base.len() && d.as_bytes()[d.len() - base.len() - 1] == b'.'
   }
}

/// Returns a closure that matches a domain if it exactly equals one of the
/// provided domains (case-insensitive).
///
/// # Examples
///
/// ```no_run
/// use tauri_plugin_http_client::allowlist::exact_domains_validator;
///
/// let matches = exact_domains_validator(&["api.example.com", "cdn.example.com"]);
/// assert!(matches("api.example.com"));
/// assert!(matches("CDN.Example.COM"));
/// assert!(!matches("other.example.com"));
/// ```
pub fn exact_domains_validator(domains: &[&str]) -> impl Fn(&str) -> bool + Send + Sync + 'static {
   let set: HashSet<String> = domains.iter().map(|d| d.to_lowercase()).collect();

   move |domain: &str| set.contains(&domain.to_lowercase())
}

#[cfg(test)]
mod tests {
   use super::*;
   use rstest::rstest;

   fn allowlist(patterns: &[&str]) -> DomainAllowlist {
      DomainAllowlist::new(patterns.iter().map(|s| s.to_string()).collect()).unwrap()
   }

   // --- Pattern matching ---

   #[rstest]
   #[case::exact_host("https://api.example.com/path", true)]
   #[case::sibling_subdomain("https://other.example.com/path", false)]
   fn test_exact_match(#[case] url: &str, #[case] allowed: bool) {
      let al = allowlist(&["api.example.com"]);

      assert_eq!(al.validate_url(url).is_ok(), allowed);
   }

   #[rstest]
   #[case::subdomain("https://api.example.com/path", true)]
   #[case::deep_subdomain("https://deep.sub.example.com/path", true)]
   // Wildcard does NOT match the base domain itself
   #[case::base_domain("https://example.com/path", false)]
   // "notexample.com" ends with "example.com" but should not match
   #[case::partial_suffix("https://notexample.com", false)]
   fn test_wildcard_subdomain_match(#[case] url: &str, #[case] allowed: bool) {
      let al = allowlist(&["*.example.com"]);

      assert_eq!(al.validate_url(url).is_ok(), allowed);
   }

   #[test]
   fn test_case_insensitive_matching() {
      let al = allowlist(&["API.Example.COM"]);

      assert!(al.validate_url("https://api.example.com/path").is_ok());
   }

   #[test]
   fn test_empty_allowlist_blocks_all() {
      let al = allowlist(&[]);

      assert!(al.validate_url("https://example.com").is_err());
      assert!(al.is_empty());
   }

   #[rstest]
   #[case::base_domain("https://example.com/path", true)]
   #[case::subdomain("https://api.example.com/path", true)]
   #[case::unrelated_domain("https://evil.com", false)]
   fn test_allow_domain_with_subdomains_helper(#[case] url: &str, #[case] allowed: bool) {
      let patterns = allow_domain_with_subdomains("example.com");
      let al = DomainAllowlist::new(patterns).unwrap();

      assert_eq!(al.validate_url(url).is_ok(), allowed);
   }

   // --- Scheme validation ---

   #[rstest]
   #[case::http("http://example.com")]
   #[case::https("https://example.com")]
   fn test_http_scheme_allowed(#[case] url: &str) {
      let al = allowlist(&["example.com"]);

      assert!(al.validate_url(url).is_ok());
   }

   #[test]
   fn test_non_http_scheme_rejected() {
      let al = allowlist(&["example.com"]);

      let err = al.validate_url("ftp://example.com").unwrap_err();

      assert!(matches!(err, Error::SchemeNotAllowed(_)));
   }

   // --- Userinfo rejection ---

   #[rstest]
   #[case::username_and_password("https://user:pass@example.com")]
   #[case::username_only("https://user@example.com")]
   fn test_userinfo_rejected(#[case] url: &str) {
      let al = allowlist(&["example.com"]);

      let err = al.validate_url(url).unwrap_err();

      assert!(matches!(err, Error::UserinfoNotAllowed));
   }

   // --- IP address rejection ---

   #[rstest]
   #[case::ipv4_loopback("https://127.0.0.1/path")]
   #[case::ipv6_loopback("https://[::1]/path")]
   // 2130706433 = 127.0.0.1 in decimal
   #[case::decimal_2130706433("https://2130706433/path")]
   #[case::hex_0x7f000001("https://0x7f000001/path")]
   // 0177.0.0.1 = 127.0.0.1 in octal
   #[case::octal_0177_0_0_1("https://0177.0.0.1/path")]
   fn test_ip_literal_rejected(#[case] url: &str) {
      let al = allowlist(&["example.com"]);

      let err = al.validate_url(url).unwrap_err();

      assert!(matches!(err, Error::IpAddressNotAllowed));
   }

   // --- Backslash rejection ---

   #[test]
   fn test_backslash_rejected() {
      let al = allowlist(&["example.com"]);

      let err = al
         .validate_url("https://example.com\\@evil.com")
         .unwrap_err();

      assert!(matches!(err, Error::InvalidUrl(_)));
   }

   // --- Trailing dot normalization ---

   #[test]
   fn test_trailing_dot_normalized() {
      let al = allowlist(&["example.com"]);

      assert!(al.validate_url("https://example.com./path").is_ok());
   }

   // --- Private IP detection ---

   #[rstest]
   #[case::v4_loopback("127.0.0.1", true)]
   #[case::v4_rfc1918_10("10.0.0.1", true)]
   #[case::v4_rfc1918_172_16("172.16.0.1", true)]
   #[case::v4_rfc1918_192_168("192.168.1.1", true)]
   #[case::v4_link_local("169.254.1.1", true)]
   #[case::v4_unspecified("0.0.0.0", true)]
   #[case::v4_public_google_dns("8.8.8.8", false)]
   #[case::v4_public_cloudflare_dns("1.1.1.1", false)]
   #[case::v6_loopback("::1", true)]
   #[case::v6_unique_local_fc00("fc00::1", true)]
   #[case::v6_unique_local_fd00("fd00::1", true)]
   #[case::v6_link_local("fe80::1", true)]
   #[case::v6_documentation_prefix("2001:db8::1", false)]
   #[case::v4_mapped_loopback("::ffff:127.0.0.1", true)]
   #[case::v4_mapped_public("::ffff:8.8.8.8", false)]
   fn test_is_private_ip_ranges(#[case] ip: &str, #[case] expected: bool) {
      assert_eq!(is_private_ip(&ip.parse().unwrap()), expected);
   }

   // --- is_ip_like edge cases ---

   #[rstest]
   // Octal representation: 0177.0.0.1 = 127.0.0.1
   #[case::dotted_octal("0177.0.0.1", true)]
   #[case::dotted_hex("0x7f.0x0.0x0.0x1", true)]
   #[case::pure_decimal("2130706433", true)]
   #[case::hex_prefix("0x7f000001", true)]
   #[case::normal_domain("example.com", false)]
   #[case::normal_subdomain("api.example.com", false)]
   #[case::normal_hyphenated_domain("my-domain.org", false)]
   // Domains with IP-like segments but containing non-numeric chars
   #[case::hyphenated_ip_segments("192-168-1-1.example.com", false)]
   #[case::ec2_internal_hostname("ip-10-0-0-1.ec2.internal", false)]
   #[case::alphanumeric_label("host123.example.com", false)]
   #[case::empty_string("", false)]
   // After bracket stripping, "::1" is not caught by is_ip_like
   // (it contains colons, not digits-only) - but the url crate
   // would parse it as IPv6 and catch it in validate_parsed_url
   #[case::bracketed_ipv6("[::1]", false)]
   fn test_is_ip_like(#[case] host: &str, #[case] expected: bool) {
      assert_eq!(is_ip_like(host), expected);
   }

   // --- Wildcard edge cases ---

   #[rstest]
   #[case::exact_pattern("https://api.example.com/path", true)]
   #[case::wildcard_pattern("https://img.cdn.example.com/pic.png", true)]
   #[case::unlisted_domain("https://example.com", false)]
   fn test_multiple_patterns(#[case] url: &str, #[case] allowed: bool) {
      let al = allowlist(&["api.example.com", "*.cdn.example.com"]);

      assert_eq!(al.validate_url(url).is_ok(), allowed);
   }

   // --- URL parsing edge cases ---

   #[rstest]
   #[case::explicit_port("https://example.com:8443/path")]
   #[case::query_and_fragment("https://example.com/path?key=val#frag")]
   fn test_validate_url_parsing_edge_cases_accepted(#[case] url: &str) {
      let al = allowlist(&["example.com"]);

      assert!(al.validate_url(url).is_ok());
   }

   #[rstest]
   #[case::data_scheme("data:text/html,<h1>hello</h1>")]
   // `url` crate may fail to parse this, which is also acceptable
   #[case::javascript_scheme("javascript:alert(1)")]
   #[case::empty_url("")]
   fn test_validate_url_parsing_edge_cases_rejected(#[case] url: &str) {
      let al = allowlist(&["example.com"]);

      assert!(al.validate_url(url).is_err());
   }

   // --- Private IP edge cases ---

   #[rstest]
   #[case::v4_broadcast("255.255.255.255", true)]
   #[case::v6_unspecified("::", true)]
   // 172.16.0.0 - 172.31.255.255 is private
   #[case::v4_rfc1918_172_range_start("172.16.0.1", true)]
   #[case::v4_rfc1918_172_range_end("172.31.255.254", true)]
   // 172.32.0.0 is NOT private
   #[case::v4_above_rfc1918_172_range("172.32.0.1", false)]
   fn test_is_private_ip_edge_cases(#[case] ip: &str, #[case] expected: bool) {
      assert_eq!(is_private_ip(&ip.parse().unwrap()), expected);
   }

   // --- Dynamic allowlist (add_patterns) ---

   #[test]
   fn test_add_patterns_allows_new_domain() {
      let mut al = allowlist(&["api.example.com"]);

      assert!(al.validate_url("https://new.example.com").is_err());

      al.add_patterns(vec!["new.example.com".to_string()])
         .unwrap();

      assert!(al.validate_url("https://new.example.com").is_ok());
      // Original pattern still works
      assert!(al.validate_url("https://api.example.com").is_ok());
   }

   #[test]
   fn test_add_patterns_rejects_wildcards() {
      let mut al = allowlist(&["api.example.com"]);

      let result = al.add_patterns(vec!["*.cdn.example.com".to_string()]);

      assert!(result.is_err());
      assert!(matches!(
         result.unwrap_err(),
         Error::WildcardNotAllowedAtRuntime(_)
      ));
      // Allowlist unchanged after rejection
      assert_eq!(al.pattern_count(), 1);
   }

   #[test]
   fn test_add_patterns_rejects_wildcard_in_batch() {
      let mut al = allowlist(&[]);

      // If any pattern is a wildcard, none should be added
      let result = al.add_patterns(vec![
         "good.example.com".to_string(),
         "*.bad.example.com".to_string(),
      ]);

      assert!(result.is_err());
      assert!(al.is_empty());
   }

   #[test]
   fn test_add_patterns_to_empty_allowlist() {
      let mut al = allowlist(&[]);

      assert!(al.is_empty());
      assert!(al.validate_url("https://example.com").is_err());

      al.add_patterns(vec!["example.com".to_string()]).unwrap();

      assert!(!al.is_empty());
      assert!(al.validate_url("https://example.com").is_ok());
   }

   #[test]
   fn test_add_patterns_duplicates_accepted() {
      let mut al = allowlist(&["example.com"]);

      al.add_patterns(vec!["example.com".to_string()]).unwrap();

      // HashSet deduplicates runtime patterns; init pattern still counted
      // init: ["example.com"], runtime: {"example.com"} = 2 total
      assert_eq!(al.pattern_count(), 2);
      assert!(al.validate_url("https://example.com").is_ok());
   }

   #[test]
   fn test_add_patterns_empty_vec_is_noop() {
      let mut al = allowlist(&["example.com"]);
      let count_before = al.pattern_count();

      al.add_patterns(vec![]).unwrap();

      assert_eq!(al.pattern_count(), count_before);
   }

   #[test]
   fn test_add_patterns_case_insensitive() {
      let mut al = allowlist(&[]);

      al.add_patterns(vec!["API.Example.COM".to_string()])
         .unwrap();

      assert!(al.validate_url("https://api.example.com").is_ok());
   }

   #[test]
   fn test_pattern_count() {
      let al = allowlist(&["a.com", "b.com", "*.c.com"]);

      assert_eq!(al.pattern_count(), 3);
   }

   #[test]
   fn test_domain_pattern_partial_eq() {
      assert_eq!(
         DomainPattern::parse("example.com"),
         DomainPattern::parse("example.com")
      );
      assert_eq!(
         DomainPattern::parse("*.example.com"),
         DomainPattern::parse("*.example.com")
      );
      // Same inner string but different variant
      assert_ne!(
         DomainPattern::parse("example.com"),
         DomainPattern::parse("*.example.com")
      );
   }

   // --- Dynamic allowlist (remove_patterns) ---

   #[test]
   fn test_remove_patterns_removes_runtime_domain() {
      let mut al = allowlist(&[]);

      al.add_patterns(vec!["api.example.com".to_string()])
         .unwrap();
      assert!(al.validate_url("https://api.example.com").is_ok());

      let removed = al
         .remove_patterns(&["api.example.com".to_string()])
         .unwrap();

      assert_eq!(removed, 1);
      assert!(al.validate_url("https://api.example.com").is_err());
   }

   #[test]
   fn test_remove_patterns_does_not_affect_init_patterns() {
      let mut al = allowlist(&["api.example.com"]);

      // Attempt to remove a config-time domain — should be a no-op
      let removed = al
         .remove_patterns(&["api.example.com".to_string()])
         .unwrap();

      assert_eq!(removed, 0);
      assert!(al.validate_url("https://api.example.com").is_ok());
   }

   #[test]
   fn test_remove_patterns_idempotent() {
      let mut al = allowlist(&[]);

      // Removing a domain that was never added
      let removed = al
         .remove_patterns(&["nonexistent.com".to_string()])
         .unwrap();

      assert_eq!(removed, 0);
   }

   #[test]
   fn test_remove_patterns_rejects_wildcards() {
      let mut al = allowlist(&[]);

      al.add_patterns(vec!["api.example.com".to_string()])
         .unwrap();

      let result = al.remove_patterns(&["*.example.com".to_string()]);

      assert!(result.is_err());
      assert!(matches!(
         result.unwrap_err(),
         Error::WildcardNotAllowedAtRuntime(_)
      ));
      // Runtime pattern should still be present (atomic rejection)
      assert_eq!(al.runtime_pattern_count(), 1);
   }

   #[test]
   fn test_remove_patterns_partial_match() {
      let mut al = allowlist(&[]);

      al.add_patterns(vec![
         "a.example.com".to_string(),
         "b.example.com".to_string(),
      ])
      .unwrap();

      let removed = al.remove_patterns(&["a.example.com".to_string()]).unwrap();

      assert_eq!(removed, 1);
      assert!(al.validate_url("https://a.example.com").is_err());
      assert!(al.validate_url("https://b.example.com").is_ok());
   }

   #[test]
   fn test_remove_patterns_case_insensitive() {
      let mut al = allowlist(&[]);

      al.add_patterns(vec!["api.example.com".to_string()])
         .unwrap();

      let removed = al
         .remove_patterns(&["API.Example.COM".to_string()])
         .unwrap();

      assert_eq!(removed, 1);
      assert!(al.validate_url("https://api.example.com").is_err());
   }

   #[test]
   fn test_remove_all_runtime_patterns() {
      let mut al = allowlist(&["init.example.com"]);

      al.add_patterns(vec![
         "a.example.com".to_string(),
         "b.example.com".to_string(),
      ])
      .unwrap();

      let removed = al.remove_all_runtime_patterns();

      assert_eq!(removed, 2);
      assert!(al.validate_url("https://a.example.com").is_err());
      assert!(al.validate_url("https://b.example.com").is_err());
      // Config-time pattern preserved
      assert!(al.validate_url("https://init.example.com").is_ok());
   }

   #[test]
   fn test_remove_all_runtime_patterns_empty() {
      let mut al = allowlist(&["init.example.com"]);

      let removed = al.remove_all_runtime_patterns();

      assert_eq!(removed, 0);
   }

   #[test]
   fn test_runtime_pattern_count() {
      let mut al = allowlist(&["init.example.com"]);

      assert_eq!(al.runtime_pattern_count(), 0);

      al.add_patterns(vec![
         "a.example.com".to_string(),
         "b.example.com".to_string(),
      ])
      .unwrap();

      assert_eq!(al.runtime_pattern_count(), 2);
   }

   #[test]
   fn test_add_then_remove_then_add_again() {
      let mut al = allowlist(&[]);

      al.add_patterns(vec!["api.example.com".to_string()])
         .unwrap();
      assert!(al.validate_url("https://api.example.com").is_ok());

      al.remove_patterns(&["api.example.com".to_string()])
         .unwrap();
      assert!(al.validate_url("https://api.example.com").is_err());

      al.add_patterns(vec!["api.example.com".to_string()])
         .unwrap();
      assert!(al.validate_url("https://api.example.com").is_ok());
   }

   #[test]
   fn test_pattern_count_reflects_both_init_and_runtime() {
      let mut al = allowlist(&["a.com", "*.b.com"]);

      assert_eq!(al.pattern_count(), 2);
      assert_eq!(al.config_pattern_count(), 2);
      assert_eq!(al.runtime_pattern_count(), 0);

      al.add_patterns(vec!["c.com".to_string(), "d.com".to_string()])
         .unwrap();

      assert_eq!(al.pattern_count(), 4);
      assert_eq!(al.config_pattern_count(), 2);
      assert_eq!(al.runtime_pattern_count(), 2);
   }

   #[test]
   fn test_is_empty_after_removing_all_runtime() {
      let mut al = allowlist(&[]);

      al.add_patterns(vec!["api.example.com".to_string()])
         .unwrap();
      assert!(!al.is_empty());

      al.remove_all_runtime_patterns();
      assert!(al.is_empty());

      // With init patterns, still not empty
      let mut al2 = allowlist(&["init.example.com"]);

      al2.add_patterns(vec!["api.example.com".to_string()])
         .unwrap();
      al2.remove_all_runtime_patterns();
      assert!(!al2.is_empty());
   }

   #[test]
   fn test_remove_patterns_empty_vec_is_noop() {
      let mut al = allowlist(&[]);

      al.add_patterns(vec!["api.example.com".to_string()])
         .unwrap();

      let removed = al.remove_patterns(&[]).unwrap();

      assert_eq!(removed, 0);
      assert_eq!(al.runtime_pattern_count(), 1);
   }

   #[rstest]
   #[case::runtime_domain("runtime.example.com", true)]
   #[case::init_domain("init.example.com", false)]
   #[case::nonexistent_domain("nonexistent.com", false)]
   fn test_is_runtime_domain(#[case] domain: &str, #[case] expected: bool) {
      let mut al = allowlist(&["init.example.com"]);

      al.add_patterns(vec!["runtime.example.com".to_string()])
         .unwrap();

      assert_eq!(al.is_runtime_domain(domain), expected);
   }

   #[test]
   fn test_add_patterns_deduplicates_in_hashset() {
      let mut al = allowlist(&[]);

      al.add_patterns(vec![
         "api.example.com".to_string(),
         "api.example.com".to_string(),
      ])
      .unwrap();

      assert_eq!(al.runtime_pattern_count(), 1);
   }

   // --- validate_domain_pattern ---

   #[rstest]
   #[case::plain_domain("example.com")]
   #[case::subdomain("api.example.com")]
   #[case::wildcard("*.example.com")]
   #[case::hyphenated_domain("my-domain.org")]
   fn test_validate_domain_pattern_valid(#[case] pattern: &str) {
      assert!(validate_domain_pattern(pattern).is_ok());
   }

   #[test]
   fn test_validate_domain_pattern_empty() {
      let err = validate_domain_pattern("").unwrap_err();

      assert!(matches!(err, Error::InvalidDomainPattern(_)));
   }

   #[rstest]
   #[case::spaces("   ")]
   #[case::tab("\t")]
   fn test_validate_domain_pattern_whitespace_only(#[case] pattern: &str) {
      assert!(validate_domain_pattern(pattern).is_err());
   }

   #[test]
   fn test_validate_domain_pattern_leading_trailing_whitespace_rejected() {
      let err = validate_domain_pattern(" example.com ").unwrap_err();

      assert!(matches!(err, Error::InvalidDomainPattern(_)));
      assert!(err.to_string().contains("whitespace"));
   }

   #[rstest]
   #[case::leading_space(" example.com")]
   #[case::trailing_space("example.com ")]
   #[case::leading_tab("\texample.com")]
   #[case::embedded_newline("example\n.com")]
   #[case::embedded_carriage_return("example\r.com")]
   #[case::embedded_tab("example\t.com")]
   #[case::embedded_null("example\0.com")]
   fn test_validate_domain_pattern_rejected(#[case] pattern: &str) {
      assert!(validate_domain_pattern(pattern).is_err());
   }

   #[test]
   fn test_validate_domain_pattern_too_long() {
      let long_pattern = "a".repeat(254);
      let err = validate_domain_pattern(&long_pattern).unwrap_err();

      assert!(matches!(err, Error::InvalidDomainPattern(_)));

      // Exactly 253 is fine
      let max_pattern = "a".repeat(253);

      assert!(validate_domain_pattern(&max_pattern).is_ok());
   }

   #[rstest]
   #[case::port_colon("example.com:8080")]
   #[case::path_slash("example.com/path")]
   #[case::query_question_mark("example.com?q=1")]
   #[case::fragment_hash("example.com#frag")]
   #[case::userinfo_at("user@example.com")]
   fn test_validate_domain_pattern_url_reserved_chars(#[case] pattern: &str) {
      assert!(validate_domain_pattern(pattern).is_err());
   }

   #[test]
   fn test_add_patterns_validates_before_mutating() {
      let mut al = allowlist(&[]);

      // Batch with one valid, one invalid: none should be added
      let result = al.add_patterns(vec![
         "good.example.com".to_string(),
         "bad\n.example.com".to_string(),
      ]);

      assert!(result.is_err());
      assert!(al.is_empty());
   }

   #[test]
   fn test_validate_domain_pattern_bare_wildcard_rejected() {
      let err = validate_domain_pattern("*").unwrap_err();

      assert!(matches!(err, Error::InvalidDomainPattern(_)));
      assert!(err.to_string().contains("bare '*'"));
   }

   #[rstest]
   // "*." strips to "", which fails the empty check
   #[case::wildcard_with_empty_base("*.")]
   // The base domain after "*." contains a URL-reserved character
   #[case::wildcard_with_invalid_base("*.com:443")]
   fn test_new_rejects_invalid_wildcard_pattern(#[case] pattern: &str) {
      let result = DomainAllowlist::new(vec![pattern.to_string()]);

      assert!(result.is_err());
      assert!(matches!(
         result.unwrap_err(),
         Error::InvalidDomainPattern(_)
      ));
   }

   #[rstest]
   #[case::valid_plain_domain("example.com", true)]
   #[case::valid_wildcard("*.example.com", true)]
   #[case::empty_pattern("", false)]
   #[case::bare_wildcard("*", false)]
   #[case::embedded_newline("example\n.com", false)]
   #[case::port_colon("example.com:443", false)]
   fn test_init_patterns_validated(#[case] pattern: &str, #[case] valid: bool) {
      assert_eq!(
         DomainAllowlist::new(vec![pattern.to_string()]).is_ok(),
         valid
      );
   }

   #[test]
   fn test_init_patterns_atomic_validation() {
      // If any pattern is invalid, none should be accepted
      let result = DomainAllowlist::new(vec![
         "good.example.com".to_string(),
         "bad\n.example.com".to_string(),
      ]);

      assert!(result.is_err());
   }

   #[rstest]
   #[case::empty_pattern("")]
   #[case::port_colon("example.com:443")]
   fn test_add_patterns_rejects_invalid_pattern(#[case] pattern: &str) {
      let mut al = allowlist(&[]);

      let result = al.add_patterns(vec![pattern.to_string()]);

      assert!(result.is_err());
      assert!(matches!(
         result.unwrap_err(),
         Error::InvalidDomainPattern(_)
      ));
   }

   // --- subdomain_validator ---

   #[rstest]
   #[case::base_domain("example.com", "example.com", true)]
   #[case::subdomain("example.com", "api.example.com", true)]
   #[case::deep_subdomain("example.com", "deep.sub.example.com", true)]
   #[case::partial_suffix("example.com", "notexample.com", false)]
   #[case::unrelated_domain("example.com", "evil.com", false)]
   #[case::mixed_case_base_lowercase_domain("Example.COM", "example.com", true)]
   #[case::mixed_case_base_uppercase_subdomain("Example.COM", "API.EXAMPLE.COM", true)]
   fn test_subdomain_validator(#[case] base: &str, #[case] domain: &str, #[case] expected: bool) {
      let matches = subdomain_validator(base);

      assert_eq!(matches(domain), expected);
   }

   // --- exact_domains_validator ---

   #[rstest]
   #[case::first_listed_domain(&["api.example.com", "cdn.example.com"], "api.example.com", true)]
   #[case::second_listed_domain(&["api.example.com", "cdn.example.com"], "cdn.example.com", true)]
   #[case::sibling_subdomain(&["api.example.com"], "other.example.com", false)]
   #[case::base_domain(&["api.example.com"], "example.com", false)]
   #[case::mixed_case_domain(&["api.example.com"], "API.Example.COM", true)]
   #[case::empty_list(&[], "anything.com", false)]
   fn test_exact_domains_validator(
      #[case] domains: &[&str],
      #[case] domain: &str,
      #[case] expected: bool,
   ) {
      let matches = exact_domains_validator(domains);

      assert_eq!(matches(domain), expected);
   }

   // --- validate_parsed_url direct tests ---

   #[test]
   fn test_validate_parsed_url_rejects_non_http_scheme() {
      let al = allowlist(&["example.com"]);
      let url = Url::parse("ftp://example.com/file").unwrap();

      assert!(matches!(
         al.validate_parsed_url(&url).unwrap_err(),
         Error::SchemeNotAllowed(_)
      ));
   }

   #[test]
   fn test_validate_parsed_url_rejects_userinfo() {
      let al = allowlist(&["example.com"]);
      let url = Url::parse("https://user:pass@example.com").unwrap();

      assert!(matches!(
         al.validate_parsed_url(&url).unwrap_err(),
         Error::UserinfoNotAllowed
      ));
   }

   #[test]
   fn test_validate_parsed_url_rejects_ip_address() {
      let al = allowlist(&["example.com"]);
      let url = Url::parse("https://127.0.0.1/path").unwrap();

      assert!(matches!(
         al.validate_parsed_url(&url).unwrap_err(),
         Error::IpAddressNotAllowed
      ));
   }

   #[test]
   fn test_validate_parsed_url_allows_matching_domain() {
      let al = allowlist(&["example.com"]);
      let url = Url::parse("https://example.com/path").unwrap();

      assert!(al.validate_parsed_url(&url).is_ok());
   }

   #[test]
   fn test_validate_parsed_url_rejects_disallowed_domain() {
      let al = allowlist(&["example.com"]);
      let url = Url::parse("https://evil.com/path").unwrap();

      assert!(matches!(
         al.validate_parsed_url(&url).unwrap_err(),
         Error::DomainNotAllowed(_)
      ));
   }

   // --- Port-based access ---

   // All ports should be allowed — port is not part of the domain check
   #[rstest]
   #[case::https_443("https://example.com:443/path")]
   #[case::https_8443("https://example.com:8443/path")]
   #[case::http_8080("http://example.com:8080/path")]
   #[case::http_3000("http://example.com:3000/path")]
   fn test_any_port_on_allowed_domain_is_accessible(#[case] url: &str) {
      let al = allowlist(&["example.com"]);

      assert!(al.validate_url(url).is_ok());
   }
}
