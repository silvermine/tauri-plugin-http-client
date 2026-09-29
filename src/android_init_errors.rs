//! Android TLS init error classification (host-testable, no JNI).

pub(crate) const NO_WEBVIEW_ERR: &str =
   "no webview available to initialize Android TLS (rustls-platform-verifier)";

pub(crate) fn is_no_webview_error(message: &str) -> bool {
   message.starts_with(NO_WEBVIEW_ERR)
}

pub(crate) fn is_hard_init_failure(message: &str) -> bool {
   if is_no_webview_error(message) {
      return false;
   }

   message.contains("timed out waiting for Android TLS init")
      || message.contains("Android TLS init channel closed")
      || message.contains("rustls-platform-verifier Android init failed")
      || message.contains("failed to access webview for Android TLS init")
      || message.contains("panic during Android TLS JNI setup")
      || message.contains("http-client plugin setup may have failed")
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn no_webview_is_not_hard_failure() {
      let msg = format!("{NO_WEBVIEW_ERR}; extra context");
      assert!(is_no_webview_error(&msg));
      assert!(!is_hard_init_failure(&msg));
   }

   #[test]
   fn timeout_is_hard_failure() {
      let msg = "timed out waiting for Android TLS init on the webview thread";
      assert!(is_hard_init_failure(msg));
      assert!(!is_no_webview_error(msg));
   }

   #[test]
   fn gradle_init_failure_is_hard() {
      let msg = "rustls-platform-verifier Android init failed: ClassNotFoundException";
      assert!(is_hard_init_failure(msg));
   }
}
