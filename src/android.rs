//! Android TLS: initialize [`rustls-platform-verifier`] before reqwest performs handshakes.
//!
//! Host apps must also add the `rustls-platform-verifier` Maven artifact — see the plugin README.

use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;

use jni::errors::Error as JniError;
use jni::objects::{JClassLoader, JObject};
use jni::sys::JNIEnv as JniEnvPtr;
use jni::{EnvUnowned, Outcome};
use parking_lot::Mutex;
use rustls_platform_verifier::android;
use tauri::{AppHandle, Manager, Runtime, WebviewWindow};
use tokio::sync::Mutex as AsyncMutex;

use crate::android_init_errors::{NO_WEBVIEW_ERR, is_no_webview_error};

const JNI_INIT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const POLL_MAX_WALL: Duration = Duration::from_secs(10);

static VERIFIER_INITIALIZED: OnceLock<()> = OnceLock::new();
static INIT_MUTEX: Mutex<()> = Mutex::new(());

struct InFlightInit {
   done: Arc<AsyncMutex<Option<Result<(), String>>>>,
   notify: Arc<tokio::sync::Notify>,
}

static INIT_COORDINATOR: LazyLock<AsyncMutex<Option<InFlightInit>>> =
   LazyLock::new(|| AsyncMutex::new(None));

trait TlsAppHost: Send + Sync {
   fn ensure_tls_ready_async(
      &self,
   ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
}

struct TlsAppHostImpl<R: Runtime> {
   handle: AppHandle<R>,
}

impl<R: Runtime> TlsAppHost for TlsAppHostImpl<R> {
   fn ensure_tls_ready_async(
      &self,
   ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
      let handle = self.handle.clone();
      Box::pin(async move { ensure_tls_ready_async(&handle).await })
   }
}

static TLS_APP_HOST: OnceLock<Box<dyn TlsAppHost>> = OnceLock::new();

/// Registers the app handle used for TLS init from backend HTTP paths.
pub fn register_tls_app_host<R: Runtime>(handle: AppHandle<R>) {
   let _ = TLS_APP_HOST.set(Box::new(TlsAppHostImpl { handle }));
}

/// Ensures TLS is ready before HTTP (backend + IPC via registered host).
pub(crate) async fn ensure_tls_ready() -> Result<(), String> {
   TLS_APP_HOST
      .get()
      .ok_or_else(|| {
         String::from(
            "Android TLS app handle not registered; http-client plugin setup may have failed",
         )
      })?
      .ensure_tls_ready_async()
      .await
}

/// Returns whether Android TLS has been initialized in this process.
pub fn is_platform_verifier_initialized() -> bool {
   VERIFIER_INITIALIZED.get().is_some()
}

fn mark_platform_verifier_initialized() {
   let _ = VERIFIER_INITIALIZED.set(());
}

/// Ensures TLS is initialized; fails if no webview is available yet.
pub fn ensure_platform_verifier_initialized<R: Runtime, M: Manager<R>>(
   manager: &M,
) -> Result<(), String> {
   run_platform_verifier_init_sync(manager)
}

pub(crate) async fn ensure_tls_ready_async<R: Runtime>(
   handle: &AppHandle<R>,
) -> Result<(), String> {
   if is_platform_verifier_initialized() {
      return Ok(());
   }

   let done;
   let notify;

   {
      let mut coordinator = INIT_COORDINATOR.lock().await;
      if let Some(in_flight) = coordinator.as_ref() {
         done = in_flight.done.clone();
         notify = in_flight.notify.clone();
      } else {
         done = Arc::new(AsyncMutex::new(None));
         notify = Arc::new(tokio::sync::Notify::new());
         *coordinator = Some(InFlightInit {
            done: done.clone(),
            notify: notify.clone(),
         });

         let handle = handle.clone();
         let done_leader = done.clone();
         let notify_leader = notify.clone();
         tokio::spawn(async move {
            let result =
               tokio::task::spawn_blocking(move || run_platform_verifier_init_sync(&handle))
                  .await
                  .unwrap_or_else(|e| Err(format!("Android TLS init task failed: {e}")));

            *done_leader.lock().await = Some(result);
            notify_leader.notify_waiters();
            INIT_COORDINATOR.lock().await.take();
         });
      }
   }

   loop {
      if let Some(result) = done.lock().await.clone() {
         return result;
      }
      notify.notified().await;
   }
}

fn run_platform_verifier_init_sync<R: Runtime, M: Manager<R>>(manager: &M) -> Result<(), String> {
   if is_platform_verifier_initialized() {
      return Ok(());
   }

   let _guard = INIT_MUTEX.lock();
   if is_platform_verifier_initialized() {
      return Ok(());
   }

   init_platform_verifier_from_app_locked(manager)
      .inspect(|()| mark_platform_verifier_initialized())
}

/// Plugin setup hook: succeed when the webview is not ready yet (normal on Tauri startup).
pub fn init_platform_verifier_from_app_deferred<R: Runtime, M: Manager<R>>(
   manager: &M,
) -> Result<(), String> {
   match run_platform_verifier_init_sync(manager) {
      Ok(()) => Ok(()),
      Err(e) if is_no_webview_error(&e) => Ok(()),
      Err(e) => Err(e),
   }
}

/// Polls until TLS init succeeds or gives up on hard failures.
pub async fn poll_platform_verifier_init<R: Runtime>(handle: AppHandle<R>) {
   if is_platform_verifier_initialized() {
      return;
   }

   let deadline = tokio::time::Instant::now() + POLL_MAX_WALL;

   while tokio::time::Instant::now() < deadline {
      if is_platform_verifier_initialized() {
         return;
      }

      match ensure_tls_ready_async(&handle).await {
         Ok(()) => return,
         Err(e) if is_no_webview_error(&e) => {
            tokio::time::sleep(POLL_INTERVAL).await;
         }
         Err(e) => {
            tracing::error!(
               "rustls-platform-verifier init polling stopped: {e}; \
                HTTPS requests may fail until Android TLS is configured"
            );
            return;
         }
      }
   }

   tracing::error!(
      "rustls-platform-verifier still not initialized after polling; \
       HTTPS requests may fail until a webview exists"
   );
}

/// Initializes the platform certificate verifier using the first available webview.
pub fn init_platform_verifier_from_app<R: Runtime, M: Manager<R>>(
   manager: &M,
) -> Result<(), String> {
   let _guard = INIT_MUTEX.lock();
   if is_platform_verifier_initialized() {
      return Ok(());
   }
   init_platform_verifier_from_app_locked(manager)
}

fn init_platform_verifier_from_app_locked<R: Runtime, M: Manager<R>>(
   manager: &M,
) -> Result<(), String> {
   for (_label, window) in manager.webview_windows() {
      return init_platform_verifier_from_webview_window_locked(&window);
   }

   Err(format!(
      "{NO_WEBVIEW_ERR}; ensure the app window is created before the http-client plugin runs, \
       or call tauri_plugin_http_client::android::init_platform_verifier_from_webview_window \
       from the host app after a webview exists"
   ))
}

/// Initializes the platform certificate verifier from a specific [`WebviewWindow`].
pub fn init_platform_verifier_from_webview_window<R: Runtime>(
   window: &WebviewWindow<R>,
) -> Result<(), String> {
   let _guard = INIT_MUTEX.lock();
   if is_platform_verifier_initialized() {
      return Ok(());
   }
   init_platform_verifier_from_webview_window_locked(window)
}

fn init_platform_verifier_from_webview_window_locked<R: Runtime>(
   window: &WebviewWindow<R>,
) -> Result<(), String> {
   let (tx, rx) = mpsc::channel();

   window
      .with_webview(move |webview| {
         webview.jni_handle().exec(move |env, activity, _webview| {
            let result = (|| -> Result<(), String> {
               // wry/Tauri use jni 0.21 + jni-sys 0.3; rustls-platform-verifier uses jni 0.22.
               // The JNIEnv pointer addresses the same JVM attachment — cast across crate versions.
               let raw_env = env.get_raw();
               let context_raw = activity.as_raw();

               let mut unowned = unsafe { EnvUnowned::from_raw(raw_env.cast::<JniEnvPtr>()) };

               match unowned
                  .with_env_no_catch(|jni_env| -> Result<(), JniError> {
                     let context = unsafe { JObject::from_raw(jni_env, context_raw) };
                     let loader_local = jni_env
                        .call_method(
                           &context,
                           jni::jni_str!("getClassLoader"),
                           jni::jni_sig!(() -> JClassLoader),
                           &[],
                        )?
                        .l()?;
                     let loader = jni_env.cast_local::<JClassLoader>(loader_local)?;

                     let java_vm = jni_env.get_java_vm()?;
                     let context = jni_env.new_global_ref(context)?;
                     let loader = jni_env.new_global_ref(loader)?;

                     android::init_with_refs(java_vm, context, loader);
                     Ok(())
                  })
                  .into_outcome()
               {
                  Outcome::Ok(()) => {}
                  Outcome::Err(e) => return Err(e.to_string()),
                  Outcome::Panic(_) => {
                     return Err("panic during Android TLS JNI setup".into());
                  }
               }

               Ok(())
            })();

            let _ = tx.send(result);
         });
      })
      .map_err(|e| format!("failed to access webview for Android TLS init: {e}"))?;

   match rx.recv_timeout(JNI_INIT_TIMEOUT) {
      Ok(Ok(())) => {
         mark_platform_verifier_initialized();
         tracing::info!("rustls-platform-verifier initialized for Android");
         Ok(())
      }
      Ok(Err(e)) => {
         tracing::error!("rustls-platform-verifier Android init failed: {e}");
         Err(format!(
            "rustls-platform-verifier Android init failed: {e}. \
             Ensure the host app includes the rustls-platform-verifier Gradle dependency \
             (see tauri-plugin-http-client README, Android TLS section)."
         ))
      }
      Err(mpsc::RecvTimeoutError::Timeout) => Err(
         "timed out waiting for Android TLS init on the webview thread; \
          ensure the main webview is created before HTTP requests run"
            .into(),
      ),
      Err(mpsc::RecvTimeoutError::Disconnected) => {
         Err("Android TLS init channel closed before completion".into())
      }
   }
}
