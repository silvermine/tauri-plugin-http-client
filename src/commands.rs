use tauri::{AppHandle, Runtime, State};

use crate::client::{HttpClientState, InFlightRequests};
use crate::error::Result;
use crate::types::{FetchRequest, FetchResponse};

/// Executes an HTTP request through the plugin's security and execution pipeline.
///
/// This is the primary IPC command invoked by the TypeScript guest.
#[tauri::command]
pub(crate) async fn fetch<R: Runtime>(
   _app: AppHandle<R>,
   state: State<'_, HttpClientState>,
   in_flight: State<'_, InFlightRequests>,
   request: FetchRequest,
) -> Result<FetchResponse> {
   let request_id = request.request_id.clone();

   if let Some(ref id) = request_id {
      // Spawn as a trackable task for abort support.
      // NOTE: There is a race between spawn and register — the task could
      // complete before register() is called. The double-remove below
      // mitigates this by ensuring cleanup even if the spawned task's
      // internal remove races with register.
      let state_ref = state.inner().clone();
      let id_clone = id.clone();
      let in_flight_clone = in_flight.inner().clone();

      let handle = tokio::spawn(async move {
         let result = state_ref.execute(request).await;

         // Clean up tracking regardless of outcome
         in_flight_clone.remove(&id_clone).await;

         result
      });

      in_flight.register(id.clone(), handle.abort_handle()).await;

      let result = match handle.await {
         Ok(result) => result,
         Err(e) if e.is_cancelled() => Err(crate::error::Error::Aborted),
         Err(e) => Err(crate::error::Error::Other(format!("task panicked: {e}"))),
      };

      // Ensure cleanup even if spawn's internal remove raced with register
      in_flight.remove(id).await;

      result
   } else {
      state.execute(request).await
   }
}

/// Cancels an in-flight request by its request ID.
///
/// Returns `true` if a matching request was found and aborted,
/// `false` if no request with the given ID was in flight.
#[tauri::command]
pub(crate) async fn abort_request<R: Runtime>(
   _app: AppHandle<R>,
   in_flight: State<'_, InFlightRequests>,
   request_id: String,
) -> Result<bool> {
   Ok(HttpClientState::abort(&in_flight, &request_id).await)
}
