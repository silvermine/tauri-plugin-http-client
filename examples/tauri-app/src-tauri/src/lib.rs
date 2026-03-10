use std::time::Duration;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
   tauri::Builder::default()
      .plugin(
         tauri_plugin_http_client::Builder::new()
            .allowed_domains(vec![
               "httpbin.org".into(),
               "*.httpbin.org".into(),
            ])
            .default_timeout(Duration::from_secs(30))
            .max_response_body_size(5 * 1024 * 1024)
            .build(),
      )
      .run(tauri::generate_context!())
      .expect("error while running tauri application");
}
