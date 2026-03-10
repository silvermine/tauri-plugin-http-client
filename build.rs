const COMMANDS: &[&str] = &["fetch", "abort_request"];

fn main() {
   tauri_plugin::Builder::new(COMMANDS).build();
}
