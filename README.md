# Tauri Plugin HTTP Client

[![CI][ci-badge]][ci-url]

HTTP client plugin for Tauri 2.x apps.

This plugin provides a cross-platform interface for creating HTTP requests from Tauri
applications.

[ci-badge]: https://github.com/silvermine/tauri-plugin-http-client/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/silvermine/tauri-plugin-http-client/actions/workflows/ci.yml

| Platform | Supported |
| -------- | --------- |
| Linux    | ✓         |
| Windows  | ✓         |
| macOS    | ✓         |
| Android  | ✓         |
| iOS      | ✓         |

## Getting Started

### Installation

1. Install NPM dependencies:

   ```bash
   npm install
   ```

2. Build the TypeScript bindings:

   ```bash
   npm run build
   ```

3. Build the Rust plugin:

   ```bash
   cargo build
   ```

### Tests

Run all tests:

```bash
npm test
```

Run Rust tests only:

```bash
npm run test:rust
```

Run TypeScript tests only:

```bash
npm run test:ts
```

## Install

_This plugin requires a Rust version of at least **1.89**_

### Rust

Add the plugin to your `Cargo.toml`:

`src-tauri/Cargo.toml`

```toml
[dependencies]
tauri-plugin-http-client = { git = "https://github.com/silvermine/tauri-plugin-http-client" }
```

### JavaScript/TypeScript

Install the JavaScript bindings:

```sh
npm install @silvermine/tauri-plugin-http-client
```

## Usage

Initialize the plugin in your `tauri::Builder`:

```rust
fn main() {
   tauri::Builder::default()
      .plugin(tauri_plugin_http_client::init())
      .run(tauri::generate_context!())
      .expect("error while running tauri application");
}
```

## Development Standards

This project follows the
[Silvermine standardization](https://github.com/silvermine/standardization)
guidelines. Key standards include:

   * **EditorConfig**: Consistent editor settings across the team
   * **Markdownlint**: Markdown linting for documentation
   * **Commitlint**: Conventional commit message format
   * **Code Style**: 3-space indentation, LF line endings

### Running Standards Checks

```bash
npm run standards
```

## License

MIT

## Contributing

Contributions are welcome! Please follow the established coding standards and commit
message conventions.
