# Tauri Plugin HTTP Client

[![CI][ci-badge]][ci-url]

HTTP client plugin for Tauri 2.x apps.

This plugin provides a cross-platform interface for creating HTTP
requests from Tauri applications.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/silvermine/tauri-plugin-http-client/ci.yml
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

### Permissions

Add the plugin's default permissions to your Tauri capability
file:

`src-tauri/capabilities/default.json`

```json
{
   "permissions": [
      "http-client:default"
   ]
}
```

The `default` permission set grants access to both the `fetch`
and `abort_request` IPC commands.

### Configuration (Rust)

Initialize the plugin in your `tauri::Builder`. The simplest
setup uses `init()`, which creates an empty allowlist that
**blocks all requests** by default:

```rust
fn main() {
   tauri::Builder::default()
      .plugin(tauri_plugin_http_client::init())
      .run(tauri::generate_context!())
      .expect("error while running tauri application");
}
```

To allow requests, configure the plugin with the `Builder`:

```rust
use std::time::Duration;

fn main() {
   tauri::Builder::default()
      .plugin(
         tauri_plugin_http_client::Builder::new()
            .allowed_domains(vec![
               "api.example.com".into(),      // exact domain
               "*.cdn.example.com".into(),     // wildcard subdomain
            ])
            .default_timeout(Duration::from_secs(30))
            .max_response_body_size(5 * 1024 * 1024)
            .build()
      )
      .run(tauri::generate_context!())
      .expect("error while running tauri application");
}
```

#### Builder Options

| Method                   | Default | Description                         |
| ------------------------ | ------- | ----------------------------------- |
| `allowed_domains`        | `[]`    | Domain patterns allowed             |
| `default_timeout`        | 10s     | Request timeout (per-request too)   |
| `max_redirects`          | 10      | Max redirect hops to follow         |
| `max_response_body_size` | 10 MB   | Max response body size in bytes     |
| `max_allowlist_size`     | 128     | Max allowlist patterns (all types)  |
| `user_agent`             | None    | Custom `User-Agent` for all reqs    |
| `default_headers`        | `{}`    | Default headers for all requests    |
| `retry`                  | off     | Full `RetryConfig` (see below)      |
| `max_retries`            | 0       | Shorthand to enable retry           |

#### Retry Configuration

Retry is **disabled by default** (`max_retries: 0`). Enable it
with `max_retries` for quick setup or `retry` for full control:

```rust
use tauri_plugin_http_client::{Builder, RetryConfig};
use std::time::Duration;

// Quick: enable with default settings (3 retries, 200ms backoff)
tauri_plugin_http_client::Builder::new()
   .max_retries(3)
   .build();

// Full control
tauri_plugin_http_client::Builder::new()
   .retry(RetryConfig {
      max_retries: 5,
      initial_backoff: Duration::from_millis(500),
      max_backoff: Duration::from_secs(30),
      ..RetryConfig::default()
   })
   .build();
```

| `RetryConfig` field        | Default                                  | Description                                  |
| -------------------------- | ---------------------------------------- | -------------------------------------------- |
| `max_retries`              | 3                                        | Max attempts after the initial request       |
| `initial_backoff`          | 200ms                                    | Base delay (exponential: `base * 2^attempt`) |
| `max_backoff`              | 10s                                      | Backoff cap                                  |
| `retryable_status_codes`   | `[408, 429, 500, 502, 503, 504]`        | Status codes that trigger retry              |
| `retryable_methods`        | `["GET","HEAD","PUT","DELETE","OPTIONS"]` | Methods eligible for retry (idempotent only) |
| `max_retry_after`          | 60s                                      | Max wait when honoring `Retry-After`         |

Connection errors and timeouts are always retried (for eligible
methods). Security errors are never retried. The timeout applies
per-attempt, so a request with `max_retries: 3` and a 10s
timeout could take up to ~43s total.

Per-request retry override from TypeScript:

```typescript
// Override max retries for a single request
const resp = await request('https://api.example.com/data', {
   maxRetries: 5,
});

// Disable retry for a specific request
const resp = await request('https://api.example.com/create', {
   method: 'POST',
   maxRetries: 0,
   body: { name: 'Alice' },
});

// The response includes the retry count
console.log(`Succeeded after ${resp.retryCount} retries`);
```

### Making Requests (TypeScript)

```typescript
import { request } from '@silvermine/tauri-plugin-http-client';

const resp = await request('https://api.example.com/users');
const users = resp.json();

// POST with JSON body
const resp = await request('https://api.example.com/users', {
   method: 'POST',
   headers: { 'content-type': 'application/json' },
   body: { name: 'Alice', email: 'alice@example.com' },
});

// POST with string body
const resp = await request('https://api.example.com/data', {
   method: 'POST',
   headers: { 'content-type': 'text/plain' },
   body: 'raw text payload',
});

// PUT with binary body (Uint8Array sent as base64 over IPC)
const resp = await request('https://api.example.com/upload', {
   method: 'PUT',
   body: new Uint8Array([0x00, 0x01, 0x02]),
});

// Per-request timeout (milliseconds)
const resp = await request('https://api.example.com/slow', {
   timeout: 60000,
});
```

#### Response Object

The response provides multiple accessors for the body:

```typescript
const resp = await request('https://api.example.com/data');

resp.status;      // number (e.g. 200)
resp.statusText;  // string (e.g. "OK")
resp.ok;          // true if status is 200-299
resp.url;         // final URL (after redirects)
resp.redirected;  // true if any redirects occurred
resp.headers;     // HttpHeaders instance

resp.text();      // body as string
resp.json();      // body parsed as JSON
resp.bytes();     // body as Uint8Array
```

#### Using HttpHeaders

Headers are case-insensitive and support multiple values:

```typescript
import { HttpHeaders } from '@silvermine/tauri-plugin-http-client';

// Build headers for a request
const headers = new HttpHeaders();
headers.set('authorization', 'Bearer token123');
headers.append('accept', 'application/json');

const resp = await request('https://api.example.com/data', {
   headers,
});

resp.headers.get('content-type');     // first value or null
resp.headers.getAll('set-cookie');    // all values as string[]
resp.headers.has('x-request-id');     // boolean
```

### Aborting Requests

Use the standard `AbortController` to cancel in-flight
requests:

```typescript
const controller = new AbortController();

setTimeout(() => controller.abort(), 5000);

try {
   const resp = await request('https://api.example.com/data', {
      signal: controller.signal,
   });
} catch (err) {
   if (err.code === 'ABORTED') {
      console.log('Request was cancelled');
   }
}
```

### Managing Domains at Runtime (Rust)

The `HttpClientExt` trait lets you modify the allowlist from
Rust code at runtime. Runtime-added domains must be exact (no
wildcards).

```rust
use tauri::Manager;
use tauri_plugin_http_client::HttpClientExt;

// In a Tauri command or setup hook:
fn setup(app: &mut tauri::App) {
   // Add a single domain
   app.add_allowed_domain("new-api.example.com").unwrap();

   // Add multiple domains at once
   app.add_allowed_domains(vec![
      "cdn.example.com".into(),
      "images.example.com".into(),
   ]).unwrap();

   // Remove a runtime-added domain
   app.remove_allowed_domain("cdn.example.com").unwrap();

   // Remove all runtime domains (config-time domains stay)
   app.remove_all_runtime_domains();
}
```

> **Note:** Config-time domains (set via
> `Builder::allowed_domains`) cannot be removed. Only domains
> added at runtime can be removed.

### Error Handling

All errors include a machine-readable `code` for programmatic
handling:

```typescript
import {
   request,
   HttpClientError,
   HttpErrorCode,
} from '@silvermine/tauri-plugin-http-client';

try {
   const resp = await request('https://blocked.example.com/data');
} catch (err) {
   if (err instanceof HttpClientError) {
      switch (err.code) {
         case HttpErrorCode.DOMAIN_NOT_ALLOWED:
            console.error('Domain is not in the allowlist');
            break;
         case HttpErrorCode.TIMEOUT:
            console.error('Request timed out');
            break;
         case HttpErrorCode.ABORTED:
            console.error('Request was aborted');
            break;
         default:
            console.error(`[${err.code}]: ${err.message}`);
      }
   }
}
```

#### Error Codes

| Code                              | Description                     |
| --------------------------------- | ------------------------------- |
| `DOMAIN_NOT_ALLOWED`              | Domain not in the allowlist     |
| `SCHEME_NOT_ALLOWED`              | Scheme is not `http`/`https`    |
| `IP_ADDRESS_NOT_ALLOWED`          | IP addresses not allowed        |
| `INVALID_URL`                     | URL malformed or has userinfo   |
| `TIMEOUT`                         | Request timed out               |
| `CONNECTION_ERROR`                | Failed to connect               |
| `REQUEST_ERROR`                   | General request failure         |
| `ABORTED`                         | Cancelled via `AbortController` |
| `RESPONSE_TOO_LARGE`              | Body exceeds size limit         |
| `REDIRECT_BLOCKED`                | Redirect to disallowed domain   |
| `ALLOWLIST_SIZE_EXCEEDED`         | Would exceed max patterns       |
| `WILDCARD_NOT_ALLOWED_AT_RUNTIME` | No wildcards at runtime         |
| `INVALID_DOMAIN_PATTERN`          | Pattern is malformed            |

### Security

This plugin is **secure by default**:

   * **Empty allowlist blocks all requests** -- you must
     explicitly allow each domain
   * **Anti-SSRF protections** -- IP addresses (IPv4, IPv6,
     decimal, octal, hex), private IPs, and URLs with
     userinfo are all rejected
   * **Redirect validation** -- every redirect hop is checked
     against the allowlist
   * **Wildcard restrictions** -- wildcard patterns
     (`*.example.com`) are only allowed at config time, not
     at runtime
   * **Config-time domains are immutable** -- domains set via
     `Builder::allowed_domains` cannot be removed, ensuring a
     baseline allowlist that cannot be revoked

## Development Standards

This project follows the
[Silvermine standardization](https://github.com/silvermine/standardization)
guidelines. Key standards include:

   * **EditorConfig**: Consistent editor settings across the
     team
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

Contributions are welcome! Please follow the established coding
standards and commit message conventions.
