# Tauri Plugin HTTP Client

[![CI][ci-badge]][ci-url]

HTTP client plugin for Tauri 2.x apps.

This plugin provides a cross-platform interface for creating HTTP
requests from Tauri applications.


## Features

   * Domain allowlist with wildcard support (secure by
     default)
   * Anti-SSRF protections (rejects IPs, userinfo,
     non-HTTP schemes)
   * Redirect validation against the allowlist on every
     hop
   * Automatic retry with exponential backoff and jitter
   * Abort in-flight requests via `AbortController`
   * Case-insensitive `HttpHeaders` with multi-value
     support
   * Binary request and response bodies
   * Runtime allowlist management from Rust
   * Rust backend API -- make HTTP requests from Rust
     through the same security pipeline as the frontend


## Installation

### 1. Install the npm package

```bash
npm install @silvermine/tauri-plugin-http-client
```

Peer dependency: `@tauri-apps/api >= 2.12.0`

### 2. Add the Cargo dependency

In `src-tauri/Cargo.toml`:

```toml
[dependencies]
tauri-plugin-http-client = {
   git = "https://github.com/silvermine/tauri-plugin-http-client.git"
}
```

### 3. Register the plugin

In `src-tauri/src/lib.rs`:

```rust
use std::time::Duration;

fn main() {
   tauri::Builder::default()
      .plugin(
         tauri_plugin_http_client::Builder::new()
            .allowed_domains([
               "api.example.com",
               "*.cdn.example.com",
            ])
            .default_timeout(Duration::from_secs(30))
            .build(),
      )
      .run(tauri::generate_context!())
      .expect("error running tauri application");
}
```

### 4. Add permissions

In `src-tauri/capabilities/default.json`, add the plugin
permission:

```json
{
   "permissions": [
      "http-client:default"
   ]
}
```

This grants access to both the `fetch` and `abort_request`
IPC commands.


## Usage

### Basic Requests

```typescript
import { request } from '@silvermine/tauri-plugin-http-client';

// GET
const resp = await request('https://api.example.com/items');
const items = resp.json<Item[]>();

// POST with JSON body
const resp = await request('https://api.example.com/items', {
   method: 'POST',
   headers: { 'Content-Type': 'application/json' },
   body: { name: 'New item', quantity: 3 },
});
```

> When passing an object as `body`, it is JSON-stringified
> automatically. You must set `Content-Type` yourself.

### Reading Responses

```typescript
const resp = await request('https://api.example.com/data');

// Body accessors
const text: string = resp.text();
const data: MyType = resp.json<MyType>();
const bytes: Uint8Array = resp.bytes();

// Metadata
resp.status;      // 200
resp.statusText;  // "OK"
resp.ok;          // true (status 200-299)
resp.url;         // final URL after redirects
resp.redirected;  // true if redirected
resp.retryCount;  // number of retries before success
```

### Custom Headers

```typescript
import {
   request,
   HttpHeaders,
} from '@silvermine/tauri-plugin-http-client';

// Using HttpHeaders class
const headers = new HttpHeaders();
headers.set('Authorization', 'Bearer tok_123');
headers.set('Accept', 'application/json');

const resp = await request('https://api.example.com/me', {
   headers,
});

// Or use a plain object
const resp = await request('https://api.example.com/me', {
   headers: {
      'Authorization': 'Bearer tok_123',
      'Accept': 'application/json',
   },
});

// Reading response headers (case-insensitive)
resp.headers.get('content-type');    // first value
resp.headers.getAll('set-cookie');   // all values
resp.headers.has('x-request-id');    // boolean
```

### Aborting Requests

```typescript
import {
   request,
   HttpClientError,
   HttpErrorCode,
} from '@silvermine/tauri-plugin-http-client';

const controller = new AbortController();

// Cancel after 5 seconds
setTimeout(() => controller.abort(), 5000);

try {
   const resp = await request(
      'https://api.example.com/large-export',
      { signal: controller.signal },
   );
} catch (err) {
   if (
      err instanceof HttpClientError
      && err.code === HttpErrorCode.ABORTED
   ) {
      console.log('Request was aborted');
   }
}
```

### Timeouts

```typescript
// Per-request timeout in milliseconds
const resp = await request('https://api.example.com/slow', {
   timeout: 60000,
});
```

This overrides the plugin-level `default_timeout`.

### Binary Data

```typescript
// Sending binary
const payload = new Uint8Array([0x00, 0x01, 0x02]);

await request('https://api.example.com/upload', {
   method: 'POST',
   headers: { 'Content-Type': 'application/octet-stream' },
   body: payload,
});

// Receiving binary
const resp = await request(
   'https://api.example.com/image.png',
);
const bytes = resp.bytes();
const blob = new Blob([bytes], { type: 'image/png' });
```

### Retries

Per-request retry override (capped at the plugin-level max):

```typescript
const resp = await request('https://api.example.com/data', {
   maxRetries: 5,
});

// Disable retry for a specific request
const resp = await request('https://api.example.com/data', {
   maxRetries: 0,
});
```

See [Retry Configuration](#retry-configuration) for
plugin-level setup.

### Error Handling

```typescript
import {
   request,
   HttpClientError,
   HttpErrorCode,
} from '@silvermine/tauri-plugin-http-client';

try {
   const resp = await request('https://blocked.example.com');
} catch (err) {
   if (err instanceof HttpClientError) {
      switch (err.code) {
         case HttpErrorCode.DOMAIN_NOT_ALLOWED:
            // URL not in allowlist
            break;
         case HttpErrorCode.TIMEOUT:
            // Request timed out
            break;
         case HttpErrorCode.ABORTED:
            // Cancelled via AbortController
            break;
         default:
            console.error(err.code, err.message);
      }
   }
}
```

See [`HttpErrorCode`](guest-js/errors.ts) for the full
list of error codes and descriptions.

### Rust Backend Requests

The plugin exposes a Rust API for making HTTP requests
from backend code through the same security pipeline
(domain allowlist, private IP blocking, redirect
validation, body size limits, retry) as the frontend.

```rust
use tauri::Manager;
use tauri_plugin_http_client::HttpClientExt;

#[tauri::command]
async fn fetch_data(
   app: tauri::AppHandle,
) -> Result<String, String> {
   let resp = app.http_client()
      .get("https://api.example.com/data")
      .header("Accept", "application/json")
      .timeout(std::time::Duration::from_secs(10))
      .send()
      .await
      .map_err(|e| e.to_string())?;

   resp.text()
      .map(|s| s.to_string())
      .map_err(|e| e.to_string())
}
```

> `send()` returns
> `tauri_plugin_http_client::error::Error`, which
> provides `is_retryable()` for retry decisions and can
> be matched on specific variants (e.g.,
> `Error::DomainNotAllowed`). Response body methods like
> `text()` return standard library errors.

Available builder methods:

   * `get(url)` / `post(url)` / `head(url)` -- convenience starters
   * `request(method, url)` -- arbitrary HTTP method
   * `.header(key, val)` -- add a header (repeatable)
   * `.body(bytes)` -- set the request body
   * `.timeout(duration)` -- per-request timeout
   * `.max_retries(n)` -- per-request retry cap
   * `.send()` -- execute through the security pipeline

The response provides native `reqwest` types:

   * `status()` -- `reqwest::StatusCode`
   * `headers()` -- `&reqwest::header::HeaderMap`
   * `url()` -- `&url::Url` (final URL after redirects)
   * `redirected()` -- `bool`
   * `body()` / `into_body()` -- `&[u8]` / `Vec<u8>`
   * `text()` -- `Result<&str, std::str::Utf8Error>`
   * `retry_count()` -- number of retries performed


## Security

Both the TypeScript frontend and Rust backend API share
the same security pipeline. All protections below apply
equally to both paths.

### Domain Allowlist

The allowlist has two tiers:

   * **Init-time patterns** -- set via
     `allowed_domains()` in the builder. Supports exact
     domains (`api.example.com`) and wildcards
     (`*.example.com`). These cannot be removed at
     runtime.
   * **Runtime patterns** -- added from Rust via
     `HttpClientExt`. Exact domains only (wildcards are
     rejected). Can be added and removed at any time.

An empty allowlist blocks all requests (secure by default).

The total number of patterns (init + runtime) is capped at
`max_allowlist_size` (default: 128).

### Anti-SSRF Protections

   * Rejects IP addresses (IPv4, IPv6, decimal, octal,
     hex encodings)
   * Rejects `userinfo@` in URLs
   * Only allows `http` and `https` schemes
   * Validates every redirect hop against the allowlist

### Forbidden Headers

Certain transport-layer and security-prefix headers are
blocked from both per-request and default headers:

   * `Host`, `Connection`, `Keep-Alive`,
     `Transfer-Encoding`, `TE`, `Upgrade`, `Trailer`
   * Any header starting with `Sec-` or `Proxy-`

Default headers are validated at plugin init; per-request
headers are validated before each request. Blocked headers
produce a `FORBIDDEN_HEADER` error.

### TLS Certificates

On Android, server certificates are verified against the
Mozilla root store bundled with the plugin
(`webpki-root-certs`), not the system trust store. No JNI
or Gradle setup is needed, but user-installed and MDM CAs
and `network_security_config` are not honored. Mozilla's
domain limits do not apply: the TUBITAK root is not
limited to `.tr`. The roots are fixed at build time. To
get Mozilla root changes, run
`cargo update -p webpki-root-certs` in the app, then
rebuild. Other platforms use the system trust store.


## Rust Configuration

### Builder Options

| Method | Type | Default | Description |
| --- | --- |---|---|
| `allowed_domains` | `impl IntoIterator<Item = impl Into<String>>` | `[]` | Domain patterns |
| `default_timeout` | `Duration` | None | Request timeout |
| `max_redirects` | `usize` | `10` | Max redirect hops |
| `max_response_body_size` | `usize` | 10 MB | Body size limit |
| `max_allowlist_size` | `usize` | `128` | Pattern cap |
| `user_agent` | `String` | None | Custom User-Agent |
| `default_headers` | `HashMap` | `{}` | Default headers |
| `retry` | `RetryConfig` | disabled | Retry settings |
| `max_retries` | `u32` | -- | Convenience for retry |

Full example:

```rust
use std::time::Duration;
use tauri_plugin_http_client::config::RetryConfig;

let plugin = tauri_plugin_http_client::Builder::new()
   .allowed_domains([
      "api.example.com",
      "*.cdn.example.com",
   ])
   .default_timeout(Duration::from_secs(30))
   .max_redirects(5)
   .max_response_body_size(5 * 1024 * 1024)
   .max_allowlist_size(64)
   .user_agent("my-app/1.0")
   .default_headers([
      ("X-App-Version", "1.0"),
   ])
   .retry(RetryConfig::default())
   .build();
```

### Retry Configuration

Retry is disabled by default. Enable it with
`RetryConfig::default()` or a custom config:

| Field | Type | Default | Description |
| --- | --- |---|---|
| `max_retries` | `u32` | `3` | Max attempts after initial |
| `initial_backoff` | `Duration` | 200 ms | First retry delay |
| `max_backoff` | `Duration` | 10 s | Backoff cap |
| `retryable_status_codes` | `Vec<u16>` | 408, 429, 500, 502, 503, 504 | Status codes to retry |
| `max_retry_after` | `Duration` | 60 s | Cap for Retry-After |
| `retryable_methods` | `Option<Vec<String>>` | GET, HEAD, PUT, DELETE, OPTIONS | Methods to retry |

Key behaviors:

   * Exponential backoff with jitter
     (`initial_backoff * 2^(attempt-1)`)
   * Honors `Retry-After` headers (capped at
     `max_retry_after`)
   * POST and PATCH excluded by default (not idempotent)
   * Set `retryable_methods` to `None` to retry all
     methods
   * Timeout is per-attempt, not total
   * Security errors are never retried

```rust
use std::time::Duration;
use tauri_plugin_http_client::config::RetryConfig;

let retry = RetryConfig {
   max_retries: 5,
   initial_backoff: Duration::from_millis(500),
   max_backoff: Duration::from_secs(30),
   retryable_methods: None, // retry all methods
   ..RetryConfig::default()
};

let plugin = tauri_plugin_http_client::Builder::new()
   .allowed_domains(["api.example.com"])
   .retry(retry)
   .build();
```

### Runtime Allowlist Management

Use the `HttpClientExt` trait to manage domains from Rust:

```rust
use tauri::Manager;
use tauri_plugin_http_client::HttpClientExt;

#[tauri::command]
fn connect_service(
   app: tauri::AppHandle,
   domain: String,
) -> Result<(), String> {
   app.add_allowed_domain(domain)
      .map_err(|e| e.to_string())
}
```

Available methods:

   * `add_allowed_domain(domain)` -- add one domain
   * `add_allowed_domains(domains)` -- add multiple
     domains
   * `remove_allowed_domain(domain)` -- remove one
     (returns whether it existed)
   * `remove_allowed_domains(domains)` -- remove multiple
     (returns count removed)
   * `remove_all_runtime_domains()` -- clear all runtime
     domains

Wildcards are rejected at runtime
(`WILDCARD_NOT_ALLOWED_AT_RUNTIME`). Init-time patterns
cannot be removed.


## License

[MIT](./LICENSE)

[ci-badge]: https://img.shields.io/github/actions/workflow/status/silvermine/tauri-plugin-http-client/ci.yml
[ci-url]: https://github.com/silvermine/tauri-plugin-http-client/actions/workflows/ci.yml
