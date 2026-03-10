import type { HttpHeaders } from './headers';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
export type BodyInit = string | Uint8Array | Record<string, unknown>;

export interface RequestOptions {
   method?: HttpMethod;
   headers?: Record<string, string> | HttpHeaders;
   body?: BodyInit;
   timeout?: number;
   signal?: AbortSignal;

   /** Per-request retry override. `0` disables retry for this request.
    * Capped at the plugin-level max configured in Rust. */
   maxRetries?: number;
}

export interface HttpResponse {
   readonly status: number;
   readonly statusText: string;
   readonly headers: HttpHeaders;
   readonly url: string;
   readonly redirected: boolean;
   readonly ok: boolean;

   /** Number of retry attempts before this response (0 = no retries). */
   readonly retryCount: number;
   text(): string;
   json<T = unknown>(): T;
   bytes(): Uint8Array;
}

/** Raw IPC response from the Rust backend. */
export interface RawFetchResponse {
   status: number;
   statusText: string;
   headers: Record<string, string[]>;
   body: string;
   bodyEncoding: string;
   url: string;
   redirected: boolean;
   retryCount: number;
}

/** Raw IPC request payload sent to the Rust backend. */
export interface RawFetchRequest {
   url: string;
   method?: string;
   headers?: Record<string, string>;
   body?: string;
   bodyEncoding?: string;
   timeoutMs?: number;
   requestId?: string;
   maxRetries?: number;
}
