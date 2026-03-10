import { invoke } from '@tauri-apps/api/core';
import { HttpHeaders } from './headers';
import { parseError } from './errors';
import type { RequestOptions, HttpResponse, RawFetchRequest, RawFetchResponse } from './types';

let requestCounter = 0;

// Generates a unique ID used as both a tracking key in Rust's InFlightRequests
// map and a cancellation token for the abort_request IPC command. The counter
// handles rapid calls within the same millisecond.
function generateRequestId(): string {
   requestCounter += 1;
   return `req-${Date.now()}-${requestCounter}`;
}

/**
 * Sends an HTTP request through the Tauri HTTP client plugin.
 *
 * All URL validation and security checks happen in the Rust backend.
 *
 * @param url - The URL to request
 * @param options - Optional request configuration
 * @returns A response object with status, headers, and body accessors
 * @throws {HttpClientError} On network errors, security violations, or abort
 */
export async function request(url: string, options?: RequestOptions): Promise<HttpResponse> {
   let requestId: string | undefined,
       abortHandler: (() => void) | undefined;

   if (options?.signal) {
      requestId = generateRequestId();

      if (options.signal.aborted) {
         throw parseError({ code: 'ABORTED', message: 'request aborted' });
      }

      abortHandler = (): void => {
         // Fire-and-forget abort to Rust
         invoke('plugin:http-client|abort_request', { requestId }).catch(() => {
            // Ignore errors from abort (request may have already completed)
         });
      };

      options.signal.addEventListener('abort', abortHandler, { once: true });
   }

   try {
      const payload = buildPayload(url, requestId, options),
            raw: RawFetchResponse = await invoke('plugin:http-client|fetch', { request: payload });

      return wrapResponse(raw);
   } catch(err: unknown) {
      throw parseError(err);
   } finally {
      if (abortHandler && options?.signal) {
         options.signal.removeEventListener('abort', abortHandler);
      }
   }
}

function buildPayload(url: string, requestId: string | undefined, options?: RequestOptions): RawFetchRequest {
   const payload: RawFetchRequest = { url };

   if (options?.method) {
      payload.method = options.method;
   }

   if (options?.headers) {
      if (options.headers instanceof HttpHeaders) {
         payload.headers = options.headers.toRecord();
      } else {
         payload.headers = options.headers;
      }
   }

   if (options?.body !== undefined) {
      const encoded = encodeBody(options.body);

      payload.body = encoded.body;
      payload.bodyEncoding = encoded.encoding;
   }

   if (options?.timeout !== undefined) {
      payload.timeoutMs = options.timeout;
   }

   if (requestId) {
      payload.requestId = requestId;
   }

   return payload;
}

function encodeBody(body: string | Uint8Array | Record<string, unknown>): { body: string; encoding: string } {
   if (typeof body === 'string') {
      return { body, encoding: 'utf8' };
   }

   if (ArrayBuffer.isView(body)) {
      return { body: uint8ArrayToBase64(body), encoding: 'base64' };
   }

   return { body: JSON.stringify(body), encoding: 'utf8' };
}

// Manual loop + btoa/atob for broad WebView compatibility (avoids relying
// on Uint8Array.toBase64 which is not available in all runtimes).
function uint8ArrayToBase64(bytes: Uint8Array): string {
   let binary = '';

   for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
   }

   return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
   const binary = atob(base64),
         bytes = new Uint8Array(binary.length);

   for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
   }

   return bytes;
}

function wrapResponse(raw: RawFetchResponse): HttpResponse {
   const headers = new HttpHeaders(raw.headers);

   // Cache decoded body values
   let textValue: string | undefined,
       bytesValue: Uint8Array | undefined;

   return {
      status: raw.status,
      statusText: raw.statusText,
      headers,
      url: raw.url,
      redirected: raw.redirected,
      ok: raw.status >= 200 && raw.status < 300, // mirrors fetch() Response.ok

      text(): string {
         if (textValue === undefined) {
            if (raw.bodyEncoding === 'base64') {
               const bytes = base64ToUint8Array(raw.body);

               textValue = new TextDecoder().decode(bytes);
            } else {
               textValue = raw.body;
            }
         }

         return textValue;
      },

      json<T = unknown>(): T {
         return JSON.parse(this.text()) as T;
      },

      bytes(): Uint8Array {
         if (bytesValue === undefined) {
            if (raw.bodyEncoding === 'base64') {
               bytesValue = base64ToUint8Array(raw.body);
            } else {
               bytesValue = new TextEncoder().encode(raw.body);
            }
         }

         return bytesValue;
      },
   };
}
