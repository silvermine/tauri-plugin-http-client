/**
 * Machine-readable error codes returned by the HTTP client plugin.
 *
 * Use these with {@link HttpClientError.code} for programmatic error
 * handling.
 */
export enum HttpErrorCode {

   /** URL host is not in the domain allowlist. */
   DOMAIN_NOT_ALLOWED = 'DOMAIN_NOT_ALLOWED',

   /** Non-HTTP(S) scheme (e.g. `ftp://`, `file://`). */
   SCHEME_NOT_ALLOWED = 'SCHEME_NOT_ALLOWED',

   /** IP address used instead of a domain name. */
   IP_ADDRESS_NOT_ALLOWED = 'IP_ADDRESS_NOT_ALLOWED',

   /** Malformed URL. */
   INVALID_URL = 'INVALID_URL',

   /** Request timed out. */
   TIMEOUT = 'TIMEOUT',

   /** TCP or TLS connection failure. */
   CONNECTION_ERROR = 'CONNECTION_ERROR',

   /** Other request-level error. */
   REQUEST_ERROR = 'REQUEST_ERROR',

   /** Request cancelled via `AbortController`. */
   ABORTED = 'ABORTED',

   /** Response body exceeds the configured size limit. */
   RESPONSE_TOO_LARGE = 'RESPONSE_TOO_LARGE',

   /** A redirect targeted a domain not in the allowlist. */
   REDIRECT_BLOCKED = 'REDIRECT_BLOCKED',

   /** Adding a domain would exceed the allowlist size cap. */
   ALLOWLIST_SIZE_EXCEEDED = 'ALLOWLIST_SIZE_EXCEEDED',

   /** Wildcard patterns cannot be added at runtime. */
   WILDCARD_NOT_ALLOWED_AT_RUNTIME = 'WILDCARD_NOT_ALLOWED_AT_RUNTIME',

   /** Domain pattern is malformed. */
   INVALID_DOMAIN_PATTERN = 'INVALID_DOMAIN_PATTERN',

   /** A forbidden header was provided (e.g. Host). */
   FORBIDDEN_HEADER = 'FORBIDDEN_HEADER',

   /** Unclassified error. */
   ERROR = 'ERROR',

}

const KNOWN_CODES = new Set<string>(Object.values(HttpErrorCode));

/**
 * Error thrown by the HTTP client plugin.
 *
 * Contains a machine-readable {@link code} for programmatic error handling.
 */
export class HttpClientError extends Error {

   public readonly code: HttpErrorCode;

   public constructor(code: HttpErrorCode, message: string) {
      super(message);
      this.name = 'HttpClientError';
      this.code = code;
   }

}

/**
 * Parses the structured `{code, message}` error from the Rust backend
 * into an `HttpClientError`.
 */
export function parseError(err: unknown): HttpClientError {
   if (err instanceof HttpClientError) {
      return err;
   }

   // Tauri invoke errors come as strings or objects
   let code = HttpErrorCode.ERROR,
       message = 'unknown error';

   if (typeof err === 'string') {
      try {
         const parsed = JSON.parse(err) as { code?: string; message?: string };

         if (parsed.code && parsed.message) {
            code = toErrorCode(parsed.code);
            message = parsed.message;
         } else {
            message = err;
         }
      } catch{
         message = err;
      }
   } else if (err && typeof err === 'object') {
      const obj = err as Record<string, unknown>;

      if (typeof obj.code === 'string' && typeof obj.message === 'string') {
         code = toErrorCode(obj.code);
         message = obj.message;
      } else if (typeof obj.message === 'string') {
         message = obj.message;
      }
   }

   return new HttpClientError(code, message);
}

function toErrorCode(raw: string): HttpErrorCode {
   if (KNOWN_CODES.has(raw)) {
      return raw as HttpErrorCode;
   }

   return HttpErrorCode.ERROR;
}
