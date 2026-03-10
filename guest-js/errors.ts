export enum HttpErrorCode {
   DOMAIN_NOT_ALLOWED = 'DOMAIN_NOT_ALLOWED',
   SCHEME_NOT_ALLOWED = 'SCHEME_NOT_ALLOWED',
   IP_ADDRESS_NOT_ALLOWED = 'IP_ADDRESS_NOT_ALLOWED',
   INVALID_URL = 'INVALID_URL',
   TIMEOUT = 'TIMEOUT',
   CONNECTION_ERROR = 'CONNECTION_ERROR',
   REQUEST_ERROR = 'REQUEST_ERROR',
   ABORTED = 'ABORTED',
   RESPONSE_TOO_LARGE = 'RESPONSE_TOO_LARGE',
   REDIRECT_BLOCKED = 'REDIRECT_BLOCKED',
   ALLOWLIST_SIZE_EXCEEDED = 'ALLOWLIST_SIZE_EXCEEDED',
   WILDCARD_NOT_ALLOWED_AT_RUNTIME = 'WILDCARD_NOT_ALLOWED_AT_RUNTIME',
   INVALID_DOMAIN_PATTERN = 'INVALID_DOMAIN_PATTERN',
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
