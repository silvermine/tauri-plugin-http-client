import { describe, it, expect } from 'vitest';
import { HttpClientError, HttpErrorCode, parseError } from './errors';

describe('HttpClientError', () => {

   it('has correct name, code, and message', () => {
      const error = new HttpClientError(HttpErrorCode.TIMEOUT, 'request timed out');

      expect(error.name).toBe('HttpClientError');
      expect(error.code).toBe(HttpErrorCode.TIMEOUT);
      expect(error.message).toBe('request timed out');
      expect(error).toBeInstanceOf(Error);
   });

});

describe('parseError', () => {

   it('passes through HttpClientError instances', () => {
      const original = new HttpClientError(HttpErrorCode.ABORTED, 'aborted');

      expect(parseError(original)).toBe(original);
   });

   it('parses structured JSON string from Rust', () => {
      const json = JSON.stringify({ code: 'DOMAIN_NOT_ALLOWED', message: 'domain not allowed: evil.com' }),
            error = parseError(json);

      expect(error.code).toBe(HttpErrorCode.DOMAIN_NOT_ALLOWED);
      expect(error.message).toBe('domain not allowed: evil.com');
   });

   it('parses structured object from Rust', () => {
      const obj = { code: 'TIMEOUT', message: 'request timed out' },
            error = parseError(obj);

      expect(error.code).toBe(HttpErrorCode.TIMEOUT);
      expect(error.message).toBe('request timed out');
   });

   it('handles plain string errors', () => {
      const error = parseError('something went wrong');

      expect(error.code).toBe(HttpErrorCode.ERROR);
      expect(error.message).toBe('something went wrong');
   });

   it('handles unknown error codes gracefully', () => {
      const obj = { code: 'UNKNOWN_CODE', message: 'some error' },
            error = parseError(obj);

      expect(error.code).toBe(HttpErrorCode.ERROR);
      expect(error.message).toBe('some error');
   });

   it('handles null/undefined', () => {
      const error = parseError(null);

      expect(error.code).toBe(HttpErrorCode.ERROR);
      expect(error.message).toBe('unknown error');
   });

   it('handles objects with only message', () => {
      const error = parseError({ message: 'just a message' });

      expect(error.code).toBe(HttpErrorCode.ERROR);
      expect(error.message).toBe('just a message');
   });

   it('handles undefined', () => {
      const error = parseError(undefined);

      expect(error.code).toBe(HttpErrorCode.ERROR);
      expect(error.message).toBe('unknown error');
   });

   it('handles plain Error instances', () => {
      const error = parseError(new Error('regular error'));

      expect(error.code).toBe(HttpErrorCode.ERROR);
      expect(error.message).toBe('regular error');
   });

   it('handles number input', () => {
      const error = parseError(42);

      expect(error.code).toBe(HttpErrorCode.ERROR);
      expect(error.message).toBe('unknown error');
   });

   it('parses all known error codes from Rust', () => {
      const codes = [
         'DOMAIN_NOT_ALLOWED', 'SCHEME_NOT_ALLOWED', 'IP_ADDRESS_NOT_ALLOWED',
         'INVALID_URL', 'TIMEOUT', 'CONNECTION_ERROR', 'REQUEST_ERROR',
         'ABORTED', 'RESPONSE_TOO_LARGE', 'REDIRECT_BLOCKED',
         'ALLOWLIST_SIZE_EXCEEDED', 'WILDCARD_NOT_ALLOWED_AT_RUNTIME',
         'INVALID_DOMAIN_PATTERN',
      ];

      for (const code of codes) {
         const error = parseError({ code, message: 'test' });

         expect(error.code).toBe(code);
      }
   });

   it('handles JSON string with only message field', () => {
      const json = JSON.stringify({ message: 'partial error' }),
            error = parseError(json);

      // No code field, so should get plain string treatment since code check fails
      expect(error.code).toBe(HttpErrorCode.ERROR);
   });

});
