import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { RawFetchResponse } from './types';
import type { HttpClientError as HttpClientErrorType } from './errors';

// Mock @tauri-apps/api/core before importing the module under test
const mockInvoke = vi.fn();

vi.mock('@tauri-apps/api/core', () => {
   return { invoke: mockInvoke };
});

// Import after mock setup
const { request } = await import('./http-client');

const { HttpClientError, HttpErrorCode } = await import('./errors');

const { HttpHeaders } = await import('./headers');

function makeRawResponse(overrides?: Partial<RawFetchResponse>): RawFetchResponse {
   return {
      status: 200,
      statusText: 'OK',
      headers: { 'content-type': [ 'application/json' ] },
      body: '{"key":"value"}',
      bodyEncoding: 'utf8',
      url: 'https://api.example.com/data',
      redirected: false,
      retryCount: 0,
      ...overrides,
   };
}

describe('request()', () => {

   beforeEach(() => {
      mockInvoke.mockReset();
   });

   afterEach(() => {
      vi.restoreAllMocks();
   });

   it('sends a basic GET request and returns a response', async () => {
      const raw = makeRawResponse();

      mockInvoke.mockResolvedValueOnce(raw);

      const resp = await request('https://api.example.com/data');

      expect(mockInvoke).toHaveBeenCalledWith('plugin:http-client|fetch', {
         request: { url: 'https://api.example.com/data' },
      });
      expect(resp.status).toBe(200);
      expect(resp.statusText).toBe('OK');
      expect(resp.ok).toBe(true);
      expect(resp.url).toBe('https://api.example.com/data');
      expect(resp.redirected).toBe(false);
      expect(resp.headers.get('content-type')).toBe('application/json');
   });

   it('returns text body correctly', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse({ body: 'hello world', bodyEncoding: 'utf8' }));

      const resp = await request('https://example.com');

      expect(resp.text()).toBe('hello world');
   });

   it('parses JSON body correctly', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      const resp = await request('https://example.com'),
            data = resp.json<{ key: string }>();

      expect(data.key).toBe('value');
   });

   it('decodes base64 body to bytes', async () => {
      // "hello" in base64
      mockInvoke.mockResolvedValueOnce(makeRawResponse({ body: 'aGVsbG8=', bodyEncoding: 'base64' }));

      const resp = await request('https://example.com'),
            bytes = resp.bytes();

      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(new TextDecoder().decode(bytes)).toBe('hello');
   });

   it('sends POST with string body', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      await request('https://example.com', { method: 'POST', body: 'payload' });

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.method).toBe('POST');
      expect(payload.body).toBe('payload');
      expect(payload.bodyEncoding).toBe('utf8');
   });

   it('sends POST with object body as JSON', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      await request('https://example.com', { method: 'POST', body: { foo: 'bar' } });

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.body).toBe('{"foo":"bar"}');
      expect(payload.bodyEncoding).toBe('utf8');
   });

   it('sends POST with Uint8Array body as base64', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      // Construct Uint8Array directly (not via TextEncoder) to avoid
      // cross-realm instanceof issues in jsdom test environment.
      const encoded = new TextEncoder().encode('binary data'),
            bytes = new Uint8Array(encoded);

      await request('https://example.com', { method: 'POST', body: bytes });

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.bodyEncoding).toBe('base64');
      expect(atob(payload.body)).toBe('binary data');
   });

   it('sends headers from Record', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      await request('https://example.com', {
         headers: { 'Authorization': 'Bearer token' },
      });

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.headers).toEqual({ 'Authorization': 'Bearer token' });
   });

   it('sends headers from HttpHeaders instance', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      const headers = new HttpHeaders();

      headers.set('Authorization', 'Bearer token');

      await request('https://example.com', { headers });

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.headers).toEqual({ 'authorization': 'Bearer token' });
   });

   it('sends timeout', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      await request('https://example.com', { timeout: 5000 });

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.timeoutMs).toBe(5000);
   });

   it('ok is false for non-2xx status', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse({ status: 404, statusText: 'Not Found' }));

      const resp = await request('https://example.com');

      expect(resp.ok).toBe(false);
      expect(resp.status).toBe(404);
   });

   it('throws HttpClientError on invoke failure', async () => {
      mockInvoke.mockRejectedValueOnce(JSON.stringify({
         code: 'DOMAIN_NOT_ALLOWED',
         message: 'domain not allowed: evil.com',
      }));

      try {
         await request('https://evil.com');
         expect.fail('should have thrown');
      } catch(err) {
         expect(err).toBeInstanceOf(HttpClientError);
         expect((err as HttpClientErrorType).code).toBe(HttpErrorCode.DOMAIN_NOT_ALLOWED);
      }
   });

   it('throws ABORTED when signal is already aborted', async () => {
      const controller = new AbortController();

      controller.abort();

      try {
         await request('https://example.com', { signal: controller.signal });
         expect.fail('should have thrown');
      } catch(err) {
         expect(err).toBeInstanceOf(HttpClientError);
         expect((err as HttpClientErrorType).code).toBe(HttpErrorCode.ABORTED);
      }
   });

   it('includes requestId when signal is provided', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      const controller = new AbortController();

      await request('https://example.com', { signal: controller.signal });

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.requestId).toBeDefined();
      expect(typeof payload.requestId).toBe('string');
   });

   it('calls abort_request when signal fires', async () => {
      // Make invoke hang until we abort
      let resolveInvoke: ((v: RawFetchResponse) => void) | undefined;

      const invokePromise = new Promise<RawFetchResponse>((resolve) => {
         resolveInvoke = resolve;
      });

      mockInvoke.mockImplementation((cmd: string) => {
         if (cmd === 'plugin:http-client|fetch') {
            return invokePromise;
         }
         // abort_request call
         return Promise.resolve(true);
      });

      const controller = new AbortController(),
            reqPromise = request('https://example.com', { signal: controller.signal });

      // Abort the request
      controller.abort();

      // Resolve the fetch so the promise settles
      if (resolveInvoke) {
         resolveInvoke(makeRawResponse());
      }

      const resp = await reqPromise;

      expect(resp.status).toBe(200);

      // Check that abort_request was called
      const abortCall = mockInvoke.mock.calls.find((c: unknown[]) => {
         return c[0] === 'plugin:http-client|abort_request';
      });

      expect(abortCall).toBeDefined();
   });

   it('decodes base64 body to text via text()', async () => {
      // "héllo" in UTF-8 then base64
      const bytes = new TextEncoder().encode('héllo'),
            b64 = btoa(String.fromCharCode(...bytes));

      mockInvoke.mockResolvedValueOnce(makeRawResponse({ body: b64, bodyEncoding: 'base64' }));

      const resp = await request('https://example.com');

      expect(resp.text()).toBe('héllo');
   });

   it('converts utf8 body to bytes via bytes()', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse({ body: 'hello', bodyEncoding: 'utf8' }));

      const resp = await request('https://example.com'),
            bytes = resp.bytes();

      expect(ArrayBuffer.isView(bytes)).toBe(true);
      expect(new TextDecoder().decode(bytes)).toBe('hello');
   });

   it('caches text() return value', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse({ body: 'cached', bodyEncoding: 'utf8' }));

      const resp = await request('https://example.com');

      expect(resp.text()).toBe('cached');
      // Second call should return same value (cached)
      expect(resp.text()).toBe('cached');
   });

   it('caches bytes() return value', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse({ body: 'aGVsbG8=', bodyEncoding: 'base64' }));

      const resp = await request('https://example.com');

      const first = resp.bytes(),
            second = resp.bytes();

      // Should be the exact same reference
      expect(first).toBe(second);
   });

   it('removes abort listener after successful request', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      const controller = new AbortController(),
            removeSpy = vi.spyOn(controller.signal, 'removeEventListener');

      await request('https://example.com', { signal: controller.signal });

      expect(removeSpy).toHaveBeenCalledWith('abort', expect.any(Function));
   });

   it('does not include requestId without signal', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      await request('https://example.com');

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.requestId).toBeUndefined();
   });

   it('omits undefined optional fields from payload', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      await request('https://example.com');

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload).toEqual({ url: 'https://example.com' });
   });

   it('ok boundary: 199 is not ok, 200 is ok, 299 is ok, 300 is not ok', async () => {
      for (const [ status, expectedOk ] of [ [ 199, false ], [ 200, true ], [ 299, true ], [ 300, false ] ] as [number, boolean][]) {
         mockInvoke.mockResolvedValueOnce(makeRawResponse({ status }));

         const resp = await request('https://example.com');

         expect(resp.ok).toBe(expectedOk);
      }
   });

   it('handles redirected response', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse({
         redirected: true,
         url: 'https://api.example.com/final',
      }));

      const resp = await request('https://api.example.com/start');

      expect(resp.redirected).toBe(true);
      expect(resp.url).toBe('https://api.example.com/final');
   });

   it('passes maxRetries in payload', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      await request('https://example.com', { maxRetries: 5 });

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.maxRetries).toBe(5);
   });

   it('omits maxRetries when undefined', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      await request('https://example.com');

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.maxRetries).toBeUndefined();
   });

   it('exposes retryCount from response', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse({ retryCount: 2 }));

      const resp = await request('https://example.com');

      expect(resp.retryCount).toBe(2);
   });

   it('retryCount is 0 when no retries occurred', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      const resp = await request('https://example.com');

      expect(resp.retryCount).toBe(0);
   });

   it('sends empty string body correctly', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      await request('https://example.com', { method: 'POST', body: '' });

      const payload = mockInvoke.mock.calls[0][1].request;

      expect(payload.body).toBe('');
      expect(payload.bodyEncoding).toBe('utf8');
   });

   it('sends multi-value headers via HttpHeaders as comma-joined string', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse());

      const headers = new HttpHeaders();

      headers.set('Accept', 'text/html');
      headers.append('Accept', 'application/json');

      await request('https://example.com', { headers });

      const payload = mockInvoke.mock.calls[0][1].request;

      // HttpHeaders.toRecord() joins multi-value with ", "
      expect(payload.headers.accept).toBe('text/html, application/json');
   });

   it('generateRequestId produces unique IDs under rapid calls', async () => {
      const ids: Set<string> = new Set();

      // Fire 10 rapid requests, each generating a unique requestId
      for (let i = 0; i < 10; i++) {
         mockInvoke.mockResolvedValueOnce(makeRawResponse());

         const controller = new AbortController();

         await request('https://example.com', { signal: controller.signal });

         const payload = mockInvoke.mock.calls[i][1].request;

         ids.add(payload.requestId);
      }

      // All IDs should be unique
      expect(ids.size).toBe(10);
   });

   it('json() throws on invalid JSON body', async () => {
      mockInvoke.mockResolvedValueOnce(makeRawResponse({ body: 'not valid json', bodyEncoding: 'utf8' }));

      const resp = await request('https://example.com');

      const fn = (): unknown => { return resp.json(); };

      expect(fn).toThrow();
   });

});
