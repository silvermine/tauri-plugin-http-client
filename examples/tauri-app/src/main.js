import { request, HttpHeaders, HttpClientError } from '@silvermine/tauri-plugin-http-client';

// --- Helpers ---

function $(id) {
   return document.getElementById(id);
}

function clearElement(el) {
   while (el.firstChild) {
      el.removeChild(el.firstChild);
   }
}

function setLoading(el, message) {
   el.textContent = message || 'Loading';
   el.classList.remove('error');
   el.classList.add('loading');
}

function setResult(el, text) {
   el.classList.remove('error', 'loading');
   el.textContent = text;
}

function setError(el, err) {
   el.classList.remove('loading');
   el.classList.add('error');
   el.textContent = formatError(err);
}

function formatResponse(resp) {
   var headers = {};

   resp.headers.forEach(function(value, name) {
      var existing = headers[name];

      if (existing) {
         headers[name] = existing + ', ' + value;
      } else {
         headers[name] = value;
      }
   });

   return JSON.stringify(
      {
         status: resp.status,
         statusText: resp.statusText,
         ok: resp.ok,
         redirected: resp.redirected,
         url: resp.url,
         headers: headers,
         body: tryParseJSON(resp.text()),
      },
      null,
      2,
   );
}

function tryParseJSON(text) {
   try {
      return JSON.parse(text);
   } catch(_e) {
      return text;
   }
}

function formatError(err) {
   if (err instanceof HttpClientError) {
      return 'HttpClientError\n  code:    ' + err.code + '\n  message: ' + err.message;
   }

   return String(err);
}

// --- GET Request ---

$('get-send').addEventListener('click', async function() {
   var output = $('get-output'),
       btn = $('get-send');

   btn.disabled = true;
   setLoading(output, 'Sending GET request');

   try {
      var resp = await request($('get-url').value);

      setResult(output, formatResponse(resp));
   } catch(err) {
      setError(output, err);
   } finally {
      btn.disabled = false;
   }
});

// --- POST Request ---

$('post-send').addEventListener('click', async function() {
   var output = $('post-output'),
       btn = $('post-send');

   btn.disabled = true;
   setLoading(output, 'Sending POST request');

   try {
      // Explicitly set Content-Type when sending JSON.
      // encodeBody() serializes objects to JSON strings but does not
      // auto-set the Content-Type header.
      var headers = new HttpHeaders();

      headers.set('Content-Type', 'application/json');

      var body = JSON.parse($('post-body').value),
          resp = await request($('post-url').value, {
             method: 'POST',
             headers: headers,
             body: body,
          });

      setResult(output, formatResponse(resp));
   } catch(err) {
      setError(output, err);
   } finally {
      btn.disabled = false;
   }
});

// --- Headers ---

$('headers-send').addEventListener('click', async function() {
   var output = $('headers-output'),
       btn = $('headers-send');

   btn.disabled = true;
   setLoading(output, 'Sending request with custom headers');

   try {
      var headers = new HttpHeaders();

      headers.set('X-Custom-Header', 'hello-from-tauri');
      headers.set('Accept', 'application/json');

      var resp = await request('https://httpbin.org/headers', { headers: headers });

      // Demonstrate multi-value response header access
      var result = '--- Request sent with custom headers ---\n';

      result += 'X-Custom-Header: ' + headers.get('x-custom-header') + '\n\n';
      result += '--- Response ---\n';
      result += 'Status: ' + resp.status + '\n\n';

      result += '--- Response Headers (multi-value access) ---\n';

      resp.headers.forEach(function(value, name) {
         result += name + ': ' + value + '\n';
      });

      result += '\n--- Response Body ---\n';
      result += JSON.stringify(resp.json(), null, 2);

      setResult(output, result);
   } catch(err) {
      setError(output, err);
   } finally {
      btn.disabled = false;
   }
});

// --- Abort ---

var abortController = null;

$('abort-start').addEventListener('click', async function() {
   var output = $('abort-output'),
       cancelBtn = $('abort-cancel'),
       startBtn = $('abort-start');

   abortController = new AbortController();
   setLoading(output, 'Request started (10s delay)... click Abort to cancel');
   cancelBtn.disabled = false;
   startBtn.disabled = true;

   try {
      var resp = await request('https://httpbin.org/delay/10', {
         signal: abortController.signal,
      });

      setResult(output, 'Request completed (was not aborted):\n' + formatResponse(resp));
   } catch(err) {
      setError(output, err);
   } finally {
      cancelBtn.disabled = true;
      startBtn.disabled = false;
      abortController = null;
   }
});

$('abort-cancel').addEventListener('click', function() {
   if (abortController) {
      abortController.abort();
   }
});

// --- Error Handling ---

$('err-domain').addEventListener('click', async function() {
   var output = $('err-output'),
       btn = $('err-domain');

   btn.disabled = true;
   setLoading(output, 'Requesting blocked domain');

   try {
      await request('https://evil.com/steal-data');
      setResult(output, 'Unexpected success');
   } catch(err) {
      setError(output, err);
   } finally {
      btn.disabled = false;
   }
});

$('err-timeout').addEventListener('click', async function() {
   var output = $('err-output'),
       btn = $('err-timeout');

   btn.disabled = true;
   setLoading(output, 'Requesting with 1s timeout against 10s delay');

   try {
      await request('https://httpbin.org/delay/10', { timeout: 1000 });
      setResult(output, 'Unexpected success');
   } catch(err) {
      setError(output, err);
   } finally {
      btn.disabled = false;
   }
});

$('err-invalid').addEventListener('click', async function() {
   var output = $('err-output'),
       btn = $('err-invalid');

   btn.disabled = true;
   setLoading(output, 'Sending invalid URL');

   try {
      await request('not-a-valid-url');
      setResult(output, 'Unexpected success');
   } catch(err) {
      setError(output, err);
   } finally {
      btn.disabled = false;
   }
});

// --- Binary Response ---

$('binary-fetch').addEventListener('click', async function() {
   var output = $('binary-output'),
       btn = $('binary-fetch');

   btn.disabled = true;
   clearElement(output);

   var loadingSpan = document.createElement('span');

   loadingSpan.className = 'loading';
   loadingSpan.textContent = 'Loading image';
   output.appendChild(loadingSpan);

   try {
      var resp = await request('https://httpbin.org/image/png'),
          bytes = resp.bytes(),
          blob = new Blob([bytes], { type: 'image/png' }),
          url = URL.createObjectURL(blob),
          img = document.createElement('img');

      img.src = url;
      img.alt = 'Image from httpbin.org';

      clearElement(output);
      output.classList.remove('error', 'loading');
      output.appendChild(document.createTextNode(
         'Status: ' + resp.status + ' | Size: ' + bytes.length + ' bytes\n',
      ));
      output.appendChild(img);
   } catch(err) {
      clearElement(output);
      setError(output, err);
   } finally {
      btn.disabled = false;
   }
});
