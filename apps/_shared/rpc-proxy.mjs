// Bounded read-only Pages RPC transport shared by both public frontends.
// CORS is deliberately public; it does not authenticate a caller or origin.
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cache-Control': 'no-store',
};
class LimitError extends Error {}
class DeadlineError extends Error {}
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const validId = id => id === null || (typeof id === 'string' && id.length <= 128)
  || (typeof id === 'number' && Number.isSafeInteger(id));
// Inspect number tokens before JSON.parse can round them. Strings are skipped,
// including escapes. Public read parameters require safe integer literals;
// larger quantities must use an upstream-supported decimal-string field.
function exactNumberTokens(text) {
  const tokens = text.match(/"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g) ?? [];
  return tokens.every(token => token.startsWith('"')
    || (/^-?(?:0|[1-9]\d*)$/.test(token) && Number.isSafeInteger(Number(token))));
}
const json = (status, id, code, message) => new Response(JSON.stringify({
  jsonrpc: '2.0', id, error: { code, message },
}), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

export function secureUpstream(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash
      || /(?:^|\.)(?:sslip\.io|nip\.io|xip\.io)$/.test(url.hostname.replace(/\.$/, ''))) {
    throw new Error('a configured HTTPS upstream without URL credentials or public wildcard DNS is required');
  }
  return url.href;
}

async function boundedText(message, limit, timeoutMs) {
  const size = message.headers.get('content-length');
  if (size !== null && /^\d+$/.test(size) && Number(size) > limit) {
    if (message.body) void message.body.cancel().catch(() => {});
    throw new LimitError();
  }
  if (!message.body) return '';
  const reader = message.body.getReader();
  const chunks = [];
  let total = 0;
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new DeadlineError()), timeoutMs);
  });
  try {
    while (true) {
      const { value, done } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      total += value.byteLength;
      if (total > limit) throw new LimitError();
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } finally {
    clearTimeout(timer);
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export function createRpcProxy(methods, { fetchImpl = (...args) => fetch(...args),
  requestLimit = 64 * 1024, responseLimit = 2 * 1024 * 1024,
  requestTimeoutMs = 8000, upstreamTimeoutMs = 12000 } = {}) {
  const allowed = new Set(methods);
  return {
    onRequestOptions: () => new Response(null, { status: 204, headers: CORS }),
    async onRequestPost({ request, env }) {
      let upstream;
      try { upstream = secureUpstream(env.BLOCH_RPC_URL); }
      catch { return json(503, null, -32000, 'secure RPC upstream is not configured'); }
      if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json') {
        return json(415, null, -32600, 'application/json required');
      }
      let body;
      try {
        const text = await boundedText(request, requestLimit, requestTimeoutMs);
        if (!exactNumberTokens(text)) throw new Error();
        body = JSON.parse(text);
      }
      catch (error) {
        return json(error instanceof LimitError ? 413 : error instanceof DeadlineError ? 408 : 400,
          null, -32700, 'invalid, oversized or incomplete JSON request');
      }
      if (!object(body) || body.jsonrpc !== '2.0' || !validId(body.id ?? null)
          || typeof body.method !== 'string' || (body.params !== undefined && !Array.isArray(body.params))) {
        return json(400, null, -32600, 'invalid JSON-RPC request');
      }
      const id = body.id ?? null;
      if (!allowed.has(body.method)) return json(403, id, -32601, 'method not allowed via public proxy');
      const abort = new AbortController();
      const started = Date.now();
      let timer;
      const deadline = new Promise((_, reject) => {
        timer = setTimeout(() => { abort.abort(); reject(new DeadlineError()); }, upstreamTimeoutMs);
      });
      try {
        const response = await Promise.race([fetchImpl(upstream, {
          method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id, method: body.method, params: body.params ?? [] }),
          signal: abort.signal,
        }), deadline]);
        if (!response.ok) { if (response.body) void response.body.cancel().catch(() => {}); throw new Error(); }
        const remaining = upstreamTimeoutMs - (Date.now() - started);
        if (remaining <= 0) throw new DeadlineError();
        const text = await boundedText(response, responseLimit, remaining);
        const decoded = JSON.parse(text);
        if (!object(decoded) || decoded.jsonrpc !== '2.0' || decoded.id !== id
            || Object.hasOwn(decoded, 'result') === Object.hasOwn(decoded, 'error')
            || (Object.hasOwn(decoded, 'error') && !object(decoded.error))) throw new Error();
        // Return the original JSON bytes: reserializing legacy numeric amounts
        // after JSON.parse would silently round integers above 2^53.
        return new Response(text, { status: 200, headers: { ...CORS, 'Content-Type': 'application/json' } });
      } catch {
        abort.abort();
        return json(502, id, -32000, 'upstream RPC failed or returned an invalid response');
      } finally { clearTimeout(timer); }
    },
  };
}
