export const maxRpcResponseBytes = 1024 * 1024;

export class RpcResponseError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RpcResponseError';
  }
}

export async function readRpcResponse(response, expectedId) {
  const statedLength = response.headers?.get('content-length');
  if (statedLength && /^\d+$/.test(statedLength) && Number(statedLength) > maxRpcResponseBytes) {
    throw new RpcResponseError('Gateway response exceeds the 1 MiB limit.');
  }
  if (!response.body?.getReader) throw new RpcResponseError('Gateway response could not be read.');

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let body = '';
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxRpcResponseBytes) {
        await reader.cancel().catch(() => {});
        throw new RpcResponseError('Gateway response exceeds the 1 MiB limit.');
      }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
  } catch (error) {
    if (error instanceof RpcResponseError) throw error;
    throw new RpcResponseError('Gateway response could not be read.');
  } finally {
    reader.releaseLock();
  }

  let parsed;
  try { parsed = JSON.parse(body); }
  catch { throw new RpcResponseError(`Gateway returned HTTP ${response.status} without valid JSON.`); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) ||
      parsed.jsonrpc !== '2.0' || parsed.id !== expectedId ||
      Object.hasOwn(parsed, 'result') === Object.hasOwn(parsed, 'error') ||
      (Object.hasOwn(parsed, 'error') &&
        (!parsed.error || typeof parsed.error !== 'object' || Array.isArray(parsed.error) ||
          !Number.isSafeInteger(parsed.error.code) || typeof parsed.error.message !== 'string'))) {
    throw new RpcResponseError('Gateway returned an invalid JSON-RPC envelope.');
  }
  return parsed;
}
