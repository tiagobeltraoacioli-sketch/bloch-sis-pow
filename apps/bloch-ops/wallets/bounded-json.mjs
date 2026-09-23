export class LookupResponseError extends Error {}

export async function readBoundedJson(response, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new LookupResponseError('Invalid response limit.');
  const declared = response.headers?.get('content-length');
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > maxBytes) {
    throw new LookupResponseError('The response exceeds the lookup size limit.');
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw new LookupResponseError('The response body is unavailable.');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel();
        throw new LookupResponseError('The response exceeds the lookup size limit.');
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof LookupResponseError) throw error;
    throw new LookupResponseError('Unable to read the lookup response.');
  } finally {
    reader.releaseLock();
  }
  const payload = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    payload.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload));
  } catch {
    throw new LookupResponseError('The lookup response is not valid JSON.');
  }
}
