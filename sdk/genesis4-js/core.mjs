// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs';
import { createHash, randomFillSync } from 'node:crypto';

const CORE_SHA256 = '2f6548cd822d4840e4584b0200467fcb352aaf84a70ea2b3be0e3f099bfa5f49';
const bytes = readFileSync(new URL('./bloch_wallet_wasm.wasm', import.meta.url));
if (createHash('sha256').update(bytes).digest('hex') !== CORE_SHA256) {
  throw new Error('Genesis-4 signing core checksum mismatch');
}
const module = new WebAssembly.Module(bytes);
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export function createCore() {
  let memory;
  const wasi = { wasi_snapshot_preview1: {
    random_get(ptr, len) { randomFillSync(new Uint8Array(memory.buffer, ptr, len)); return 0; },
    environ_sizes_get(count, size) {
      const view = new DataView(memory.buffer);
      view.setUint32(count, 0, true); view.setUint32(size, 0, true);
      return 0;
    },
    environ_get() { return 0; },
    fd_write(_fd, iov, count, written) {
      const view = new DataView(memory.buffer);
      let total = 0;
      for (let i = 0; i < count; i++) total += view.getUint32(iov + i * 8 + 4, true);
      view.setUint32(written, total, true);
      return 0;
    },
    proc_exit(code) { throw new Error(`Genesis-4 core exited (${code})`); },
  } };
  const instance = new WebAssembly.Instance(module, wasi);
  const exports = instance.exports;
  memory = exports.memory;

  return {
    call(method, args) {
      const methodBytes = encoder.encode(method);
      const argBytes = encoder.encode(JSON.stringify(args));
      let methodPtr, argPtr, resultPtr, resultLen;
      try {
        methodPtr = exports.bw_alloc(methodBytes.length);
        new Uint8Array(memory.buffer, methodPtr, methodBytes.length).set(methodBytes);
        argPtr = exports.bw_alloc(argBytes.length);
        new Uint8Array(memory.buffer, argPtr, argBytes.length).set(argBytes);
        resultPtr = exports.bw_call(methodPtr, methodBytes.length, argPtr, argBytes.length);
        const view = new DataView(memory.buffer);
        const ok = view.getUint8(resultPtr);
        resultLen = view.getUint32(resultPtr + 1, true);
        const payload = decoder.decode(new Uint8Array(memory.buffer, resultPtr + 5, resultLen));
        if (!ok) throw new Error(payload);
        return JSON.parse(payload);
      } finally {
        // Clear the serialized arguments before returning the allocation.
        if (argPtr !== undefined) {
          new Uint8Array(memory.buffer, argPtr, argBytes.length).fill(0);
          exports.bw_free(argPtr, argBytes.length);
        }
        if (methodPtr !== undefined) exports.bw_free(methodPtr, methodBytes.length);
        if (resultPtr !== undefined) exports.bw_free(resultPtr, 5 + resultLen);
      }
    },
    dispose() { new Uint8Array(memory.buffer).fill(0); },
  };
}
