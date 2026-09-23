// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-only status check for a previously stored SDK signed transaction.
// Usage: node examples/track-signed.mjs signed.json [previous-observation.json]
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { trackSignedTransaction } from '../index.mjs';

const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const HASH = /^[0-9a-f]{64}$/i;
const USAGE = 'Usage: node examples/track-signed.mjs signed.json [previous-observation.json]';

class CliInputError extends Error {}

function readJson(path, label) {
  let fd;
  try {
    // O_NOFOLLOW and fstat on the opened descriptor avoid following a swapped symlink.
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size === 0 || stat.size > MAX_INPUT_BYTES) {
      throw new CliInputError(`${label} must be a nonempty regular JSON file of at most 2 MiB`);
    }
    const buffer = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length !== stat.size) {
      throw new CliInputError(`${label} changed while being read`);
    }
    try { return JSON.parse(buffer.toString('utf8', 0, length)); }
    catch { throw new CliInputError(`${label} must contain valid JSON`); }
  } catch (error) {
    if (error instanceof CliInputError) throw error;
    throw new CliInputError(`${label} could not be opened as a regular file`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function signedEnvelope(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !HASH.test(value.txid) || !HASH.test(value.signingRootHex) ||
      !HASH.test(value.rawHash) || typeof value.rawHex !== 'string' ||
      value.rawHex.length < 128 || !/^[0-9a-f]+$/i.test(value.rawHex) || value.rawHex.length % 2) {
    throw new CliInputError('signed.json needs SDK txid, signingRootHex, rawHash and rawHex fields');
  }
  // Pass only the four identity fields to the SDK. Other saved wallet data,
  // including a mistakenly stored mnemonic, must not reach output or errors.
  return {
    txid: value.txid, signingRootHex: value.signingRootHex,
    rawHash: value.rawHash, rawHex: value.rawHex,
  };
}

function previousObservation(value, txid) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !HASH.test(value.txid) || value.txid.toLowerCase() !== txid.toLowerCase() ||
      !value.observation || typeof value.observation !== 'object' ||
      Array.isArray(value.observation) ||
      !HASH.test(value.observation.txid) ||
      value.observation.txid.toLowerCase() !== txid.toLowerCase() ||
      !['included', 'unresolved'].includes(value.observation.kind) ||
      (value.observation.kind === 'unresolved' &&
        (!['pending', 'included', 'justified', 'finalized', 'unknown', null]
          .includes(value.observation.nodeStatus) ||
         typeof value.observation.source !== 'string' ||
         typeof value.observation.note !== 'string')) ||
      !value.comparison || typeof value.comparison !== 'object' ||
      !HASH.test(value.comparison.txid) ||
      value.comparison.txid.toLowerCase() !== txid.toLowerCase() ||
      typeof value.comparison.status !== 'string' ||
      typeof value.comparison.requiresReview !== 'boolean' ||
      typeof value.comparison.detail !== 'string') {
    throw new CliInputError('Previous file must be a track-signed result for the same txid');
  }
  return value.observation;
}

function endpoint(name) {
  const value = process.env[name];
  if (value === undefined) return undefined;
  let url;
  try { url = new URL(value); }
  catch { throw new CliInputError(`${name} must be an HTTPS URL`); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search || url.hash) {
    throw new CliInputError(`${name} must be an HTTPS URL without credentials, query or fragment`);
  }
  return url.href;
}

function redact(value, secret) {
  if (typeof value === 'string') return value.replace(new RegExp(secret, 'gi'), '[redacted signed bytes]');
  if (Array.isArray(value)) return value.map(item => redact(item, secret));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redact(item, secret)]));
  }
  return value;
}

async function main() {
  const paths = process.argv.slice(2);
  if (paths.length < 1 || paths.length > 2 || paths.some(path => !path || path.startsWith('-'))) {
    throw new CliInputError(USAGE);
  }
  const signed = signedEnvelope(readJson(paths[0], 'Signed file'));
  const previous = paths[1] ? previousObservation(readJson(paths[1], 'Previous file'), signed.txid) : null;
  const rpcUrl = endpoint('BLOCH_RPC_URL');
  const explorerUrl = endpoint('BLOCH_EXPLORER_URL');
  const result = await trackSignedTransaction(signed, {
    previousObservation: previous,
    ...(rpcUrl ? { rpcUrl } : {}),
    ...(explorerUrl ? { explorerUrl } : {}),
  });
  process.stdout.write(`${JSON.stringify(redact(result, signed.rawHex), null, 2)}\n`);
}

try { await main(); }
catch (error) {
  // SDK/network exceptions can carry third-party text. Keep stderr independent
  // of saved bytes, mnemonics, file names and response bodies.
  process.stderr.write(`${error instanceof CliInputError ? error.message : 'Transaction tracking failed; check the signed envelope and configured endpoints'}\n`);
  process.exitCode = 1;
}
