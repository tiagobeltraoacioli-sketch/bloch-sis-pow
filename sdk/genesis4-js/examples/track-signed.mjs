// Read-only status check for a previously stored SDK signed transaction.
// Usage: node examples/track-signed.mjs signed.json [previous-observation.json]
import { lstatSync, readFileSync } from 'node:fs';
import { trackSignedTransaction } from '../index.mjs';

function readJson(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024) {
    throw new Error('Input must be a regular JSON file of at most 2 MiB');
  }
  return JSON.parse(readFileSync(path, 'utf8'));
}

const [signedPath, previousPath] = process.argv.slice(2);
if (!signedPath || process.argv.length > 4) {
  throw new Error('Usage: node examples/track-signed.mjs signed.json [previous-observation.json]');
}
const signed = readJson(signedPath);
const previousObservation = previousPath ? readJson(previousPath).observation : null;
const result = await trackSignedTransaction(signed, {
  previousObservation,
  ...(process.env.BLOCH_RPC_URL ? { rpcUrl: process.env.BLOCH_RPC_URL } : {}),
  ...(process.env.BLOCH_EXPLORER_URL ? { explorerUrl: process.env.BLOCH_EXPLORER_URL } : {}),
});
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
