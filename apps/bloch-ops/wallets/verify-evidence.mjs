#!/usr/bin/env node
import { lstat, readFile } from 'node:fs/promises';
import { verifyReconciliationEvidence } from './reconciliation-evidence.mjs';

const MAX_BYTES = 6 * 1024 * 1024;

async function main() {
  if (process.argv.length !== 3) {
    throw new Error('usage');
  }
  const path = process.argv[2];
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > MAX_BYTES) {
    throw new Error('invalid file');
  }
  const bytes = await readFile(path);
  if (bytes.length > MAX_BYTES) throw new Error('oversized file');
  const evidence = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  process.stdout.write(`${JSON.stringify(verifyReconciliationEvidence(evidence))}\n`);
}

main().catch(() => {
  process.stderr.write('Evidence verification failed. Supply one regular v2 JSON evidence file (up to 6 MiB).\n');
  process.exitCode = 1;
});
