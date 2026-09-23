import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolveDepositTarget } from './address-target.mjs';

const hash160 = 'e986db5149cff7499b282a048272a09aff0af4ff';
const address = `bloch1q${hash160}84242073`;
const scriptHash = `${hash160}${'0'.repeat(24)}`;

test('browser address verifier is pinned to the SDK address implementation', () => {
  assert.deepEqual(readFileSync(new URL('./g4.js', import.meta.url)),
    readFileSync(new URL('../../../sdk/genesis4-js/g4.cjs', import.meta.url)));
});

test('derives the exact script hash only from a verified mainnet address', () => {
  assert.deepEqual(resolveDepositTarget(address), {
    scriptHash, kind: 'checksummed_address', address,
  });
  assert.deepEqual(resolveDepositTarget(scriptHash.toUpperCase()), {
    scriptHash, kind: 'raw_script_hash', address: null,
  });
  assert.throws(() => resolveDepositTarget(`${address.slice(0, -1)}0`), /checksum failed/);
  assert.throws(() => resolveDepositTarget(`bloch1t${address.slice(7)}`), /mainnet/);
  assert.throws(() => resolveDepositTarget(hash160), /64-character/);
});
