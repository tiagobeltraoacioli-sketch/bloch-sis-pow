// SPDX-License-Identifier: AGPL-3.0-or-later
// Offline compatibility check for two exact, locally supplied SDK artifacts.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const [previousArgument, candidateArgument] = process.argv.slice(2);
if (!previousArgument || !candidateArgument || process.argv.length !== 4) {
  console.error('Usage: node scripts/verify-sdk-upgrade.mjs <0.1.13.tgz> <0.1.14.tgz>');
  process.exit(2);
}
const temporary = mkdtempSync(join(tmpdir(), 'bloch-sdk-upgrade-'));
try {
  const packagePaths = [];
  for (const [version, argument] of [['0.1.13', previousArgument], ['0.1.14', candidateArgument]]) {
    const project = join(temporary, version);
    mkdirSync(project);
    writeFileSync(join(project, 'package.json'), '{"private":true,"type":"module"}\n');
    execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', [
      'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund',
      '--no-package-lock', '--no-save', resolve(argument),
    ], { cwd: project, stdio: 'pipe', timeout: 60_000,
      env: { ...process.env, npm_config_offline: 'true', npm_config_cache: join(project, 'empty-cache') } });
    const installed = join(project, 'node_modules', '@blochprotocol', 'genesis4-sdk');
    const metadata = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
    assert.equal(metadata.name, '@blochprotocol/genesis4-sdk');
    assert.equal(metadata.version, version);
    packagePaths.push(installed);
  }
  assert.ok(readFileSync(join(packagePaths[0], 'bloch_wallet_wasm.wasm'))
    .equals(readFileSync(join(packagePaths[1], 'bloch_wallet_wasm.wasm'))), 'Signing core changed');
  const [previous, candidate] = await Promise.all(packagePaths.map(path => import(pathToFileURL(join(path, 'index.mjs')).href)));
  assert.deepEqual(Object.keys(candidate).sort(), Object.keys(previous).sort(), 'Public exports changed');
  const wallet = previous.createLocalWallet();
  const response = body => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  let transmissions = 0;
  for (const epoch of [4, 800]) {
    const signed = await previous.createSignedTransaction({ addressFrom: wallet.address,
      mnemonic: wallet.mnemonic, addressTo: wallet.address, amount: '0.002',
      fetchImpl: async (_url, options) => {
        const request = JSON.parse(options.body);
        const result = request.method === 'getutxos' ? {
          utxos: [1, 2, 3].map(i => ({ txid: i.toString(16).padStart(64, '0'), vout: 0, value_sat: '100000' })),
          total: 3, returned: 3, truncated: false,
        } : request.method === 'getchaininfo' ? {
          height: 100, slot: 120, epoch, next_base_fee_millisat_per_gas: '10', behind_by_slots: 0,
        } : null;
        assert.notEqual(result, null, 'Unexpected fixture RPC method');
        return response({ jsonrpc: '2.0', id: request.id, result });
      } });
    // Simulate persistence without storing phrases, then upgrade the consumer.
    const restored = JSON.parse(JSON.stringify(signed));
    assert.equal(Object.hasOwn(restored, 'mnemonic'), false);
    for (const status of ['accepted', 'duplicate']) {
      const admitted = await candidate.broadcastSignedTransaction(restored, { fetchImpl: async (_url, options) => {
        transmissions++;
        const request = JSON.parse(options.body);
        assert.equal(request.method, 'sendrawtransaction');
        assert.equal(request.params.length, 1);
        assert.ok(request.params[0] === signed.rawHex, 'Retry changed signed bytes');
        return response({ jsonrpc: '2.0', id: request.id, result: {
          accepted: true, status, bytes: signed.rawHex.length / 2, tx_hash: signed.rawHash,
        } });
      } });
      assert.equal(admitted.txid, signed.txid);
      assert.equal(admitted.admission.status, status);
    }
    const observed = await candidate.trackSignedTransaction(restored, { fetchImpl: async (_url, options) => {
      if (!options?.body) return new Response('', { status: 404 });
      const request = JSON.parse(options.body);
      assert.equal(request.method, 'gettxstatus');
      assert.deepEqual(request.params, [signed.txid]);
      return response({ jsonrpc: '2.0', id: request.id, result: { status: 'pending' } });
    } });
    assert.equal(observed.txid, signed.txid);
    assert.equal(observed.observation.kind, 'unresolved');
  }
  assert.equal(transmissions, 4, 'Only the four explicit in-memory requests are allowed');
  console.log('SDK 0.1.13 -> 0.1.14: exports/core unchanged; persisted V1/V2 envelopes, explicit byte-identical retries and read-only tracking passed');
  console.log('Offline synthetic compatibility only; no network, real funds, node admission or P2B adoption evidence');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
