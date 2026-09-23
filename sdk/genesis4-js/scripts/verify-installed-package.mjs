// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, writeFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

const PACKAGE_NAME = '@blochprotocol/genesis4-sdk';
const [tarballArgument, expectedVersion] = process.argv.slice(2);
if (!tarballArgument || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(expectedVersion ?? '')) {
  console.error('Usage: node scripts/verify-installed-package.mjs <package.tgz> <expected-version>');
  process.exit(2);
}

const tarball = resolve(tarballArgument);
assert.ok(statSync(tarball).isFile(), 'Package tarball must be a file');
const temporary = mkdtempSync(join(tmpdir(), 'bloch-sdk-package-'));
try {
  // An empty cache and offline mode make the package itself the only install source.
  writeFileSync(join(temporary, 'package.json'), '{"private":true,"type":"module"}\n');
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  execFileSync(npm, ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund',
    '--no-package-lock', '--no-save', tarball], {
    cwd: temporary,
    env: { ...process.env, npm_config_cache: join(temporary, 'npm-cache'), npm_config_offline: 'true' },
    stdio: 'pipe',
    timeout: 60_000,
  });
  const installed = join(temporary, 'node_modules', '@blochprotocol', 'genesis4-sdk');
  const metadata = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
  assert.equal(metadata.name, PACKAGE_NAME, 'Unexpected installed package name');
  assert.equal(metadata.version, expectedVersion, 'Installed package version differs from expected version');
  for (const file of ['index.mjs', 'core.mjs', 'g4.cjs', 'bloch_wallet_wasm.wasm', 'LICENSE', 'README.md']) {
    assert.ok(statSync(join(installed, file)).size > 0, `Missing or empty package file: ${file}`);
  }

  const smoke = `
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createLocalWallet, deriveLocalAddress, createSignedTransaction, getDepositTransaction } from '${PACKAGE_NAME}';

const wallet = createLocalWallet();
assert.equal(wallet.network, 'mainnet');
assert.match(wallet.address, /^bloch1q[0-9a-f]{48}$/);
assert.deepEqual(deriveLocalAddress({ mnemonic: wallet.mnemonic }), {
  address: wallet.address, network: 'mainnet',
});

let requestCount = 0;
const fetchImpl = async (_url, options) => {
  const request = JSON.parse(options.body);
  requestCount++;
  let result;
  if (request.method === 'getutxos') {
    result = { utxos: [{ txid: 'ab'.repeat(32), vout: 0, value_sat: '1000000' }],
      total: 1001, returned: 1, truncated: true };
  } else if (request.method === 'getchaininfo') {
    result = { height: 100, slot: 120, epoch: 4,
      next_base_fee_millisat_per_gas: '10', behind_by_slots: 0 };
  } else {
    throw new Error('Unexpected RPC method');
  }
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
    headers: { 'content-type': 'application/json' },
  });
};

const signed = await createSignedTransaction({ addressFrom: wallet.address,
  mnemonic: wallet.mnemonic, addressTo: wallet.address, amount: '0.001', fetchImpl });
assert.equal(requestCount, 2);
assert.equal(signed.amountSat, '100000');
assert.match(signed.txid, /^[0-9a-f]{64}$/);
assert.match(signed.rawHex, /^[0-9a-f]+$/);
assert.ok(signed.rawHex.length > 1000);
assert.equal(createHash('sha3-256').update(Buffer.from(signed.rawHex, 'hex')).digest('hex'), signed.rawHash);
const depositTxid = 'cd'.repeat(32);
const depositReceipt = {
  txid: depositTxid, block_id: 'ef'.repeat(32), height: 80, slot: 100, index: 0,
  kind: 'transfer_v2', size_bytes: 8000, fee_sat: '20', stake_sat: '0',
  inputs: [{ txid: 'ab'.repeat(32), vout: 0, value_sat: '120', script_hash: '01'.repeat(32) }],
  outputs: [{ txid: depositTxid, vout: 0, value_sat: '100',
    script_hash: wallet.address.slice(7, 47) + '0'.repeat(24) }],
  confirmations: 22, status: 'finalized', finalized: true, finalized_height: 90,
  observed_head_height: 101, observed_head_slot: 121, corroboration: 'corroborated',
  source: 'offline smoke', verification: 'fixture',
};
const deposit = await getDepositTransaction({ txid: depositTxid,
  addressTo: wallet.address, amount: '0.00000100',
  fetchImpl: async () => new Response(JSON.stringify(depositReceipt)) });
assert.equal(deposit.match.exactTotal, true);
assert.equal(deposit.match.matchingOutputs[0].vout, 0);
console.log('Installed package import, local wallet, mocked signing and deposit query: OK');
`;
  writeFileSync(join(temporary, 'smoke.mjs'), smoke);
  execFileSync(process.execPath, [join(temporary, 'smoke.mjs')], {
    cwd: temporary, stdio: 'inherit', timeout: 60_000,
  });
  console.log(`${PACKAGE_NAME}@${expectedVersion} offline package verification: OK`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
