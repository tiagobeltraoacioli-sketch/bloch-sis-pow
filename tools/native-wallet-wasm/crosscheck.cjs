// Offline cross-runtime test driver. All seeds are public fixture material.
// Usage: node crosscheck.cjs artifact.wasm vectors.json wallet/browser/native-core.js signed.json
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { webcrypto, createHash } = require('node:crypto');
const [artifactPath, vectorPath, loaderPath, outputPath] = process.argv.slice(2);
if (!outputPath) throw new Error('Expected artifact, fixture, loader and output paths');
if (!global.crypto) Object.defineProperty(global, 'crypto', { value: webcrypto });
vm.runInThisContext(fs.readFileSync(loaderPath, 'utf8'), { filename: loaderPath });
(async () => {
  const artifact = new Uint8Array(fs.readFileSync(artifactPath));
  const pin = createHash('sha256').update(artifact).digest('hex');
  const fixture = JSON.parse(fs.readFileSync(vectorPath));
  assert.equal(fixture.schema, 'postern.native-wasm-vectors.v1');
  const core = await PosternNativeCore.instantiate(artifact, pin);
  const vectors = [];
  try {
    for (const f of fixture.vectors) {
      assert.equal(f.publicTestSeedHex, '07'.repeat(32));
      core.call('open', { seedHex: f.publicTestSeedHex, domainHex: f.domainHex });
      const args = { transactionHex: f.transactionHex, context: f.context, height: f.height };
      const review = core.call('review', args);
      assert.equal(review.packetHex, f.transactionHex);
      assert.equal(review.feeSat, f.feeSat);
      const confirm = { ...args, reviewId: review.id, confirmed: true };
      const signed = core.call('sign', confirm);
      assert.match(signed.txid, /^[0-9a-f]{64}$/);
      assert.throws(() => core.call('sign', confirm));
      vectors.push({ operation: f.operation, signedTransactionHex: signed.transactionHex, txid: signed.txid });
    }
  } finally { core.dispose(); }
  fs.writeFileSync(outputPath, JSON.stringify({ artifactSha256: pin, vectors }, null, 2));
  console.log(JSON.stringify({ artifactSha256: pin, operations: vectors.map(v => v.operation) }));
})().catch(error => { console.error(error); process.exitCode = 1; });
