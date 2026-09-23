// SPDX-License-Identifier: AGPL-3.0-or-later
// Run from any directory: node apps/bloch-ops/rpc/validate-catalog.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const here = __dirname;
const root = path.resolve(here, '../../..');
const catalog = JSON.parse(fs.readFileSync(path.join(here, 'catalog.v1.json'), 'utf8'));
const rpcSource = fs.readFileSync(path.join(root, 'crates/bloch-pos-node/src/rpc.rs'), 'utf8');
const engineSource = fs.readFileSync(path.join(root, 'crates/bloch-pos-node/src/engine.rs'), 'utf8');
const route = rpcSource.match(/pub fn route\(method:[\s\S]*?\n}\n/);
assert.ok(route, 'RPC route function must be present');

const routed = new Set([...route[0].matchAll(/"([a-z]+)"\s*(?:\|\s*"([a-z]+)")?\s*=>/g)]
  .flatMap(match => [match[1], match[2]].filter(Boolean)));
const declared = new Set(catalog.methods.flatMap(method => [method.name, ...(method.aliases || [])])
  .concat(catalog.excluded.map(method => method.name)));
assert.deepEqual([...declared].sort(), [...routed].sort(), 'catalog must cover every routed method and alias');
assert.equal(catalog.methods.length, 15, 'read-only method count');
assert.equal(catalog.schema_version, '1.0.0');

for (const method of catalog.methods) {
  assert.ok(Array.isArray(method.params));
  assert.ok(method.result_fields?.length > 0);
  assert.ok(method.limits);
  assert.ok(rpcSource.includes(method.source_symbol) || engineSource.includes(method.source_symbol),
    `${method.name}: response source symbol missing`);
}
assert.deepEqual(catalog.excluded.map(method => method.name).sort(),
  ['getnewaddress', 'gettransaction', 'sendrawtransaction']);
console.log(`Catalog valid: ${catalog.methods.length} read-only methods, ${routed.size} routed names.`);
