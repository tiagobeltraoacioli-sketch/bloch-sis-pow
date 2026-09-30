// SPDX-License-Identifier: AGPL-3.0-or-later
import { createLocalWallet, createSignedTransaction } from '../index.mjs';
import G4 from '../g4.cjs';

// Disposable test identity, synthetic outpoint, injected reads only. Never
// print or persist the generated phrase or connect this fixture to a node.
const wallet = createLocalWallet();
export function syntheticTransfer({ epoch = 4, amount = '0.001', inputs = 1 } = {}) {
  return createSignedTransaction({
    addressFrom: wallet.address, mnemonic: wallet.mnemonic,
    addressTo: wallet.address, amount,
    fetchImpl: async (_url, options) => {
      const request = JSON.parse(options.body);
      let result;
      if (request.method === 'getutxos') {
        result = { script_hash: G4.inspectAddress(wallet.address).scriptHash,
          utxos: Array.from({ length: inputs }, (_, i) => ({
            txid: (i + 1).toString(16).padStart(64, '0'), vout: 0,
            value_sat: inputs === 1 ? '1000000' : '100000',
          })), total: inputs, returned: inputs, truncated: false };
      } else if (request.method === 'getchaininfo') {
        result = { height: 100, slot: 120, epoch,
          next_base_fee_millisat_per_gas: '10', behind_by_slots: 0 };
      } else throw new Error('Unexpected synthetic fixture RPC method');
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }),
        { headers: { 'content-type': 'application/json' } });
    },
  });
}
