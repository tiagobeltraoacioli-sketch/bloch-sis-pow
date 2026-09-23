import { getTransactionObservation } from '../index.mjs';

const txid = process.argv[2];
if (!txid) throw new Error('Usage: node examples/observe.mjs <txid>');
console.log(JSON.stringify(await getTransactionObservation(txid), null, 2));
