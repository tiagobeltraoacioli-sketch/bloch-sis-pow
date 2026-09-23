import { getTransaction } from '../index.mjs';

const txid = process.argv[2];
if (!txid) throw new Error('Usage: node examples/lookup.mjs <txid>');
console.log(JSON.stringify(await getTransaction(txid), null, 2));
