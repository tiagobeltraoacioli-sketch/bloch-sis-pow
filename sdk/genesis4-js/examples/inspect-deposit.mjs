import { getTransaction, inspectDepositOutputs } from '../index.mjs';

const [txid, addressTo, amount] = process.argv.slice(2);
if (!txid || !addressTo || !amount) {
  throw new Error('Usage: node examples/inspect-deposit.mjs <txid> <addressTo> <decimal-BLOCH-amount>');
}
const transaction = await getTransaction(txid);
console.log(JSON.stringify(inspectDepositOutputs({ transaction, addressTo, amount }), null, 2));
