import { getDepositTransaction } from '../index.mjs';

const [txid, addressTo, amount] = process.argv.slice(2);
if (!txid || !addressTo || !amount) {
  throw new Error('Usage: node examples/query-deposit.mjs <txid> <mainnet-address> <decimal-BLOCH-amount>');
}
const result = await getDepositTransaction({ txid, addressTo, amount });
console.log(JSON.stringify(result, null, 2));
