import { createSignedTransaction, broadcastSignedTransaction } from '../index.mjs';

const [addressFrom, addressTo, amount] = process.argv.slice(2);
const mnemonic = process.env.BLOCH_MNEMONIC;
const rpcUrl = process.env.BLOCH_RPC_URL;
if (!addressFrom || !addressTo || !amount || !mnemonic || !rpcUrl) {
  throw new Error('Set BLOCH_MNEMONIC and BLOCH_RPC_URL, then pass addressFrom addressTo amount');
}
const signed = await createSignedTransaction({ addressFrom, mnemonic, addressTo, amount, rpcUrl });
console.log(JSON.stringify({ txid: signed.txid, amountSat: signed.amountSat, feeSat: signed.feeSat }));
// Reuse signed.rawHex on a transport retry. Never rebuild a second transaction
// until the first txid has been checked for inclusion or expiry.
if (process.env.BLOCH_BROADCAST === '1') {
  const result = await broadcastSignedTransaction(signed, { rpcUrl });
  console.log(JSON.stringify({ txid: signed.txid, broadcast: result }));
} else {
  console.log(JSON.stringify({ txid: signed.txid, rawHex: signed.rawHex }));
}
