import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { Connection, Keypair, PublicKey, SystemProgram, Transaction,
  TransactionInstruction, sendAndConfirmTransaction } from '@solana/web3.js';

const [programId, endpoint = 'http://127.0.0.1:8899', keyfile = '.bloch-dev/developer.json'] = process.argv.slice(2);
if (!programId) throw new Error('Usage: node client.mjs PROGRAM_ID [LOCAL_RPC] [KEYFILE]');
const url = new URL(endpoint);
if (url.protocol !== 'http:' || !['localhost', '127.0.0.1'].includes(url.hostname)) {
  throw new Error('This example only sends transactions to a local development validator.');
}
const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(keyfile, 'utf8'))));
const counter = Keypair.generate();
const program = new PublicKey(programId);
const connection = new Connection(endpoint, 'confirmed');
const instruction = (code, authority, initializing = false) => new TransactionInstruction({
  programId: program,
  keys: [{pubkey: counter.publicKey, isWritable: true, isSigner: initializing},
    {pubkey: authority, isWritable: false, isSigner: true}],
  data: Buffer.from([code])
});
await sendAndConfirmTransaction(connection, new Transaction().add(
  SystemProgram.createAccount({fromPubkey: payer.publicKey, newAccountPubkey: counter.publicKey,
    lamports: await connection.getMinimumBalanceForRentExemption(40), space: 40, programId: program}),
  instruction(0, payer.publicKey, true)), [payer, counter]);
await sendAndConfirmTransaction(connection, new Transaction().add(instruction(1, payer.publicKey)), [payer]);
const account = await connection.getAccountInfo(counter.publicKey);
assert.equal(account.data.readBigUInt64LE(32), 1n);
const stranger = Keypair.generate();
const bad = new Transaction().add(instruction(1, stranger.publicKey));
bad.feePayer = payer.publicKey;
await assert.rejects(sendAndConfirmTransaction(connection, bad, [payer, stranger]),
  error => /invalid account data/i.test(error.message));
const after = await connection.getAccountInfo(counter.publicKey);
assert.equal(after.data.readBigUInt64LE(32), 1n);
console.log(`Counter ${counter.publicKey}: value 1; unauthorized increment rejected.`);
