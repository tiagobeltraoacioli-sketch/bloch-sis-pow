import { readFile } from 'node:fs/promises';
import { getTransactionObservation, compareTransactionObservations } from '../index.mjs';

const [txid, previousPath] = process.argv.slice(2);
if (!txid) throw new Error('Usage: node examples/compare-observations.mjs <txid> [previous.json]');
const saved = previousPath ? JSON.parse(await readFile(previousPath, 'utf8')) : null;
const previous = saved?.observation ?? saved;
const observation = await getTransactionObservation(txid);
const comparison = compareTransactionObservations(previous, observation);
console.log(JSON.stringify({ observedAt: new Date().toISOString(), comparison, observation }, null, 2));
