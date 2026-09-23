import './g4.js';

const HASH = /^[0-9a-f]{64}$/i;

/** Resolve only a checksummed Genesis-4 mainnet address or an explicit raw script hash. */
export function resolveDepositTarget(value) {
  if (typeof value !== 'string') throw new Error('Enter a mainnet address or a 64-character public script hash.');
  const candidate = value.trim();
  const inspect = globalThis.PosternG4?.inspectAddress;
  if (typeof inspect !== 'function') throw new Error('Address verification is unavailable in this browser.');
  const address = inspect(candidate);
  if (address.verified === true && address.network === 'mainnet' && HASH.test(address.scriptHash)) {
    return { scriptHash: address.scriptHash.toLowerCase(), kind: 'checksummed_address',
      address: candidate.toLowerCase() };
  }
  if (HASH.test(candidate) && address.status === 'no_checksum') {
    return { scriptHash: candidate.toLowerCase(), kind: 'raw_script_hash', address: null };
  }
  if (address.status === 'checksum_bad') throw new Error('The address checksum failed. Re-copy the mainnet address.');
  if (address.network === 'testnet') throw new Error('A Genesis-4 mainnet address is required.');
  throw new Error('Enter a checksummed mainnet address or a 64-character public script hash.');
}
