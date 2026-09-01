// SPDX-License-Identifier: AGPL-3.0-or-later
//
// What a person can paste, turned into the 32-byte script hash the node wants.
//
// The rule is the same one `src/lib/g4.ts` documents for the browser, restated
// here because the public API accepts the same three forms and must refuse the
// same way:
//
//   bloch1q…   a full address. The checksum is VERIFIED, not stripped. A
//              mistyped address hashes to a valid-looking script hash that
//              holds nothing, so accepting it would answer "0 BLOCH" to a
//              question nobody asked.
//   40 hex     the bare hash-160 from inside such an address.
//   64 hex     a script hash already.
//
// The 20-byte forms are left-aligned and zero-padded to 32. That padding is
// the rule consensus itself applies when deciding whether a key owns an
// output, so it is the identity and not a convenience.

import { addressFromHashHex } from './sha3.js';

/** `{ scriptHash, form, address? }` or `{ error }`. Never guesses. */
export function toScriptHash(input) {
  const raw = String(input || '').trim().toLowerCase();
  if (!raw) return { error: 'empty' };

  if (raw.startsWith('bloch1')) {
    const m = /^bloch1(q|t)([0-9a-f]{48})$/.exec(raw);
    if (!m) {
      return {
        error: 'malformed_address',
        detail:
          'a Bloch address is bloch1q or bloch1t followed by exactly 48 hex ' +
          'characters (40 of pubkey hash, 8 of checksum)',
      };
    }
    const hashHex = m[2].slice(0, 40);
    const recomputed = addressFromHashHex(hashHex, m[1] === 'q');
    if (recomputed !== raw) {
      return {
        error: 'bad_checksum',
        detail:
          'the address checksum does not match. This is refused rather than ' +
          'stripped: the script hash of a mistyped address is a valid script ' +
          'hash that holds nothing, so accepting it would show you an empty ' +
          'balance for an address that was never yours.',
      };
    }
    return { scriptHash: hashHex + '0'.repeat(24), form: 'address', address: raw };
  }

  const s = raw.replace(/^0x/, '');
  if (!/^[0-9a-f]+$/.test(s)) return { error: 'not_hex' };
  if (s.length === 64) return { scriptHash: s, form: 'script_hash' };
  if (s.length === 40) return { scriptHash: s + '0'.repeat(24), form: 'hash160' };
  return {
    error: 'wrong_length',
    detail: `expected a bloch1 address, 40 hex characters or 64; got ${s.length}`,
  };
}

/** True when the script hash is a zero-padded hash-160 rather than a raw hash. */
export function isPaddedH160(scriptHash) {
  return scriptHash.length === 64 && scriptHash.slice(40) === '0'.repeat(24);
}

/** The display address for a padded hash-160, or null when there is none. */
export function displayAddress(scriptHash) {
  return isPaddedH160(scriptHash) ? addressFromHashHex(scriptHash.slice(0, 40), true) : null;
}
