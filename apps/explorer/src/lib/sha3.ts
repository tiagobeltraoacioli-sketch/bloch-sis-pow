// SPDX-License-Identifier: AGPL-3.0-or-later
// Minimal FIPS-202 SHA3-256 (Keccak-f[1600], 0x06 domain padding), BigInt lanes.
// Used only to derive display addresses from 20-byte pubkey hashes — low volume,
// so clarity beats micro-optimisation. Verified against the founder address:
//   e986db51…af4ff  ->  bloch1qe986db51…af4ff84242073 (checksum 84242073).

const RC: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const R = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const MASK = (1n << 64n) - 1n;

function rotl(x: bigint, n: number): bigint {
  const nn = BigInt(n);
  return ((x << nn) | (x >> (64n - nn))) & MASK;
}

function keccakF(s: bigint[]) {
  for (let round = 0; round < 24; round++) {
    const C = new Array<bigint>(5);
    for (let x = 0; x < 5; x++) C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    const D = new Array<bigint>(5);
    for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x + 5 * y] ^= D[x];

    const B = new Array<bigint>(25);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], R[x + 5 * y]);

    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++)
        s[x + 5 * y] = B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y]);

    s[0] ^= RC[round];
  }
}

export function sha3_256(input: Uint8Array): Uint8Array {
  const rate = 136; // 1088 bits
  const s = new Array<bigint>(25).fill(0n);
  // absorb
  const padded = new Uint8Array(Math.ceil((input.length + 1) / rate) * rate);
  padded.set(input);
  padded[input.length] = 0x06;
  padded[padded.length - 1] |= 0x80;

  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 0; b < 8; b++) lane |= BigInt(padded[off + i * 8 + b]) << BigInt(8 * b);
      s[i] ^= lane;
    }
    keccakF(s);
  }
  // squeeze 32 bytes
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = s[i];
    for (let b = 0; b < 8; b++) {
      out[i * 8 + b] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

// 20-byte pubkey-hash hex -> bloch1q… address (mainnet). Checksum = first 4
// bytes of SHA3-256(SHA3-256(payload)).
export function addressFromHashHex(hashHex: string, mainnet = true): string | null {
  if (!/^[0-9a-fA-F]{40}$/.test(hashHex)) return null;
  const payload = hexToBytes(hashHex.toLowerCase());
  const checksum = sha3_256(sha3_256(payload)).slice(0, 4);
  const prefix = mainnet ? "bloch1q" : "bloch1t";
  return prefix + hashHex.toLowerCase() + bytesToHex(checksum);
}
