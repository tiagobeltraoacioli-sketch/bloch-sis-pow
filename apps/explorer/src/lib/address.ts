// Client-side Bloch address validation + parsing.
//
// A Bloch address is  bloch1q<40-hex pubkey-hash><8-hex checksum>  (mainnet)
// or  bloch1t…  (testnet). Checksum = first 4 bytes of SHA3-256(SHA3-256(hash)).
// So the part after the `bloch1q`/`bloch1t` prefix is 48 hex chars (40 + 8), and
// the whole string is 55 chars. We validate structurally AND by recomputing the
// checksum (round-trip through addressFromHashHex) — no fake "looks like it"
// acceptance.

import { addressFromHashHex } from "./sha3";

export interface ParsedAddress {
  address: string; // normalized (lowercase)
  hashHex: string; // 40-char pubkey-hash hex
  mainnet: boolean;
}

export function parseBlochAddress(input: string): ParsedAddress | null {
  const s = (input || "").trim().toLowerCase();
  const m = /^bloch1(q|t)([0-9a-f]{48})$/.exec(s);
  if (!m) return null;
  const mainnet = m[1] === "q";
  const hashHex = m[2].slice(0, 40);
  const recomputed = addressFromHashHex(hashHex, mainnet);
  if (recomputed !== s) return null; // checksum mismatch
  return { address: s, hashHex, mainnet };
}

export function isValidBlochAddress(input: string): boolean {
  return parseBlochAddress(input) != null;
}

// Cheap structural check (prefix + length) without the SHA3 round-trip — used to
// give live feedback as the user types before the full checksum verdict.
export function looksLikeBlochAddress(input: string): boolean {
  return /^bloch1[qt][0-9a-f]{0,48}$/i.test((input || "").trim());
}
