// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Address helpers for Bloch's bech32-style address format.
//
// NOTE on terminology: the roadmap calls these "bech32-style", but the node's
// actual encoding (crates/bloch-crypto/src/address.rs and the `validateaddress`
// RPC in src/rpc/mod.rs) is NOT bech32 GF(32) — it is:
//
//     <prefix> || hex(20-byte pubkey hash) || hex(4-byte checksum)
//
//   - prefix:   "bloch1q" (mainnet) or "bloch1t" (testnet)
//   - hash:     20 bytes = SHA3-256(pubkey)[..20]      -> 40 lowercase hex
//   - checksum: SHA3-256(SHA3-256(hash))[..4]          ->  8 lowercase hex
//
// Total string length is 55 chars (7 + 40 + 8). This helper reproduces the
// node's checksum check byte-for-byte using Node's built-in SHA3-256 (FIPS-202,
// via OpenSSL) so validation matches the node with no external dependency.

import { createHash } from "node:crypto";
import type { Address, Network } from "./types.js";

export const MAINNET_PREFIX = "bloch1q";
export const TESTNET_PREFIX = "bloch1t";

const HEX_HASH_LEN = 40; // 20 bytes
const HEX_CHECKSUM_LEN = 8; // 4 bytes
const HEX_BODY_LEN = HEX_HASH_LEN + HEX_CHECKSUM_LEN; // 48

function sha3_256(data: Uint8Array): Buffer {
  return createHash("sha3-256").update(data).digest();
}

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Compute the 4-byte checksum for a 20-byte pubkey hash, as lowercase hex. */
export function checksumHex(hash20: Uint8Array): string {
  if (hash20.length !== 20) throw new RangeError("hash must be 20 bytes");
  const outer = sha3_256(sha3_256(hash20));
  return bytesToHex(outer.subarray(0, 4));
}

export interface ParsedAddress {
  valid: boolean;
  network: Network | "unknown";
  /** 40-hex pubkey hash, present when the format parsed (even if checksum bad). */
  hashHex?: string;
  /** True only when the checksum bytes verified. */
  checksum: boolean;
  reason?: string;
}

/**
 * Parse and fully validate a Bloch address (format + checksum). Mirrors the
 * node's `validateaddress` logic exactly.
 */
export function parseAddress(address: string): ParsedAddress {
  const isMain = address.startsWith(MAINNET_PREFIX);
  const isTest = address.startsWith(TESTNET_PREFIX);
  const network: Network | "unknown" = isMain
    ? "mainnet"
    : isTest
      ? "testnet"
      : "unknown";

  if (!isMain && !isTest) {
    return { valid: false, network, checksum: false, reason: "invalid prefix (expected bloch1q or bloch1t)" };
  }

  const prefix = isMain ? MAINNET_PREFIX : TESTNET_PREFIX;
  const body = address.slice(prefix.length);

  if (body.length !== HEX_BODY_LEN) {
    return { valid: false, network, checksum: false, reason: `wrong length (expected ${HEX_BODY_LEN} hex chars after prefix)` };
  }

  const bytes = hexToBytes(body);
  if (!bytes) {
    return { valid: false, network, checksum: false, reason: "body is not lowercase hex" };
  }

  const hash20 = bytes.subarray(0, 20);
  const wantChecksum = bytesToHex(bytes.subarray(20, 24));
  const gotChecksum = checksumHex(hash20);
  const checksumOk = wantChecksum === gotChecksum;

  return {
    valid: checksumOk,
    network,
    hashHex: bytesToHex(hash20),
    checksum: checksumOk,
    ...(checksumOk ? {} : { reason: "checksum mismatch" }),
  };
}

/** True if `address` is a well-formed, checksum-valid Bloch address. */
export function isValidAddress(address: string): boolean {
  return parseAddress(address).valid;
}

/** Network of a valid address, or `undefined` if invalid. */
export function addressNetwork(address: string): Network | undefined {
  const p = parseAddress(address);
  return p.valid && p.network !== "unknown" ? p.network : undefined;
}

/**
 * Extract the 20-byte pubkey hash (as hex) from a valid address.
 * Throws if the address is invalid.
 */
export function addressToHashHex(address: string): string {
  const p = parseAddress(address);
  if (!p.valid || !p.hashHex) {
    throw new RangeError(`invalid Bloch address: ${p.reason ?? "unknown"}`);
  }
  return p.hashHex;
}

/**
 * The P2PKH `script_pubkey` for an address. On Bloch there is no script
 * system — the "script" is literally the 20-byte hash (see roadmap §1.3), so
 * this returns the 40-hex pubkey hash. Throws if the address is invalid.
 */
export function addressToScriptPubkey(address: Address): string {
  return addressToHashHex(address);
}

/**
 * Build an address string from a 20-byte pubkey hash (hex or bytes) and
 * network, appending the correct SHA3-256 double-hash checksum. Useful for
 * tests and for turning a WalletCore-derived hash into a display address.
 */
export function encodeAddress(
  hash20: Uint8Array | string,
  network: Network,
): Address {
  const bytes = typeof hash20 === "string" ? hexToBytes(hash20) : hash20;
  if (!bytes || bytes.length !== 20) {
    throw new RangeError("hash must be 20 bytes (40 hex chars)");
  }
  const prefix = network === "mainnet" ? MAINNET_PREFIX : TESTNET_PREFIX;
  return `${prefix}${bytesToHex(bytes)}${checksumHex(bytes)}`;
}

export { bytesToHex as _bytesToHex, hexToBytes as _hexToBytes };
