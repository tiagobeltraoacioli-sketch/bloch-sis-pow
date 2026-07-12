// SPDX-License-Identifier: MIT OR Apache-2.0
// Bloch address helpers (testnet-aware).
//
// An address is: <prefix> + hex(20-byte pubkey hash) + hex(4-byte checksum),
// where checksum = SHA3-256(SHA3-256(hash20))[..4]  (double SHA3-256, first 4
// bytes). This mirrors the node's validateaddress logic in src/rpc/mod.rs.
//
//   mainnet prefix: "bloch1q"   testnet prefix: "bloch1t"
//
// The on-chain `script_pubkey` is exactly the 20-byte hash (hex), so these
// helpers convert between an address and a script_pubkey.

import { createHash } from "node:crypto";

export const MAINNET_PREFIX = "bloch1q";
export const TESTNET_PREFIX = "bloch1t";

function sha3_256(buf: Buffer): Buffer {
  return createHash("sha3-256").update(buf).digest();
}

function checksum4(hash20: Buffer): Buffer {
  return sha3_256(sha3_256(hash20)).subarray(0, 4);
}

export type Network = "mainnet" | "testnet";

export interface ParsedAddress {
  network: Network;
  hashHex: string; // 40 hex chars (the 20-byte pubkey hash == script_pubkey)
}

/** Encode a 20-byte hash (hex or Buffer) into a checksummed address. */
export function encodeAddress(hash20: Buffer | string, network: Network): string {
  const h = typeof hash20 === "string" ? Buffer.from(hash20, "hex") : hash20;
  if (h.length !== 20) throw new Error(`hash must be 20 bytes, got ${h.length}`);
  const prefix = network === "mainnet" ? MAINNET_PREFIX : TESTNET_PREFIX;
  return prefix + h.toString("hex") + checksum4(h).toString("hex");
}

/**
 * Parse + checksum-validate an address. Returns null when malformed. This is a
 * pure local check; the node's `validateaddress` RPC is the ultimate authority
 * and should be preferred when a node is reachable.
 */
export function parseAddress(addr: string): ParsedAddress | null {
  let network: Network;
  let body: string;
  if (addr.startsWith(TESTNET_PREFIX)) {
    network = "testnet";
    body = addr.slice(TESTNET_PREFIX.length);
  } else if (addr.startsWith(MAINNET_PREFIX)) {
    network = "mainnet";
    body = addr.slice(MAINNET_PREFIX.length);
  } else {
    return null;
  }
  // 40 hex (hash) + 8 hex (checksum) = 48 hex chars.
  if (body.length !== 48 || !/^[0-9a-fA-F]+$/.test(body)) return null;
  const hashHex = body.slice(0, 40).toLowerCase();
  const csHex = body.slice(40).toLowerCase();
  const expected = checksum4(Buffer.from(hashHex, "hex")).toString("hex");
  if (csHex !== expected) return null;
  return { network, hashHex };
}

export function isTestnetAddress(addr: string): boolean {
  const p = parseAddress(addr);
  return p !== null && p.network === "testnet";
}
