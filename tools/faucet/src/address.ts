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

// ── script_hash: what the node actually speaks ──────────────────────────────
//
// The RPC surface does NOT take addresses. `getutxos`/`listunspent`,
// `getbalance` and the `--pay` flag of `submit-tx` all take a 32-byte
// `script_hash` as 64 hex characters (`rpc.rs`, `want_hex32(params, 0,
// "script_hash")`). There is no `validateaddress` method at all. An earlier
// version of this service passed bech32-style addresses to those calls, which
// could never have worked against a real node.
//
// Two things live in this namespace and they are NOT interchangeable:
//
//   * A **Genesis-3 carryover address** owns 20 bytes of hash, and the chain
//     zero-extends it on the right to 32 (`genesis.rs`: `script_hash[0..20] =
//     the snapshot's hash160`, `script_hash[20..32] = 0x00`). That is what
//     `addressScriptHash` reproduces.
//
//   * A **native Genesis-4 key** owns `SHA3-256(hybrid pubkey)` — a full 32
//     bytes, printed by `bloch-pos spendkey`. It has NO address encoding,
//     because 32 bytes do not fit in the 20-byte address body.
//
// So a partner who follows the onboarding guide (`keygen` then `spendkey`) has
// a script_hash that CANNOT be written as a `bloch1t…` address. A faucet that
// only accepted addresses could not fund them. Accept both, and treat the
// 64-hex script_hash as the primary form.

/** Zero-extend a 20-byte address hash to the 32-byte script_hash, G3-style. */
export function addressScriptHash(addr: string): string | null {
  const p = parseAddress(addr);
  if (!p) return null;
  return p.hashHex + "00".repeat(12);
}

export interface Recipient {
  scriptHashHex: string;
  /** How the requester expressed it, for the response and the logs. */
  kind: "script_hash" | "address";
  /** Present only when they gave an address. */
  address?: string;
}

/**
 * Accept either form. Returns null when neither parses.
 *
 * A bare 64-hex script_hash carries NO network marker — it cannot, it is a
 * hash — so this function cannot tell a testnet script_hash from a mainnet
 * one, and does not pretend to. That is safe here for the reason set out in
 * `deploy/testnet/REPLAY-ISOLATION.md`: paying coins TO a hash is harmless
 * whichever chain the requester also uses it on, because the outpoint this
 * creates exists only on this chain. The direction that matters is what the
 * faucet spends FROM, and that is checked at startup (`index.ts` preflight).
 */
export function parseRecipient(input: string): Recipient | null {
  const s = input.trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) {
    return { scriptHashHex: s.toLowerCase(), kind: "script_hash" };
  }
  const sh = addressScriptHash(s);
  if (sh) return { scriptHashHex: sh, kind: "address", address: s };
  return null;
}
