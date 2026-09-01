// SPDX-License-Identifier: MIT OR Apache-2.0
// Bloch Genesis-4 recipient parsing for the testnet faucet.
//
// Genesis-4 identifies a payee by a 32-byte `script_hash`, never by an address.
// This file therefore parses addresses ONLY so it can refuse them with a useful
// message; it contains no address-to-script_hash conversion. See the long
// comment further down for why adding one back would be a bug, not a feature.
//
// An address, where one still appears (Genesis-3 material, operator typos), is:
//   <prefix> + hex(20-byte pubkey hash) + hex(4-byte checksum)
// with checksum = SHA3-256(SHA3-256(hash20))[..4].
//   mainnet prefix: "bloch1q"   testnet prefix: "bloch1t"

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

// ── script_hash: THE one derivation, and why this file no longer has one ────
//
// A Genesis-4 output is locked by a 32-byte `script_hash`. There is exactly
// ONE way to derive one for a key you control:
//
//     script_hash = SHA3-256(hybrid public key)        // full 32 bytes
//
// That is what `bloch-pos spendkey` prints, what a genesis allocation commits
// to, and what every output a Genesis-4 transaction creates uses
// (`transition.rs`, `owns`: "every output a Genesis-4 transaction creates uses
// [the native form]"). It has NO address encoding — 32 bytes do not fit in the
// 20-byte body of a `bloch1q…`/`bloch1t…` address.
//
// A SECOND 32-byte shape exists on mainnet and is NOT a second derivation:
// the Genesis-3 carryover writes a snapshot's 20-byte hash160 into
// `script_hash[0..20]` and zeroes the rest (`genesis.rs`). Those outputs were
// minted by the carryover ingest, once, from a file. Nothing derives them from
// a key, and nothing may: `SHA3-256(pubkey)[0..20] ‖ 0x00*12` has the carried
// shape but is a DIFFERENT eUTXO-set key from `SHA3-256(pubkey)`, so coins paid
// to one are invisible to `getbalance` on the other. Consensus tolerates the
// truncated form (`owns` matches on the 20-byte prefix when the tail is zero),
// which is why the mistake is silent rather than loud — and it costs the
// recipient 160 bits of preimage resistance instead of 256.
//
// This faucet serves a testnet built with NO carryover. Therefore the carried
// shape can never address a fundable output here, and this file deliberately
// contains no address→script_hash conversion at all. An address is refused
// with an explanation, not silently converted. The address parser below
// survives only so that refusal can be specific.

/** A recipient the faucet will pay. Always the native 32-byte form. */
export interface Recipient {
  scriptHashHex: string;
  /** Kept for symmetry with the logs; only one kind is accepted. */
  kind: "script_hash";
}

/** Why an input was refused, in words a partner can act on. */
export type RecipientError = { code: "bad_address" | "not_testnet"; message: string };

/**
 * Accept the ONLY identifier this chain has: a 64-hex `script_hash`.
 *
 * A bare script_hash carries no network marker — it cannot, it is a hash — so
 * this function cannot tell a testnet script_hash from a mainnet one and does
 * not pretend to. That is safe in the RECEIVING direction, for the reason set
 * out in `deploy/testnet/REPLAY-ISOLATION.md`: paying coins TO a hash creates
 * an outpoint that exists only on this chain. The direction that matters is
 * what the faucet spends FROM, and that is bound to a specific genesis block
 * at startup (`index.ts` preflight), which is a far stronger check than any
 * address prefix ever was.
 */
export function parseRecipient(input: string): Recipient | RecipientError {
  const s = input.trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) {
    return { scriptHashHex: s.toLowerCase(), kind: "script_hash" };
  }
  const addr = parseAddress(s);
  if (addr) {
    if (addr.network === "mainnet") {
      return {
        code: "not_testnet",
        message:
          "that is a bloch1q… MAINNET address, and this faucet is testnet-only. " +
          "Genesis-4 does not identify recipients by address at all: run " +
          "`bloch-pos keygen` then `bloch-pos spendkey` and send the 64-hex script_hash it prints.",
      };
    }
    return {
      code: "bad_address",
      message:
        "Genesis-4 does not pay to addresses. An address carries 20 bytes; a native " +
        "Genesis-4 key is locked by SHA3-256(pubkey), all 32 of them, and the two are " +
        "different keys in the UTXO set — funding the address form would leave you " +
        "looking at a zero balance. Run `bloch-pos keygen` then `bloch-pos spendkey` " +
        "and send the 64-hex script_hash it prints.",
    };
  }
  return {
    code: "bad_address",
    message:
      "expected a 64-hex script_hash, as printed by `bloch-pos spendkey`.",
  };
}

/** Narrowing helper so callers do not have to duck-type the union. */
export function isRecipient(r: Recipient | RecipientError): r is Recipient {
  return (r as Recipient).scriptHashHex !== undefined;
}
