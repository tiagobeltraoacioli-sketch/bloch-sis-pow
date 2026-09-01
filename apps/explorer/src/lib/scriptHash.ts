// SPDX-License-Identifier: AGPL-3.0-or-later
//
// What an "address" is on Genesis-4, stated once, for the browser.
//
// The authority is `crates/bloch-pos-committee/src/script_hash.rs`. This file
// is the TypeScript restatement of that module and nothing else; when the two
// disagree, the Rust one is right and this one is a bug. `scripts/
// verify-address-pages.mjs` pins them to the same vectors and refuses to pass
// if a second derivation appears anywhere under `src/`.
//
// ── The shape of the thing ──────────────────────────────────────────────────
//
// A Genesis-4 output is locked by 32 bytes: a `script_hash`. Those 32 bytes
// reach the eUTXO set by exactly two routes, and only ONE of them is a
// function of a key:
//
//   1. NATIVE   script_hash = SHA3-256(hybrid public key)      — all 32 bytes.
//               No address encoding exists for it, because 32 bytes do not fit
//               in the 20-byte body of a `bloch1q…`. This is what
//               `bloch-pos spendkey` prints and what a Genesis-4 transaction
//               pays to.
//
//   2. CARRIED  script_hash = <20-byte Genesis-3 hash160> ‖ 0x00 × 12.
//               NOT a derivation. The carryover ingest transcribed 452,726
//               rows of `carryover.tsv` into the opening ledger, once, at
//               genesis. Nothing computes it from a public key and nothing may.
//
// ── The mistake this file exists to make impossible ─────────────────────────
//
// A `bloch1q…` address carries SHA3-256(pubkey) TRUNCATED to 20 bytes. Zero-
// extending that back to 32 produces something with the carried shape:
//
//     SHA3-256(pubkey)[0..20] ‖ 0x00 × 12     <-- WRONG for a live key
//     SHA3-256(pubkey)                        <-- what the key actually owns
//
// Those are different keys in the eUTXO set. The faucet and the withdrawal
// client each computed one of them and the same funded key read
// 74,999,997,782 sat under one and 0 under the other. Consensus's `owns`
// accepts BOTH forms (`transition.rs:1381` — equal, or tail-zero with matching
// 20-byte prefix), so nothing errored anywhere: it was a silent zero.
//
// The explorer used to contain that conversion, in `g4.ts`, as
// `toScriptHash()`, and its own help text taught it to the reader in so many
// words ("the 20-byte hash inside your address, padded with twelve zero
// bytes… the same rule consensus uses"). That sentence is true of a CARRIED
// entry and false of a native key, and the page could not tell you which one
// you were looking at. It is gone.
//
// So this file deliberately contains NO address→native conversion. Given an
// address, the honest answer is "that names a Genesis-3 carried entry, and if
// you hold a Genesis-4 key its coins are somewhere this identifier cannot
// name". The page says exactly that.

import { parseBlochAddress } from "./address";
import { sha3_256 } from "./sha3";

/** Width of a `script_hash`: 32 bytes, 64 hex characters. */
export const SCRIPT_HASH_HEX = 64;
/** Width of a Genesis-3 address hash (hash160): 20 bytes, 40 hex characters. */
export const G3_HASH160_HEX = 40;

/** The twelve zero bytes a carried hash ends in. */
const CARRIED_TAIL = "0".repeat(SCRIPT_HASH_HEX - G3_HASH160_HEX);

function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/**
 * **The** derivation: the 32-byte key a hybrid public key's coins live under.
 *
 * `pubkey` is the suite-framed hybrid ML-DSA-65 ‖ Falcon-1024 public key —
 * exactly the bytes that travel in a transfer's witness, not either half on
 * its own and not a re-encoding. Hashing anything else yields a hash nobody
 * can spend from.
 *
 * The explorer never has a public key to hand (nothing on the wire carries
 * one), so nothing in the UI calls this. It is here so that the rule has a
 * single executable statement in this codebase too, and so the verifier can
 * check it against the Rust vectors rather than against prose.
 */
export function scriptHashFromPubkey(pubkey: Uint8Array): string {
  return toHex(sha3_256(pubkey));
}

/**
 * The carried shape, for a Genesis-3 hash160 and nothing else.
 *
 * Zero-extends to the RIGHT. The direction is consensus: padded on the left,
 * every carried output has a different owner and the opening ledger is a
 * different ledger.
 *
 * Never call this with 20 bytes you just derived from a public key. If those
 * bytes came out of an `Address`, you want a `script_hash` you cannot compute
 * — ask its holder for it.
 */
export function carriedFromG3Hash160(h160Hex: string): string {
  const h = h160Hex.trim().toLowerCase();
  if (!new RegExp(`^[0-9a-f]{${G3_HASH160_HEX}}$`).test(h)) {
    throw new Error("carriedFromG3Hash160: expected 40 hex characters");
  }
  return h + CARRIED_TAIL;
}

/**
 * Does this hash have the carried shape (last twelve bytes zero)?
 *
 * A read-side predicate for telling a reader WHY a balance came back empty.
 * It is not an ownership test, and a native hash can land in this shape by
 * chance with probability 2^-96.
 */
export function isCarriedShape(scriptHash: string): boolean {
  return scriptHash.length === SCRIPT_HASH_HEX && scriptHash.endsWith(CARRIED_TAIL);
}

/** "native" | "carried" — which of the two routes this hash looks like. */
export type ScriptHashShape = "native" | "carried";

export function shapeOf(scriptHash: string): ScriptHashShape {
  return isCarriedShape(scriptHash) ? "carried" : "native";
}

/**
 * The other entry the same key can open, when there is one.
 *
 * `owns()` matches a key against an output two ways, so a key whose native
 * hash is `H` can also spend anything locked under `H[0..20] ‖ 0×12`. Those
 * are two distinct rows in the eUTXO set with two distinct balances, and a
 * page that shows only one of them is the zero-balance bug wearing a
 * different hat.
 *
 *   native  → its truncated sibling (computable: just drop the tail)
 *   carried → null. The native hash of the key behind a carried entry is
 *             SHA3-256 of a public key nobody has published; it cannot be
 *             recovered from 20 bytes, and guessing is what started all this.
 */
export function siblingOf(scriptHash: string): string | null {
  if (scriptHash.length !== SCRIPT_HASH_HEX) return null;
  if (isCarriedShape(scriptHash)) return null;
  return scriptHash.slice(0, G3_HASH160_HEX) + CARRIED_TAIL;
}

// ── What a person can paste ─────────────────────────────────────────────────

/** A resolved search input, with the provenance the page needs to explain it. */
export type Query =
  | {
      kind: "script_hash";
      /** The 64 hex the node is asked for. Never transformed. */
      scriptHash: string;
      shape: ScriptHashShape;
    }
  | {
      kind: "g3_address";
      /** Normalised `bloch1q…`, checksum verified. */
      address: string;
      hash160: string;
      /** The carried entry that address names — the ONLY one it can name. */
      scriptHash: string;
    }
  | {
      kind: "g3_hash160";
      hash160: string;
      scriptHash: string;
    }
  | { kind: "bad_address"; input: string }
  | { kind: "unrecognised"; input: string };

/**
 * Classify what someone typed, without guessing.
 *
 * Four accepted forms, and each keeps its provenance so the page can say what
 * it is showing:
 *
 *   64 hex        a `script_hash`. Used verbatim; this is the only identifier
 *                 the chain actually has.
 *   `bloch1q…`    a Genesis-3 address. Its checksum is VERIFIED, not stripped:
 *                 a mistyped address zero-extends into a perfectly valid
 *                 script hash that simply holds nothing, and the reader would
 *                 believe the empty balance.
 *   40 hex        the bare hash160 inside such an address, unchecksummed.
 *   anything else refused, rather than coerced.
 *
 * The two Genesis-3 forms resolve to the CARRIED entry and are labelled as
 * such. They are not a way to look up a Genesis-4 key.
 */
export function classify(input: string): Query {
  const raw = (input ?? "").trim().toLowerCase();
  if (!raw) return { kind: "unrecognised", input };

  if (raw.startsWith("bloch1")) {
    const parsed = parseBlochAddress(raw);
    if (!parsed) return { kind: "bad_address", input: raw };
    return {
      kind: "g3_address",
      address: parsed.address,
      hash160: parsed.hashHex,
      scriptHash: carriedFromG3Hash160(parsed.hashHex),
    };
  }

  const s = raw.replace(/^0x/, "");
  if (!/^[0-9a-f]+$/.test(s)) return { kind: "unrecognised", input: raw };

  if (s.length === SCRIPT_HASH_HEX) {
    return { kind: "script_hash", scriptHash: s, shape: shapeOf(s) };
  }
  if (s.length === G3_HASH160_HEX) {
    return { kind: "g3_hash160", hash160: s, scriptHash: carriedFromG3Hash160(s) };
  }
  return { kind: "unrecognised", input: raw };
}

/**
 * The canonical permalink for whatever was pasted, or null if it was refused.
 *
 * Every accepted form collapses to `/hash/<64 hex>`: one URL per eUTXO-set
 * entry, so two people looking at "the same address" are demonstrably looking
 * at the same row. The Genesis-3 forms are a redirect INTO that URL, not an
 * alternative spelling of it — which is the point, because they name the
 * carried entry and only that.
 */
export function permalink(q: Query): string | null {
  switch (q.kind) {
    case "script_hash":
    case "g3_address":
    case "g3_hash160":
      return `/hash/${q.scriptHash}`;
    default:
      return null;
  }
}

/** An outpoint permalink. See `pages/Outpoint.tsx` for why it is not a txid. */
export function outpointLink(txid: string, vout: number): string {
  return `/outpoint/${txid}/${vout}`;
}
