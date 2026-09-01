// SPDX-License-Identifier: AGPL-3.0-or-later
//
// What a person can type into the search box, and what it might mean.
//
// Search on a Bitcoin explorer is a solved, boring problem, because a
// transaction id is a universal handle: paste one and you get the thing. On
// Genesis-4 that handle **does not exist**. `gettransaction` is refused by
// design and permanently — a transaction at this layer carries no id and the
// block store keeps no index — so the single most-used search on every
// explorer anyone has used before is not available here.
//
// That fact drives the whole design of this file. Two consequences:
//
//   * **The box must be honest about ambiguity rather than resolve it
//     silently.** A bare number is genuinely both a plausible slot and a
//     plausible height, and those are 21,000 apart on this chain. Picking one
//     and navigating is a wrong answer delivered confidently; the page that
//     comes back looks entirely normal, which is what makes it dangerous.
//     So a bare number produces two candidates and the reader chooses.
//
//   * **A 32-byte value that resolves to nothing is the interesting case, not
//     the failure case.** It is almost certainly a `tx_hash` — every wallet
//     and every exchange integration hands the user one, because
//     `sendrawtransaction` returns one. It is node-local, other nodes do not
//     agree on it, and feeding it to `gettxout` returns a well-formed
//     `unspent: false` that is indistinguishable from a spent output or a lost
//     withdrawal (verified live: a random 32-byte value returns exactly that,
//     HTTP 200, no error). A 404 would send that person to `gettxout` to get
//     the confident wrong answer. So the miss routes to an explanation.
//
// This module is pure: parsing only, no I/O. Resolving the ambiguous shapes
// needs the chain, and that lives in the search component.

import { parseBlochAddress } from "./address";

/** One reading of what the user typed. Several may be plausible at once. */
export type Candidate =
  /** A slot number. One RPC call resolves it. */
  | { readonly kind: "slot"; readonly slot: number }
  /** A block height. Needs a search — there is no `getblockbyheight`. */
  | { readonly kind: "height"; readonly height: number }
  /** An epoch. Maps to a slot range by arithmetic, no lookup needed. */
  | { readonly kind: "epoch"; readonly epoch: number }
  /** A validator's index in the registry. */
  | { readonly kind: "validator"; readonly index: number }
  /** A 32-byte script hash — the ledger key. Possibly zero-padded from 20. */
  | { readonly kind: "scriptHash"; readonly scriptHash: string; readonly padded: boolean }
  /** A 32-byte value that could be a block id. Must be asked about. */
  | { readonly kind: "blockId"; readonly blockId: string }
  /** An outpoint: a 32-byte id and an output index. */
  | { readonly kind: "outpoint"; readonly txid: string; readonly vout: number };

export interface Parsed {
  /** Normalised input, for echoing back. */
  readonly normalised: string;
  /** Readings, most likely first. Empty means we could not read it at all. */
  readonly candidates: Candidate[];
  /**
   * True when the reader has to choose because we genuinely cannot tell.
   * Distinct from "several candidates" — a 64-hex value has several readings
   * but they can be told apart by asking the chain, whereas a bare number
   * cannot be told apart at all.
   */
  readonly mustChoose: boolean;
}

const HEX = /^[0-9a-f]+$/;

/** Slots per epoch. Fixed by consensus; also echoed in every `getchaininfo`. */
export const SLOTS_PER_EPOCH = 32;

/** Left-align a 20-byte hash into the 32-byte key consensus actually compares. */
export function padH160(h160: string): string {
  return h160 + "0".repeat(24);
}

/** True when a 32-byte key is a zero-padded 20-byte one. */
export function isPadded(scriptHash: string): boolean {
  return scriptHash.length === 64 && scriptHash.slice(40) === "0".repeat(24);
}

/**
 * Read one search box entry.
 *
 * Accepted, in the order they are tested:
 *
 *   `bloch1q…`            an address — checksum **verified**, never stripped.
 *   `slot 42` / `s42`     an explicit slot.
 *   `height 42` / `h42`   an explicit height.
 *   `epoch 42` / `e42`    an explicit epoch.
 *   `v42` / `#42`         a validator index.
 *   `<64 hex>:<n>`        an outpoint.
 *   `<64 hex>`            script hash **or** block id — ask the chain.
 *   `<40 hex>`            a Genesis-3 hash-160; padded to the 32-byte key.
 *   `42`                  slot **or** height — the reader must choose.
 */
export function parseQuery(input: string): Parsed {
  const normalised = input.trim().toLowerCase();
  const none: Parsed = { normalised, candidates: [], mustChoose: false };
  if (!normalised) return none;

  // An address, checksum-verified. Verified rather than stripped because the
  // padded hash of a *mistyped* address is a perfectly valid script hash that
  // simply holds nothing — the reader would be shown an empty balance and
  // would believe it. A refusal is the only safe answer to a bad checksum.
  if (normalised.startsWith("bloch1")) {
    const parsed = parseBlochAddress(normalised);
    if (!parsed) return none;
    return {
      normalised,
      candidates: [{ kind: "scriptHash", scriptHash: padH160(parsed.hashHex), padded: true }],
      mustChoose: false,
    };
  }

  // Explicit prefixes: the reader has already told us which number this is,
  // so there is nothing to disambiguate.
  const kw = /^(slot|height|epoch|validator|block)\s*[:#]?\s*(\d+)$/.exec(normalised);
  const letter = /^([shev#])\s*(\d+)$/.exec(normalised);
  const word = kw ? kw[1] : letter ? { s: "slot", h: "height", e: "epoch", v: "validator", "#": "validator" }[letter[1]] : null;
  const num = kw ? Number(kw[2]) : letter ? Number(letter[2]) : NaN;
  if (word && Number.isSafeInteger(num) && num >= 0) {
    const one = (c: Candidate): Parsed => ({ normalised, candidates: [c], mustChoose: false });
    if (word === "slot" || word === "block") return one({ kind: "slot", slot: num });
    if (word === "height") return one({ kind: "height", height: num });
    if (word === "epoch") return one({ kind: "epoch", epoch: num });
    if (word === "validator") return one({ kind: "validator", index: num });
  }

  const bare = normalised.replace(/^0x/, "").replace(/[\s,_]/g, "");

  // An outpoint. Both separators are in the wild: `:` is Bitcoin's convention
  // and `-` is what several block explorers emit when they URL-encode one.
  const op = /^([0-9a-f]{64})[:\-](\d{1,10})$/.exec(bare);
  if (op) {
    return {
      normalised,
      candidates: [{ kind: "outpoint", txid: op[1], vout: Number(op[2]) }],
      mustChoose: false,
    };
  }

  if (HEX.test(bare) && bare.length === 64) {
    // Genuinely ambiguous in shape — a block id and a script hash are both 32
    // bytes — but *resolvable*: the chain can be asked whether a block with
    // this id exists. Block id first because it is the cheaper, sharper
    // question: `getblockbyid` either knows it or does not, whereas
    // `getbalance` answers "zero" for every 32-byte value ever conceived.
    return {
      normalised,
      candidates: [
        { kind: "blockId", blockId: bare },
        { kind: "scriptHash", scriptHash: bare, padded: isPadded(bare) },
      ],
      mustChoose: false,
    };
  }

  if (HEX.test(bare) && bare.length === 40) {
    // A bare hash-160 — the form carried Genesis-3 balances use. Consensus
    // compares the zero-padded 32-byte key, so the padding is the identity
    // here rather than a convenience.
    return {
      normalised,
      candidates: [{ kind: "scriptHash", scriptHash: padH160(bare), padded: true }],
      mustChoose: false,
    };
  }

  if (/^\d+$/.test(bare)) {
    const n = Number(bare);
    if (!Number.isSafeInteger(n)) return none;
    // The one case the box cannot resolve for the reader, and must not try.
    //
    // Slot and height are both plausible readings of a bare number and there
    // is no signal in the input that separates them. They are also far apart:
    // 38.3% of slots on this chain carry no block, so height 33,690 lives at
    // slot 54,585. Guessing "slot" — which this box used to do — sends anyone
    // thinking in heights about 21,000 slots away, to a page that renders
    // perfectly and is about a different block.
    //
    // A validator index is offered too, but last and only for small numbers:
    // the registry is 64 entries, so it is a live reading of "7" and a
    // nonsensical one of "54000".
    const candidates: Candidate[] = [
      { kind: "slot", slot: n },
      { kind: "height", height: n },
    ];
    if (n < 1024) candidates.push({ kind: "validator", index: n });
    return { normalised, candidates, mustChoose: true };
  }

  return none;
}

/**
 * The slot range an epoch covers. Pure arithmetic — no lookup, and no promise
 * that any of those slots carries a block.
 */
export function epochSlots(epoch: number, slotsPerEpoch = SLOTS_PER_EPOCH): [number, number] {
  return [epoch * slotsPerEpoch, epoch * slotsPerEpoch + slotsPerEpoch - 1];
}

/** The epoch a slot falls in. */
export function epochOf(slot: number, slotsPerEpoch = SLOTS_PER_EPOCH): number {
  return Math.floor(slot / slotsPerEpoch);
}
