// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The front door.
//
// Search here is a real design problem rather than a formality, because the
// handle every visitor arrives holding — a transaction id — does not exist on
// this chain. See `lib/query.ts` for the grammar and the reasoning; this file
// is the part that talks to the chain and decides where to send someone.
//
// Three behaviours are deliberate and all three are departures from what the
// box used to do:
//
//   1. **A bare number is not silently read as a slot.** Slot and height are
//      different numbers here — 20,895 apart today, because 38.3% of slots
//      carry no block — and there is no `getblockbyheight` to resolve the
//      second. Guessing sends a reader thinking in heights to a page about a
//      completely different block that looks perfectly correct. So the box
//      asks, and resolves a height properly when that is what was meant.
//
//   2. **A 32-byte value that resolves to nothing routes to an explanation,
//      not to a 404.** It is almost always a `tx_hash`. See `pages/TxAnswer`.
//
//   3. **A bad address checksum is refused, not stripped.** The zero-padded
//      hash of a mistyped address is a valid script hash that holds nothing,
//      so accepting it would show a confident empty balance for an address
//      that was never typed correctly.

import { useEffect, useRef, useState } from "react";
import { useRouter } from "../lib/router";
import { parseQuery, Candidate, epochSlots } from "../lib/query";
import { read, RpcRefusal, CODE, findSlotForHeight, HeightSearch } from "../lib/source";
import { G4Block, G4Head } from "../lib/g4";
import { fmtInt } from "../lib/format";

type Phase =
  | { kind: "idle" }
  | { kind: "busy"; what: string }
  /** A bare number: we cannot tell slot from height, so the reader picks. */
  | { kind: "choose"; n: number; slotHint: string | null }
  | { kind: "heightSearch"; height: number; probes: number }
  | { kind: "heightNarrowed"; height: number; lo: number; hi: number }
  | { kind: "error"; message: string };

export function G4Search({ hero }: { hero?: boolean }) {
  const { navigate } = useRouter();
  const [q, setQ] = useState("");
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const abort = useRef<AbortController | null>(null);

  useEffect(() => () => abort.current?.abort(), []);

  const reset = () => {
    abort.current?.abort();
    abort.current = null;
    setPhase({ kind: "idle" });
  };

  const go = (to: string) => {
    reset();
    setQ("");
    navigate(to);
  };

  /** Resolve a 32-byte value: block id, then funded script hash, then tx_hash. */
  async function resolve32(hex: string, signal: AbortSignal) {
    setPhase({ kind: "busy", what: "Asking whether that is a block…" });
    try {
      // `getblockbyid` serves non-canonical blocks too, so this also finds an
      // orphan — which `getblockbyslot` structurally cannot.
      const b = await read<G4Block>("getblockbyid", [hex], { signal });
      go(b.finality === "not_canonical" ? `/block/${hex}` : `/slot/${b.slot}`);
      return;
    } catch (e) {
      if (!(e instanceof RpcRefusal && e.code === CODE.BLOCK_NOT_FOUND)) {
        if (signal.aborted) return;
        // Could not ask. Do not fall through to "it must be an address" —
        // that would turn an outage into a wrong answer.
        setPhase({ kind: "error", message: `Could not reach the chain: ${(e as Error).message}` });
        return;
      }
    }

    setPhase({ kind: "busy", what: "Not a block. Checking the ledger…" });
    try {
      const bal = await read<{ balance_sat: string; utxo_count: number }>(
        "getbalance",
        [hex],
        { signal },
      );
      // Only treat it as an address if something is actually there. Every
      // 32-byte value has a balance of zero, so a zero reading is not evidence
      // that this was a script hash — and routing a tx_hash to a balance page
      // showing 0 is the confident-wrong-answer failure all over again.
      if (bal.utxo_count > 0 || (bal.balance_sat && bal.balance_sat !== "0")) {
        go(`/balance/${hex}`);
        return;
      }
    } catch {
      /* fall through — the explanation below is still the best answer */
    }
    if (signal.aborted) return;

    // Not a block, and nothing holds a balance under it. Overwhelmingly the
    // likeliest thing a person is holding that looks like this.
    go(`/tx/${hex}`);
  }

  async function runHeight(height: number, signal: AbortSignal, budget?: number) {
    setPhase({ kind: "heightSearch", height, probes: 0 });
    let head: G4Head;
    try {
      head = await read<G4Head>("getchaininfo", [], { signal });
    } catch (e) {
      setPhase({ kind: "error", message: `Could not read the head: ${(e as Error).message}` });
      return;
    }
    const r: HeightSearch = await findSlotForHeight(height, head, {
      signal,
      maxProbes: budget,
      onProgress: (probes) => setPhase({ kind: "heightSearch", height, probes }),
    });
    if (signal.aborted) return;
    if (r.kind === "found") go(`/slot/${r.slot}`);
    else if (r.kind === "future") {
      setPhase({
        kind: "error",
        message: `The chain is at height ${fmtInt(r.headHeight)}; ${fmtInt(height)} does not exist yet.`,
      });
    } else setPhase({ kind: "heightNarrowed", height, lo: r.lo, hi: r.hi });
  }

  async function take(c: Candidate) {
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    switch (c.kind) {
      case "slot":
        go(`/slot/${c.slot}`);
        return;
      case "validator":
        go(`/validators#v${c.index}`);
        return;
      case "epoch": {
        const [lo, hi] = epochSlots(c.epoch);
        go(`/blocks/${hi}`);
        void lo;
        return;
      }
      case "scriptHash":
        go(`/balance/${c.scriptHash}`);
        return;
      case "outpoint":
        go(`/outpoint/${c.txid}:${c.vout}`);
        return;
      case "blockId":
        await resolve32(c.blockId, ac.signal);
        return;
      case "height":
        await runHeight(c.height, ac.signal);
        return;
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const parsed = parseQuery(q);
    if (parsed.candidates.length === 0) {
      setPhase({
        kind: "error",
        message: q.trim().startsWith("bloch1")
          ? "That address does not checksum. Retype it — a mistyped address maps to a valid-looking key that simply holds nothing, so we will not guess."
          : "Not a slot, a height, an epoch, a validator index, an address, a script hash, a block id or an outpoint.",
      });
      return;
    }

    // The ambiguity we refuse to resolve for the reader. Everything else the
    // chain can settle; this one it cannot, because both readings are valid
    // numbers and only the reader knows which they meant.
    if (parsed.mustChoose) {
      const n = (parsed.candidates[0] as { slot: number }).slot;
      setPhase({ kind: "choose", n, slotHint: null });
      // Peek at what that slot holds, so the choice is informed rather than
      // abstract — showing "slot 33,690 is empty" next to the choice is often
      // enough on its own to tell the reader they meant a height.
      const ac = new AbortController();
      abort.current = ac;
      try {
        const b = await read<G4Block>("getblockbyslot", [n], { signal: ac.signal });
        if (!ac.signal.aborted) {
          setPhase({
            kind: "choose",
            n,
            slotHint: `holds block ${b.block_id.slice(0, 12)}… at height ${fmtInt(b.height ?? 0)}`,
          });
        }
      } catch (err) {
        if (!ac.signal.aborted && err instanceof RpcRefusal && err.code === CODE.SLOT_EMPTY) {
          setPhase({ kind: "choose", n, slotHint: "is empty — the proposer missed it" });
        }
      }
      return;
    }

    await take(parsed.candidates[0]);
  }

  return (
    <div className={"search-wrap" + (hero ? " hero" : "")}>
      <form className={"search" + (hero ? " hero" : "")} onSubmit={submit}>
        <input
          className="search-input"
          placeholder="Slot, height, block id, address, script hash, outpoint, v‹n›"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            if (phase.kind !== "idle") reset();
          }}
          spellCheck={false}
          autoComplete="off"
          aria-label="Search Genesis-4"
        />
        <button className="search-go" type="submit" disabled={phase.kind === "busy"}>
          {phase.kind === "busy" || phase.kind === "heightSearch" ? "…" : "Go"}
        </button>
      </form>

      {phase.kind === "busy" && <div className="search-note">{phase.what}</div>}

      {phase.kind === "error" && <div className="search-err">{phase.message}</div>}

      {phase.kind === "choose" && (
        <div className="search-choose">
          <div className="choose-lede">
            <strong>{fmtInt(phase.n)}</strong> could be a slot or a height, and on this chain
            those are far apart — about 38% of slots carry no block, so the two numbers differ by
            tens of thousands. Which did you mean?
          </div>
          <div className="choose-opts">
            <button className="pill-tab go" onClick={() => take({ kind: "slot", slot: phase.n })}>
              Slot {fmtInt(phase.n)}
              {phase.slotHint && <span className="choose-hint"> — {phase.slotHint}</span>}
            </button>
            <button className="pill-tab" onClick={() => take({ kind: "height", height: phase.n })}>
              Height {fmtInt(phase.n)}
              <span className="choose-hint"> — needs a search; there is no lookup by height</span>
            </button>
            {phase.n < 1024 && (
              <button
                className="pill-tab"
                onClick={() => take({ kind: "validator", index: phase.n })}
              >
                Validator v{phase.n}
              </button>
            )}
          </div>
        </div>
      )}

      {phase.kind === "heightSearch" && (
        <div className="search-note">
          Searching for height {fmtInt(phase.height)} — {phase.probes} slots probed. There is no
          lookup by height, so this closes a bracket on it.
        </div>
      )}

      {phase.kind === "heightNarrowed" && (
        <div className="search-choose">
          <div className="choose-lede">
            Height {fmtInt(phase.height)} is somewhere in slots {fmtInt(phase.lo)}–
            {fmtInt(phase.hi)}, and the search ran out of budget before pinning it down. That
            range is inside the stretch where the chain barely produced — most slots there are
            empty, so probes come back with nothing to learn from. It is findable, just
            expensive.
          </div>
          <div className="choose-opts">
            <button
              className="pill-tab go"
              onClick={() => {
                const ac = new AbortController();
                abort.current = ac;
                void runHeight(phase.height, ac.signal, 600);
              }}
            >
              Keep looking
            </button>
            <button className="pill-tab" onClick={() => go(`/blocks/${phase.hi}`)}>
              Browse slots {fmtInt(phase.lo)}–{fmtInt(phase.hi)}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
