// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pieces shared by the validator pages.
//
// The recurring job here is to render a fact together with the thing that
// qualifies it — a stake next to how much of it is still weight, a number next
// to whether a second node agreed. Splitting those apart across components is
// how a caveat gets dropped in a later edit, so they are one component each.

import { ReactNode } from "react";
import { Link } from "../lib/router";
import { fmtBloch, fmtInt } from "../lib/format";
import { Corroboration } from "../lib/validators";
import { stateTone, Cited } from "../lib/g4params";

/** The node's own `state` word, plus its separate `slashed` flag. */
export function StateBadge({ state, slashed }: { state: string; slashed: boolean }) {
  const tone = stateTone(state, slashed);
  // `slashed` is a field of its own, not a state. A validator can read
  // "exiting" and be slashed at the same time, and showing only the state word
  // would hide the half that matters.
  return (
    <span className="vstate">
      <span className={"pill " + tone}>{state}</span>
      {slashed && state !== "slashed" && <span className="pill bad">slashed</span>}
    </span>
  );
}

/** A constant, with the line of consensus that defines it available on hover. */
export function CitedValue({ c, children }: { c: Cited<unknown>; children: ReactNode }) {
  return (
    <span className="cited" title={c.src}>
      {children}
      <span className="cited-mark" aria-hidden="true">
        ⌁
      </span>
    </span>
  );
}

/**
 * Whether the second archival agreed, stated in the open.
 *
 * A `conflict` is rendered loudly and on purpose. These two nodes run a
 * different binary from the validator fleet and are read directly on :8080,
 * past the public proxy — so when they disagree with each other, the right
 * response is to distrust the page, not to pick a side quietly.
 */
export function CorroborationLine({ c, at }: { c?: Corroboration; at: number }) {
  const when = new Date(at * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC");
  if (!c) {
    return <p className="provenance">Read at {when}. Corroboration not reported.</p>;
  }
  if (c.state === "conflict") {
    return (
      <div className="errbox">
        <strong>The two archival nodes disagree about finality.</strong> They differ on{" "}
        {c.differing.join(", ")}. Every stake figure on this page was read from one of them, and
        which one is now a question — treat the numbers below as unconfirmed until they converge.
        <div className="conflict-claims">
          {c.sources
            .filter((s) => s.claim)
            .map((s) => (
              <div key={s.url}>
                <code>{s.url}</code> — slot {fmtInt(s.claim!.slot)}, finalized epoch{" "}
                {fmtInt(s.claim!.finalized_epoch)} <code>{s.claim!.finalized_root.slice(0, 12)}</code>
              </div>
            ))}
        </div>
      </div>
    );
  }
  const answered = c.sources.filter((s) => s.ok).length;
  return (
    <p className="provenance">
      Read at {when} from {answered === 2 ? "both archival nodes" : "one archival node"}
      {c.state === "corroborated"
        ? ", which agree on the justified and finalized checkpoints."
        : "; the second did not answer, so nothing corroborates this."}{" "}
      The archivals run a different build from the validator fleet, so agreement between them is
      not by itself agreement with the chain.
    </p>
  );
}

/**
 * A horizontal bar of one validator's stake, split into weight it still has
 * and weight the leak has taken.
 *
 * Drawn as one bar rather than two numbers because the split is the point: the
 * bond and the consensus weight are different quantities on this chain today,
 * and a table of bonds alone would overstate every validator by roughly half.
 */
export function StakeBar({
  own,
  effective,
  max,
}: {
  own: bigint;
  effective: bigint | null;
  max: bigint;
}) {
  if (max === 0n) return null;
  const pct = (v: bigint) => Number((v * 10_000n) / max) / 100;
  const eff = effective ?? 0n;
  const lost = own > eff ? own - eff : 0n;
  return (
    <span className="stakebar" title={`${fmtBloch(eff, 0)} effective · ${fmtBloch(lost, 0)} leaked`}>
      <span className="stakebar-eff" style={{ width: `${pct(eff)}%` }} />
      <span className="stakebar-leak" style={{ width: `${pct(lost)}%` }} />
    </span>
  );
}

export function ValidatorLink({ index }: { index: number }) {
  return (
    <Link to={`/validators/${index}`} className="mono-link">
      v{index}
    </Link>
  );
}

/**
 * The single fact that most changes how the table below should be read.
 *
 * Kept as a component and placed on every validator page, because the set
 * looks like 64 independent operators and is not one. It is not a criticism of
 * the launch — a fresh proof-of-stake genesis has nothing to bootstrap from —
 * but a reader counting 64 rows and inferring 64 parties has been misled by
 * the shape of the data, and only an explicit sentence fixes that.
 */
export function OneOperatorNote({ withdrawalHash }: { withdrawalHash: string }) {
  return (
    <div className="notebox">
      <h3>These 64 rows are one operator</h3>
      <p>
        Every validator in the genesis cohort declares the same withdrawal address, so whatever
        each one earns returns to the same place. That address is also the script hash of all five
        genesis allocation buckets — founder, VC, team, marketing and liquidity — and of the
        largest carryover balance from Genesis-3.
      </p>
      <p className="mono-wrap">
        <code>{withdrawalHash}</code>
      </p>
      <p>
        Read every concentration figure on this page with that in mind. Stake spread evenly across
        64 validators that share a withdrawal address is not distribution; it is one balance shown
        sixty-four times. The measure that would mean something — stake by operator — cannot be
        computed from chain data, because consensus cannot see who is behind an address.
      </p>
    </div>
  );
}
