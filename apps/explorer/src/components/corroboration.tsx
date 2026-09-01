// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The badge that says how well corroborated the number beside it is.
//
// # Why a number needs a badge at all
//
// The public proxy this explorer used to read from answers `getchaininfo`
// SOFTLY: when the nodes behind it do not agree, it returns one node's answer
// rather than an error. That is the right call — a wallet that blanks whenever
// the fleet disagrees is worse than one showing a dated number — but it means
// a reader is handed a height with no way to tell whether two independent
// nodes stood behind it or one did.
//
// This chain has produced exactly that situation, more than once: nodes at the
// same height returning different block ids and different balances, and a
// transfer that appeared in a wallet and then disappeared. A UI that renders
// "33,697" identically in both cases is not neutral about it — it is asserting
// something the endpoint never said.
//
// So the level is always rendered, including when it is the good one. A badge
// that only appears when something is wrong trains readers to ignore its
// absence, and the absence is not the same as `final`.

import { G4Corroboration } from "../lib/g4";

const COPY: Record<
  G4Corroboration["level"],
  { label: string; tone: string; title: string }
> = {
  final: {
    label: "final",
    tone: "ok",
    title:
      "At or below the finalised checkpoint, confirmed by two independent " +
      "archival nodes and certified against a fleet validator. Under proof of " +
      "stake this — not a confirmation count — is what makes a value settled: " +
      "reverting it would require slashing at least a third of the total stake.",
  },
  corroborated: {
    label: "corroborated",
    tone: "ok",
    title:
      "Two independent archival nodes returned the same answer, and a fleet " +
      "validator confirms they are on the chain the validator set is building " +
      "on. This is about the tip, so it can still be reorganised — wait for " +
      "'final' before treating it as settled.",
  },
  uncorroborated: {
    label: "uncorroborated",
    tone: "warn",
    title:
      "Shown, but not confirmed: something the endpoint normally checks was " +
      "missing. This is not evidence that the number is wrong; it is the " +
      "endpoint declining to imply a confidence it does not have.",
  },
  node_local: {
    label: "node-local",
    tone: "info",
    title:
      "A property of the node that was asked, not of the chain. The mempool " +
      "does not converge on this chain — one sweep of the fleet in a single " +
      "minute returned pending counts of 0, 1, 2, 4 and 5 — so two nodes " +
      "disagreeing here is ordinary and is not a fork.",
  },
};

export function CorroborationBadge({
  c,
  compact,
}: {
  c: G4Corroboration | null;
  compact?: boolean;
}) {
  if (!c) return null;
  const copy = COPY[c.level] ?? COPY.uncorroborated;

  // The reasons are appended to the tooltip rather than hidden behind a second
  // interaction: "uncorroborated" without "because the fleet witness timed out"
  // tells a reader that something is wrong and nothing about what.
  const detail: string[] = [];
  if (c.missing?.length) detail.push("Missing: " + c.missing.join("; ") + ".");
  if (c.note) detail.push(c.note);
  if (c.degraded === "upstream_budget_exhausted") {
    detail.push(
      "Served from cache because this endpoint had reached the number of calls " +
        "per second it is willing to make to the nodes: a Genesis-4 node answers " +
        "RPC from the same thread that produces blocks.",
    );
  }
  if (typeof c.served_from_cache_age_ms === "number") {
    detail.push(`Answer is ${Math.round(c.served_from_cache_age_ms / 1000)}s old.`);
  }
  if (c.witness && !c.witness.available) {
    detail.push(`No fleet witness (${c.witness.reason ?? "unavailable"}).`);
  }
  if (c.reorg_events?.length) {
    detail.push(
      `The endpoint has detected ${c.reorg_events.length} lineage event(s); ` +
        `cached answers were discarded.`,
    );
  }

  return (
    <span
      className={`corro corro-${copy.tone}`}
      title={[copy.title, ...detail].join("\n\n")}
      aria-label={`corroboration: ${copy.label}`}
    >
      <span className="corro-dot" aria-hidden="true" />
      {compact ? null : copy.label}
      {c.archival_witnesses && c.of && !compact ? (
        <span className="corro-count">
          {c.archival_witnesses}/{c.of}
        </span>
      ) : null}
    </span>
  );
}

/**
 * The one-line explanation shown under the head, when there is one to give.
 *
 * Deliberately null in the healthy case. A permanent banner saying everything
 * is fine is a banner nobody reads, and the badge already carries the good
 * news.
 */
export function CorroborationNote({ c }: { c: G4Corroboration | null }) {
  if (!c) return null;
  if (c.level === "final" || c.level === "corroborated") return null;
  if (c.level === "node_local") return null;

  return (
    <div className="corro-note">
      <strong>Not corroborated.</strong>{" "}
      {c.missing?.length
        ? c.missing.join("; ") + "."
        : "A check this endpoint normally makes could not be made."}{" "}
      The numbers below are what the nodes it can reach reported. Nothing here
      says the chain is unhealthy — this endpoint is telling you what it did and
      did not verify.
    </div>
  );
}
