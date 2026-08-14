// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The banner that marks a page as Genesis-3.
//
// Half this explorer now describes a chain that has stopped. Deleting those
// pages would be worse than keeping them — Genesis-3's history is the ledger
// Genesis-4 opened with, and an integrator checking a carried balance needs to
// read it. What is not acceptable is a page that *looks* live. This says so
// once, in the same place, on every such page.
import { Link } from "../lib/router";

export function ArchiveBanner({ what }: { what?: string }) {
  return (
    <div className="archive-banner">
      <span className="archive-tag">Genesis-3 · archive</span>
      <span className="archive-text">
        {what ?? "This page"} covers the proof-of-work era, which ended at height 39,918. Nothing
        here updates. The live chain is Genesis-4 — see the{" "}
        <Link to="/">dashboard</Link>, a <Link to="/balance">current balance</Link>, or the{" "}
        <Link to="/snapshot">snapshot</Link> that joins the two.
      </span>
    </div>
  );
}
