// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The route table.
//
// # Why this is a table and not an if-chain
//
// It used to be an if-chain inside `App.tsx`: a sequence of `if (path === …)`
// and `matchRoute` calls, each returning a page. That shape has three
// properties that cost us real pages.
//
//  1. **Reachability was invisible.** Half the files in `src/pages` were not
//     referenced by the chain at all and nobody could tell by looking. A page
//     that is never routed is indistinguishable from a page that is, until
//     someone types the URL. `ROUTES` below is the whole answer, and
//     `src/pages` having a file that appears nowhere in it is now obvious.
//
//  2. **Correctness depended on line order.** `/validators/queues` had to be
//     tested before `/validators/:index`, or the literal was captured by the
//     pattern and read as validator number NaN. That is a trap that rearms
//     every time somebody adds a route, and it is invisible in review because
//     the two lines look independent. Here it is structural instead: `match()`
//     tries every LITERAL first and only then the patterns, so a literal can
//     never be shadowed by a pattern no matter where either sits in the file.
//
//  3. **Six branches editing one if-chain is six conflicts.** A table takes
//     rows. That is the actual reason this refactor happened now.
//
// # What a route is
//
// `pattern` is matched by `matchRoute` (see `lib/router`). `guard` rejects a
// match that parsed but is not valid — a non-numeric validator index, say —
// and rejection falls through to the remaining routes rather than rendering an
// error, so `/validators/queues` and `/validators/7` can share a shape.

import { ReactNode } from "react";
import { matchRoute } from "./lib/router";

export type Params = Record<string, string>;

export interface Route {
  /** `/blocks` or `/slot/:s`. Matched by `matchRoute`. */
  pattern: string;
  /** Render the page. `key` forces a remount when the parameters change. */
  render: (p: Params) => ReactNode;
  /** A parsed match that is nonetheless not for this route. Falls through. */
  guard?: (p: Params) => boolean;
  /** React key, so navigating between two instances remounts rather than reuses. */
  key?: (p: Params) => string;
}

/** True when the pattern has no `:params` — i.e. it is a literal path. */
export function isLiteral(pattern: string): boolean {
  return !pattern.split("/").some((seg) => seg.startsWith(":"));
}

/**
 * Resolve a path against the table.
 *
 * Two passes, literals first. See note 2 in the header: this is what makes
 * `/validators/queues` immune to `/validators/:index` regardless of the order
 * the two were added in.
 */
export function match(
  routes: Route[],
  path: string,
): { route: Route; params: Params } | null {
  const norm = path === "" ? "/" : path;
  for (const pass of [true, false]) {
    for (const route of routes) {
      if (isLiteral(route.pattern) !== pass) continue;
      const params = matchRoute(norm, route.pattern);
      if (!params) continue;
      if (route.guard && !route.guard(params)) continue;
      return { route, params };
    }
  }
  return null;
}
