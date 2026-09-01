// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Let plain `node` import the explorer's own modules.
//
// `src/` is written for Vite, which resolves `./address` to `./address.ts`.
// Node's ESM resolver does not, so importing the real module in a verifier
// fails on the first relative import. This hook adds the extension and nothing
// else — no transpile (node --experimental-strip-types does that), no aliases,
// no `node_modules` behaviour. It exists so the checks run against the SAME
// file the browser gets rather than against a copy, which is the entire point
// of a guard against copies.
import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

export async function resolve(specifier, context, next) {
  if (specifier.startsWith(".") && !/\.[cm]?[jt]sx?$/.test(specifier)) {
    const base = new URL(specifier, context.parentURL);
    for (const ext of [".ts", ".tsx", "/index.ts"]) {
      const candidate = new URL(base.href + ext);
      if (existsSync(fileURLToPath(candidate))) {
        return next(pathToFileURL(fileURLToPath(candidate)).href, context);
      }
    }
  }
  return next(specifier, context);
}
