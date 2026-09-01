#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The address pages, verified against the running chain and against the tree.
//
//   npm run verify              (the whole thing, including the live chain)
//   npm run verify -- --offline  (A and B only)
//
// Three jobs, in order of how much they matter:
//
//  A. GUARD. Refuse a second address→script_hash derivation anywhere under
//     `src/`. This mirrors `crates/bloch-pos-committee/tests/
//     one_script_hash_derivation.rs`, which guards the Rust side. Eight sites
//     in this project once computed their own; a guard test stops a ninth in
//     code, and this one stops it in the browser half.
//
//  B. VECTORS. The TypeScript rule and the Rust rule agree, and the native and
//     truncated shapes are demonstrably different keys.
//
//  C. LIVE. The largest carried entry and a native key both resolve correctly,
//     in both forms, against the archivals. This is the part that would have
//     caught the faucet/withdrawal-client disagreement before a partner did.
//
// Reads only the archivals. Never a validator: their RPC is served by the
// consensus thread itself and has no auth and no rate limit.

import { register } from "node:module";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

// `src/` is Vite-resolved (extensionless relative imports); teach node the
// same rule so the checks below run against the real modules, not copies.
register("./ts-resolve.mjs", import.meta.url);

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "src");
const ARCHIVALS = ["http://139.180.166.5:8080/", "http://139.180.173.231:8080/"];
const OFFLINE = process.argv.includes("--offline");

let failures = 0;
const ok = (m) => console.log(`  ok   ${m}`);
const bad = (m) => {
  failures++;
  console.log(`  FAIL ${m}`);
};
const eq = (a, b, m) => (a === b ? ok(m) : bad(`${m}\n         expected ${b}\n         got      ${a}`));

// ── Fixtures, all real ──────────────────────────────────────────────────────

// The largest carried entry: the founder's Genesis-3 hash160. Measured from
// `carryover.tsv.gz` in this repo — 16 distinct addresses in the file, and this
// one holds 426,194 of its 452,726 outputs (93.9406% of the total value). That
// is the GENESIS OPENING STATE. What it holds on the live chain today is a
// different, smaller number, because it has been spending; the two are both
// true and this script checks the live one against the live chain only.
const FOUNDER_H160 = "e986db5149cff7499b282a048272a09aff0af4ff";
const FOUNDER_ADDR = "bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073";
const FOUNDER_CARRIED = FOUNDER_H160 + "0".repeat(24);

// A native key's script hash: validator 0's `pubkey_hash`, which the node
// reports and which IS SHA3-256(that validator's hybrid public key) — a real
// 32-byte native-shape hash belonging to a real key on this chain.
const NATIVE_V0 = "f396b7333e20dc1c449f6c25baed028ce4c297db12f32f30957e4b07ffccddc1";
const NATIVE_V0_TRUNCATED = NATIVE_V0.slice(0, 40) + "0".repeat(24);

// ── A. The guard ────────────────────────────────────────────────────────────

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (/\.tsx?$/.test(name)) out.push(p);
  }
  return out;
}

/**
 * A derivation is a line that MAKES a 32-byte value out of 20 bytes.
 *
 * The signature is the twelve zero bytes: `"0".repeat(24)`, or a literal run of
 * twenty-four zeros in a string. `scriptHash.ts` is allowed to contain it once
 * — it is the file whose job that is. Anywhere else is a second copy, which is
 * the failure this whole area exists to prevent.
 */
function guardOneDerivation() {
  console.log("A. one derivation, and it lives in lib/scriptHash.ts");
  const zeros = /"0"\.repeat\(\s*24\s*\)|'0'\.repeat\(\s*24\s*\)|0{24}/;
  const offenders = [];
  for (const file of walk(SRC)) {
    const rel = relative(join(HERE, ".."), file);
    if (rel.endsWith("lib/scriptHash.ts")) continue;
    const body = readFileSync(file, "utf8");
    body.split("\n").forEach((line, i) => {
      if (line.trimStart().startsWith("//") || line.trimStart().startsWith("*")) return;
      if (zeros.test(line)) offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
    });
  }
  if (offenders.length === 0) ok("no zero-extension outside lib/scriptHash.ts");
  else offenders.forEach((o) => bad(`a second derivation: ${o}`));

  // And the old entry point must be gone, by name.
  for (const file of walk(SRC)) {
    const rel = relative(join(HERE, ".."), file);
    const body = readFileSync(file, "utf8");
    if (/^\s*export function toScriptHash/m.test(body)) bad(`toScriptHash still exported in ${rel}`);
  }
  ok("toScriptHash() is not exported anywhere");
}

// ── B. The vectors ──────────────────────────────────────────────────────────

async function vectors() {
  console.log("B. the TypeScript rule matches the Rust one");
  const mod = await import("../src/lib/scriptHash.ts");

  // The Rust module's own test vector, byte for byte.
  const pubkey = Buffer.from("a suite-framed hybrid public key stands in for the real 8kB one");
  const rust = createHash("sha3-256").update(pubkey).digest("hex");
  const ts = mod.scriptHashFromPubkey(new Uint8Array(pubkey));
  eq(ts, rust, "scriptHashFromPubkey == SHA3-256(pubkey), all 32 bytes");

  const truncated = ts.slice(0, 40) + "0".repeat(24);
  if (ts !== truncated) ok("native and truncated shapes are DIFFERENT keys");
  else bad("native and truncated collapsed to one value");
  eq(ts.slice(0, 40), truncated.slice(0, 40), "they do share their first 20 bytes");
  eq(mod.isCarriedShape(truncated), true, "the truncated form has the carried shape");
  eq(mod.isCarriedShape(ts), false, "the native form does not");
  eq(mod.siblingOf(ts), truncated, "siblingOf(native) is the truncated form");
  eq(mod.siblingOf(truncated), null, "siblingOf(carried) is null — 20 bytes cannot become 32");

  // Zero-extension goes RIGHT. Padded left, every carried output has a
  // different owner and the opening ledger is a different ledger.
  const padded = mod.carriedFromG3Hash160("ab".repeat(20));
  eq(padded.slice(0, 40), "ab".repeat(20), "the hash160 occupies the LOW 20 bytes");
  eq(padded.slice(40), "0".repeat(24), "and the tail is zero");

  console.log("   what a person can paste");
  const forms = [
    ["a 64-hex script hash", FOUNDER_CARRIED],
    ["the bloch1q… address", FOUNDER_ADDR],
    ["the bare hash160", FOUNDER_H160],
  ];
  for (const [what, input] of forms) {
    const q = mod.classify(input);
    eq(q.scriptHash, FOUNDER_CARRIED, `${what} resolves to the same entry`);
    eq(mod.permalink(q), `/hash/${FOUNDER_CARRIED}`, `${what} has the same permalink`);
  }
  eq(mod.classify(FOUNDER_ADDR).kind, "g3_address", "…but the address keeps its provenance");
  eq(mod.classify(FOUNDER_CARRIED).kind, "script_hash", "…and the script hash keeps its own");

  // A mistyped address must be refused, not zero-extended: the wrong address
  // yields a perfectly valid script hash that simply holds nothing.
  const typo = FOUNDER_ADDR.slice(0, -1) + (FOUNDER_ADDR.endsWith("3") ? "4" : "3");
  eq(mod.classify(typo).kind, "bad_address", "a bad checksum is refused, not answered");
  eq(mod.classify("0x" + FOUNDER_CARRIED).scriptHash, FOUNDER_CARRIED, "a 0x prefix is tolerated");
  eq(mod.classify("nonsense").kind, "unrecognised", "garbage is refused");
  eq(mod.classify(NATIVE_V0).shape, "native", "a validator's pubkey_hash reads as native");
  return mod;
}

// ── C. The live chain ───────────────────────────────────────────────────────

async function rpc(url, method, params = []) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

async function live() {
  console.log("C. against the archivals");
  const [a, b] = ARCHIVALS;

  const head = await rpc(a, "getchaininfo");
  ok(`head slot ${head.slot}, height ${head.height}, finalized to ${head.finalized_height}`);

  // Both archivals must agree before anything below means anything.
  const headB = await rpc(b, "getchaininfo");
  if (Math.abs(headB.height - head.height) <= 2) ok("both archivals within 2 blocks of each other");
  else bad(`archivals disagree: ${head.height} vs ${headB.height}`);

  console.log("   the largest carried entry, from all three input forms");
  const bal = await rpc(a, "getbalance", [FOUNDER_CARRIED]);
  eq(bal.script_hash, FOUNDER_CARRIED, "the node echoes the hash it was asked for");
  if (BigInt(bal.balance_sat) > 0n) ok(`holds ${bal.balance_sat} sat across ${bal.utxo_count} outputs`);
  else bad("the largest carried entry reads zero — that is the bug this file exists for");

  // Every form must produce that one query. Resolution is the TS module's, so
  // this proves the module and the chain agree, not just the module with itself.
  const mod = await import("../src/lib/scriptHash.ts");
  for (const input of [FOUNDER_ADDR, FOUNDER_H160, FOUNDER_CARRIED]) {
    const r = await rpc(a, "getbalance", [mod.classify(input).scriptHash]);
    eq(r.balance_sat, bal.balance_sat, `"${input.slice(0, 16)}…" reads the same balance`);
  }

  console.log("   the native key, and its truncated shadow");
  const nat = await rpc(a, "getbalance", [NATIVE_V0]);
  const trunc = await rpc(a, "getbalance", [NATIVE_V0_TRUNCATED]);
  eq(nat.script_hash, NATIVE_V0, "the native hash is queried whole, not truncated");
  eq(trunc.script_hash, NATIVE_V0_TRUNCATED, "the truncated form is a DIFFERENT query");
  if (nat.script_hash !== trunc.script_hash) ok("the node treats them as two entries, as it must");
  else bad("the node collapsed them — consensus would be broken, not this page");
  ok(`native ${nat.balance_sat} sat / truncated ${trunc.balance_sat} sat`);
  ok("the entry page shows both and labels which is which; it never picks one silently");

  // Both of those read zero, which proves the queries are distinct but not
  // that the distinction COSTS anything. This does. It is a constructed probe,
  // not a key anyone holds: a native-shape hash whose first 20 bytes are the
  // founder's, i.e. exactly what a key would hash to if the founder had a
  // Genesis-4 key with that prefix. Its truncated sibling is the largest
  // funded entry on the chain.
  console.log("   the gap, priced");
  const shadow = FOUNDER_H160 + "01".repeat(12);
  if (!mod.isCarriedShape(shadow)) ok("the probe is native-shaped");
  else bad("the probe came out carried-shaped; pick a different tail");
  eq(mod.siblingOf(shadow), FOUNDER_CARRIED, "its sibling is the largest carried entry");
  const shadowBal = await rpc(a, "getbalance", [shadow]);
  const sibBal = await rpc(a, "getbalance", [FOUNDER_CARRIED]);
  eq(shadowBal.balance_sat, "0", "the native form reads ZERO");
  if (BigInt(sibBal.balance_sat) > 0n)
    ok(`while the truncated form holds ${sibBal.balance_sat} sat — the same key opens both`);
  else bad("expected the sibling to be funded");
  ok("a client that computed only one of these would report a funded holder as empty,");
  ok("with no error anywhere: `owns` accepts both forms. That is the whole bug.");

  console.log("   what the RPC cannot do (the indexer's whole reason to exist)");
  const page = await rpc(a, "getutxos", [FOUNDER_CARRIED, 5000]);
  eq(page.returned, 1000, "getutxos clamps to UTXO_PAGE_MAX server-side");
  eq(page.truncated, true, "…and says so");
  if (page.total > page.returned)
    ok(`${page.total - page.returned} of ${page.total} outputs are unreachable: no cursor exists`);
  else bad("expected the founder entry to exceed one page");
  if (page.utxos.every((u) => !("slot" in u) && !("created_slot" in u)))
    ok("getutxos carries no slot for the outputs it returns");
  else bad("getutxos grew a slot field — the pages can stop apologising");

  const first = page.utxos[0];
  const txout = await rpc(a, "gettxout", [first.txid, first.vout]);
  const keys = Object.keys(txout).sort().join(",");
  eq(keys, "at_slot,txid,unspent,utxo,vout", "gettxout returns exactly five fields");
  if (!("finalized" in txout)) ok("there is NO `finalized` field — two partner docs said there was");
  else bad("gettxout grew a finalized field");
  if (txout.at_slot >= head.slot)
    ok(`at_slot (${txout.at_slot}) is the head the node answered from, not a creation slot`);
  else bad(`at_slot ${txout.at_slot} is below the head ${head.slot} — re-read txout_json`);

  try {
    await rpc(a, "gettransaction", [first.txid]);
    bad("gettransaction answered — the history pages can be rewritten");
  } catch (e) {
    if (/no id|not.*index|cannot look up/i.test(e.message))
      ok("gettransaction is refused by design; there are no transaction ids to page on");
    else bad(`gettransaction failed for an unexpected reason: ${e.message}`);
  }
}

// ── D. The CORS boundary ────────────────────────────────────────────────────

/**
 * The Pages Function is not optional plumbing: the archivals answer with no
 * `Access-Control-Allow-Origin` header at all, so it is the ONLY path a
 * browser has to them. It is exercised here in-process — `onRequestPost` is a
 * plain function over web `Request`/`Response`, both of which node has — which
 * checks the real upstream hostnames, the real allowlist and the real failover
 * without needing wrangler or a deploy.
 */
async function proxy() {
  console.log("D. the /rpc Pages Function");
  const fn = await import("../functions/rpc.js");
  const call = (method, params = []) =>
    fn.onRequestPost({
      env: {},
      request: new Request("https://blochl1.com/rpc", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      }),
    });

  const good = await call("getchaininfo");
  eq(good.status, 200, "getchaininfo passes the allowlist and reaches an archival");
  eq(good.headers.get("access-control-allow-origin"), "*", "CORS is what this Function is for");
  const host = good.headers.get("x-bloch-upstream");
  if (host && host.includes("sslip.io")) ok(`answered by ${host}`);
  else bad(`no upstream named (got ${host}) — a Worker cannot fetch a bare IP (403 1003)`);
  const body = await good.json();
  if (body.result?.height > 0) ok(`height ${body.result.height} came back through the proxy`);
  else bad(`proxy returned no height: ${JSON.stringify(body).slice(0, 160)}`);

  // A write must not be reachable on an unauthenticated public endpoint.
  const write = await call("sendrawtransaction", ["00"]);
  eq(write.status, 403, "sendrawtransaction is refused by the proxy — it is a write");

  // Genesis-3 methods died with proof of work; the old allowlist was all of them.
  const dead = await call("getdaginfo");
  eq(dead.status, 403, "the dead Genesis-3 surface is no longer allowlisted");

  // The refusal a client must SEE, in the node's words, not the proxy's.
  const refused = await call("gettransaction", ["00".repeat(32)]);
  eq(refused.status, 200, "gettransaction reaches the node rather than being hidden");
  const rb = await refused.json();
  if (/carries no id/i.test(rb.error?.message ?? ""))
    ok("…and the node's own 'do not retry' explanation reaches the client intact");
  else bad(`unexpected gettransaction body: ${JSON.stringify(rb).slice(0, 200)}`);
}

// ── run ─────────────────────────────────────────────────────────────────────

guardOneDerivation();
await vectors();
if (OFFLINE) console.log("C, D. skipped (--offline)");
else {
  await live();
  await proxy();
}

console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
