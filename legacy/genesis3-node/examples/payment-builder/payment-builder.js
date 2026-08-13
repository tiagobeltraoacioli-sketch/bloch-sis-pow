#!/usr/bin/env node
/*
 * Bloch Payment Builder (preview) — reference app
 * ================================================
 * STATUS: reference, UNTESTED against a live node. Dependency-light: pure Node
 *         (>= 18, uses global fetch). No build step, no npm install.
 *
 * WHAT IT DOES: given your address, a recipient, and an amount, it reads your
 *   UTXOs over JSON-RPC, does naive largest-first coin selection, and PRINTS THE
 *   UNSIGNED TRANSACTION PLAN (inputs, outputs, change, fee). It is a PREVIEW /
 *   BUILDER: it does NOT sign and does NOT broadcast.
 *
 * WHY IT CAN'T SIGN: a Bloch script_sig is a hybrid Falcon-1024 || ML-DSA-65
 *   post-quantum signature. That MUST come from the reference signer
 *   (bloch-wallet / WalletCore), which is byte-compatible with the node. This
 *   script deliberately stops at the unsigned plan and tells you the exact
 *   signer command to run next. Optionally it can call a signer you PROVIDE via
 *   --signer "<cmd>" (see below) — it will not invent signing itself.
 *
 * HONESTY RAILS (binding): Building on Bloch today is EXPERIMENTAL.
 *   - Unaudited mainnet-beta; relaxed PoW (k=4) => work is TRIVIALLY FORGEABLE;
 *     small, 51%-attackable network. No security is claimed today.
 *   - Bloch is OWNERLESS / NEUTRAL / AGNOSTIC. Anyone can build. Postern Labs is
 *     one builder among many, with NO special protocol access.
 *   - BLCH is neutral native gas (usable for development, ETH-like at the
 *     protocol level). NEVER a value or investment claim. No price, no value
 *     claim from anyone; 17% founder premine disclosed. Do NOT build here
 *     because "the token will appreciate" — no one promises it will.
 *   - Integer satoshis are the truth (1 BLOCH = 1e8 sat); "bloch" is display only.
 *
 * LICENSE: MIT OR Apache-2.0 (permissive). Adopt freely, including commercially.
 *
 * USAGE:
 *   node payment-builder.js --from <addr> --to <addr> --amount <BLOCH> \
 *     [--endpoint http://127.0.0.1:16210/] [--fee-rate <sat>] [--api-key <key>] \
 *     [--signer "<cmd with {from} {to} {amount} placeholders>"] [--broadcast]
 *
 *   Preview only (default, safe):
 *     node payment-builder.js --from bloch1q... --to bloch1q... --amount 1.5
 */

"use strict";

const SAT_PER_BLOCH = 100_000_000n; // 1e8; satoshis are the truth.

// ---- Reusable JSON-RPC caller, handling Bloch's result.error quirk ----------
async function callRpc(endpoint, method, params, apiKey) {
  const headers = { "content-type": "application/json" };
  if (apiKey) headers["X-API-Key"] = apiKey;
  const res = await fetch(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params || [] }),
  });
  let body;
  try { body = await res.json(); }
  catch { throw new Error("HTTP " + res.status + ": non-JSON response"); }
  // 1) Standard transport/auth/rate-limit error.
  if (body.error) throw new Error("RPC error " + body.error.code + ": " + body.error.message);
  // 2) The Bloch quirk: method-level failure inside result.error (HTTP 200).
  const result = body.result;
  if (result && typeof result === "object" && "error" in result) {
    throw new Error("method error: " + result.error);
  }
  return result;
}

// ---- Helpers ----------------------------------------------------------------
function blochToSat(s) {
  // Parse a decimal BLOCH string into integer satoshis without float rounding.
  const m = String(s).trim().match(/^(\d+)(?:\.(\d{1,8}))?$/);
  if (!m) throw new Error("amount must be a decimal BLOCH value, up to 8 dp");
  const whole = BigInt(m[1]);
  const frac = BigInt((m[2] || "").padEnd(8, "0"));
  return whole * SAT_PER_BLOCH + frac;
}
function satToBloch(sat) {
  const s = BigInt(sat), w = s / SAT_PER_BLOCH, f = (s % SAT_PER_BLOCH).toString().padStart(8, "0");
  return w.toString() + "." + f;
}

// Naive largest-first coin selection. Returns picked inputs + change.
function selectCoins(utxos, targetSat, feeReserveSat) {
  const need = targetSat + feeReserveSat;
  const sorted = [...utxos].sort((a, b) => (BigInt(b.value) > BigInt(a.value) ? 1 : -1));
  const picked = [];
  let sum = 0n;
  for (const o of sorted) {
    picked.push(o);
    sum += BigInt(o.value);
    if (sum >= need) break;
  }
  if (sum < need) {
    throw new Error(
      "insufficient funds: have " + satToBloch(sum) + " BLOCH, need " +
      satToBloch(need) + " (amount + fee reserve)"
    );
  }
  return { picked, inputSum: sum, changeSat: sum - need };
}

function parseArgs(argv) {
  const a = { endpoint: "http://127.0.0.1:16210/", broadcast: false };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    const next = () => argv[++i];
    switch (k) {
      case "--from": a.from = next(); break;
      case "--to": a.to = next(); break;
      case "--amount": a.amount = next(); break;
      case "--endpoint": a.endpoint = next(); break;
      case "--fee-rate": a.feeRate = next(); break;
      case "--api-key": a.apiKey = next(); break;
      case "--signer": a.signer = next(); break;
      case "--broadcast": a.broadcast = true; break;
      case "--help": case "-h": a.help = true; break;
      default: throw new Error("unknown arg: " + k);
    }
  }
  return a;
}

function usage() {
  console.log(`Bloch Payment Builder (preview) — reference, UNTESTED against a live node.

  node payment-builder.js --from <addr> --to <addr> --amount <BLOCH> [options]

Options:
  --endpoint <url>   JSON-RPC endpoint (default http://127.0.0.1:16210/)
  --fee-rate <sat>   fee reserve in sat (default: estimatefeeadvanced medium)
  --api-key <key>    X-API-Key (reads are usually public; writes may need it)
  --signer "<cmd>"   external signer command; {from} {to} {amount} are substituted.
                     Must print signed raw tx hex to stdout. This script never
                     signs itself (post-quantum hybrid signing lives in the
                     reference signer, e.g. bloch-cli / WalletCore).
  --broadcast        after signing via --signer, send with sendrawtransaction.

Without --signer this prints the UNSIGNED plan only and stops (safe default).`);
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || !args.from || !args.to || args.amount === undefined) {
    usage();
    process.exit(args.help ? 0 : 1);
    return;
  }

  console.log("== Bloch Payment Builder (preview) — reference, untested ==");
  console.log("Rails: experimental/unaudited; k=4 => work trivially forgeable;");
  console.log("       BLCH is neutral gas, never a value claim. Satoshis are truth.\n");

  const { endpoint, from, to, apiKey } = args;
  const amountSat = blochToSat(args.amount);

  // 1) Validate both addresses (never pay an unvalidated address).
  for (const [label, addr] of [["from", from], ["to", to]]) {
    const v = await callRpc(endpoint, "validateaddress", [addr], apiKey);
    if (!v.isvalid) throw new Error(label + " address is invalid (" + addr + ")");
  }

  // 2) Fee reserve: explicit --fee-rate, else estimatefeeadvanced medium tier.
  let feeReserve;
  if (args.feeRate !== undefined) {
    feeReserve = BigInt(args.feeRate);
  } else {
    const fa = await callRpc(endpoint, "estimatefeeadvanced", [], apiKey);
    feeReserve = BigInt(fa.medium_priority || fa.mempool_median || 1000);
  }

  // 3) Read UTXOs and select coins.
  const u = await callRpc(endpoint, "getutxos", [from], apiKey);
  if (!u.utxos || u.utxos.length === 0) throw new Error("no UTXOs for " + from);
  const { picked, inputSum, changeSat } = selectCoins(u.utxos, amountSat, feeReserve);
  const actualFee = inputSum - amountSat - changeSat; // == feeReserve here

  // 4) Print the UNSIGNED plan.
  console.log("Inputs selected (" + picked.length + "):");
  for (const o of picked) console.log("  " + o.txid + ":" + o.index + "  " + o.value + " sat");
  console.log("\nOutputs:");
  console.log("  -> " + to + "  " + amountSat + " sat  (" + satToBloch(amountSat) + " BLOCH)  [recipient, P2PKH]");
  if (changeSat > 0n)
    console.log("  -> " + from + "  " + changeSat + " sat  (" + satToBloch(changeSat) + " BLOCH)  [change, P2PKH]");
  console.log("\nFee (input - outputs): " + actualFee + " sat  (" + satToBloch(actualFee) + " BLOCH)");
  console.log("Input total: " + inputSum + " sat\n");

  console.log("This is the UNSIGNED plan. Bloch outputs are fixed P2PKH (no scripting),");
  console.log("and signing requires the hybrid Falcon-1024 || ML-DSA-65 post-quantum");
  console.log("signature produced by the reference signer. Next step:\n");
  console.log("  bloch-cli send " + from + " " + to + " " + args.amount + "\n");

  // 5) Optional: delegate to a signer YOU provide, then optionally broadcast.
  if (args.signer) {
    const { execSync } = require("node:child_process");
    const cmd = args.signer
      .replaceAll("{from}", from)
      .replaceAll("{to}", to)
      .replaceAll("{amount}", String(args.amount));
    console.log("Delegating to external signer: " + cmd);
    const signedHex = execSync(cmd, { encoding: "utf8" }).trim();
    console.log("Signer returned " + signedHex.length + " hex chars.");

    // Dry-run decode (no broadcast) to sanity-check the bytes.
    const decoded = await callRpc(endpoint, "decoderawtransaction", [signedHex], apiKey);
    console.log("decoderawtransaction OK: txid " + decoded.txid + ", size " + decoded.size + " bytes.");

    if (args.broadcast) {
      const out = await callRpc(endpoint, "sendrawtransaction", [signedHex], apiKey);
      console.log("Broadcast OK: txid " + out.txid);
      console.log("Track it with: gettxstatus [" + out.txid + "]  (0=mempool, 1-99=confirmed, 100+=final)");
    } else {
      console.log("Not broadcasting (pass --broadcast to send). Under k=4, confirmations carry no real security today.");
    }
  }
}

main().catch((e) => {
  console.error("\nERROR: " + e.message);
  console.error("Is a Bloch node reachable at the endpoint? Reads are public; writes may need --api-key.");
  process.exit(1);
});
