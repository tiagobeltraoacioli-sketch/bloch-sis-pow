// g4.js — Genesis-4 chain primitives: the read path, and the two RPC facts the
// send path needs (the current base fee, and broadcasting signed bytes).
//
// Classic script (no ES modules, no build step), matching ui.js / api.js /
// modules/*.js / browser/*.js. Loaded FIRST in index.html — before ui.js —
// because ui.js's number formatter and every pane's balance path depend on it,
// and a lazy `globalThis.PosternG4 &&` guard at each call site is exactly how a
// missing dependency turns into a silently-unformatted (or worse, silently
// Number()-corrupted) balance.
//
// WHY THIS FILE EXISTS AT ALL
// ---------------------------
// Genesis-4 is a different chain from Genesis-3 with a different RPC contract,
// and three of the differences are the kind that produce a WRONG NUMBER rather
// than an error:
//
//   1. `getbalance` / `getutxos` / `listunspent` take a **script_hash**, not a
//      bech32 address. Passing an address is a -32602, which is at least loud.
//      But the derivation is not obvious, so without a shared helper each pane
//      invents its own — and one of them gets the padding wrong and reads a
//      DIFFERENT account's balance, which is silent.
//
//   2. Balances are decimal STRINGS that exceed Number.MAX_SAFE_INTEGER. The
//      founder script_hash currently answers 5604682938086017913 sat. That is
//      ~622x past 2^53: `Number("5604682938086017913")` is 5604682938086018048
//      — off by 135 sat, no error, no warning. Any parseInt / parseFloat /
//      Number / toLocaleString on a G4 amount corrupts it. Satoshis are the
//      source of truth; everything here is BigInt end-to-end and formats by
//      BigInt divmod, never through a float.
//
//   3. `getblockcount` changed SHAPE (Genesis-3 returned a scalar height; G4
//      returns an object) and is unreliable — the RPC is served by the
//      consensus loop itself, so it can answer
//      `{"code":-32004,"message":"consensus thread did not answer within 10s"}`.
//      `getchaininfo` is the height source. (It can time out too — measured —
//      which is why the honest-failure contract below is not optional.)
//
// HONEST FAILURE (the point of the whole file)
// --------------------------------------------
// A user who owns 56 billion BLOCH and is shown "0 BLOCH" because the node
// timed out has been lied to. So: `call()` THROWS on every non-answer, and it
// never returns a default. "The node answered and you have 0" and "the node
// did not answer" are different outcomes and must render differently. Parsers
// here throw on an unrecognised shape rather than coercing it to zero, for the
// same reason.
(function (root, factory) {
  "use strict";
  const G4 = factory();
  // `globalThis`, not `window`: the canonical global, plus a slot on the
  // Postern namespace for panes that already hold `P`.
  //
  // WHY THIS IS NOT COSMETIC. This used to be `if (typeof window !== "undefined")`.
  // Inside an MV3 extension service worker there is no `window` — and there is
  // no `module` either, so the Node branch below did not catch it. Both arms
  // were skipped, `factory()` was computed, and its result was DISCARDED in
  // silence. `PosternG4` simply never existed, and the failure did not look
  // like a load failure: every caller in this codebase guards with a lazy
  // `const G = g4(); if (!G)` (browser/wallet.js:160-165, browser/rpc.js:45),
  // which is worded for "this build predates Contract L" — so a total absence
  // of the module would have been reported to the user as a stale build.
  // In a page `globalThis === window`, so this is rigorously a no-op for the
  // PWA; it is what lets the extension worker run THIS file rather than a fork.
  globalThis.PosternG4 = G4;
  globalThis.Postern = globalThis.Postern || {};
  globalThis.Postern.g4 = G4;
  // Node: so the pure helpers can be unit-tested outside a browser. This file
  // has no browser-only code at module scope precisely so that works.
  if (typeof module !== "undefined" && module.exports) module.exports = G4;
})(this, function () {
  "use strict";

  // ── RPC surface ───────────────────────────────────────────────────────────
  // The same-origin path served by functions/g4rpc.js (already deployed). It is
  // RELATIVE on purpose: the browser resolves it against the page's own origin,
  // so no absolute external origin is ever hardcoded in the app and the
  // no-external-origin scan stays honest with zero allowlist edits.
  //
  // NOT `/rpc` — that Pages Function proxies Genesis-3, a dead chain that will
  // happily answer with balances from a ledger nobody is producing blocks on.
  const RPC_PATH = "/g4rpc";

  // Byte-for-byte mirror of functions/g4rpc.js's READ_METHODS / WRITE_METHODS.
  // It is a MIRROR, not an independent policy: a method absent here is refused
  // client-side before any network I/O, with a message that names the reason,
  // which beats a 12s round-trip to a -32601.
  //
  // Deliberately much smaller than the Genesis-3 mirror this replaces. G4's
  // node exposes no wallet and no transaction index at all — measured, the
  // proxy's own words: "there is no transaction id at this layer and the node
  // holds no wallet". So listtransactions / gettransaction / gettxstatus /
  // getrecentblocks / gettipinfo / getdaginfo / getnetworkinfo / getpeerinfo
  // are GONE, not merely renamed. Leaving them in the mirror would let panes
  // issue calls that can never succeed and then render the timeout as "no
  // transactions yet".
  const READ_METHODS = Object.freeze([
    "getchaininfo",
    // Present at the edge, and DELIBERATELY UNUSED by this app: unreliable
    // (times out under load) and its shape changed from G3's scalar to an
    // object. `getchaininfo` is the height source everywhere. Kept in the
    // mirror only because the mirror's job is to match the edge exactly.
    "getblockcount",
    "getmempoolinfo",
    "getblockbyslot", "getblockbyid",
    "getvalidator", "getvalidatorcount",
    // All three take a script_hash (NOT an address) — see scriptHashFromAddress.
    "getbalance", "getutxos", "listunspent",
    // ONE outpoint, answered as present-or-absent: (txid_hex, vout) →
    // {txid, vout, unspent: bool, utxo|null, at_slot}. Exists because
    // `listunspent` cannot answer "is this output still there?": it caps at
    // 1000 with no cursor (see the UTXO-enumeration block below), so for any
    // wallet past 1000 outputs the same first page comes back every time and
    // an absent entry proves nothing. The node's own doc says exactly this
    // (bloch-pos-node/src/rpc.rs:696-713). Use it where ENUMERATION fails —
    // "was this specific coin spent?" — never as a substitute for getbalance
    // (it cannot sum) or getutxos (it cannot list).
    "gettxout",
  ]);
  // The only write: already-locally-signed transaction bytes. Keys, mnemonics
  // and passwords never reach this layer.
  const WRITE_METHODS = Object.freeze(["sendrawtransaction"]);

  const READ_SET = new Set(READ_METHODS);
  const WRITE_SET = new Set(WRITE_METHODS);

  // Client-side deadline. It must be strictly LONGER than everything downstream
  // of it, or it aborts work that was still going to succeed and reports
  // "unreachable" for a node that was about to answer.
  //
  // The real budgets, read out of functions/g4rpc.js rather than assumed
  // (the previous comment here said "the edge gives the upstream 12s", which was
  // never true, and the 15000 it justified cut the edge off mid-retry):
  //   ATTEMPT_TIMEOUT_MS = 11000   per upstream attempt (>10s on purpose, so the
  //                                node's articulate -32004 arrives instead of
  //                                our vague timeout)
  //   MAX_ATTEMPTS       = 3, but with ONE upstream configured today
  //                        `Math.min(3, Math.max(2, order.length))` = 2 attempts,
  //                        and the second is the one that wins the measured
  //                        cold-path case
  //   TOTAL_BUDGET_MS    = 26000   wall clock for the whole exchange
  // So the worst honest case is ~22s of upstream wait inside a 26s ceiling. A
  // 15s client deadline fired DURING the second attempt — precisely the attempt
  // that recovers the cold path — and turned a recoverable read into a failure
  // the user sees as "could not reach the node".
  //
  // 30s = the edge's own 26s ceiling plus room for TLS setup, the Worker's own
  // scheduling and the response body. Past this the edge has certainly given up,
  // so a timeout here means every hop gave up, which is the only thing this
  // deadline is allowed to mean.
  const TIMEOUT_MS = 30000;
  // Quoted in the timeout message so the wording cannot drift from the constant.
  const EDGE_TOTAL_BUDGET_MS = 26000;

  // 1 BLOCH = 1e8 sat.
  const SATS_PER_BLOCH = 100000000n;
  const DECIMALS = 8;

  // JSON-RPC "method not found". Named because the public endpoint answers
  // exactly this for `sendrawtransaction` — see broadcast() — and a caller has
  // to be able to tell that apart from a rejected transaction.
  const METHOD_NOT_FOUND = -32601;

  // ── UTXO enumeration limits (measured against the live node) ──────────────
  // `getutxos`/`listunspent` HARD-CAP `returned` at 1000 and take NO offset or
  // cursor — a third parameter is accepted and silently ignored (probed with
  // [sh,3,2]: the returned page starts at the same txid as [sh,3]).
  //
  // Two consequences that are load-bearing for anything built on top:
  //   - A client CANNOT enumerate a large UTXO set. The founder script_hash has
  //     426,199 outputs; 1000 is 0.23% of them and there is no way to ask for
  //     the rest. So there is NO client-side "sum the UTXOs" balance path in
  //     this app — that would under-report by three orders of magnitude while
  //     looking entirely plausible. `getbalance` is the only balance source.
  //   - `truncated` must be surfaced wherever a list is shown. A truncated list
  //     presented as complete is the same class of lie as a stale balance.
  const UTXO_MAX_RETURNED = 1000;
  // Default page size. Deliberately well under the cap: asking for exactly 1000
  // has been observed to blow the node's own 10s consensus-thread budget and
  // come back -32004, so the ceiling is not a safe operating point.
  const UTXO_PAGE_DEFAULT = 250;

  // ── SHA3-256, by hand ─────────────────────────────────────────────────────
  //
  // WHY THIS IS HERE AND WHY IT IS NOT A DEPENDENCY
  // A Bloch address carries a 4-byte checksum whose whole job is to catch a
  // mistyped or mis-transcribed character before it costs anybody anything. The
  // rule (bloch-crypto/src/address.rs:88-93) is
  //     checksum = SHA3-256(SHA3-256(hash160))[0..4]
  // and there is no way to check it without SHA3. WebCrypto cannot help: it
  // offers SHA-1 and the SHA-2 family (256/384/512) and no SHA-3 at all, in
  // every browser. So Keccak-f[1600] is written out below. It is ~70 lines of
  // arithmetic with no imports, no fetch and no package — the zero-dependency
  // rule is about not pulling in code we have not read, and this is the
  // opposite of that.
  //
  // Note SHA3-256, NIST FIPS-202 (domain padding 0x06), NOT the older
  // Keccak-256 that Ethereum uses (padding 0x01). Same permutation, different
  // pad byte, completely different digest. Getting that wrong would reject every
  // valid address, which is why the known-answer test below is not optional.
  //
  // Written with BigInt lanes rather than split 32-bit halves. It is the slower
  // of the two shapes and that is the right trade here: this hashes 20 and then
  // 32 bytes, twice, when a user types an address — microseconds — and the
  // 64-bit form is the one a reader can check against the spec line by line.
  //
  // THIS IS A TYPO DETECTOR, NOT A SECURITY BOUNDARY. A checksum is four bytes
  // and anyone constructing a hostile address simply computes the right one. The
  // WASM core re-derives and re-checks the address before it signs anything
  // (Address::parse, "checksum mismatch") and it must keep doing so. Nothing
  // here is permitted to become the authority.
  const M64 = (1n << 64n) - 1n;

  // Round constants, iota step.
  const KECCAK_RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
  ];
  // Rho: rotation offset per lane, lane index i = x + 5y.
  const KECCAK_ROT = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
    41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
  ];
  // Pi: where lane i moves to, i.e. dest = y + 5*((2x + 3y) mod 5).
  const KECCAK_PI = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22,
    23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
  ];

  function rotl64(x, n) {
    if (n === 0) return x;
    const b = BigInt(n);
    return ((x << b) | (x >> (64n - b))) & M64;
  }

  /** Keccak-f[1600], in place, on 25 BigInt lanes. */
  function keccakF1600(A) {
    const C = new Array(5);
    const D = new Array(5);
    const B = new Array(25);
    for (let round = 0; round < 24; round++) {
      // theta
      for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
      for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
      for (let i = 0; i < 25; i++) A[i] ^= D[i % 5];
      // rho + pi
      for (let i = 0; i < 25; i++) B[KECCAK_PI[i]] = rotl64(A[i], KECCAK_ROT[i]);
      // chi
      for (let y = 0; y < 5; y++) {
        for (let x = 0; x < 5; x++) {
          A[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y] & M64) & B[((x + 2) % 5) + 5 * y]);
        }
      }
      // iota
      A[0] ^= KECCAK_RC[round];
    }
  }

  /**
   * SHA3-256. Uint8Array in, 32-byte Uint8Array out.
   * Rate 136 bytes (1088 bits), capacity 512, FIPS-202 domain padding 0x06…0x80.
   */
  function sha3_256(bytes) {
    const RATE = 136;
    const LANES = RATE / 8; // 17
    const A = new Array(25).fill(0n);
    const len = bytes.length;
    // Pad10*1 with the SHA-3 domain separator. When len is an exact multiple of
    // the rate this appends a WHOLE extra block, which is correct and is the
    // case implementations most often get wrong.
    const padLen = RATE - (len % RATE);
    const buf = new Uint8Array(len + padLen);
    buf.set(bytes);
    buf[len] = 0x06;
    buf[buf.length - 1] |= 0x80;
    for (let off = 0; off < buf.length; off += RATE) {
      for (let i = 0; i < LANES; i++) {
        // Little-endian lane load.
        let lane = 0n;
        for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(buf[off + i * 8 + b]);
        A[i] ^= lane;
      }
      keccakF1600(A);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 4; i++) {
      let lane = A[i];
      for (let b = 0; b < 8; b++) { out[i * 8 + b] = Number(lane & 0xffn); lane >>= 8n; }
    }
    return out;
  }

  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length >> 1);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToHex(b) {
    let s = "";
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
    return s;
  }

  // ── KNOWN-ANSWER TEST, run once at load ───────────────────────────────────
  // A broken SHA3 would make every address fail its checksum, i.e. it would
  // brick sending and balance lookup for everyone, silently and identically to
  // "you typed it wrong". So the implementation proves itself against FIPS-202's
  // own vectors before it is allowed to reject anything, and if it cannot, the
  // checksum layer disables ITSELF and the app falls back to the structural
  // checks it had before. Loud in the console, invisible to correctness.
  const SHA3_KAT = [
    // SHA3-256("")
    ["", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"],
    // SHA3-256("abc")
    ["abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"],
  ];
  const SHA3_OK = (function () {
    try {
      for (const [msg, want] of SHA3_KAT) {
        const bytes = new Uint8Array(msg.length);
        for (let i = 0; i < msg.length; i++) bytes[i] = msg.charCodeAt(i);
        if (bytesToHex(sha3_256(bytes)) !== want) return false;
      }
      return true;
    } catch (_) { return false; }
  })();
  if (!SHA3_OK && typeof console !== "undefined" && console.error) {
    console.error(
      "PosternG4: the built-in SHA3-256 failed its known-answer test. Address CHECKSUMS cannot be " +
      "verified in this build, so a mistyped address will not be caught here — it will still be caught " +
      "by the signing core before anything is signed. Everything else is unaffected.");
  }

  /**
   * The 8-hex checksum for a 40-hex hash160, per bloch-crypto address.rs:
   * first 4 bytes of SHA3-256(SHA3-256(hash160_bytes)).
   * @returns {string|null} 8 lowercase hex, or null if SHA3 is not operational
   */
  function checksumForHash160(h160hex) {
    if (!SHA3_OK) return null;
    const inner = sha3_256(hexToBytes(h160hex));
    const outer = sha3_256(inner);
    return bytesToHex(outer.subarray(0, 4));
  }

  // ── script_hash derivation ────────────────────────────────────────────────
  // A Bloch address is `bloch1q` + 40 hex (the hash160) + 8 hex checksum = 55
  // chars. The script_hash G4 indexes by is that hash160 followed by 12 ZERO
  // BYTES — 24 ASCII '0' — to fill the 32-byte field. This is the same padding
  // consensus applies in `owns()`, which is why it must be reproduced exactly
  // and not approximated: a wrong pad is a valid-looking 64-hex string that
  // addresses a different (empty) account, and an empty account renders as a
  // perfectly plausible "0 BLOCH".
  //
  // Verified live: e986db5149cff7499b282a048272a09aff0af4ff + 24 zeros ->
  // {"balance_sat":"5604682938086017913","utxo_count":426199}.
  const PAD = "0".repeat(24);
  const HASH160_HEX_LEN = 40;
  const SCRIPT_HASH_HEX_LEN = 64;

  // Accepted address prefixes -> where the hash160 starts.
  //
  // Read out of the crate, not guessed: `MAINNET_PREFIX = "bloch1q"` and
  // `TESTNET_PREFIX = "bloch1t"` (bloch-crypto/src/core/mod.rs:135-136), and
  // `Address::parse` strips one of the two and then requires EXACTLY 48 hex of
  // payload (20-byte hash + 4-byte checksum) — so both address forms are 7 + 48
  // = 55 characters.
  //
  // This table used to read `tbloch1q` at offset 8, length 56, for testnet. That
  // prefix does not exist anywhere in the chain: a real `bloch1t…` address
  // matched neither entry and was rejected outright, while the imaginary
  // `tbloch1q…` form was accepted. Nothing on mainnet noticed, which is how it
  // survived.
  const ADDR_PREFIXES = [
    { prefix: "bloch1q", at: 7, total: 55, network: "mainnet" },
    { prefix: "bloch1t", at: 7, total: 55, network: "testnet" },
  ];
  const CHECKSUM_HEX_LEN = 8;

  const isHex = (s, n) => typeof s === "string" && s.length === n && /^[0-9a-f]+$/.test(s);

  /**
   * Examine an address (or raw hash) and say EXACTLY what is known about it.
   *
   * Three states are not enough, so there are six — each one a different claim,
   * and collapsing any two of them into a single "valid/invalid" boolean is how
   * a UI ends up telling a user "looks fine" about an address it never checked:
   *
   *   "empty"        nothing typed yet. Not an error; do not show one.
   *   "malformed"    not an address shape at all — wrong prefix, wrong length,
   *                  non-hex. Nothing to check further.
   *   "checksum_bad" RIGHT SHAPE, WRONG CHECKSUM. This is a typo, and it is the
   *                  single most valuable thing this function detects. Say so
   *                  plainly: the user mistyped or mis-pasted a character.
   *   "verified"     shape correct AND checksum recomputed and matched. The only
   *                  status that earns the word "verified" in the UI.
   *   "no_checksum"  a raw 40-hex hash160 or 64-hex script_hash. Structurally
   *                  usable, but it carries NO checksum, so there is nothing to
   *                  verify and no typo protection at all. Never call this
   *                  "verified" — a raw hash with one character changed is
   *                  another perfectly valid raw hash.
   *   "unchecked"    shape correct, but this build's SHA3 failed its self-test,
   *                  so the checksum could not be examined. Distinct from
   *                  "verified" and from "checksum_bad": we do not know.
   *
   * @param {string} input
   * @returns {{status:string, ok:boolean, verified:boolean, scriptHash:string|null,
   *            hash160:string|null, network:string|null, message:string}}
   */
  function inspectAddress(input) {
    const out = (status, extra) => Object.assign({
      status,
      // `ok` means "usable for a lookup or a send". A failed checksum is NOT ok.
      ok: status === "verified" || status === "no_checksum" || status === "unchecked",
      // `verified` is the strong claim, and only one status may make it.
      verified: status === "verified",
      scriptHash: null, hash160: null, network: null, message: "",
    }, extra || {});

    if (typeof input !== "string" || !input.trim()) {
      return out("empty", { message: "Enter a Bloch address." });
    }
    // Case-fold and drop surrounding whitespace: addresses are hex-bodied and
    // case-insensitive, and users paste them out of anything.
    const s = input.trim().toLowerCase();

    // A raw script_hash — what getbalance/getutxos echo back. No checksum rides
    // along, so it is accepted as given and labelled honestly.
    if (isHex(s, SCRIPT_HASH_HEX_LEN)) {
      return out("no_checksum", {
        scriptHash: s,
        hash160: s.slice(0, HASH160_HEX_LEN),
        message: "This is a raw 64-character script hash. It carries no checksum, so a mistyped " +
                 "character cannot be detected — check it against your source.",
      });
    }
    // A bare hash160 — pad it the way consensus does.
    if (isHex(s, HASH160_HEX_LEN)) {
      return out("no_checksum", {
        scriptHash: s + PAD,
        hash160: s,
        message: "This is a raw 40-character hash. It carries no checksum, so a mistyped character " +
                 "cannot be detected — check it against your source.",
      });
    }

    const p = ADDR_PREFIXES.find((q) => s.startsWith(q.prefix));
    if (!p) {
      return out("malformed", {
        message: "A Bloch address starts with bloch1q (or bloch1t on testnet).",
      });
    }
    // Length is checked EXACTLY, not as a minimum: a truncated or padded address
    // that happens to carry 40 hex in the right window would otherwise derive a
    // hash for an address the user never typed.
    if (s.length !== p.total) {
      return out("malformed", {
        network: p.network,
        message: `A Bloch address is ${p.total} characters; this one is ${s.length}. ` +
                 (s.length < p.total ? "It looks cut short." : "It looks like something extra came along with it."),
      });
    }
    const h160 = s.slice(p.at, p.at + HASH160_HEX_LEN);
    const got = s.slice(p.at + HASH160_HEX_LEN);
    if (!isHex(h160, HASH160_HEX_LEN) || !isHex(got, CHECKSUM_HEX_LEN)) {
      return out("malformed", {
        network: p.network,
        message: "This address contains characters that cannot appear in one (only 0-9 and a-f).",
      });
    }

    const want = checksumForHash160(h160);
    if (want === null) {
      // SHA3 self-test failed. Do NOT reject — that would brick every address in
      // the app over our own bug. Pass it through, say we could not check, and
      // let the signing core be the backstop it already is.
      return out("unchecked", {
        scriptHash: h160 + PAD, hash160: h160, network: p.network,
        message: "This build could not check the address checksum. It has the right shape; a typo " +
                 "would not be caught here, only when the transfer is signed.",
      });
    }
    if (want !== got) {
      return out("checksum_bad", {
        // The derived hash is deliberately NOT returned. A failed checksum means
        // we do not know which address was meant, and handing back a script hash
        // is precisely how a caller "helpfully" looks up the wrong account.
        network: p.network,
        message: "This address fails its checksum — at least one character is wrong. Bloch addresses " +
                 "carry a check code exactly so a mistyped or mis-copied character is caught before " +
                 "anything is sent. Re-copy it from the source; do not retype it.",
      });
    }
    return out("verified", {
      scriptHash: h160 + PAD, hash160: h160, network: p.network,
      message: p.network === "testnet"
        ? "Checksum verified — this is a TESTNET address."
        : "Checksum verified.",
    });
  }

  /**
   * Derive the 64-hex script_hash G4 indexes UTXOs by.
   *
   * Liberal in what it accepts, strict in what it sends:
   *   - a Bloch address (`bloch1q…` / `bloch1t…`)  -> hash160 + 24 zeros,
   *                                                  ONLY IF THE CHECKSUM PASSES
   *   - a raw 64-hex script_hash                   -> returned verbatim
   *   - a raw 40-hex hash160                       -> padded
   * Anything else -> null. NEVER a guess: returning a plausible-but-wrong hash
   * is how a user gets shown someone else's (empty) balance — which was, until
   * the checksum went in above, exactly what this function did for a
   * one-character typo. It checked the prefix, the length and that the body was
   * hex, and never looked at the 8 checksum characters sitting right there.
   *
   * @param {string} addr
   * @returns {string|null} lowercase 64-hex, or null
   */
  function scriptHashFromAddress(addr) {
    const r = inspectAddress(addr);
    return r.ok ? r.scriptHash : null;
  }

  /**
   * True when `s` is usable as an address or raw hash.
   *
   * DELIBERATELY WEAKER THAN "verified" — a raw script hash has no checksum to
   * check, so this cannot promise one passed. Anything writing on-screen copy
   * should call `inspectAddress` and read `.status`, so it can tell a user the
   * difference between "this looks like an address" and "this address checks
   * out". Those are different claims and only one of them is worth much.
   */
  function isAddressLike(s) {
    return inspectAddress(s).ok;
  }
  /** True only when the checksum was recomputed and matched. */
  function isAddressVerified(s) {
    return inspectAddress(s).verified;
  }

  // ══ CONTRACT B — exact sat arithmetic ═════════════════════════════════════
  //
  // This block is the ONLY place in the application where satoshis become BLOCH
  // or BLOCH becomes satoshis. `PosternG4.sats` is the published surface (DEV 1,
  // DEV 3 and DEV 4 build against it); everything below it in this file, and
  // every legacy name at the bottom of the module, is a thin delegate to these
  // four functions. If you are about to write `/ 1e8`, `* 1e8`, `toFixed`,
  // `toLocaleString` or `Number()` on an amount anywhere in this app: that is
  // the bug this block exists to make unnecessary.
  //
  // BigInt in, BigInt out. Never Number. The reason is not fastidiousness:
  // Genesis-4 issues 57,146,400,000 BLOCH = 5,714,640,000,000,000,000 sat, which
  // is 634x past Number.MAX_SAFE_INTEGER (9,007,199,254,740,991) and within a
  // factor of ~3.2 of u64::MAX. The founder script_hash alone answers
  // 5,604,682,938,086,017,913 sat today. An ORDINARY large holder already breaks
  // a JS number here; this is not an edge case and it does not warn.

  // ── the numbers this file is sized against, read out of the frozen crates ──
  // (/Users/tiagoacioli/dev/BlochPOS/crates — cited, not assumed, because every
  // bound below is a refusal and a wrong bound refuses real money.)
  //
  // A single UTXO output value is a Rust u64 — `pub value: u64` at
  // bloch-pos-committee/src/state_root.rs:482, whose own doc note reads "A
  // single output fits u64; SUMS of values must use u128". So u64::MAX is the
  // widest thing that can legitimately appear in a `value_sat`, and anything
  // above it is a malformed or hostile reply.
  //
  // THERE IS NO PER-OUTPUT VALUE CAP IN CONSENSUS. `apply_transfer`
  // (transition.rs:1553-1670) checks structure, set membership, script hash,
  // value conservation and signatures — and never bounds an individual output.
  // Measured consequences, which are why nothing here may narrow to a Number:
  //   - THREE GENESIS ALLOCATION OUTPUTS ARE 1,000,000,000,000,000,000 sat each
  //     (FOUNDER / VC / TEAM, genesis/mainnet.manifest; one EutxoEntry apiece at
  //     vout 0, genesis.rs:1060-1083). That is 111x Number.MAX_SAFE_INTEGER, on
  //     the live chain, today. It is not a hypothetical.
  //   - the founder script_hash holds 5,604,682,938,086,017,947 sat in total and
  //     can consolidate it into ONE output of ~5.6e18 sat — 622x 2^53-1 — with
  //     no consensus objection.
  //   - carryover outputs are all small by comparison (largest 190,476,190,476,247
  //     sat, ~0.021x 2^53-1), which is exactly why a Number-based wallet appears
  //     to work right up until it meets an allocation output.
  const U64_MAX = 18446744073709551615n;
  // A u64 needs at most 20 decimal digits. Keep a little compatibility room
  // for callers that retained leading zeroes, but reject attacker-sized text
  // before the regexp, BigInt constructor, or an error message can copy it.
  const SAT_DECIMAL_MAX_CHARS = 128;

  // The HARD supply cap: 100,000,000,000 BLOCH = 1e19 sat.
  // `TOTAL_SUPPLY_BLOCH: u128 = 100_000_000_000` /
  // `TOTAL_SUPPLY_SAT` at bloch-pos-committee/src/tokenomics_v4.rs:84-85, and it
  // is enforced — `st.issued_sat > TOTAL_SUPPLY_SAT` is `SupplyCapExceeded` at
  // transition.rs:2310. Consensus can never mint past it, so it is the only
  // ceiling this file is entitled to impose on a user-typed amount.
  const TOTAL_SUPPLY_BLOCH = 100000000000n;
  const TOTAL_SUPPLY_SATS = TOTAL_SUPPLY_BLOCH * SATS_PER_BLOCH; // 10000000000000000000n

  // What genesis actually put in circulation: 57,146,400,000 BLOCH
  // (18,146,400,000 carried over from Genesis-3 across 452,726 outputs, plus the
  // five allocations). `GENESIS_ISSUED_SAT` at tokenomics_v4.rs:251.
  //
  // NOT used as a bound anywhere, on purpose. The remaining 42,853,600,000 BLOCH
  // is validator emission that is issued over time, so a ceiling pinned to
  // today's issuance would start refusing legitimate amounts as the chain runs.
  // It is exported for display only.
  const GENESIS_ISSUED_BLOCH = 57146400000n;
  const GENESIS_ISSUED_SATS = GENESIS_ISSUED_BLOCH * SATS_PER_BLOCH; // 5714640000000000000n

  /**
   * Group an integer digit string with thousands separators.
   *
   * String in, string out. No Number anywhere, so it is exact at any magnitude —
   * this is the primitive `toLocaleString` cannot be, because toLocaleString
   * takes a Number and a Number cannot hold this chain's amounts.
   *
   * @param {string} digits bare digits, no sign, no dot
   * @returns {string}
   */
  function groupDigits(digits) {
    return String(digits).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  // ── Contract B.1 — parse ──────────────────────────────────────────────────

  /**
   * A decimal sat string off the wire -> BigInt.
   *
   * STRICT, by contract: the input must match /^\d+$/ exactly. No sign, no
   * whitespace, no separators, no exponent, no dot, no `0x`. Every sat field the
   * Genesis-4 node emits goes through its `Json::sat` helper and is a bare
   * unsigned decimal string, so anything else is a reply this wallet does not
   * understand — and the rule for those, everywhere in this file, is to throw
   * rather than to coerce. A parser that returns 0 for a malformed reply
   * produces a zero that is indistinguishable on screen from a zero produced by
   * the chain.
   *
   * A BigInt passes through (range-checked). A Number is REFUSED outright, with
   * no safe-integer exemption: by the time a sat amount is a Number the question
   * of whether it is still correct has already been decided somewhere else, and
   * accepting it here would launder that decision. Callers holding a Number have
   * a bug upstream, and the message says where to look.
   *
   * @param {string|bigint} v
   * @returns {bigint}
   * @throws {TypeError}
   */
  function satsParse(v) {
    let n;
    if (typeof v === "bigint") {
      n = v;
    } else if (typeof v === "number") {
      throw new TypeError(
        "sat amount arrived as a JS number, not a decimal string. Genesis-4 amounts run past " +
        "Number.MAX_SAFE_INTEGER, so a number here has already lost satoshis silently — pass the " +
        "string the node sent.");
    } else if (typeof v === "string") {
      if (v.length > SAT_DECIMAL_MAX_CHARS) {
        throw new TypeError(
          `sat amount: decimal string is too long (maximum ${SAT_DECIMAL_MAX_CHARS} characters)`);
      }
      if (!/^\d+$/.test(v)) {
        throw new TypeError(
          `sat amount: expected an unsigned decimal string, got ${JSON.stringify(v)}`);
      }
      n = BigInt(v);
    } else {
      throw new TypeError(`sat amount: expected a decimal string or BigInt, got ${v === null ? "null" : typeof v}`);
    }
    if (n < 0n) {
      throw new TypeError(`sat amount: negative (${n}) — every amount field on this chain is unsigned`);
    }
    if (n > U64_MAX) {
      // Safe as a bound even for the SUM fields. `getbalance` computes
      // `balance_sat` in u128 (transition.rs:1887-1893) precisely because sums
      // can outgrow a single output — but every sum is still bounded by the hard
      // supply cap of 1e19 sat, which is comfortably below u64::MAX
      // (1.8446e19). So this can never refuse a real balance. Do not "fix" it
      // upward to u128 range: that would only widen what a hostile reply can say.
      throw new TypeError(
        `sat amount: ${n} is larger than u64::MAX (${U64_MAX}), which is wider than any field on this ` +
        "chain — this is not an amount a healthy node produced");
    }
    return n;
  }

  /** Non-throwing satsParse — null instead of an exception. Null means UNKNOWN
   *  and must never be rendered as 0. */
  function satsTryParse(v) {
    try { return satsParse(v); } catch (_) { return null; }
  }

  // ── Contract B.2 — user input ─────────────────────────────────────────────

  /**
   * User-typed BLOCH -> BigInt sats, from the DECIMAL STRING, never a float.
   *
   * `parseFloat("0.07") * 1e8` is 7000000.000000001; Math.round hides that only
   * until the amount is large enough to matter, which on this chain is not far.
   * Splitting on the dot and padding the fraction to 8 places is exact for every
   * input at every magnitude.
   *
   * DELIBERATE ANSWER FOR EVERY AMBIGUOUS INPUT. Each of these was decided, not
   * left to fall out of a regex, and each rejection carries copy a user can act
   * on — these messages ARE user-facing, they are shown next to the field:
   *
   *   "1.23456789"   ->  123456789n            the ordinary case
   *   "  12  "       ->  1200000000n           surrounding whitespace trimmed
   *   "0"            ->  0n                    parsed fine; whether zero is
   *                                            SENDABLE is the caller's rule
   *   "007"          ->  700000000n            leading zeros are unambiguous
   *   "5." / ".5"    ->  500000000n / 50000000n  a lone dot on one side is
   *                                            unambiguous
   *   ""             ->  THROW  nothing typed
   *   "."            ->  THROW  no digits at all
   *   "abc" "0x10"   ->  THROW  not a number. `0x10` in particular must never be
   *                     read as 16: a user typing hex into an amount field has
   *                     made a mistake, and 16 BLOCH is a confident wrong answer
   *   "1.2.3"        ->  THROW  two dots, no reading is safe
   *   "-1"           ->  THROW  amounts are unsigned
   *   "+1"           ->  THROW  a sign in an amount field means something went
   *                     wrong upstream; refusing costs one keystroke
   *   "1e9"          ->  THROW  exponent notation. Not because it is
   *                     unparseable but because "1e9" and "1E9" and "1e-9" all
   *                     look alike at a glance and one of them is a billion
   *                     times the other
   *   "1,5"          ->  THROW  a comma is a decimal point in some countries and
   *                     a thousands separator in others: 1.5 or 15, a 10x
   *                     difference in what gets signed. There is no safe guess
   *   "1 500"        ->  THROW  same ambiguity, space as a group separator
   *   "1_000"        ->  THROW  same
   *   "1.234567891"  ->  THROW  9 decimal places
   *   "0.000000001"  ->  THROW  below one satoshi. Rounding it to 0 would let a
   *                     user believe they sent something; rounding it UP would
   *                     spend money they did not ask to spend
   *   above supply   ->  THROW  more BLOCH than exists. Only reachable by a typo
   *                     or a paste accident, and the core would refuse it later
   *                     anyway — refusing here means no network round-trip and a
   *                     sentence that names the problem
   *
   * @param {string} input the raw field value
   * @returns {bigint} sats
   * @throws {TypeError} with a message written for the user
   */
  function satsFromUserBLCH(input) {
    if (typeof input === "number") {
      // Not a style rule. `0.1 + 0.2` is 0.30000000000000004 and 5714640000.5 is
      // not exactly representable; by the time an amount is a Number the digits
      // the user typed are already gone. Read the input element's .value.
      throw new TypeError(
        "amount: pass the text the user typed, not a number — a JS number cannot hold a Bloch amount exactly");
    }
    if (typeof input === "bigint") {
      // A BigInt here is unambiguous (whole BLOCH) but still needs the range
      // check, and previously did not get one: the old code was
      // `input * SATS_PER_BLOCH` with no validation, so a negative BigInt
      // produced a negative sat amount and sailed onward.
      return checkUserRange(input * SATS_PER_BLOCH, input.toString());
    }
    if (input == null) throw new TypeError("amount: enter an amount");
    if (typeof input !== "string") {
      throw new TypeError(`amount: enter an amount (got ${typeof input})`);
    }

    // Trim only the OUTSIDE. Whitespace in the middle is a group separator in
    // several locales ("1 500"), so stripping it silently would turn 1 500 into
    // 1500 for one user and "1 5" into 15 for another — the same class of guess
    // the comma rejection exists to refuse.
    const raw = input;
    const t = raw.trim();
    if (!t) throw new TypeError("amount: enter an amount");

    if (/[,_]/.test(t)) {
      throw new TypeError(
        `amount: remove the separators from “${t}”. A comma is the decimal point in some countries and a ` +
        "thousands separator in others — reading it wrong would change the amount by 1000x. Write it with " +
        "a dot and no grouping, like 1500.75");
    }
    if (/\s/.test(t)) {
      throw new TypeError(
        `amount: remove the spaces from “${t}”. A space is a thousands separator in some countries, so ` +
        "there is no safe way to read it. Write it with a dot and no grouping, like 1500.75");
    }
    if (/e/i.test(t)) {
      throw new TypeError(
        `amount: write “${t}” out in full. Exponent notation is not accepted here — 1e9, 1E9 and 1e-9 are ` +
        "hard to tell apart at a glance and a billion times apart in value");
    }
    if (/^-/.test(t)) throw new TypeError("amount: an amount cannot be negative");
    if (/^\+/.test(t)) throw new TypeError("amount: remove the leading + — write just the digits");

    const m = /^(\d*)(?:\.(\d*))?$/.exec(t);
    // `!m[1] && !m[2]` catches "." — matched by the regex, but carrying no digit
    // on either side of the dot.
    if (!m || (!m[1] && !m[2])) {
      throw new TypeError(`amount: “${t}” is not an amount. Use digits and at most one dot, like 12.5`);
    }
    const whole = m[1] || "0";
    const frac = m[2] || "";
    if (frac.length > DECIMALS) {
      throw new TypeError(
        `amount: “${t}” has ${frac.length} decimal places. The smallest unit on Bloch is ` +
        `0.00000001 BLOCH (one satoshi), so ${DECIMALS} is the limit — this amount cannot be sent exactly, ` +
        "and rounding someone's money is not this wallet's decision to make");
    }
    const sats = BigInt(whole) * SATS_PER_BLOCH + BigInt(frac.padEnd(DECIMALS, "0") || "0");
    return checkUserRange(sats, t);
  }

  /**
   * Ceiling check for a user-typed amount. Separate from satsParse's u64 bound
   * on purpose: this one is about a typo, not about a malformed reply, so its
   * message is written for the person at the keyboard.
   *
   * The bound is the HARD SUPPLY CAP (1e19 sat), not today's issuance. Refusing
   * at the cap catches every realistic typo — nobody means to type more than a
   * hundred billion BLOCH — while never refusing an amount that consensus could
   * one day make real. A ceiling that drifts out of date starts rejecting
   * legitimate sends, which is a worse bug than the one it prevents.
   */
  function checkUserRange(sats, shown) {
    if (sats < 0n) throw new TypeError("amount: an amount cannot be negative");
    if (sats > TOTAL_SUPPLY_SATS) {
      throw new TypeError(
        `amount: “${shown}” is more BLOCH than can ever exist. Bloch is capped at ` +
        `${groupDigits(TOTAL_SUPPLY_BLOCH.toString())} BLOCH, of which ` +
        `${groupDigits(GENESIS_ISSUED_BLOCH.toString())} was issued at genesis. Check the amount`);
    }
    return sats;
  }

  // ── Contract B.3 — rendering ──────────────────────────────────────────────

  /**
   * sats -> exact BLOCH decimal string, by BigInt divmod. No float, no toFixed,
   * no toLocaleString, ungrouped.
   *
   * Trailing fractional zeros are trimmed (4000000000000n -> "40000", not
   * "40000.00000000") because eight zeros after every number is noise. `minDp`
   * keeps a floor — a balance hero that alternates between "40000" and "40000.5"
   * reads as unstable — and `grouped` is what `format` sets.
   *
   * Negative BigInts render with a leading "-". They cannot arrive from the wire
   * or from a user (both paths refuse a sign); they can only be the result of
   * local BigInt arithmetic, e.g. a balance delta, and rendering one as though
   * it were positive would be its own lie.
   *
   * @param {bigint|string} v sats
   * @param {{minDp?:number, grouped?:boolean}} [opts]
   * @returns {string}
   */
  function satsToBLOCH(v, opts) {
    const o = opts || {};
    const n = typeof v === "bigint" ? v : satsParse(v);
    const neg = n < 0n;
    const a = neg ? -n : n;
    const whole = (a / SATS_PER_BLOCH).toString();
    let frac = (a % SATS_PER_BLOCH).toString().padStart(DECIMALS, "0");
    frac = frac.replace(/0+$/, "");
    // minDp is a DISPLAY precision, never money — it is safe as a Number, and it
    // is clamped rather than trusted. (`o.minDp | 0` used to do this job; `| 0`
    // is a 32-bit truncation and does not belong anywhere near this file even
    // when it happens to be harmless, because the next person to copy the line
    // will copy it onto an amount.)
    const want = Number(o.minDp);
    const minDp = Number.isFinite(want) ? Math.max(0, Math.min(DECIMALS, Math.trunc(want))) : 0;
    if (frac.length < minDp) frac = frac.padEnd(minDp, "0");
    const head = o.grouped ? groupDigits(whole) : whole;
    return (neg ? "-" : "") + head + (frac ? "." + frac : "");
  }

  /**
   * sats -> grouped BLOCH for display. Exact at every magnitude.
   * satsFormat(571464000000000000n) === "5,714,640,000"
   *
   * @param {bigint|string} v
   * @param {{minDp?:number}} [opts]
   * @returns {string}
   */
  function satsFormat(v, opts) {
    return satsToBLOCH(v, Object.assign({}, opts, { grouped: true }));
  }

  /**
   * sats -> grouped INTEGER satoshis, for the "…  sat" line under a BLOCH figure.
   * satsFormatSats("5604682938086017913") === "5,604,682,938,086,017,913"
   */
  function satsFormatSats(v) {
    const n = typeof v === "bigint" ? v : satsParse(v);
    const neg = n < 0n;
    return (neg ? "-" : "") + groupDigits((neg ? -n : n).toString());
  }

  // ── Contract B.4 — the WASM boundary ──────────────────────────────────────

  /**
   * BigInt sats -> the decimal STRING the signing core takes.
   *
   * The one function that should ever produce an amount argument for the core.
   * Range-checked on the way out, because the core deserialises these into u64
   * and a value it cannot hold is a refusal several layers away from the mistake.
   *
   * @param {bigint} v
   * @returns {string}
   */
  function satsToWire(v) {
    if (typeof v !== "bigint") {
      throw new TypeError(
        `wire amount: expected a BigInt, got ${typeof v} — convert with PosternG4.sats.parse first`);
    }
    if (v < 0n) throw new TypeError(`wire amount: negative (${v}) — the core takes unsigned amounts`);
    if (v > U64_MAX) throw new TypeError(`wire amount: ${v} does not fit in the u64 the core takes`);
    return v.toString();
  }

  // ── Contract B.5 — comparison and sorting ─────────────────────────────────

  /**
   * BigInt-correct comparator, for `Array.prototype.sort`.
   *
   * Sorting amounts is where a wallet quietly picks the wrong coins. Two ways to
   * get it wrong, both of which look like working code:
   *   - sorting the decimal STRINGS lexicographically puts "9" above "10" and
   *     "900" above "5000000000";
   *   - `(a, b) => Number(a - b)` on BigInts throws, and `(a, b) => a - b` on
   *     BigInts returns a BigInt, which `sort` coerces through Number — so a
   *     difference above 2^53 sorts by a rounded value, and a difference that
   *     rounds to 0 leaves the pair in whatever order it was already in.
   * This returns a real -1/0/1 Number, which is what sort wants, computed by
   * BigInt comparison, which is exact.
   *
   * @param {bigint} a @param {bigint} b @returns {-1|0|1}
   */
  function satsCompare(a, b) {
    const x = typeof a === "bigint" ? a : satsParse(a);
    const y = typeof b === "bigint" ? b : satsParse(b);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  /** Largest first — the order coin selection wants. */
  function satsCompareDesc(a, b) { return satsCompare(b, a); }

  /** Exact sum of a list of sat amounts. BigInt accumulator, never `+=` on a
   *  Number, and never `reduce((a,b) => a + Number(b))`. */
  function satsSum(list) {
    let t = 0n;
    for (const v of list || []) t += (typeof v === "bigint" ? v : satsParse(v));
    return t;
  }

  /** The published Contract B surface. */
  const sats = Object.freeze({
    // Contract B, exactly as specified
    parse: satsParse,
    fromUserBLCH: satsFromUserBLCH,
    toBLCH: satsToBLOCH,
    format: satsFormat,
    // The rest of what callers need so they never reach for a float
    tryParse: satsTryParse,
    formatSats: satsFormatSats,
    toWire: satsToWire,
    compare: satsCompare,
    compareDesc: satsCompareDesc,
    sum: satsSum,
    group: groupDigits,
    // Constants, as BigInt
    PER_BLOCH: SATS_PER_BLOCH,
    DECIMALS,
    U64_MAX,
    TOTAL_SUPPLY_BLOCH,
    TOTAL_SUPPLY_SATS,
    GENESIS_ISSUED_BLOCH,
    GENESIS_ISSUED_SATS,
  });

  // ══ CONTRACT L — per-block consensus limits, and the input ceiling ════════
  //
  // The ONLY place in the application that knows what fits in a Genesis-4
  // block. browser/wallet.js's cap guard and modules/wallet.js's staged sender
  // both READ from here; neither carries its own copy of these numbers any
  // more, because the two copies they used to carry disagreed ("about 31
  // coins" vs. the arithmetic below, which said 30 and says 61 since the
  // block cap doubled).
  //
  // Every figure is read out of the frozen node crates
  // (/Users/tiagoacioli/dev/BlochPOS/crates), cited line by line, and every
  // DERIVED figure is written as the derivation, never as its result — so that
  // when the block cap changes, changing MAX_BLOCK_TX_BYTES here is the whole
  // client-side edit.
  //
  //   MAX_BLOCK_TX_BYTES = 524,288   fee_market.rs MAX_BLOCK_TX_BYTES_V2 —
  //                                  the cap on a whole block's transaction
  //                                  payload. A block over it is invalid
  //                                  regardless of gas, so a TRANSACTION over
  //                                  it can never be included anywhere, ever.
  //                                  It was 262,144 (MAX_BLOCK_TX_BYTES, the
  //                                  V1 constant) until EPOCH 800, the flag
  //                                  day at params.rs:170
  //                                  BLOCK_BYTES_V2_ACTIVATION_EPOCH, which
  //                                  passed on 2026-08-21.
  //   BLOCK_GAS_LIMIT    = 60,000,000  fee_market.rs:71. Bytes bind first for
  //                                  signature-heavy transfers — the crate's
  //                                  own `bytes_bind_before_gas` test pins
  //                                  that — so no input ceiling is derived
  //                                  from gas here; the gas cap stays the
  //                                  backstop check it is in the crate.
  //
  // WHY THIS FILE CARRIES THE V2 CAP UNCONDITIONALLY AND DOES NOT REPLICATE
  // THE NODE'S EPOCH GATE.
  //
  // The node asks `max_block_tx_bytes(epoch)` and never a bare constant,
  // because a validator has to judge blocks from BOTH eras — it replays
  // history, and a cap read from node-local state instead of the block's own
  // header slot is how a fleet on one binary splits (the 2026-08-08
  // `expected_bits` fork is the standing reason, cited in params.rs itself).
  // This wallet never replays anything. It only ever builds a transfer for
  // the NEXT block, whose epoch is >= 800 and always will be, so the gate has
  // exactly one answer here — and a JS copy of it would be a second
  // implementation of a consensus rule, which is precisely the failure this
  // whole block exists to remove.
  //
  // The cost of that choice, stated rather than hidden: pointed at a chain
  // still below epoch 800, this planner would over-size and offer a transfer
  // that chain refuses. It would not be silent — the authority named below
  // catches it — and no such chain exists.
  //
  // WHAT ONE TRANSFER INPUT COSTS, at the ceiling (bloch-crypto/src/core/
  // mod.rs:328,330):
  //   txid 32 + vout 4 + PUBKEY_SIZE 3,749 + SIG_SIZE 4,775 = 8,560 bytes.
  //
  // THE FALCON SIGNATURE IS VARIABLE LENGTH AND 4,775 IS ITS CEILING, not its
  // typical size — mod.rs's own comment calls SIG_SIZE "an upper bound;
  // Falcon max 1462". Measured against the shipped core, a real 1-input
  // transfer DECLARES 8,499 bytes (4,000-signature measurement, recorded at
  // browser/wallet.js SIGN_ATTEMPTS), i.e. ~8.4 KB — BELOW this ceiling.
  //
  // THE PLANNER SIZES BY THE CEILING ANYWAY, and here is the decision spelled
  // out, because it is the central call of this block:
  //
  //   - What the consensus cap counts is `declared_tx_bytes` — the size the
  //     CORE declares, which this client cannot know without running the core.
  //     A planner needs a per-input bound that no declaration can exceed, and
  //     the crate's own fee-sizing ceiling is exactly that bound.
  //   - The two mistakes cost wildly different amounts. Sizing by the ceiling
  //     can refuse a transfer the core would have declared just under the cap
  //     — the model puts a 61-input transfer at 522,368 of the 524,288
  //     budget, 99.63%, while the measured slope below extrapolates to
  //     ~511,659, so a 62nd coin might genuinely have fit — costing at most
  //     ONE extra transaction in a staged run. Sizing by the typical lets a
  //     transfer through that the
  //     hedged Falcon then rolls long on, and an over-cap transaction is
  //     ADMITTED to the mempool and never mined and never removed
  //     (engine.rs select_transactions does `break`, not `continue`). One
  //     mistake is a minute of the user's time; the other is a permanently
  //     stuck object the user was told was sent.
  //   - The knife edge is real, not theoretical: under the V1 cap
  //     modules/wallet.js's staged sender recorded that a full 31-coin stage
  //     "sits at the knife edge" and reached for a 32nd coin the moment fees
  //     moved. Doubling the cap did not remove that edge, it MOVED it to
  //     61/62 — and narrowed the framing-allowance window that holds it
  //     there (see LIMIT_TX_OVERHEAD_ALLOWANCE below).
  //
  // THE PLANNER IS NOT THE AUTHORITY. The binding check is, and remains, the
  // core's own `declared_tx_bytes` against MAX_BLOCK_TX_BYTES
  // (browser/wallet.js assertFitsConsensusCaps, run at preview and again on
  // the signed object). The ceiling here exists to refuse EARLY, with a
  // sentence that explains, before the expensive PQ work is attempted — it
  // must never be read as permission the authority did not grant.
  //
  // WHAT THE DOUBLED EIP-1559 TARGET DOES TO THIS WALLET: NOTHING — AND THAT
  // IS A MAINTAINED PROPERTY, NOT AN ACCIDENT.
  //
  // Epoch 800 moved TWO switches, never one: the cap 262,144 -> 524,288 and
  // the byte target 131,072 -> 262,144 (`block_tx_bytes_target`, pinned by
  // fee_market.rs's `the_cap_and_the_target_are_one_switch_not_two`). For any
  // wallet that estimated fees from how full blocks are, that second switch
  // would have changed the MEANING of its estimate without changing a line of
  // its code: 260,079 bytes used to be a saturated block — twice its 131,072
  // target, so the controller raised the price — and the same 260,079 bytes
  // now sits exactly AT the 262,144 target, where the price does not move at
  // all. Same block, opposite fee signal.
  //
  // This wallet does not estimate. It READS `next_base_fee_millisat_per_gas`
  // out of getchaininfo (`getBaseFee`, further down this file) and REFUSES TO
  // SIGN when the field is absent (browser/wallet.js, reason `no-base-fee`),
  // because the base fee is consensus state that every node recomputes and
  // checks value conservation against — a guessed fee is not "slightly
  // wrong", it is rejected everywhere AFTER the wallet has already reported
  // the transfer as sent. There is no target, no utilisation ratio and no
  // tx_bytes/target arithmetic anywhere in this application, so the target's
  // doubling touches nothing on the fee path.
  //
  // tests/limits.test.js asserts that ABSENCE directly, against the source
  // text, with the behavioural control beside it. An absence is only a
  // property while something is watching for it coming back.
  const LIMIT_MAX_BLOCK_TX_BYTES = 524288n;   // fee_market.rs MAX_BLOCK_TX_BYTES_V2 (epoch 800+)
  const LIMIT_BLOCK_GAS_LIMIT = 60000000n;    // fee_market.rs:71
  const LIMIT_PUBKEY_SIZE = 3749n;            // core/mod.rs:328 (hdr + hybrid pk)
  const LIMIT_SIG_SIZE_MAX = 4775n;           // core/mod.rs:330 — CEILING; Falcon is variable
  // The sums are written as sums so a reader can check them against the crate.
  const LIMIT_INPUT_BYTES_MAX = 32n + 4n + LIMIT_PUBKEY_SIZE + LIMIT_SIG_SIZE_MAX; // 8,560
  const LIMIT_OUTPUT_BYTES = 8n + 32n;        // value u64 + script_hash 32 — 40
  // Framing outside inputs/outputs: the 1-byte kind tag and the fixed-width
  // little-endian count/size fields of the canonical encoding (transition.rs
  // canonical_bytes — no varints). Not citable to a single constant in the
  // node, so it is an ALLOWANCE, checked rather than trusted: the calibration
  // test (tests/limits.test.js) asserts the whole per-input model over-covers
  // the core's measured 1-input declaration (8,499 B) with this allowance in
  // place. Any value in [0, 2,048] leaves MAX_TRANSFER_INPUTS at 61; 128 is
  // comfortably past any fixed-field framing a 1-byte-tag encoding carries.
  //
  // THAT WINDOW NARROWED WHEN THE CAP GREW — re-measured here, not inherited.
  // Under the 262,144 cap the window was [0, 5,264]; under 524,288 it is
  // [0, 2,048], 2.57x narrower. Doubling the cap did not double the leftover,
  // because the leftover is what remains after a whole number of 8,560-byte
  // inputs: 61 of them plus two outputs leave 1,920 B of slack (99.63% of the
  // payload used), where 30 of them left 5,136 B (98.04% used). The allowance
  // in force is 128, still 16x inside the window, so nothing here is close to
  // the edge — but the edge moved, and this comment says where it is now
  // instead of repeating a number that stopped being true at epoch 800.
  const LIMIT_TX_OVERHEAD_ALLOWANCE = 128n;
  // THE DERIVED CEILING: how many ceiling-sized inputs fit beside two outputs
  // (recipient + change) and the framing allowance, in one block's whole
  // payload budget. floor((524,288 − 128 − 80) / 8,560) = 61 today; it was 30
  // under the V1 cap, and moving the one constant above is the entire edit
  // that took it from 30 to 61. To raise the cap when the chain does, change
  // MAX_BLOCK_TX_BYTES above and nothing else — this number follows.
  //
  // WHY THE CEILING STILL OVER-COVERS AT 61, with no 61-input measurement in
  // anyone's hand. The model's slope is 8,560 B per input. The MEASURED
  // slope, across the only two declarations ever taken from the shipped core
  // — 8,499 B at 1 input and 260,079 B at 31 — is (260,079 − 8,499)/30 =
  // 8,386 B per input. The model is STEEPER than reality, so the gap between
  // them widens with n instead of closing: at 61 inputs the model says
  // 522,368 against ~511,659 extrapolated. A bound that pulls away from the
  // thing it bounds stays a bound at every n above the ones measured, which
  // is what carries the 61 without inventing a measurement nobody took.
  // tests/limits.test.js pins the two slopes against each other.
  const LIMIT_MAX_TRANSFER_INPUTS =
    (LIMIT_MAX_BLOCK_TX_BYTES - LIMIT_TX_OVERHEAD_ALLOWANCE - 2n * LIMIT_OUTPUT_BYTES)
      / LIMIT_INPUT_BYTES_MAX;
  // What one consolidation round achieves, net: up to MAX_TRANSFER_INPUTS
  // coins in, TWO outputs back out (the transfer op always builds an amount
  // output and a change output; this wallet has no single-output send-max op,
  // so the honest arithmetic is the two-output one). 61 − 2 = 59 fewer coins
  // per round, and the floor a consolidation can reach is 2 coins, not 1.
  const LIMIT_CONSOLIDATION_NET = LIMIT_MAX_TRANSFER_INPUTS - 2n;

  // ── THE DEDUPLICATED FORMAT (TransferV2, wire tag 0x06) ───────────────────
  //
  // From epoch 800 a transfer may carry ONE (pubkey, signature) pair per OWNER
  // in a witness table, with each input pointing at its entry by index instead
  // of carrying its own copy. For a wallet consolidating its own coins — one
  // owner, many inputs — that replaces n witness pairs with one.
  //
  // MEASURED against the compiled crate (not derived from the docs): with one
  // table entry and two outputs, a V2 transfer at the signature ceiling is
  // 8,649 bytes plus 40 bytes per input, against V1's 8,681 + 8,568 per input.
  // At n = 1 V2 is 8 bytes LARGER; the crossover is immediate at n = 2. That
  // is why the core chooses per transfer (`choose_format`: V2 only when there
  // are strictly fewer owners than inputs) instead of "V2 after the flag day".
  const LIMIT_V2_INPUT_BYTES = 32n + 4n + 4n;          // txid + vout + key_index — 40
  // One table entry: each variable-length field carries a 4-byte LE length
  // prefix (transition.rs canonical_bytes `put`), which the V1 per-input model
  // above folds into its allowance and this one states outright.
  const LIMIT_V2_WITNESS_ENTRY_BYTES = 4n + LIMIT_PUBKEY_SIZE + 4n + LIMIT_SIG_SIZE_MAX; // 8,532
  // Fixed framing of the 0x06 encoding: kind tag 1 + three u32 counts (keys,
  // inputs, outputs) + tx_bytes u64 + tip u128.
  const LIMIT_V2_FRAMING_BYTES = 1n + 4n + 4n + 4n + 8n + 16n; // 37

  // THE SECOND CEILING, WHICH IS NOT THE BLOCK'S.
  //
  // A transfer also has to be SUBMITTED. `sendrawtransaction` carries the
  // transaction as HEX — two characters per byte — inside a JSON-RPC envelope,
  // and the node refuses a body over MAX_BODY_BYTES (rpc.rs:77, 1 MiB) before
  // parsing any of it. So the largest raw transaction that can be handed to a
  // node is about half the block cap's worth of bytes, and there is a DEAD
  // BAND above it: transactions consensus would accept and no client can
  // deliver. The guard checks both ceilings, not just the block's.
  const LIMIT_RPC_MAX_BODY_BYTES = 1048576n;      // rpc.rs:77 MAX_BODY_BYTES
  const LIMIT_RPC_ENVELOPE_ALLOWANCE = 68n;       // {"jsonrpc","id","method","params":[""]}
  const LIMIT_RPC_MAX_RAW_TX_BYTES =
    (LIMIT_RPC_MAX_BODY_BYTES - LIMIT_RPC_ENVELOPE_ALLOWANCE) / 2n;   // 524,254

  // THE THIRD CEILING, AND THE ONE THAT ACTUALLY BINDS.
  //
  // `getutxos`/`listunspent` return at most UTXO_PAGE_MAX outputs and take NO
  // cursor (rpc.rs:99, and rpc.rs:704 says so in as many words). A wallet
  // cannot spend a coin it cannot see, so no single transfer this client
  // builds can reach past one page — whatever the block cap would allow.
  //
  // HOW BIG THIS BLIND SPOT ACTUALLY IS, measured rather than described: the
  // founder address (script_hash e986db51…) held 407,844 unspent outputs on
  // 2026-08-25 and the node returns 1,000 of them. This wallet can see 0.24%
  // of that address, and `truncated: true` is the node's own admission of it.
  //
  // WHAT WOULD BE NEEDED TO REMOVE IT — a NODE change, out of this client's
  // reach, recorded here so the gap is a known debt and not a mystery:
  //   1. A real cursor on `getutxos`. Measured 2026-08-22: `offset`, `cursor`
  //      and `start` are all accepted and SILENTLY IGNORED — every call
  //      returns the same first page — and `limit: 5000` clamps to 1,000. A
  //      parameter that is ignored rather than rejected is worse than absent,
  //      because a client that pages against it loops forever on page one
  //      believing it is making progress.
  //   2. A STABLE ORDER to page over. The node promises none today, so two
  //      calls can return different subsets; without an order, a cursor would
  //      still be able to skip and repeat coins.
  //   3. Ideally a server-side "coins totalling at least N" selection, so a
  //      large spend does not require the client to hold the whole set.
  // Until (1) and (2) exist, every coin list in this wallet is a SAMPLE, and
  // the honest thing a UI can do is say so — which is what `truncated` is
  // propagated for. Balances do NOT have this problem: `getbalance` reports
  // the true total and the true `utxo_count` for the whole address, which is
  // why it, and never a sum of this list, is the only balance source here.
  const LIMIT_UTXO_PAGE_MAX = 1000n;              // rpc.rs:99 UTXO_PAGE_MAX

  // THE DERIVED V2 CEILING: the smallest of the three, written as the
  // derivation so that fixing any one of them moves this number by itself.
  //
  //   from the block cap ... 12,890   (524,288 − 37 − 80 − 8,532) / 40
  //   from the RPC body ..... 12,890   (524,254 − 37 − 80 − 8,532) / 40
  //   from one UTXO page ..... 1,000
  //
  // SO THE HONEST NUMBER TO SAY IS 1,000 INPUTS, NOT 12,890. The format is
  // worth ~12,890 and this client can reach 1,000 of it; the gap is the node's
  // missing UTXO cursor, not something the wallet can arrange around. Quoting
  // the number the format could carry, rather than the number this wallet can
  // actually spend, would be exactly the kind of claim the balance path in
  // this file already refuses to make.
  function maxTransferInputsV2(blockTxBytesCap) {
    if (typeof blockTxBytesCap !== "bigint" || blockTxBytesCap < 0n) {
      throw new TypeError("maxTransferInputsV2: pass the cap as a BigInt byte count");
    }
    const cap = blockTxBytesCap < LIMIT_RPC_MAX_RAW_TX_BYTES
      ? blockTxBytesCap
      : LIMIT_RPC_MAX_RAW_TX_BYTES;
    const room = cap - LIMIT_V2_FRAMING_BYTES - 2n * LIMIT_OUTPUT_BYTES
      - LIMIT_V2_WITNESS_ENTRY_BYTES;
    const byBytes = room > 0n ? room / LIMIT_V2_INPUT_BYTES : 0n;
    return byBytes < LIMIT_UTXO_PAGE_MAX ? byBytes : LIMIT_UTXO_PAGE_MAX;
  }
  const LIMIT_MAX_TRANSFER_INPUTS_V2 = maxTransferInputsV2(LIMIT_MAX_BLOCK_TX_BYTES);
  const LIMIT_CONSOLIDATION_NET_V2 = LIMIT_MAX_TRANSFER_INPUTS_V2 - 2n;

  // ── CHOOSING BETWEEN THE TWO CEILINGS ─────────────────────────────────────
  //
  // WHY THE DEFAULT IS V1, AND WHY THAT IS NOT TIMIDITY. Only the exact token
  // "transfer_v2" selects the larger ceiling; undefined, null, "", a Number,
  // "v2" and "TRANSFER_V2" all land on V1. A caller that has not yet learned
  // what the loaded core can do must plan with the SMALLER number, because the
  // two errors are not the same size:
  //   over-promising  builds a transfer no block can carry — the PQ signing is
  //                   already paid for and the node refuses it, AFTER the user
  //                   was told the send was on its way;
  //   under-promising costs one extra transfer.
  // That asymmetry, not caution, is the whole reason the fallthrough arm is
  // V1. The capability is discovered late (browser/core.js `features()` reads
  // it out of the verified wasm bytes), so "not known yet" is a state this
  // path is in routinely, not an error case.
  //
  // The normalisation lives in ONE place so the ceiling, the consolidation net
  // and the token a caller is shown can never disagree about what was chosen.
  function transferFormatToken(format) {
    if (format === "transfer_v2") return "transfer_v2";
    return "transfer_v1";
  }
  /** The input ceiling in force for a format token. @returns {bigint} */
  function inputCeilingFor(format) {
    if (transferFormatToken(format) === "transfer_v2") return LIMIT_MAX_TRANSFER_INPUTS_V2;
    return LIMIT_MAX_TRANSFER_INPUTS;
  }
  /** What one consolidation round nets under that same format. @returns {bigint} */
  function consolidationNetFor(format) {
    if (transferFormatToken(format) === "transfer_v2") return LIMIT_CONSOLIDATION_NET_V2;
    return LIMIT_CONSOLIDATION_NET;
  }

  /**
   * How many transactions it takes to consolidate `utxoCount` coins down to
   * the 2-coin floor. This is the number the consolidation plan must SAY —
   * "combine my coins" is N transactions, not one, and pretending otherwise
   * is the lie this whole front exists to remove.
   *
   * ceil((K − 2) / net) with net = 59 today. "About": a round the core
   * settles with fewer than the offered inputs reduces less, so treat this as
   * a schedule, not a promise. Input is a COUNT (getbalance's utxo_count,
   * which is NOT truncated — unlike the getutxos list, which caps at 1000 and
   * must never be counted for this).
   *
   * @param {number} utxoCount
   * @returns {number|null} rounds, 0 when nothing to do, null when the count
   *   is not a usable number (unknown must never render as 0)
   */
  function consolidationSteps(utxoCount, format) {
    const k = parseCount(utxoCount, 0, null);
    if (k === null) return null;
    if (k <= 2) return 0;
    // Default stays V1 so an un-updated caller keeps its old, LARGER answer.
    // A stale caller over-stating the work is a schedule that comes in early;
    // a stale caller silently inheriting the V2 number would under-state it,
    // which is the direction that turns into a broken promise. The choice is
    // consolidationNetFor's, so this and the input ceiling cannot drift apart.
    const net = Number(consolidationNetFor(format));
    return Math.ceil((k - 2) / net);
  }

  /**
   * How many SEPARATE TRANSFERS an amount needs, when the coins that cover it
   * outnumber what one transfer can spend.
   *
   * This is NOT consolidationSteps. That one answers "how many rounds to merge
   * K coins into 2"; this one answers the question the user actually asked —
   * "I typed 30,000,000, what happens now?" — and the two have different
   * arithmetic (ceil(needed/ceiling) against ceil((K−2)/net)) because merging
   * hands two coins back into the pile each round and sending does not.
   *
   * Kept here, beside the ceiling it divides by, so the wallet and the
   * extension cannot quote two different numbers of transfers for one amount.
   *
   * @param {number} coinsNeeded coins the amount reaches for, largest first —
   *   `assessInputBudget().coinsNeeded`.
   * @param {string} [format] transfer format token; anything but the exact
   *   "transfer_v2" judges at the V1 ceiling, as everywhere else in this file.
   * @returns {number|null} transfers, or null when `coinsNeeded` is not a
   *   usable count — UNKNOWN must never render as 1.
   */
  function transfersForAmount(coinsNeeded, format) {
    const n = parseCount(coinsNeeded, 0, null);
    if (n === null) return null;
    if (n === 0) return 0;
    const ceiling = Number(inputCeilingFor(format));
    if (!(ceiling > 0)) return null;
    return Math.ceil(n / ceiling);
  }

  /**
   * The planner's arithmetic, pure and testable: can `want` sats be covered
   * by coins of these values WITHIN the input ceiling, before any fee?
   *
   * Deliberately fee-blind, and therefore sound in one direction only: a fee
   * only ever makes coverage HARDER, so `coversWithinBudget: false` on a set
   * that covers in full is a certain refusal at the ceiling model, while
   * `true` promises nothing — the core may still reach for one more coin to
   * pay the fee, and the declared-bytes authority judges that.
   *
   * @param {bigint[]} values coin values in sats (BigInt each — throws on
   *   anything else; money never transits this file as a Number)
   * @param {bigint} want the amount to cover
   * @param {string} [format] the transfer format the core will build. Only the
   *   exact token "transfer_v2" raises the ceiling; anything else, including
   *   omitting the argument, judges against V1 — see inputCeilingFor above for
   *   why the unknown case must take the smaller number.
   * @returns {{coinsFit:number, coinsAvailable:number, totalSats:bigint,
   *            topSats:bigint, coversInFull:boolean, coversWithinBudget:boolean,
   *            coinsNeeded:number|null, format:string}} coinsNeeded = how many
   *   coins, largest first, the amount reaches for before any fee; null when
   *   even every coin together cannot cover it. `format` is the NORMALISED
   *   token — "transfer_v2" or "transfer_v1" — naming the ceiling that actually
   *   judged this set, not the string the caller passed in, so a refusal can
   *   quote the rule it was refused under.
   */
  function assessInputBudget(values, want, format) {
    if (typeof want !== "bigint" || want < 0n) {
      throw new TypeError("assessInputBudget: pass the amount as an unsigned BigInt of sats");
    }
    const vals = (values || []).map((v, i) => {
      if (typeof v !== "bigint" || v < 0n) {
        throw new TypeError(`assessInputBudget: coin ${i} is not an unsigned BigInt`);
      }
      return v;
    }).sort(satsCompareDesc);
    const fmt = transferFormatToken(format);
    const coinsFit = Number(inputCeilingFor(fmt));
    let total = 0n, top = 0n, needed = null, acc = 0n;
    for (let i = 0; i < vals.length; i++) {
      total += vals[i];
      if (i < coinsFit) top += vals[i];
      if (needed === null) { acc += vals[i]; if (acc >= want) needed = i + 1; }
    }
    return {
      coinsFit,
      coinsAvailable: vals.length,
      totalSats: total,
      topSats: top,
      coversInFull: total >= want,
      coversWithinBudget: top >= want,
      coinsNeeded: needed,
      format: fmt,
    };
  }

  /** The published Contract L surface. BigInt fields; do arithmetic in BigInt. */
  const limits = Object.freeze({
    MAX_BLOCK_TX_BYTES: LIMIT_MAX_BLOCK_TX_BYTES,
    BLOCK_GAS_LIMIT: LIMIT_BLOCK_GAS_LIMIT,
    PUBKEY_SIZE: LIMIT_PUBKEY_SIZE,
    SIG_SIZE_MAX: LIMIT_SIG_SIZE_MAX,
    INPUT_BYTES_MAX: LIMIT_INPUT_BYTES_MAX,
    OUTPUT_BYTES: LIMIT_OUTPUT_BYTES,
    TX_OVERHEAD_ALLOWANCE: LIMIT_TX_OVERHEAD_ALLOWANCE,
    MAX_TRANSFER_INPUTS: LIMIT_MAX_TRANSFER_INPUTS,
    CONSOLIDATION_NET: LIMIT_CONSOLIDATION_NET,
    // The deduplicated format, and the three ceilings it is the minimum of.
    V2_INPUT_BYTES: LIMIT_V2_INPUT_BYTES,
    V2_WITNESS_ENTRY_BYTES: LIMIT_V2_WITNESS_ENTRY_BYTES,
    V2_FRAMING_BYTES: LIMIT_V2_FRAMING_BYTES,
    RPC_MAX_BODY_BYTES: LIMIT_RPC_MAX_BODY_BYTES,
    RPC_MAX_RAW_TX_BYTES: LIMIT_RPC_MAX_RAW_TX_BYTES,
    UTXO_PAGE_MAX: LIMIT_UTXO_PAGE_MAX,
    MAX_TRANSFER_INPUTS_V2: LIMIT_MAX_TRANSFER_INPUTS_V2,
    CONSOLIDATION_NET_V2: LIMIT_CONSOLIDATION_NET_V2,
    maxTransferInputsV2,
    inputCeilingFor,
    consolidationNetFor,
    consolidationSteps,
    transfersForAmount,
    assessInputBudget,
    /**
     * The same derivation over an arbitrary block cap — exported so a test can
     * prove the ceiling FOLLOWS the cap (the reason it is derived at all)
     * without asserting anything about caps this chain does not have.
     */
    maxTransferInputsForCap(blockTxBytesCap) {
      if (typeof blockTxBytesCap !== "bigint" || blockTxBytesCap < 0n) {
        throw new TypeError("maxTransferInputsForCap: pass the cap as a BigInt byte count");
      }
      const room = blockTxBytesCap - LIMIT_TX_OVERHEAD_ALLOWANCE - 2n * LIMIT_OUTPUT_BYTES;
      return room > 0n ? room / LIMIT_INPUT_BYTES_MAX : 0n;
    },
  });

  // ── legacy names ──────────────────────────────────────────────────────────
  // Kept because modules/wallet.js and modules/explorer.js (other owners' files)
  // call them today. Every one is a DELEGATE — there is no second implementation
  // of the conversion behind any of them.

  /**
   * Liberal coercion of an amount that may have been typed into a SATS field.
   *
   * Differs from `sats.parse` in exactly one way, deliberately: it tolerates
   * group separators and surrounding whitespace, because a user pasting a
   * satoshi figure may well paste "5,604,682,938,086,017,913". A separator in an
   * INTEGER cannot be a decimal point, so unlike the BLOCH field there is no
   * ambiguity to guess at. Everything else — sign, range, exponent — is
   * `sats.parse`'s rules, so a negative or an out-of-range value is refused here
   * too. (It used to accept `[+-]?\d+`, which let "-100" through into the send
   * path as a negative amount.)
   */
  function toSats(v) {
    if (typeof v === "bigint") return satsParse(v);
    if (typeof v === "number") return satsParse(v); // refuses, with the right message
    if (typeof v !== "string") return satsParse(v);
    return satsParse(v.trim().replace(/[_,\s]/g, ""));
  }
  /** Non-throwing toSats — null (UNKNOWN) instead of an exception. */
  function trySats(v) {
    try { return toSats(v); } catch (_) { return null; }
  }
  /** @deprecated use sats.toBLCH */
  const satsToBloch = satsToBLOCH;
  /** @deprecated use sats.format */
  const fmtBloch = satsFormat;
  /** @deprecated use sats.formatSats */
  const fmtSatsGrouped = satsFormatSats;
  /** @deprecated use sats.fromUserBLCH */
  const blochToSats = satsFromUserBLCH;

  // ── reply parsers ─────────────────────────────────────────────────────────
  // These THROW on an unrecognised shape. They must never fall back to 0: a
  // zero produced by a parser is indistinguishable, on screen, from a zero
  // produced by the chain.
  //
  // MONEY vs COUNTS. Every field below is one or the other, and they get
  // different treatment:
  //   money  (balance_sat, value_sat, *_fee_millisat_per_gas, stake) — BigInt
  //          via sats.parse. Never a Number, at any point, for any reason.
  //   counts (height, slot, epoch, utxo_count, returned, total, vout, bytes) —
  //          genuinely small integers, safe as Numbers, but parsed STRICTLY.
  // The strictness on counts is not pedantry. `Number(null)` is 0, `Number("")`
  // is 0, `Number([])` is 0, `Number(true)` is 1 and `Number("0x10")` is 16 —
  // so a plain `Number(x)` turns an ABSENT field into a confident claim. For a
  // `vout` that claim is "spend output 0 of that transaction", which is not a
  // rounding error, it is signing over the wrong outpoint.

  /**
   * Strict small-integer parse for a COUNT — never for money.
   * Accepts a JS number that is a safe integer, or a bare decimal string.
   * Returns null (UNKNOWN) for anything else, including null/undefined/bool/
   * array/hex/exponent. Callers must render null as "—", never as 0.
   */
  function parseCount(v, min, max) {
    let n = null;
    if (typeof v === "number") {
      n = Number.isSafeInteger(v) ? v : null;
    } else if (typeof v === "string" && /^\d+$/.test(v.trim()) && v.trim() !== "") {
      const t = v.trim();
      // A digit string longer than 15 chars may not survive Number() exactly;
      // no count on this chain is that large, so treat it as unrecognised.
      n = t.length <= 15 ? Number(t) : null;
    }
    if (n === null) return null;
    if (min != null && n < min) return null;
    if (max != null && n > max) return null;
    return n;
  }

  /** parseCount, but a failure THROWS — for a count that is load-bearing rather
   *  than decorative (a vout about to be signed over, a height being asserted). */
  function requireCount(v, min, max, what) {
    const n = parseCount(v, min, max);
    if (n === null) {
      throw new Error(`${what}: expected a whole number in [${min}, ${max}], got ${JSON.stringify(v)}`);
    }
    return n;
  }

  /**
   * Parse a `getbalance` result: {script_hash, balance_sat:"…", utxo_count}.
   * @returns {{scriptHash:string, sats:bigint, utxoCount:number}}
   */
  function parseBalance(result) {
    if (!result || typeof result !== "object") {
      throw new Error("getbalance: node returned no result object");
    }
    // `balance_sat` is the G4 field. The G3 aliases are NOT accepted: G3's
    // `bloch` was a float in whole BLOCH and its `satoshis` was a JSON number,
    // so silently reading either here would reintroduce exactly the precision
    // loss this module exists to remove.
    if (result.balance_sat === undefined || result.balance_sat === null) {
      throw new Error(
        "getbalance: reply has no `balance_sat` — this is not a Genesis-4 answer " +
        `(got keys: ${Object.keys(result).join(", ") || "none"})`);
    }
    // MONEY. Strict: the node emits this through its `Json::sat` helper, which
    // is documented to produce a bare unsigned decimal string. `toSats`'s
    // liberality (commas, whitespace, an accepted leading sign) has no business
    // on the wire path — a balance that arrives with a "-" is a reply to refuse,
    // not one to render as a negative balance.
    const sats = satsParse(result.balance_sat);
    return {
      scriptHash: String(result.script_hash || ""),
      sats,
      // A COUNT, not money. An absent or unrecognised one is null (unknown),
      // never 0 (a claim that the address holds nothing).
      utxoCount: parseCount(result.utxo_count, 0, null),
    };
  }

  /**
   * Parse a `getutxos` / `listunspent` result.
   * G4 shape: {script_hash, total, returned, truncated, utxos:[{txid, vout,
   * value_sat:"…", script_hash}]}. Note `vout` (G3 called it `index`) and
   * `value_sat` as a STRING (G3 sent `value` as a number).
   * @returns {{scriptHash:string, total:number|null, returned:number,
   *            truncated:boolean, utxos:Array, sumSats:bigint}}
   */
  function parseUtxos(result) {
    if (!result || typeof result !== "object") {
      throw new Error("getutxos: node returned no result object");
    }
    const list = Array.isArray(result.utxos) ? result.utxos
      : Array.isArray(result) ? result
      : null;
    if (!list) throw new Error("getutxos: reply carries no `utxos` array");
    if (list.length > UTXO_MAX_RETURNED) {
      throw new Error(`getutxos: node returned ${list.length} entries above the ${UTXO_MAX_RETURNED} cap`);
    }
    let sum = 0n;
    const utxos = list.map((u, i) => {
      if (!u || typeof u !== "object") throw new Error(`getutxos: entry ${i} is not an object`);
      // Accept `vout` (G4) or `index` (G3) for the outpoint, but the VALUE is
      // read only from a field we know carries a lossless string.
      //
      // `vout` is parsed STRICTLY. The old line was `Number(voutRaw)` behind an
      // Number.isInteger range check, which looks airtight and is not:
      // `Number(null)` is 0, `Number(true)` is 1, `Number([])` is 0 and
      // `Number("0x10")` is 16 — all whole numbers inside [0, 2^32), so all of
      // them passed. An entry whose `vout` was explicitly null therefore became
      // "output 0", and this value is signed over. Wrong outpoint, no error.
      const voutRaw = u.vout !== undefined ? u.vout : u.index;
      const vout = requireCount(voutRaw, 0, 0xffffffff, `getutxos: entry ${i} vout`);
      if (u.value_sat === undefined || u.value_sat === null) {
        throw new Error(`getutxos: entry ${i} has no \`value_sat\` — not a Genesis-4 UTXO`);
      }
      // MONEY, and money that is about to be signed over — the strictest path in
      // the file. A live allocation output here is 1e18 sat (111x 2^53-1), so
      // nothing on this line may narrow to a Number even for an instant.
      const value = satsParse(u.value_sat);
      sum += value;
      return {
        txid: String(u.txid || ""),
        vout,
        sats: value,
        scriptHash: String(u.script_hash || result.script_hash || ""),
      };
    });
    const total = parseCount(result.total, 0, null);
    const returned = parseCount(result.returned, 0, null);
    return {
      scriptHash: String(result.script_hash || ""),
      total,
      returned: returned === null ? utxos.length : returned,
      // `truncated` is only false when the node SAYS so; an absent flag with a
      // total above what we got back is still truncated. Count comparison, and
      // both sides are counts — never let an amount reach this line.
      truncated: result.truncated === true || (total !== null && total > utxos.length),
      utxos,
      sumSats: sum,
    };
  }

  /**
   * Parse a `gettxout` result: {txid, vout, unspent, utxo|null, at_slot}
   * (bloch-pos-node/src/rpc.rs txout_json, :1515).
   *
   * `unspent` must be a BOOLEAN LITERAL. The node states it as its own field
   * precisely so a caller never has to guess what a null `utxo` means, and
   * this parser holds it to that: `"true"`, 1, or an absent field all THROW,
   * because coercing any of them decides a "was this coin spent?" question —
   * a question people settle money on — from a shape the node never produced.
   *
   * The answer is from COMMITTED state (`at_slot` is the head it answered
   * from), so a just-broadcast transfer's inputs still read unspent:true for
   * ~a block. And note what `unspent: false` does and does not claim: this
   * outpoint is not in the committed set — spent, or never existed. It does
   * NOT say WHO spent it; a caller watching its own transfer land must word
   * that honestly ("these coins are spent" is provable, "our transfer
   * applied" is not, if the same seed lives on two devices).
   *
   * @returns {{txid:string, vout:number|null, unspent:boolean,
   *            utxo:{txid:string, vout:number, sats:bigint, scriptHash:string}|null,
   *            atSlot:number|null}}
   */
  function parseTxout(result) {
    if (!result || typeof result !== "object") {
      throw new Error("gettxout: node returned no result object");
    }
    if (result.unspent !== true && result.unspent !== false) {
      throw new Error(
        "gettxout: reply carries no boolean `unspent` (got " + JSON.stringify(result.unspent) +
        ") — refusing to guess whether this coin is spent from a shape the node does not produce");
    }
    let utxo = null;
    if (result.utxo !== null && result.utxo !== undefined) {
      const u = result.utxo;
      if (typeof u !== "object") {
        throw new Error("gettxout: `utxo` is neither an object nor null");
      }
      if (u.value_sat === undefined || u.value_sat === null) {
        throw new Error("gettxout: utxo has no `value_sat` — not a Genesis-4 answer");
      }
      utxo = {
        txid: String(u.txid || ""),
        // A COUNT about to identify an outpoint — strict, like parseUtxos.
        vout: requireCount(u.vout, 0, 0xffffffff, "gettxout: utxo vout"),
        // MONEY. BigInt via the strict wire parser, never a Number.
        sats: satsParse(u.value_sat),
        scriptHash: String(u.script_hash || ""),
      };
    }
    // txout_json always pairs unspent:true with the entry itself; a reply that
    // claims "unspent" while withholding the output is not that shape.
    if (result.unspent === true && utxo === null) {
      throw new Error("gettxout: `unspent` is true but no `utxo` came with it — unrecognised reply");
    }
    return {
      txid: String(result.txid || ""),
      vout: parseCount(result.vout, 0, 0xffffffff),
      unspent: result.unspent,
      utxo,
      // A COUNT (the committed slot this answer is pinned to). Null when the
      // node did not say — rendered as unknown, never as slot 0.
      atSlot: parseCount(result.at_slot, 0, null),
    };
  }

  /**
   * Parse a `getchaininfo` result. The authoritative height source — G4's
   * `getblockcount` is unreliable and shape-changed.
   * Big string fields (total_active_stake_sat) come back as BigInt.
   */
  function parseChainInfo(result) {
    if (!result || typeof result !== "object") {
      throw new Error("getchaininfo: node returned no result object");
    }
    // Every field here is a COUNT (height, slot, epoch, validator tallies) apart
    // from the three amount fields at the bottom, which are money. The old `num`
    // helper was `Number.isFinite(Number(v)) ? Number(v) : null`, which turns an
    // explicit `null` into 0 and "0x10" into 16 — so an absent finalized_height
    // rendered as "finalized at 0", a claim the node never made.
    const h = parseCount(result.height, 0, null);
    if (h === null) {
      throw new Error("getchaininfo: reply carries no usable `height`");
    }
    const num = (v) => parseCount(v, 0, null);
    return {
      height: h,
      slot: num(result.slot),
      finalizedHeight: num(result.finalized_height),
      epoch: num(result.epoch),
      slotInEpoch: num(result.slot_in_epoch),
      slotsPerEpoch: num(result.slots_per_epoch),
      blockId: String(result.block_id || ""),
      stateRoot: String(result.state_root || ""),
      validatorsTotal: num(result.validators && result.validators.total),
      validatorsActive: num(result.validators && result.validators.active),
      // MONEY. Total active stake is 64 validators x 25,000 BLOCH today, but it
      // is an aggregate with no small bound — BigInt or null, never a rounded
      // Number.
      totalActiveStakeSat: satsTryParse(result.total_active_stake_sat),
      // ── the gas price a Genesis-4 transfer must be built against ──────────
      // Both are emitted by the node's chaininfo builder through `Json::sat`
      // (rpc.rs: `("base_fee_millisat_per_gas", Json::sat(state.base_fee_
      // millisat_per_gas()))` and the same for `next_…`), i.e. decimal STRINGS
      // under R3 — so they get the same BigInt-or-null treatment as every other
      // amount and are NEVER defaulted.
      //
      // WHICH ONE PRICES A NEW TRANSFER: the NEXT one. These two names are a
      // trap, and the trap is worth spelling out because picking the obvious
      // field produces a transaction the entire network refuses.
      //   `base_fee_millisat_per_gas`      = what the HEAD block charged. Past
      //                                      tense. transition.rs is explicit:
      //                                      "The price this state's block
      //                                      charged. The **next** block's
      //                                      price is Self::next_base_fee —
      //                                      never this value carried forward".
      //   `next_base_fee_millisat_per_gas` = what the block this transfer can
      //                                      actually land in will charge.
      // `apply_block` fixes a block's price with `let base_fee =
      // pre.next_base_fee();` and charges EVERY transaction in that block at
      // it, and the producer prices its mempool with the very same call. A
      // transfer built against the head's price fails value conservation at
      // every validating node.
      baseFeeMillisatPerGas: satsTryParse(result.base_fee_millisat_per_gas),
      nextBaseFeeMillisatPerGas: satsTryParse(result.next_base_fee_millisat_per_gas),
      mempool: num(result.mempool),
      wallSlot: num(result.wall_slot),
      // A count, but signed — a node behind the wall clock reports a positive
      // lag and one running ahead could report a negative one, so this is the
      // one field here that is allowed below zero.
      behindBySlots: (() => {
        if (typeof result.behind_by_slots === "number") {
          return Number.isSafeInteger(result.behind_by_slots) ? result.behind_by_slots : null;
        }
        const s = typeof result.behind_by_slots === "string" ? result.behind_by_slots.trim() : "";
        if (!/^-?\d{1,15}$/.test(s)) return null;
        return Number(s);
      })(),
      raw: result,
    };
  }

  // Reviewed mainnet identity shared by the existing native-account and route
  // boundaries. This does NOT claim an endpoint currently serves these fields;
  // it is the value a future native DEX/bridge boundary must compare against
  // before trusting any node-authored capability, quote or state response.
  const MAINNET_CHAIN_IDENTITY = Object.freeze({
    rule: "canonical-manifest-v1",
    genesis: "9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415",
    nativeDomain: "f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966",
    nativeFormat: "BPOSMAN1",
  });

  /**
   * Require the canonical identity fields from a raw `getchaininfo` result.
   *
   * This is deliberately separate from `parseChainInfo`: current base-chain
   * reads predate the identity fields, while future native DEX/bridge state
   * must fail closed until a node supplies all four. Callers cannot pass their
   * own expectation and thereby let a response choose the network. The result
   * remains trusted-node observation, not an independent consensus proof.
   */
  function requireMainnetChainIdentity(result) {
    if (!result || typeof result !== "object" || Array.isArray(result)) {
      throw new Error("getchaininfo: canonical mainnet identity is unavailable or mismatched");
    }
    const ownString = (name) => {
      let descriptor;
      try { descriptor = Object.getOwnPropertyDescriptor(result, name); } catch (_) {}
      // Reject inherited fields and accessors. Network JSON produces own data
      // properties; accepting anything else only gives a Proxy/getter a second
      // interpretation path at this trust boundary.
      if (!descriptor || !("value" in descriptor) || typeof descriptor.value !== "string") {
        throw new Error("getchaininfo: canonical mainnet identity is unavailable or mismatched");
      }
      return descriptor.value;
    };
    const rule = ownString("chain_identity_rule");
    const genesis = ownString("genesis");
    const nativeDomain = ownString("native_domain");
    const nativeFormat = ownString("native_format");
    if (rule !== MAINNET_CHAIN_IDENTITY.rule ||
        genesis.length !== 64 || !/^[0-9a-f]{64}$/.test(genesis) ||
        genesis !== MAINNET_CHAIN_IDENTITY.genesis ||
        nativeDomain.length !== 64 || !/^[0-9a-f]{64}$/.test(nativeDomain) ||
        nativeDomain !== MAINNET_CHAIN_IDENTITY.nativeDomain ||
        nativeFormat !== MAINNET_CHAIN_IDENTITY.nativeFormat) {
      throw new Error("getchaininfo: canonical mainnet identity is unavailable or mismatched");
    }
    return Object.freeze({ rule, genesis, nativeDomain, nativeFormat });
  }

  // ── the call seam ─────────────────────────────────────────────────────────
  // Every G4 read in the app goes through here so the failure contract is
  // written once. Host-agnostic (it reaches for globalThis.Postern.rpc at CALL time,
  // not load time, so this file still imports cleanly under Node for tests).

  // An error carrying WHY it failed, so a pane can word its message honestly
  // instead of collapsing every cause into "couldn't reach the node".
  //   "unavailable" — refused before any I/O (method not on this chain)
  //   "unreachable" — no answer at all (network, proxy, or our own deadline)
  //   "rpc"         — the node answered, with an error (incl. its 10s timeout)
  //   "shape"       — the node answered something we cannot parse
  function g4Error(kind, message, cause) {
    const e = new Error(message);
    e.kind = kind;
    e.g4 = true;
    if (cause) e.cause = cause;
    return e;
  }

  /**
   * Issue one G4 JSON-RPC read and return its `result`.
   *
   * Throws — always — when there is no trustworthy answer. It has no default
   * return and no `|| 0`, deliberately: the ONLY way a caller can render a
   * number is to have received one.
   *
   * @param {string} method
   * @param {Array} [params]
   * @returns {Promise<*>} the JSON-RPC `result`
   */
  async function call(method, params) {
    if (!READ_SET.has(method) && !WRITE_SET.has(method)) {
      throw g4Error("unavailable",
        `${method} is not part of the Genesis-4 RPC surface — refused before any request. ` +
        "Genesis-4's node exposes no wallet and no transaction index, so several Genesis-3 " +
        "methods have no Genesis-4 equivalent at all.");
    }
    const P = globalThis.Postern || null;
    if (!P || typeof P.rpc !== "function") {
      throw g4Error("unavailable", `${method}: no RPC layer is loaded in this build`);
    }

    // Backstop deadline. browser/rpc.js already aborts its fetch, but the
    // desktop backend is a different transport with its own (or no) timeout,
    // and "the balance spinner span never resolves" is the same lie as a wrong
    // number, just slower. One of these two always fires.
    let timer = null;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => reject(g4Error("unreachable",
        `${method}: no answer within ${Math.round(TIMEOUT_MS / 1000)}s. ` +
        `The node's own consensus budget is ~10s and the edge proxy retries within a ` +
        `${Math.round(EDGE_TOTAL_BUDGET_MS / 1000)}s ceiling, so every hop had already given up — ` +
        "this is NOT a balance of zero and nothing was sent")), TIMEOUT_MS);
    });

    let envelope;
    try {
      envelope = await Promise.race([P.rpc(method, params || []), deadline]);
    } catch (e) {
      if (e && e.g4) throw e;
      throw g4Error("unreachable", `${method}: ${(e && e.message) || e}`, e);
    } finally {
      if (timer) clearTimeout(timer);
    }

    if (!envelope || typeof envelope !== "object") {
      throw g4Error("shape", `${method}: the endpoint returned no JSON-RPC envelope`);
    }
    if (envelope.error) {
      const err = envelope.error;
      const msg = err && err.message ? String(err.message) : JSON.stringify(err);
      // The numeric CODE is carried through, not just the English. The node's
      // error contract (rpc.rs) gives one code per cause, and a caller that has
      // to regex a message to decide between "this node does not offer that
      // method" (-32601) and "your transaction was refused" (-32002 /
      // TX_DECODE_FAILED) will eventually get it wrong. `code` is the fact;
      // `message` is the wording, which rpc.rs explicitly reserves the right to
      // reword.
      const e = g4Error("rpc", `${method}: node error — ${msg}`);
      const code = err && typeof err === "object" ? Number(err.code) : NaN;
      if (Number.isFinite(code)) e.rpcCode = code;
      // KEEP WHAT THE ENDPOINT SAID, not only the code. A refusal can be a
      // policy the endpoint is stating on purpose, and only the endpoint knows
      // which. Discarding `data` and the raw message left callers guessing, and
      // a caller that guesses tells a user a deliberate closure is a fault.
      if (err && typeof err === "object") {
        if (typeof err.message === "string" && err.message.trim()) e.rpcMessage = err.message;
        if (err.data && typeof err.data === "object") e.rpcData = err.data;
      }
      throw e;
    }
    if (envelope.result === undefined) {
      throw g4Error("shape", `${method}: reply had neither a result nor an error`);
    }
    return envelope.result;
  }

  // ── high-level reads ──────────────────────────────────────────────────────
  // Each derives the script_hash itself so no pane can forget to, and each
  // either returns a parsed answer or throws. There is no third outcome.

  /** @returns {Promise<{scriptHash, sats: bigint, utxoCount: number|null}>} */
  async function getBalance(addrOrHash) {
    const sh = scriptHashFromAddress(addrOrHash);
    if (!sh) {
      throw g4Error("unavailable",
        `not a Bloch address or script_hash: ${JSON.stringify(String(addrOrHash || ""))} ` +
        "(expected bloch1q… , a 40-hex hash160, or a 64-hex script_hash)");
    }
    return parseBalance(await call("getbalance", [sh]));
  }

  /**
   * @param {number} [limit] outputs to ask for. Clamped to UTXO_MAX_RETURNED
   *   because the node caps there anyway, and a caller who thinks it asked for
   *   50,000 and got 1000 has a wrong idea of what it is holding.
   */
  async function getUtxos(addrOrHash, limit) {
    const sh = scriptHashFromAddress(addrOrHash);
    if (!sh) {
      throw g4Error("unavailable",
        `not a Bloch address or script_hash: ${JSON.stringify(String(addrOrHash || ""))}`);
    }
    // A page size, not money. Clamped to a whole number in [1, cap]; anything
    // unrecognised (including 0, which `Number(limit) || DEFAULT` used to turn
    // into the default by accident rather than by decision) falls back to the
    // default page size.
    const asked = limit == null ? null : parseCount(limit, 1, null);
    const n = asked === null ? UTXO_PAGE_DEFAULT : Math.min(UTXO_MAX_RETURNED, asked);
    return parseUtxos(await call("getutxos", [sh, n]));
  }

  /** The height source. Never getblockcount. */
  async function getChainInfo() {
    return parseChainInfo(await call("getchaininfo", []));
  }

  /**
   * Is this ONE outpoint still in the committed unspent set?
   *
   * The question `listunspent` cannot answer for any wallet past 1000 outputs
   * (no cursor, hard 1000 cap — see the UTXO-enumeration block at the top).
   * Inputs are validated BEFORE any I/O: a malformed txid must fail here with
   * a sentence, not spend a 10-second round trip to earn a -32602.
   *
   * WHERE NOT TO USE IT, as load-bearing as where to: not for balance
   * (getbalance sums; this cannot), not for enumeration (it answers one
   * outpoint), and not as a pre-broadcast sweep over every selected input —
   * thirty round-trips against a node with a 10-second consensus budget, for
   * a race the quote/reservation machinery already covers.
   *
   * An endpoint that has not learned this method answers -32601; callers must
   * treat that as "could not check" via isMethodNotFound(e) — NEVER as spent,
   * and never as unspent.
   *
   * @param {string} txidHex 64 hex chars
   * @param {number} vout
   * @returns {Promise<ReturnType<parseTxout>>}
   */
  async function getTxOut(txidHex, vout) {
    const t = String(txidHex == null ? "" : txidHex).trim().toLowerCase();
    if (!isHex(t, 64)) {
      throw g4Error("unavailable",
        `gettxout: txid must be 32 bytes of hex (64 characters), got ` +
        `${JSON.stringify(String(txidHex == null ? "" : txidHex))} — refused before any request`);
    }
    const v = requireCount(vout, 0, 0xffffffff, "gettxout: vout");
    return parseTxout(await call("gettxout", [t, v]));
  }

  // ── the send path ─────────────────────────────────────────────────────────

  /**
   * The base fee, in millisat per gas, that a transfer signed NOW must be
   * priced at — as a DECIMAL STRING, the shape the signing core takes.
   *
   * This reads `next_base_fee_millisat_per_gas`, NOT `base_fee_millisat_per_
   * gas`. See parseChainInfo for the full citation; the short version is that
   * the unprefixed field is what the head block already charged, and a transfer
   * cannot be included in a block that has been produced. The producer prices
   * its mempool with `next_base_fee()` and `apply_block` charges every
   * transaction at it, so that is the price a new transfer has to meet.
   *
   * There is no default and there is no fallback, and that is the whole point.
   * A Genesis-4 transfer's fee is `gas x (base_fee + tip)`, and the base fee is
   * consensus state: every validating node recomputes it and checks the
   * transaction's value conservation against ITS number, not against ours. A
   * transfer priced at a guessed base fee is therefore not "slightly wrong" —
   * it is rejected by every node on the network, while the wallet that guessed
   * has already told the user it was sent. So a missing field THROWS.
   *
   * HONEST BOUND: this is exact for the next block. The fee market moves each
   * block with usage, so a transfer that sits in the mempool past that block
   * can be underpriced by the controller's per-block step. That is a property
   * of an EIP-1559-style market, not something a wallet can precompute away.
   *
   * Field names are the node's, read out of the chaininfo builder rather than
   * assumed (crates/bloch-pos-node/src/rpc.rs).
   *
   * @returns {Promise<{baseFee: string, headBaseFee: string|null, height: number}>}
   */
  async function getBaseFee() {
    const info = await getChainInfo();
    if (info.nextBaseFeeMillisatPerGas === null) {
      throw g4Error("shape",
        "getchaininfo answered without `next_base_fee_millisat_per_gas` — this node does not publish the " +
        "gas price the next block will charge, so a transfer cannot be priced against it. Refusing to " +
        "sign against a guessed fee: the wrong base fee is rejected by every node, after the wallet has " +
        "already reported the transfer as sent." +
        (info.baseFeeMillisatPerGas === null ? "" :
          " (It did report `base_fee_millisat_per_gas`, but that is what the head block already charged " +
          "and pricing a new transfer with it fails value conservation.)"));
    }
    return {
      baseFee: info.nextBaseFeeMillisatPerGas.toString(),
      // What the head block charged. Returned for display/diagnostics only —
      // never as a fallback for the one above.
      headBaseFee: info.baseFeeMillisatPerGas === null ? null : info.baseFeeMillisatPerGas.toString(),
      height: info.height,
    };
  }

  /**
   * getutxos entries -> the `utxos` array the signing core takes.
   *
   * `parseUtxos` has already turned every value into a BigInt from the node's
   * decimal string; this hands the core `.toString()` of that BigInt. At no
   * point does a satoshi amount exist as a JS Number, which is not a style
   * preference: the founder script_hash alone holds outputs whose sum is ~622x
   * past 2^53, and a rounded input value is signed over silently.
   *
   * @param {{utxos: Array}} parsed the return of parseUtxos
   * @returns {Array<{txid:string, vout:number, value:string}>}
   */
  function toSignerUtxos(parsed) {
    const list = (parsed && parsed.utxos) || [];
    return list.map((u, i) => {
      if (!isHex(String(u.txid || "").toLowerCase(), 64)) {
        throw g4Error("shape", `utxo ${i}: txid is not 32 bytes of hex (${JSON.stringify(u.txid)})`);
      }
      if (typeof u.sats !== "bigint") {
        throw g4Error("shape", `utxo ${i}: value did not survive as a BigInt — refusing to sign over it`);
      }
      return {
        txid: String(u.txid).toLowerCase(),
        // Re-checked rather than trusted: this object is about to be handed to
        // the signer, and it is the last place the outpoint can be wrong for
        // free.
        vout: requireCount(u.vout, 0, 0xffffffff, `utxo ${i}: vout`),
        // sats.toWire, not `.toString()` — same output, but it range-checks
        // against the u64 the core deserialises into, so an impossible value
        // fails here with a sentence rather than inside the WASM with a serde
        // message.
        value: satsToWire(u.sats),
      };
    });
  }

  /** True when the node/endpoint answered "no such method" rather than
   *  rejecting the request on its merits. The public `/g4rpc` proxy answers
   *  this for `sendrawtransaction` BY DESIGN — it forwards reads only — so this
   *  is the ordinary outcome of broadcasting from the public endpoint, not a
   *  rare fault. Callers use it to say "point the wallet at a node you run"
   *  instead of "your transaction was rejected", which would be false. */
  function isMethodNotFound(e) {
    return !!(e && e.rpcCode === METHOD_NOT_FOUND);
  }

  /**
   * Broadcast already-signed canonical bytes.
   *
   * PARAM SHAPE, taken from the node's own parser rather than from a Genesis-3
   * habit (rpc.rs, "sendrawtransaction" arm): `pick(params, 0, "hex")`, whose
   * value must be `as_str()` — so it is ONE positional argument, a hex string
   * of the canonical bytes, no `0x`, no options object, no second parameter.
   * (`pick` also accepts a named object with a `hex` key; positional is what
   * every other call in this file uses, so positional is what it sends.)
   *
   * RESULT SHAPE (rpc.rs `submitted_json`): {accepted:true, status:"accepted"
   * |"duplicate", kind, bytes, tx_hash, tx_hash_note, confirmation}. Note what
   * is NOT there: a txid. The node says so itself — a PosTransaction has no
   * identity at this layer, and `tx_hash` is documented as a LOCAL correlation
   * handle (SHA3-256 of the canonical bytes) that no block commits to. So this
   * returns the node's own words and lets the caller pair them with the txid
   * the signing core computed; it does not promote `tx_hash` to a txid.
   *
   * Refusals arrive as a top-level JSON-RPC `error` (the node's R4 convention:
   * "failures are the top-level JSON-RPC error object, never a result.error
   * string under HTTP 200"), so `call()` already throws on them — including
   * TX_DECODE_FAILED (-32002) and MEMPOOL_FULL (-32003). Nothing here can
   * return successfully for a transaction the node refused.
   *
   * @param {string} rawHex
   * @returns {Promise<{accepted:boolean, status:string, kind:string, bytes:number|null,
   *                    txHash:string, note:string, confirmation:string}>}
   */
  async function broadcast(rawHex) {
    const hex = String(rawHex == null ? "" : rawHex).trim().toLowerCase();
    if (!hex || !/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) {
      throw g4Error("unavailable",
        "sendrawtransaction: the signed transaction is not an even-length hex string — nothing was sent");
    }
    const r = await call("sendrawtransaction", [hex]);
    if (!r || typeof r !== "object") {
      throw g4Error("shape",
        "sendrawtransaction: the node returned no result object — it is NOT safe to assume the " +
        "transaction was accepted");
    }
    // `accepted` is the node's assertion that the bytes went into ITS mempool.
    // Anything else — including a well-formed object without the flag — is
    // treated as not-accepted, because the cost of the two mistakes is not
    // symmetric: reporting a rejected transfer as sent is the failure this
    // whole file is written around.
    if (r.accepted !== true) {
      throw g4Error("rpc",
        `sendrawtransaction: the node did not confirm acceptance (${JSON.stringify(r)}) — ` +
        "treat the transaction as NOT broadcast");
    }
    return {
      accepted: true,
      status: String(r.status || ""),
      kind: String(r.kind || ""),
      // A byte count, not money. Null when the node did not say, never 0 — "the
      // node accepted 0 bytes" is not a thing that happened.
      bytes: parseCount(r.bytes, 0, null),
      txHash: String(r.tx_hash || ""),
      note: String(r.tx_hash_note || ""),
      confirmation: String(r.confirmation || ""),
    };
  }

  /**
   * One-line, user-facing wording for a failed read. Panes call this instead of
   * printing a raw exception, so a timeout never reads like an empty wallet.
   */
  function failureText(e) {
    const kind = e && e.kind;
    const msg = (e && e.message) || String(e);
    if (kind === "unavailable") return msg;
    if (kind === "rpc") return `${msg} — the node answered, but with an error. This is NOT a balance of zero.`;
    if (kind === "shape") return `${msg} — unrecognised reply. Not showing a number rather than showing a wrong one.`;
    return `${msg} — could not reach the Genesis-4 node. This is NOT a balance of zero; retry.`;
  }

  return {
    // RPC surface
    RPC_PATH, READ_METHODS, WRITE_METHODS, TIMEOUT_MS, METHOD_NOT_FOUND,
    isReadMethod: (m) => READ_SET.has(m),
    isWriteMethod: (m) => WRITE_SET.has(m),
    isMethodNotFound,

    // ── address derivation + checksum ───────────────────────────────────────
    // `inspectAddress` is the one to build UI copy on: it distinguishes
    // malformed / checksum-failed / verified rather than collapsing them.
    inspectAddress, scriptHashFromAddress, isAddressLike, isAddressVerified,
    checksumForHash160, sha3_256, SHA3_OK, PAD,

    // ── CONTRACT B — exact amounts ─────────────────────────────────────────
    // `sats` is the published namespace. Use it. The bare names below it are
    // delegates kept for the call sites that already exist.
    sats,
    // ── CONTRACT L — per-block consensus limits ────────────────────────────
    // The ONE home of the block caps and the derived input ceiling. Panes and
    // backends read these; none may carry its own copy of the numbers.
    limits,
    SATS_PER_BLOCH, DECIMALS, UTXO_MAX_RETURNED, UTXO_PAGE_DEFAULT,
    toSats, trySats, satsToBloch, blochToSats, fmtSatsGrouped, fmtBloch, groupDigits,
    // Strict small-integer parsing for COUNTS (heights, slots, vouts, byte
    // counts). Exported so no pane reinvents `Number(x) || 0`, which claims 0
    // for an absent field.
    parseCount, requireCount,

    // parsers
    parseBalance, parseUtxos, parseTxout, parseChainInfo,
    MAINNET_CHAIN_IDENTITY, requireMainnetChainIdentity,
    // calls
    call, getBalance, getUtxos, getTxOut, getChainInfo, failureText, g4Error,
    // send path
    getBaseFee, toSignerUtxos, broadcast,
  };
});
