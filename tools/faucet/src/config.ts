// SPDX-License-Identifier: MIT OR Apache-2.0
// Configuration loader for the Bloch testnet faucet.
// All values come from the environment (see .env.example). No secrets are
// hardcoded; the signing key lives entirely behind FAUCET_SIGNER_CMD.

function envStr(name: string, fallback: string): string {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

function envInt(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

/**
 * Strict boolean. FAIL-CLOSED on anything unrecognised: the only flag this
 * parses is the one that decides whether the service spends real coins, and
 * the old lenient form treated `FAUCET_DRY_RUN=treu` as `false` and booted
 * LIVE. A typo must never be the thing that arms a payout.
 */
function envBool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  if (/^(1|true|yes|on)$/i.test(v)) return true;
  if (/^(0|false|no|off)$/i.test(v)) return false;
  throw new Error(
    `${name}=${JSON.stringify(v)} is not a boolean. Use one of 1/true/yes/on or 0/false/no/off. ` +
      `Refusing to guess, because guessing wrong here means spending coins.`,
  );
}

export interface FaucetConfig {
  rpcUrl: string;
  rpcApiKey: string | undefined;
  /**
   * The 32-byte `script_hash` (64 hex) the faucet spends FROM — never an
   * address. Genesis-4 has no address form for a native key, so an address
   * here could only ever name a hash that owns nothing on a carryover-free
   * testnet. `FAUCET_FUNDING_ADDRESS` is refused outright rather than
   * reinterpreted; see `migrationError`.
   */
  fundingScriptHash: string;
  changeScriptHash: string;
  /**
   * `getblockbyslot(0).block_id` of the chain this faucet is allowed to spend
   * on, 64 hex. THIS is the network binding. It replaces the old `bloch1t…`
   * prefix check, which never proved anything about the node at the other end
   * of `FAUCET_RPC_URL` — the string and the RPC were checked independently
   * and nothing tied them together. Required in LIVE mode.
   */
  expectGenesisBlockId: string;
  amountSats: number;
  feeSats: number;
  host: string;
  port: number;
  signerCmd: string | undefined;
  dryRun: boolean;
  perAddressWindowMs: number;
  perIpWindowMs: number;
  perIpMax: number;
  globalWindowMs: number;
  globalMaxSats: number;
}

/**
 * A retired variable name is a fault, not a default. The old names took an
 * ADDRESS; the new ones take a `script_hash`, and the two are different keys in
 * the eUTXO set. Silently carrying an old value forward would point the faucet
 * at a hash that owns nothing and express it as "the testnet is broken".
 */
function refuseRetired(): void {
  const retired: [string, string][] = [
    ["FAUCET_FUNDING_ADDRESS", "FAUCET_FUNDING_SCRIPT_HASH"],
    ["FAUCET_CHANGE_ADDRESS", "FAUCET_CHANGE_SCRIPT_HASH"],
  ];
  for (const [old, now] of retired) {
    if (process.env[old]) {
      throw new Error(
        `${old} is no longer read. Genesis-4 pays to a 32-byte script_hash, not an ` +
          `address, and converting one to the other silently produces a different UTXO-set ` +
          `key. Set ${now} to the 64-hex value 'bloch-pos spendkey' prints for the faucet ` +
          `keystore.`,
      );
    }
  }
}

/** 64 lowercase hex, or "" — anything else is an operator error, loudly. */
function envScriptHash(name: string, fallback: string): string {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const s = v.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(s)) {
    throw new Error(
      `${name}=${JSON.stringify(v)} is not a 64-hex script_hash. It is the value ` +
        `'bloch-pos spendkey --dir <keystore>' prints on its script_hash line.`,
    );
  }
  return s;
}

export function loadConfig(): FaucetConfig {
  refuseRetired();
  const funding = envScriptHash("FAUCET_FUNDING_SCRIPT_HASH", "");
  return {
    rpcUrl: envStr("FAUCET_RPC_URL", "http://127.0.0.1:18500/"),
    rpcApiKey: process.env.FAUCET_RPC_API_KEY || undefined,
    fundingScriptHash: funding,
    changeScriptHash: envScriptHash("FAUCET_CHANGE_SCRIPT_HASH", funding),
    expectGenesisBlockId: envScriptHash("FAUCET_EXPECT_GENESIS_BLOCK_ID", ""),
    amountSats: envInt("FAUCET_AMOUNT_SATS", 100_000_000),
    feeSats: envInt("FAUCET_FEE_SATS", 1000),
    host: envStr("FAUCET_HOST", "127.0.0.1"),
    port: envInt("FAUCET_PORT", 8080),
    signerCmd: process.env.FAUCET_SIGNER_CMD || undefined,
    dryRun: envBool("FAUCET_DRY_RUN", true),
    perAddressWindowMs: envInt("FAUCET_PER_ADDRESS_WINDOW_MS", 86_400_000),
    perIpWindowMs: envInt("FAUCET_PER_IP_WINDOW_MS", 3_600_000),
    perIpMax: envInt("FAUCET_PER_IP_MAX", 5),
    // Drain ceiling across ALL clients. The per-address and per-IP limits bound
    // ONE client; nothing bounded the sum of them, and an attacker with a
    // routed IPv6 /64 has 2^64 distinct per-IP keys. Default 500 BLCH per
    // rolling 24 h: generous for a partner integrating a withdrawal flow
    // (500 drips at the 1 BLCH default), and a bounded loss if abused.
    globalWindowMs: envInt("FAUCET_GLOBAL_WINDOW_MS", 86_400_000),
    globalMaxSats: envInt("FAUCET_GLOBAL_MAX_SATS", 50_000_000_000),
  };
}
