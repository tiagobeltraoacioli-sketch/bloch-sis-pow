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
  fundingAddress: string;
  changeAddress: string;
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

export function loadConfig(): FaucetConfig {
  const funding = envStr("FAUCET_FUNDING_ADDRESS", "");
  return {
    rpcUrl: envStr("FAUCET_RPC_URL", "http://127.0.0.1:16210/"),
    rpcApiKey: process.env.FAUCET_RPC_API_KEY || undefined,
    fundingAddress: funding,
    changeAddress: envStr("FAUCET_CHANGE_ADDRESS", funding),
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
