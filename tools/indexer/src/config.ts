// SPDX-License-Identifier: MIT OR Apache-2.0
// Configuration loader for the Bloch reorg-safe indexer.

import type { Network } from "./address.js";

function envStr(name: string, fallback: string): string {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}
function envInt(name: string, fallback: number, min: number, max: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  if (!/^[0-9]+$/.test(v)) throw new Error(`${name} must be an integer`);
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new Error(`${name} must be between ${min} and ${max}`);
  return n;
}
function envBool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  if (/^(1|true|yes|on)$/i.test(v)) return true;
  if (/^(0|false|no|off)$/i.test(v)) return false;
  throw new Error(`${name} must be an explicit boolean`);
}

export interface IndexerConfig {
  rpcUrl: string;
  rpcApiKey: string | undefined;
  network: Network;
  dataFile: string;
  pollMs: number;
  syncTimeoutMs: number;
  apiHost: string;
  apiPort: number;
  stub: boolean;
}

export function loadConfig(): IndexerConfig {
  const net = envStr("INDEXER_NETWORK", "testnet");
  if (net !== "mainnet" && net !== "testnet") throw new Error("INDEXER_NETWORK must be mainnet or testnet");
  return {
    rpcUrl: envStr("INDEXER_RPC_URL", "http://127.0.0.1:16210/"),
    rpcApiKey: process.env.INDEXER_RPC_API_KEY || undefined,
    network: net,
    dataFile: envStr("INDEXER_DATA_FILE", "./data/indexer-data.json"),
    pollMs: envInt("INDEXER_POLL_MS", 3000, 10, 3_600_000),
    syncTimeoutMs: envInt("INDEXER_SYNC_TIMEOUT_MS", 30_000, 1, 300_000),
    apiHost: envStr("INDEXER_API_HOST", "127.0.0.1"),
    apiPort: envInt("INDEXER_API_PORT", 8081, 1, 65535),
    stub: envBool("INDEXER_STUB", false),
  };
}
