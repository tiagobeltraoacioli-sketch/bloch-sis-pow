// SPDX-License-Identifier: MIT OR Apache-2.0
// Configuration loader for the Bloch reorg-safe indexer.

import type { Network } from "./address.js";

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
function envBool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  return /^(1|true|yes|on)$/i.test(v);
}

export interface IndexerConfig {
  rpcUrl: string;
  rpcApiKey: string | undefined;
  network: Network;
  dataFile: string;
  pollMs: number;
  apiHost: string;
  apiPort: number;
  stub: boolean;
}

export function loadConfig(): IndexerConfig {
  const net = envStr("INDEXER_NETWORK", "testnet") === "mainnet" ? "mainnet" : "testnet";
  return {
    rpcUrl: envStr("INDEXER_RPC_URL", "http://127.0.0.1:16210/"),
    rpcApiKey: process.env.INDEXER_RPC_API_KEY || undefined,
    network: net,
    dataFile: envStr("INDEXER_DATA_FILE", "./data/indexer-data.json"),
    pollMs: envInt("INDEXER_POLL_MS", 3000),
    apiHost: envStr("INDEXER_API_HOST", "127.0.0.1"),
    apiPort: envInt("INDEXER_API_PORT", 8081),
    stub: envBool("INDEXER_STUB", false),
  };
}
