// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Response and domain types for the Bloch JSON-RPC surface.
//
// These are modelled against the REAL dispatcher in the node source
// (`src/rpc/mod.rs`) rather than the older `docs/openapi.yaml`, which still
// carries the pre-rename "Entanglement Layer / ENTL / ent1q" naming. The live
// node emits `bloch`-suffixed float fields, `bloch1q`/`bloch1t` addresses, and
// `chain: "bloch-sis"`. Where the node and the spec disagree, the node wins.
//
// Numeric truth is always the integer satoshi field; the float `*_bloch`
// / `bloch` fields are display-only (see units.ts). satoshi values large
// enough to exceed Number.MAX_SAFE_INTEGER are rare on this chain today but,
// to be safe, all satoshi-typed fields are surfaced as `number` exactly as the
// node returns them in JSON. If you need bigint-safe accounting, re-parse with
// a bigint-aware JSON reader.

/** 32-byte value as 64 lowercase hex chars. */
export type Hex32 = string;
/** 20-byte value as 40 lowercase hex chars. */
export type Hex20 = string;
/** Bloch address string: `bloch1q…` (mainnet) / `bloch1t…` (testnet). */
export type Address = string;
/** Integer value in satoshis (1 BLOCH = 100_000_000 sat). This is the truth. */
export type Satoshis = number;
/** Selected-chain block height. */
export type Height = number;

export type Network = "mainnet" | "testnet";

// ── getnetworkinfo ────────────────────────────────────────────────────────
export interface NetworkInfo {
  network: string;
  version: string;
  protocol: number;
  net_protocol: number;
  blue_score: number;
  blocks: number;
  peers: number;
  mempool: number;
  syncing: boolean;
  /** The live node returns `"bloch-sis"`. */
  chain: string;
  pruned_height: number;
}

// ── getmempoolinfo ────────────────────────────────────────────────────────
export interface MempoolInfo {
  size: number;
}

// ── getdaginfo ────────────────────────────────────────────────────────────
export interface DagInfo {
  tip: Hex32 | null;
  tip_blue_score: number;
  tip_blue_work: string;
  tip_height: number;
  block_count: number;
  tip_count: number;
  tips: Hex32[];
  chain_length: number;
  k: number;
}

// ── getpeerinfo / getpeers ────────────────────────────────────────────────
export interface PeerInfo {
  peer_count: number;
  syncing: boolean;
}

export interface Peer {
  address: string;
  ip?: string;
  peer_id?: string;
}

export interface PeersList {
  peer_count: number;
  peers: Peer[];
}

// ── Blocks ────────────────────────────────────────────────────────────────
export interface BlockSummary {
  hash: Hex32;
  height: Height;
  tx_count: number;
  timestamp: number;
  size: number;
  bits: number;
}

export interface TxInput {
  prev_txid: Hex32;
  prev_index: number;
  sequence: number;
}

export interface TxOutput {
  index: number;
  value: Satoshis;
  bloch: number;
  script_pubkey: string;
}

export interface Transaction {
  txid: Hex32;
  version: number;
  coinbase?: boolean;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
}

export interface Block {
  hash: Hex32;
  height: Height;
  blue_score: number;
  tx_count: number;
  timestamp: number;
  bits: string;
  nonce: number;
  parents: Hex32[];
  merkle_root: Hex32;
  size: number;
  /** Present when verbose=false. */
  txids?: Hex32[];
  /** Present when verbose=true. */
  transactions?: Transaction[];
}

export interface TransactionLookup {
  txid: Hex32;
  block_hash: Hex32;
  block_height: Height;
  timestamp: number;
  confirmations: number;
  transaction: Transaction;
}

// ── Addresses / balances ──────────────────────────────────────────────────
export interface Balance {
  satoshis: Satoshis;
  bloch: number;
  utxo_count: number;
  address: Address;
}

export interface Utxo {
  txid: Hex32;
  index: number;
  value: Satoshis;
  script_pubkey: string;
}

export interface UtxoList {
  address: Address;
  utxo_count: number;
  satoshis: Satoshis;
  bloch: number;
  utxos: Utxo[];
}

export interface AddressInfo {
  address: Address;
  balance_sats: Satoshis;
  balance_bloch: number;
  utxo_count: number;
  pending_incoming: Satoshis;
  pending_outgoing: Satoshis;
  /** e.g. "treasury" / "validator" / null. Node field is `pool_role`. */
  pool_role: string | null;
}

export interface AddressBalanceAtHeight {
  address: Address;
  height: Height;
  balance_sats: Satoshis;
  balance_bloch: number;
  tx_count_up_to_height: number;
}

export type TxDirection = "incoming" | "outgoing" | "self";

export interface AddressHistoryEntry {
  txid: Hex32;
  block_height: Height;
  timestamp: number;
  confirmations: number;
  direction: TxDirection;
  amount_sats: Satoshis;
  amount_bloch: number;
}

export interface ListTransactionsResult {
  address: Address;
  count: number;
  total_available: number;
  start_height: number;
  end_height: number;
  limit: number;
  offset: number;
  transactions: AddressHistoryEntry[];
}

export interface ListTransactionsOptions {
  limit?: number;
  startHeight?: number;
  endHeight?: number;
  offset?: number;
}

// ── Validation ────────────────────────────────────────────────────────────
export interface AddressValidation {
  address: string;
  isvalid: boolean;
  network: "mainnet" | "testnet" | "unknown";
  checksum: boolean;
}

export type AddressValidationVerbose =
  | {
      valid: true;
      address: string;
      network: Network;
      hash_hex: Hex20;
      prefix: string;
    }
  | {
      valid: false;
      address: string;
      reason: string;
    };

// ── Broadcast ─────────────────────────────────────────────────────────────
export interface BroadcastResult {
  txid: Hex32;
}

// ── Fees ──────────────────────────────────────────────────────────────────
export interface FeeEstimate {
  feerate_sats: number;
  feerate_bloch: number;
  mempool_size: number;
  note: string;
}

export interface FeeEstimateAdvanced {
  next_block_sats: number;
  medium_priority: number;
  slow_priority: number;
  mempool_median: number;
  mempool_size: number;
  recommended_bloch: string;
}

// ── Mempool ───────────────────────────────────────────────────────────────
export interface MempoolEntry {
  txid: Hex32;
  fee: number;
  fee_bloch: number;
  time: number;
}

export type RawMempool =
  | { size: number; txids: Hex32[] }
  | { size: number; transactions: MempoolEntry[] };

export interface MempoolBucket {
  range: string;
  tx_count: number;
}

export interface MempoolStats {
  size: number;
  total_fees: number;
  min_fee: number;
  max_fee: number;
  median_fee: number;
  avg_fee: number;
  buckets: MempoolBucket[];
}

// ── Transaction status ────────────────────────────────────────────────────
export type TxStatusKind = "unknown" | "pending" | "confirmed" | "final";

export interface TxStatus {
  status: TxStatusKind;
  in_mempool: boolean;
  confirmations: number;
  block_height?: number;
  txid: Hex32;
}

// ── Analytics ─────────────────────────────────────────────────────────────
export interface ChainStats {
  total_blocks: number;
  total_txs: number;
  avg_txs_per_block: number;
  blocks_last_24h: number;
  txs_last_24h: number;
  avg_block_time_secs: number;
  current_difficulty: number;
  hashrate_hs: number;
  hashrate_human: string;
}

export interface HashrateInfo {
  hashrate_hs: number;
  hashrate_human: string;
  avg_block_time_secs: number;
  current_difficulty: number;
}

export interface SupplyTier {
  label: string;
  address_count: number;
  total_sats: Satoshis;
  total_bloch: number;
  pct_of_supply: number;
}

export interface SupplyDistribution {
  tiers: SupplyTier[];
  total_addresses: number;
  total_sats: Satoshis;
  total_bloch: number;
}

export interface DifficultyPoint {
  height: Height;
  bits: number;
  bits_hex: string;
  timestamp: number;
  target_hex: string;
}

export interface DifficultyHistory {
  count: number;
  points: DifficultyPoint[];
}

export interface BlockTimePercentiles {
  sample_size: number;
  window: number;
  min_secs: number;
  p50_secs: number;
  p90_secs: number;
  p99_secs: number;
  max_secs: number;
  avg_secs: number;
  target_secs: number;
}

export interface TxInBlock {
  txid: Hex32;
  size_bytes: number;
  inputs_count: number;
  outputs_count: number;
  fee_sats: number;
  is_coinbase: boolean;
}

export interface TxsByBlock {
  block_hash: Hex32;
  block_height: Height;
  block_timestamp: number;
  count: number;
  txs: TxInBlock[];
}
