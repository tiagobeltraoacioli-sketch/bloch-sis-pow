# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
# @generated from docs/openapi.yaml — do not edit by hand.
#
# Typed models for the Bloch JSON-RPC surface (TypedDicts + scalar aliases).
# The integer satoshi field is the on-chain truth; the float `*_bloch`
# fields are display-only. See units.py.

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from typing import TypedDict


# ── Scalar aliases ─────────────────────────────────────────────────────────
Hex32 = str
Hex20 = str
Address = str
Satoshis = int
Height = int


# ── Models ─────────────────────────────────────────────────────────────────

class ResultError(TypedDict, total=False):
    """Non-standard method-level error. Delivered inside `result` with HTTP 200 (NOT via the top-level `error` object). Any `result` carrying a string `error` key is a failed call."""
    error: str

class TxInput(TypedDict, total=False):
    prev_txid: Hex32
    prev_index: int
    sequence: int

class TxOutput(TypedDict, total=False):
    index: int
    value: Satoshis
    bloch: float
    script_pubkey: str

class Transaction(TypedDict, total=False):
    """Decoded transaction (format_tx). decoderawtransaction adds `size`."""
    txid: Hex32
    version: int
    coinbase: bool
    inputs: List[TxInput]
    outputs: List[TxOutput]
    locktime: int
    size: int

class NetworkInfo(TypedDict, total=False):
    network: str
    version: str
    protocol: int
    net_protocol: int
    blue_score: int
    blocks: int
    peers: int
    mempool: int
    syncing: bool
    chain: str
    pruned_height: int

class MempoolInfo(TypedDict, total=False):
    size: int

class DagInfo(TypedDict, total=False):
    tip: Optional[Hex32]
    tip_blue_score: int
    tip_blue_work: str
    tip_height: int
    block_count: int
    tip_count: int
    tips: List[Hex32]
    chain_length: int
    k: int

class PeerInfo(TypedDict, total=False):
    peer_count: int
    syncing: bool

class Peer(TypedDict, total=False):
    address: str
    ip: str
    peer_id: str

class PeersList(TypedDict, total=False):
    peer_count: int
    peers: List[Peer]

class BlockSummary(TypedDict, total=False):
    """getrecentblocks list item."""
    hash: Hex32
    height: int
    tx_count: int
    timestamp: int
    size: int
    bits: int

class Block(TypedDict, total=False):
    """Full block (getblock / getblockbyheight). `txids` when verbose=false, `transactions` when verbose=true."""
    hash: Hex32
    height: int
    blue_score: int
    tx_count: int
    timestamp: int
    bits: str
    nonce: int
    parents: List[Hex32]
    merkle_root: Hex32
    size: int
    txids: List[Hex32]
    transactions: List[Transaction]

class TransactionLookup(TypedDict, total=False):
    """gettransaction result."""
    txid: Hex32
    block_hash: Hex32
    block_height: int
    timestamp: int
    confirmations: int
    transaction: Transaction

class Balance(TypedDict, total=False):
    satoshis: Satoshis
    bloch: float
    utxo_count: int
    address: Address

class AddressCount(TypedDict, total=False):
    """getaddresscount — distinct on-chain wallets holding >= 1 UTXO."""
    addresses_with_balance: int
    utxo_entries: int
    note: str

class Utxo(TypedDict, total=False):
    txid: Hex32
    index: int
    value: Satoshis
    script_pubkey: str

class UtxoList(TypedDict, total=False):
    address: Address
    utxo_count: int
    satoshis: Satoshis
    bloch: float
    utxos: List[Utxo]

class AddressInfo(TypedDict, total=False):
    """getaddressinfo result."""
    address: Address
    balance_sats: Satoshis
    balance_bloch: float
    utxo_count: int
    pending_incoming: Satoshis
    pending_outgoing: Satoshis
    pool_role: Optional[str]

class AddressBalanceAtHeight(TypedDict, total=False):
    """getaddressbalance_at_height result."""
    address: Address
    height: int
    balance_sats: Satoshis
    balance_bloch: float
    tx_count_up_to_height: int

class AddressHistoryEntry(TypedDict, total=False):
    txid: Hex32
    block_height: int
    timestamp: int
    confirmations: int
    direction: str
    amount_sats: Satoshis
    amount_bloch: float

class ListTransactionsResult(TypedDict, total=False):
    """listtransactions result."""
    address: Address
    count: int
    total_available: int
    start_height: int
    end_height: int
    limit: int
    offset: int
    transactions: List[AddressHistoryEntry]

class AddressValidation(TypedDict, total=False):
    """validateaddress result."""
    address: str
    isvalid: bool
    network: str
    checksum: bool

class AddressValidationVerbose(TypedDict, total=False):
    """validateaddressverbose — one of two shapes depending on validity. (merged union of variant shapes)."""
    valid: bool
    address: str
    network: str
    hash_hex: Hex20
    prefix: str
    reason: str

class BroadcastResult(TypedDict, total=False):
    """sendrawtransaction success."""
    txid: Hex32

class FeeEstimate(TypedDict, total=False):
    """estimatefee — median fee of current mempool entries."""
    feerate_sats: int
    feerate_bloch: float
    mempool_size: int
    note: str

class FeeEstimateAdvanced(TypedDict, total=False):
    """estimatefeeadvanced result."""
    next_block_sats: int
    medium_priority: int
    slow_priority: int
    mempool_median: int
    mempool_size: int
    recommended_bloch: str

class MempoolEntry(TypedDict, total=False):
    """getrawmempool verbose entry."""
    txid: Hex32
    fee: int
    fee_bloch: float
    time: int

class RawMempool(TypedDict, total=False):
    """getrawmempool — compact (txids) or verbose (transactions) shape. (merged union of variant shapes)."""
    size: int
    txids: List[Hex32]
    transactions: List[MempoolEntry]

class MempoolBucket(TypedDict, total=False):
    range: str
    tx_count: int

class MempoolStats(TypedDict, total=False):
    """getmempoolstats result."""
    size: int
    total_fees: int
    min_fee: int
    max_fee: int
    median_fee: int
    avg_fee: float
    buckets: List[MempoolBucket]

class TxStatus(TypedDict, total=False):
    """gettxstatus result."""
    status: str
    in_mempool: bool
    confirmations: int
    block_height: int
    txid: Hex32

class ChainStats(TypedDict, total=False):
    """getchainstats result."""
    total_blocks: int
    total_txs: int
    avg_txs_per_block: float
    blocks_last_24h: int
    txs_last_24h: int
    avg_block_time_secs: float
    current_difficulty: float
    hashrate_hs: float
    hashrate_human: str

class HashrateInfo(TypedDict, total=False):
    """gethashrate result."""
    hashrate_hs: float
    hashrate_human: str
    avg_block_time_secs: float
    current_difficulty: float

class SupplyTier(TypedDict, total=False):
    label: str
    address_count: int
    total_sats: Satoshis
    total_bloch: float
    pct_of_supply: float

class SupplyDistribution(TypedDict, total=False):
    """getsupplydistribution result."""
    tiers: List[SupplyTier]
    total_addresses: int
    total_sats: Satoshis
    total_bloch: float

class DifficultyPoint(TypedDict, total=False):
    height: int
    bits: int
    bits_hex: str
    timestamp: int
    target_hex: str

class DifficultyHistory(TypedDict, total=False):
    """getdifficultyhistory result."""
    count: int
    points: List[DifficultyPoint]

class BlockTimePercentiles(TypedDict, total=False):
    """getblocktimepercentiles result."""
    sample_size: int
    window: int
    min_secs: float
    p50_secs: float
    p90_secs: float
    p99_secs: float
    max_secs: float
    avg_secs: float
    target_secs: float

class TxInBlock(TypedDict, total=False):
    txid: Hex32
    size_bytes: int
    inputs_count: int
    outputs_count: int
    fee_sats: int
    is_coinbase: bool

class TxsByBlock(TypedDict, total=False):
    """gettxsbyblock result."""
    block_hash: Hex32
    block_height: int
    block_timestamp: int
    count: int
    txs: List[TxInBlock]

class PoolReportEntry(TypedDict, total=False):
    """One protocol pool in getpools. Founder entry adds vesting fields; a pool with no configured address reports status "pending_phase_6"."""
    share_bps: Optional[int]
    subsidy_per_block_sat: int
    address_hash_hex: Optional[Hex20]
    address: Optional[Address]
    balance_sat: int
    balance_bloch: float
    utxo_count: int
    status: str
    vesting_per_month_sat: int
    vesting_amount_at_next_sat: int
    vesting_active_at_next: bool
    vesting_total_sat: int
    vesting_months: int

class Pools(TypedDict, total=False):
    """getpools — next-block subsidy split plus per-pool address/balance."""
    current_height: int
    next_block_height: int
    subsidy_per_block_sat: int
    subsidy_per_block_bloch: float
    miner_share_sat: int
    pools: PoolsPools

class BlockTemplateTx(TypedDict, total=False):
    txid: Hex32
    fee: int
    data: str

class BlockTemplate(TypedDict, total=False):
    """getblocktemplate — everything a SIS-aware pool needs to assemble a candidate block. `bits` is computed exactly as accept_block validates (ASERT-Lattice anchored at genesis, keyed on the parent timestamp)."""
    parents: List[Hex32]
    height: int
    blue_score: int
    bits: int
    cur_time: int
    parent_time: int
    subsidy_sat: int
    founder_vesting_sat: int
    founder_address_hash: Hex20
    total_fees: int
    transactions: List[BlockTemplateTx]
    residual_coeffs: List[int]

class SubmitBlockResult(TypedDict, total=False):
    """submitblock — accepted, or a result.error on rejection / when the pool seam is not wired. (merged union of variant shapes)."""
    accepted: bool
    hash: str
    error: str

class AttestationReport(TypedDict, total=False):
    """getattestation — TEE attestation status. Reports `attested: false` when no TEE provider is active (the honest default on a non-confidential host). Serialized directly from the node's AttestationReport."""
    attested: bool
    tee: str
    nonce: Optional[str]
    measurement: Optional[str]
    hostdata: Optional[str]
    image_digest: Optional[str]
    quote_b64: Optional[str]
    os_roothash: Optional[str]
    note: str

class PoolsPools(TypedDict, total=False):
    validator_pool: PoolReportEntry
    oracle_pool: PoolReportEntry
    founder: PoolReportEntry

