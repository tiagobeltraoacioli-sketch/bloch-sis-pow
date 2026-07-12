// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
// @generated from docs/openapi.yaml — do not edit by hand.
//
// Typed models for the Bloch JSON-RPC surface.
// The integer satoshi field is the on-chain truth; float `*_bloch` fields
// are display-only. See units.go.

package blochclient

// ── Scalar aliases ──────────────────────────────────────────────────────────

type Hex32 = string
type Hex20 = string
type Address = string
type Satoshis = int64
type Height = int64

// ── Models ──────────────────────────────────────────────────────────────────

// ResultError — Non-standard method-level error. Delivered inside `result` with HTTP 200 (NOT via the top-level `error` object). Any `result` carrying a string `error` key is a failed call.
type ResultError struct {
	Error string `json:"error,omitempty"`
}

type TxInput struct {
	PrevTxid  string `json:"prev_txid,omitempty"`
	PrevIndex int64  `json:"prev_index,omitempty"`
	Sequence  int64  `json:"sequence,omitempty"`
}

type TxOutput struct {
	Index        int64   `json:"index,omitempty"`
	Value        int64   `json:"value,omitempty"`
	Bloch        float64 `json:"bloch,omitempty"`
	ScriptPubkey string  `json:"script_pubkey,omitempty"`
}

// Transaction — Decoded transaction (format_tx). decoderawtransaction adds `size`.
type Transaction struct {
	Txid     string     `json:"txid,omitempty"`
	Version  int64      `json:"version,omitempty"`
	Coinbase bool       `json:"coinbase,omitempty"`
	Inputs   []TxInput  `json:"inputs,omitempty"`
	Outputs  []TxOutput `json:"outputs,omitempty"`
	Locktime int64      `json:"locktime,omitempty"`
	Size     int64      `json:"size,omitempty"`
}

type NetworkInfo struct {
	Network      string `json:"network,omitempty"`
	Version      string `json:"version,omitempty"`
	Protocol     int64  `json:"protocol,omitempty"`
	NetProtocol  int64  `json:"net_protocol,omitempty"`
	BlueScore    int64  `json:"blue_score,omitempty"`
	Blocks       int64  `json:"blocks,omitempty"`
	Peers        int64  `json:"peers,omitempty"`
	Mempool      int64  `json:"mempool,omitempty"`
	Syncing      bool   `json:"syncing,omitempty"`
	Chain        string `json:"chain,omitempty"`
	PrunedHeight int64  `json:"pruned_height,omitempty"`
}

type MempoolInfo struct {
	Size int64 `json:"size,omitempty"`
}

type DagInfo struct {
	Tip          *string  `json:"tip,omitempty"`
	TipBlueScore int64    `json:"tip_blue_score,omitempty"`
	TipBlueWork  string   `json:"tip_blue_work,omitempty"`
	TipHeight    int64    `json:"tip_height,omitempty"`
	BlockCount   int64    `json:"block_count,omitempty"`
	TipCount     int64    `json:"tip_count,omitempty"`
	Tips         []string `json:"tips,omitempty"`
	ChainLength  int64    `json:"chain_length,omitempty"`
	K            int64    `json:"k,omitempty"`
}

type PeerInfo struct {
	PeerCount int64 `json:"peer_count,omitempty"`
	Syncing   bool  `json:"syncing,omitempty"`
}

type Peer struct {
	Address string `json:"address,omitempty"`
	Ip      string `json:"ip,omitempty"`
	PeerId  string `json:"peer_id,omitempty"`
}

type PeersList struct {
	PeerCount int64  `json:"peer_count,omitempty"`
	Peers     []Peer `json:"peers,omitempty"`
}

// BlockSummary — getrecentblocks list item.
type BlockSummary struct {
	Hash      string `json:"hash,omitempty"`
	Height    int64  `json:"height,omitempty"`
	TxCount   int64  `json:"tx_count,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Bits      int64  `json:"bits,omitempty"`
}

// Block — Full block (getblock / getblockbyheight). `txids` when verbose=false, `transactions` when verbose=true.
type Block struct {
	Hash         string        `json:"hash,omitempty"`
	Height       int64         `json:"height,omitempty"`
	BlueScore    int64         `json:"blue_score,omitempty"`
	TxCount      int64         `json:"tx_count,omitempty"`
	Timestamp    int64         `json:"timestamp,omitempty"`
	Bits         string        `json:"bits,omitempty"`
	Nonce        int64         `json:"nonce,omitempty"`
	Parents      []string      `json:"parents,omitempty"`
	MerkleRoot   string        `json:"merkle_root,omitempty"`
	Size         int64         `json:"size,omitempty"`
	Txids        []string      `json:"txids,omitempty"`
	Transactions []Transaction `json:"transactions,omitempty"`
}

// TransactionLookup — gettransaction result.
type TransactionLookup struct {
	Txid          string       `json:"txid,omitempty"`
	BlockHash     string       `json:"block_hash,omitempty"`
	BlockHeight   int64        `json:"block_height,omitempty"`
	Timestamp     int64        `json:"timestamp,omitempty"`
	Confirmations int64        `json:"confirmations,omitempty"`
	Transaction   *Transaction `json:"transaction,omitempty"`
}

type Balance struct {
	Satoshis  int64   `json:"satoshis,omitempty"`
	Bloch     float64 `json:"bloch,omitempty"`
	UtxoCount int64   `json:"utxo_count,omitempty"`
	Address   string  `json:"address,omitempty"`
}

// AddressCount — getaddresscount — distinct on-chain wallets holding >= 1 UTXO.
type AddressCount struct {
	AddressesWithBalance int64  `json:"addresses_with_balance,omitempty"`
	UtxoEntries          int64  `json:"utxo_entries,omitempty"`
	Note                 string `json:"note,omitempty"`
}

type Utxo struct {
	Txid         string `json:"txid,omitempty"`
	Index        int64  `json:"index,omitempty"`
	Value        int64  `json:"value,omitempty"`
	ScriptPubkey string `json:"script_pubkey,omitempty"`
}

type UtxoList struct {
	Address   string  `json:"address,omitempty"`
	UtxoCount int64   `json:"utxo_count,omitempty"`
	Satoshis  int64   `json:"satoshis,omitempty"`
	Bloch     float64 `json:"bloch,omitempty"`
	Utxos     []Utxo  `json:"utxos,omitempty"`
}

// AddressInfo — getaddressinfo result.
type AddressInfo struct {
	Address         string  `json:"address,omitempty"`
	BalanceSats     int64   `json:"balance_sats,omitempty"`
	BalanceBloch    float64 `json:"balance_bloch,omitempty"`
	UtxoCount       int64   `json:"utxo_count,omitempty"`
	PendingIncoming int64   `json:"pending_incoming,omitempty"`
	PendingOutgoing int64   `json:"pending_outgoing,omitempty"`
	PoolRole        *string `json:"pool_role,omitempty"`
}

// AddressBalanceAtHeight — getaddressbalance_at_height result.
type AddressBalanceAtHeight struct {
	Address           string  `json:"address,omitempty"`
	Height            int64   `json:"height,omitempty"`
	BalanceSats       int64   `json:"balance_sats,omitempty"`
	BalanceBloch      float64 `json:"balance_bloch,omitempty"`
	TxCountUpToHeight int64   `json:"tx_count_up_to_height,omitempty"`
}

type AddressHistoryEntry struct {
	Txid          string  `json:"txid,omitempty"`
	BlockHeight   int64   `json:"block_height,omitempty"`
	Timestamp     int64   `json:"timestamp,omitempty"`
	Confirmations int64   `json:"confirmations,omitempty"`
	Direction     string  `json:"direction,omitempty"`
	AmountSats    int64   `json:"amount_sats,omitempty"`
	AmountBloch   float64 `json:"amount_bloch,omitempty"`
}

// ListTransactionsResult — listtransactions result.
type ListTransactionsResult struct {
	Address        string                `json:"address,omitempty"`
	Count          int64                 `json:"count,omitempty"`
	TotalAvailable int64                 `json:"total_available,omitempty"`
	StartHeight    int64                 `json:"start_height,omitempty"`
	EndHeight      int64                 `json:"end_height,omitempty"`
	Limit          int64                 `json:"limit,omitempty"`
	Offset         int64                 `json:"offset,omitempty"`
	Transactions   []AddressHistoryEntry `json:"transactions,omitempty"`
}

// AddressValidation — validateaddress result.
type AddressValidation struct {
	Address  string `json:"address,omitempty"`
	Isvalid  bool   `json:"isvalid,omitempty"`
	Network  string `json:"network,omitempty"`
	Checksum bool   `json:"checksum,omitempty"`
}

// AddressValidationVerbose — validateaddressverbose — one of two shapes depending on validity.
// (merged union of variant shapes; fields are optional).
type AddressValidationVerbose struct {
	Valid   *bool   `json:"valid,omitempty"`
	Address *string `json:"address,omitempty"`
	Network *string `json:"network,omitempty"`
	HashHex *string `json:"hash_hex,omitempty"`
	Prefix  *string `json:"prefix,omitempty"`
	Reason  *string `json:"reason,omitempty"`
}

// BroadcastResult — sendrawtransaction success.
type BroadcastResult struct {
	Txid string `json:"txid,omitempty"`
}

// FeeEstimate — estimatefee — median fee of current mempool entries.
type FeeEstimate struct {
	FeerateSats  int64   `json:"feerate_sats,omitempty"`
	FeerateBloch float64 `json:"feerate_bloch,omitempty"`
	MempoolSize  int64   `json:"mempool_size,omitempty"`
	Note         string  `json:"note,omitempty"`
}

// FeeEstimateAdvanced — estimatefeeadvanced result.
type FeeEstimateAdvanced struct {
	NextBlockSats    int64  `json:"next_block_sats,omitempty"`
	MediumPriority   int64  `json:"medium_priority,omitempty"`
	SlowPriority     int64  `json:"slow_priority,omitempty"`
	MempoolMedian    int64  `json:"mempool_median,omitempty"`
	MempoolSize      int64  `json:"mempool_size,omitempty"`
	RecommendedBloch string `json:"recommended_bloch,omitempty"`
}

// MempoolEntry — getrawmempool verbose entry.
type MempoolEntry struct {
	Txid     string  `json:"txid,omitempty"`
	Fee      int64   `json:"fee,omitempty"`
	FeeBloch float64 `json:"fee_bloch,omitempty"`
	Time     int64   `json:"time,omitempty"`
}

// RawMempool — getrawmempool — compact (txids) or verbose (transactions) shape.
// (merged union of variant shapes; fields are optional).
type RawMempool struct {
	Size         *int64         `json:"size,omitempty"`
	Txids        []string       `json:"txids,omitempty"`
	Transactions []MempoolEntry `json:"transactions,omitempty"`
}

type MempoolBucket struct {
	Range   string `json:"range,omitempty"`
	TxCount int64  `json:"tx_count,omitempty"`
}

// MempoolStats — getmempoolstats result.
type MempoolStats struct {
	Size      int64           `json:"size,omitempty"`
	TotalFees int64           `json:"total_fees,omitempty"`
	MinFee    int64           `json:"min_fee,omitempty"`
	MaxFee    int64           `json:"max_fee,omitempty"`
	MedianFee int64           `json:"median_fee,omitempty"`
	AvgFee    float64         `json:"avg_fee,omitempty"`
	Buckets   []MempoolBucket `json:"buckets,omitempty"`
}

// TxStatus — gettxstatus result.
type TxStatus struct {
	Status        string `json:"status,omitempty"`
	InMempool     bool   `json:"in_mempool,omitempty"`
	Confirmations int64  `json:"confirmations,omitempty"`
	BlockHeight   int64  `json:"block_height,omitempty"`
	Txid          string `json:"txid,omitempty"`
}

// ChainStats — getchainstats result.
type ChainStats struct {
	TotalBlocks       int64   `json:"total_blocks,omitempty"`
	TotalTxs          int64   `json:"total_txs,omitempty"`
	AvgTxsPerBlock    float64 `json:"avg_txs_per_block,omitempty"`
	BlocksLast24h     int64   `json:"blocks_last_24h,omitempty"`
	TxsLast24h        int64   `json:"txs_last_24h,omitempty"`
	AvgBlockTimeSecs  float64 `json:"avg_block_time_secs,omitempty"`
	CurrentDifficulty float64 `json:"current_difficulty,omitempty"`
	HashrateHs        float64 `json:"hashrate_hs,omitempty"`
	HashrateHuman     string  `json:"hashrate_human,omitempty"`
}

// HashrateInfo — gethashrate result.
type HashrateInfo struct {
	HashrateHs        float64 `json:"hashrate_hs,omitempty"`
	HashrateHuman     string  `json:"hashrate_human,omitempty"`
	AvgBlockTimeSecs  float64 `json:"avg_block_time_secs,omitempty"`
	CurrentDifficulty float64 `json:"current_difficulty,omitempty"`
}

type SupplyTier struct {
	Label        string  `json:"label,omitempty"`
	AddressCount int64   `json:"address_count,omitempty"`
	TotalSats    int64   `json:"total_sats,omitempty"`
	TotalBloch   float64 `json:"total_bloch,omitempty"`
	PctOfSupply  float64 `json:"pct_of_supply,omitempty"`
}

// SupplyDistribution — getsupplydistribution result.
type SupplyDistribution struct {
	Tiers          []SupplyTier `json:"tiers,omitempty"`
	TotalAddresses int64        `json:"total_addresses,omitempty"`
	TotalSats      int64        `json:"total_sats,omitempty"`
	TotalBloch     float64      `json:"total_bloch,omitempty"`
}

type DifficultyPoint struct {
	Height    int64  `json:"height,omitempty"`
	Bits      int64  `json:"bits,omitempty"`
	BitsHex   string `json:"bits_hex,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	TargetHex string `json:"target_hex,omitempty"`
}

// DifficultyHistory — getdifficultyhistory result.
type DifficultyHistory struct {
	Count  int64             `json:"count,omitempty"`
	Points []DifficultyPoint `json:"points,omitempty"`
}

// BlockTimePercentiles — getblocktimepercentiles result.
type BlockTimePercentiles struct {
	SampleSize int64   `json:"sample_size,omitempty"`
	Window     int64   `json:"window,omitempty"`
	MinSecs    float64 `json:"min_secs,omitempty"`
	P50Secs    float64 `json:"p50_secs,omitempty"`
	P90Secs    float64 `json:"p90_secs,omitempty"`
	P99Secs    float64 `json:"p99_secs,omitempty"`
	MaxSecs    float64 `json:"max_secs,omitempty"`
	AvgSecs    float64 `json:"avg_secs,omitempty"`
	TargetSecs float64 `json:"target_secs,omitempty"`
}

type TxInBlock struct {
	Txid         string `json:"txid,omitempty"`
	SizeBytes    int64  `json:"size_bytes,omitempty"`
	InputsCount  int64  `json:"inputs_count,omitempty"`
	OutputsCount int64  `json:"outputs_count,omitempty"`
	FeeSats      int64  `json:"fee_sats,omitempty"`
	IsCoinbase   bool   `json:"is_coinbase,omitempty"`
}

// TxsByBlock — gettxsbyblock result.
type TxsByBlock struct {
	BlockHash      string      `json:"block_hash,omitempty"`
	BlockHeight    int64       `json:"block_height,omitempty"`
	BlockTimestamp int64       `json:"block_timestamp,omitempty"`
	Count          int64       `json:"count,omitempty"`
	Txs            []TxInBlock `json:"txs,omitempty"`
}

// PoolReportEntry — One protocol pool in getpools. Founder entry adds vesting fields; a pool with no configured address reports status "pending_phase_6".
type PoolReportEntry struct {
	ShareBps               *int64  `json:"share_bps,omitempty"`
	SubsidyPerBlockSat     int64   `json:"subsidy_per_block_sat,omitempty"`
	AddressHashHex         *string `json:"address_hash_hex,omitempty"`
	Address                *string `json:"address,omitempty"`
	BalanceSat             int64   `json:"balance_sat,omitempty"`
	BalanceBloch           float64 `json:"balance_bloch,omitempty"`
	UtxoCount              int64   `json:"utxo_count,omitempty"`
	Status                 string  `json:"status,omitempty"`
	VestingPerMonthSat     int64   `json:"vesting_per_month_sat,omitempty"`
	VestingAmountAtNextSat int64   `json:"vesting_amount_at_next_sat,omitempty"`
	VestingActiveAtNext    bool    `json:"vesting_active_at_next,omitempty"`
	VestingTotalSat        int64   `json:"vesting_total_sat,omitempty"`
	VestingMonths          int64   `json:"vesting_months,omitempty"`
}

// Pools — getpools — next-block subsidy split plus per-pool address/balance.
type Pools struct {
	CurrentHeight        int64       `json:"current_height,omitempty"`
	NextBlockHeight      int64       `json:"next_block_height,omitempty"`
	SubsidyPerBlockSat   int64       `json:"subsidy_per_block_sat,omitempty"`
	SubsidyPerBlockBloch float64     `json:"subsidy_per_block_bloch,omitempty"`
	MinerShareSat        int64       `json:"miner_share_sat,omitempty"`
	Pools                *PoolsPools `json:"pools,omitempty"`
}

type BlockTemplateTx struct {
	Txid string `json:"txid,omitempty"`
	Fee  int64  `json:"fee,omitempty"`
	Data string `json:"data,omitempty"`
}

// BlockTemplate — getblocktemplate — everything a SIS-aware pool needs to assemble a candidate block. `bits` is computed exactly as accept_block validates (ASERT-Lattice anchored at genesis, keyed on the parent timestamp).
type BlockTemplate struct {
	Parents            []string          `json:"parents,omitempty"`
	Height             int64             `json:"height,omitempty"`
	BlueScore          int64             `json:"blue_score,omitempty"`
	Bits               int64             `json:"bits,omitempty"`
	CurTime            int64             `json:"cur_time,omitempty"`
	ParentTime         int64             `json:"parent_time,omitempty"`
	SubsidySat         int64             `json:"subsidy_sat,omitempty"`
	FounderVestingSat  int64             `json:"founder_vesting_sat,omitempty"`
	FounderAddressHash string            `json:"founder_address_hash,omitempty"`
	TotalFees          int64             `json:"total_fees,omitempty"`
	Transactions       []BlockTemplateTx `json:"transactions,omitempty"`
	ResidualCoeffs     []int64           `json:"residual_coeffs,omitempty"`
}

// SubmitBlockResult — submitblock — accepted, or a result.error on rejection / when the pool seam is not wired.
// (merged union of variant shapes; fields are optional).
type SubmitBlockResult struct {
	Accepted *bool   `json:"accepted,omitempty"`
	Hash     *string `json:"hash,omitempty"`
	Error    *string `json:"error,omitempty"`
}

// AttestationReport — getattestation — TEE attestation status. Reports `attested: false` when no TEE provider is active (the honest default on a non-confidential host). Serialized directly from the node's AttestationReport.
type AttestationReport struct {
	Attested    bool    `json:"attested,omitempty"`
	Tee         string  `json:"tee,omitempty"`
	Nonce       *string `json:"nonce,omitempty"`
	Measurement *string `json:"measurement,omitempty"`
	Hostdata    *string `json:"hostdata,omitempty"`
	ImageDigest *string `json:"image_digest,omitempty"`
	QuoteB64    *string `json:"quote_b64,omitempty"`
	OsRoothash  *string `json:"os_roothash,omitempty"`
	Note        string  `json:"note,omitempty"`
}

type PoolsPools struct {
	ValidatorPool *PoolReportEntry `json:"validator_pool,omitempty"`
	OraclePool    *PoolReportEntry `json:"oracle_pool,omitempty"`
	Founder       *PoolReportEntry `json:"founder,omitempty"`
}
