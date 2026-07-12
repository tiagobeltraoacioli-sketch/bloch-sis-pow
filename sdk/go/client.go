// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
// @generated from docs/openapi.yaml — do not edit by hand.
//
// Typed JSON-RPC 2.0 client for Bloch over the single POST / endpoint
// (default port 16210). Normalizes BOTH failure shapes:
//   1. standard top-level `error` object (transport/auth: -32001/-32002)
//   2. non-standard string `result.error` (HTTP 200, most method errors)

package blochclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

const DefaultRPCURL = "http://127.0.0.1:16210"
const DefaultRPCPort = 16210

// Client is a typed client for the Bloch JSON-RPC surface. Reads are public;
// the only write is SendRawTransaction (already-signed raw tx hex).
type Client struct {
	URL        string
	APIKey     string
	Bearer     bool
	HTTPClient *http.Client
	Headers    map[string]string
	id         int64
}

// New returns a Client pointed at url (empty = DefaultRPCURL) with a 30s timeout.
func New(url string) *Client {
	if url == "" {
		url = DefaultRPCURL
	}
	return &Client{URL: url, HTTPClient: &http.Client{Timeout: 30 * time.Second}}
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int64         `json:"id"`
}

type rpcErrorObject struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcErrorObject `json:"error"`
}

// Call is the low-level JSON-RPC call. Prefer the typed wrappers. out may be
// nil (result discarded) or a pointer to unmarshal the result into.
func (c *Client) Call(method string, params []interface{}, out interface{}) error {
	if params == nil {
		params = []interface{}{}
	}
	id := atomic.AddInt64(&c.id, 1)
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method, Params: params, ID: id})
	if err != nil {
		return &TransportError{Method: method, Message: fmt.Sprintf("marshal request: %v", err)}
	}
	req, err := http.NewRequest("POST", c.URL, bytes.NewReader(body))
	if err != nil {
		return &TransportError{Method: method, Message: fmt.Sprintf("build request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	if c.APIKey != "" {
		if c.Bearer {
			req.Header.Set("Authorization", "Bearer "+c.APIKey)
		} else {
			req.Header.Set("X-API-Key", c.APIKey)
		}
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return &TransportError{Method: method, Message: fmt.Sprintf("transport error: %v", err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return &TransportError{Method: method, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf("read body: %v", err)}
	}
	var env rpcEnvelope
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &env); err != nil {
			return &TransportError{Method: method, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf("response was not valid JSON: %v", err)}
		}
	}
	// Shape 1: standard top-level error object (transport/auth).
	if env.Error != nil {
		return &RPCError{Method: method, Source: "jsonrpc-error", Code: env.Error.Code, HTTPStatus: resp.StatusCode, Message: env.Error.Message}
	}
	if resp.StatusCode >= 400 {
		return &TransportError{Method: method, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	// Shape 2: non-standard string result.error (HTTP 200).
	if len(env.Result) > 0 {
		var probe map[string]json.RawMessage
		if json.Unmarshal(env.Result, &probe) == nil {
			if rawErr, ok := probe["error"]; ok {
				var msg string
				if json.Unmarshal(rawErr, &msg) == nil {
					return &RPCError{Method: method, Source: "result-error", Message: msg}
				}
			}
		}
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return &TransportError{Method: method, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf("decode result: %v", err)}
		}
	}
	return nil
}

// GetNetworkInfo calls JSON-RPC `getnetworkinfo`.
func (c *Client) GetNetworkInfo() (*NetworkInfo, error) {
	params := []interface{}{}
	out := new(NetworkInfo)
	err := c.Call("getnetworkinfo", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetBlockCount calls JSON-RPC `getblockcount`.
func (c *Client) GetBlockCount() (int64, error) {
	params := []interface{}{}
	var out int64
	err := c.Call("getblockcount", params, &out)
	return out, err
}

// GetMempoolInfo calls JSON-RPC `getmempoolinfo`.
func (c *Client) GetMempoolInfo() (*MempoolInfo, error) {
	params := []interface{}{}
	out := new(MempoolInfo)
	err := c.Call("getmempoolinfo", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetDagInfo calls JSON-RPC `getdaginfo`.
func (c *Client) GetDagInfo() (*DagInfo, error) {
	params := []interface{}{}
	out := new(DagInfo)
	err := c.Call("getdaginfo", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetPeerInfo calls JSON-RPC `getpeerinfo`.
func (c *Client) GetPeerInfo() (*PeerInfo, error) {
	params := []interface{}{}
	out := new(PeerInfo)
	err := c.Call("getpeerinfo", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetPeers calls JSON-RPC `getpeers`.
func (c *Client) GetPeers() (*PeersList, error) {
	params := []interface{}{}
	out := new(PeersList)
	err := c.Call("getpeers", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetBlockHash calls JSON-RPC `getblockhash`.
func (c *Client) GetBlockHash(height int64) (string, error) {
	params := []interface{}{height}
	var out string
	err := c.Call("getblockhash", params, &out)
	return out, err
}

// GetBlock calls JSON-RPC `getblock`.
func (c *Client) GetBlock(hash string, verbose bool) (*Block, error) {
	params := []interface{}{hash}
	opt := []struct {
		v   interface{}
		def bool
	}{
		{verbose, verbose == false},
	}
	lastKeep := -1
	for i := range opt {
		if !opt[i].def {
			lastKeep = i
		}
	}
	for i := 0; i <= lastKeep; i++ {
		params = append(params, opt[i].v)
	}
	out := new(Block)
	err := c.Call("getblock", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetBlockByHeight calls JSON-RPC `getblockbyheight`.
func (c *Client) GetBlockByHeight(height int64, verbose bool) (*Block, error) {
	params := []interface{}{height}
	opt := []struct {
		v   interface{}
		def bool
	}{
		{verbose, verbose == false},
	}
	lastKeep := -1
	for i := range opt {
		if !opt[i].def {
			lastKeep = i
		}
	}
	for i := 0; i <= lastKeep; i++ {
		params = append(params, opt[i].v)
	}
	out := new(Block)
	err := c.Call("getblockbyheight", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetRecentBlocks calls JSON-RPC `getrecentblocks`.
func (c *Client) GetRecentBlocks(count int64) ([]BlockSummary, error) {
	params := []interface{}{}
	opt := []struct {
		v   interface{}
		def bool
	}{
		{count, count == 10},
	}
	lastKeep := -1
	for i := range opt {
		if !opt[i].def {
			lastKeep = i
		}
	}
	for i := 0; i <= lastKeep; i++ {
		params = append(params, opt[i].v)
	}
	var out []BlockSummary
	err := c.Call("getrecentblocks", params, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetTxsByBlock calls JSON-RPC `gettxsbyblock`.
func (c *Client) GetTxsByBlock(block interface{}) (*TxsByBlock, error) {
	params := []interface{}{block}
	out := new(TxsByBlock)
	err := c.Call("gettxsbyblock", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetTransaction calls JSON-RPC `gettransaction`.
func (c *Client) GetTransaction(txid string) (*TransactionLookup, error) {
	params := []interface{}{txid}
	out := new(TransactionLookup)
	err := c.Call("gettransaction", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetTxStatus calls JSON-RPC `gettxstatus`.
func (c *Client) GetTxStatus(txid string) (*TxStatus, error) {
	params := []interface{}{txid}
	out := new(TxStatus)
	err := c.Call("gettxstatus", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DecodeRawTransaction calls JSON-RPC `decoderawtransaction`.
func (c *Client) DecodeRawTransaction(hex string) (*Transaction, error) {
	params := []interface{}{hex}
	out := new(Transaction)
	err := c.Call("decoderawtransaction", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetRawMempool calls JSON-RPC `getrawmempool`.
func (c *Client) GetRawMempool(verbose bool) (*RawMempool, error) {
	params := []interface{}{}
	opt := []struct {
		v   interface{}
		def bool
	}{
		{verbose, verbose == false},
	}
	lastKeep := -1
	for i := range opt {
		if !opt[i].def {
			lastKeep = i
		}
	}
	for i := 0; i <= lastKeep; i++ {
		params = append(params, opt[i].v)
	}
	out := new(RawMempool)
	err := c.Call("getrawmempool", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetMempoolStats calls JSON-RPC `getmempoolstats`.
func (c *Client) GetMempoolStats() (*MempoolStats, error) {
	params := []interface{}{}
	out := new(MempoolStats)
	err := c.Call("getmempoolstats", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetBalance calls JSON-RPC `getbalance`.
func (c *Client) GetBalance(address string) (*Balance, error) {
	params := []interface{}{address}
	out := new(Balance)
	err := c.Call("getbalance", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetUtxos calls JSON-RPC `getutxos`.
func (c *Client) GetUtxos(address string) (*UtxoList, error) {
	params := []interface{}{address}
	out := new(UtxoList)
	err := c.Call("getutxos", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetAddressInfo calls JSON-RPC `getaddressinfo`.
func (c *Client) GetAddressInfo(address string) (*AddressInfo, error) {
	params := []interface{}{address}
	out := new(AddressInfo)
	err := c.Call("getaddressinfo", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetAddressBalanceAtHeight calls JSON-RPC `getaddressbalance_at_height`.
func (c *Client) GetAddressBalanceAtHeight(address string, height int64) (*AddressBalanceAtHeight, error) {
	params := []interface{}{address, height}
	out := new(AddressBalanceAtHeight)
	err := c.Call("getaddressbalance_at_height", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetAddressCount calls JSON-RPC `getaddresscount`.
func (c *Client) GetAddressCount() (*AddressCount, error) {
	params := []interface{}{}
	out := new(AddressCount)
	err := c.Call("getaddresscount", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListTransactions calls JSON-RPC `listtransactions`.
func (c *Client) ListTransactions(address string, limit int64, startHeight int64, endHeight *int64, offset int64) (*ListTransactionsResult, error) {
	params := []interface{}{address}
	opt := []struct {
		v   interface{}
		def bool
	}{
		{limit, limit == 20},
		{startHeight, startHeight == 0},
		{endHeight, endHeight == nil},
		{offset, offset == 0},
	}
	lastKeep := -1
	for i := range opt {
		if !opt[i].def {
			lastKeep = i
		}
	}
	for i := 0; i <= lastKeep; i++ {
		params = append(params, opt[i].v)
	}
	out := new(ListTransactionsResult)
	err := c.Call("listtransactions", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateAddress calls JSON-RPC `validateaddress`.
func (c *Client) ValidateAddress(address string) (*AddressValidation, error) {
	params := []interface{}{address}
	out := new(AddressValidation)
	err := c.Call("validateaddress", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateAddressVerbose calls JSON-RPC `validateaddressverbose`.
func (c *Client) ValidateAddressVerbose(address string) (*AddressValidationVerbose, error) {
	params := []interface{}{address}
	out := new(AddressValidationVerbose)
	err := c.Call("validateaddressverbose", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EstimateFee calls JSON-RPC `estimatefee`.
func (c *Client) EstimateFee() (*FeeEstimate, error) {
	params := []interface{}{}
	out := new(FeeEstimate)
	err := c.Call("estimatefee", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EstimateFeeAdvanced calls JSON-RPC `estimatefeeadvanced`.
func (c *Client) EstimateFeeAdvanced() (*FeeEstimateAdvanced, error) {
	params := []interface{}{}
	out := new(FeeEstimateAdvanced)
	err := c.Call("estimatefeeadvanced", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SendRawTransaction calls JSON-RPC `sendrawtransaction` (WRITE — needs X-API-Key on a non-local node when auth is on).
func (c *Client) SendRawTransaction(hex string) (*BroadcastResult, error) {
	params := []interface{}{hex}
	out := new(BroadcastResult)
	err := c.Call("sendrawtransaction", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetChainStats calls JSON-RPC `getchainstats`.
func (c *Client) GetChainStats() (*ChainStats, error) {
	params := []interface{}{}
	out := new(ChainStats)
	err := c.Call("getchainstats", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetHashrate calls JSON-RPC `gethashrate`.
func (c *Client) GetHashrate() (*HashrateInfo, error) {
	params := []interface{}{}
	out := new(HashrateInfo)
	err := c.Call("gethashrate", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetSupplyDistribution calls JSON-RPC `getsupplydistribution`.
func (c *Client) GetSupplyDistribution() (*SupplyDistribution, error) {
	params := []interface{}{}
	out := new(SupplyDistribution)
	err := c.Call("getsupplydistribution", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetDifficultyHistory calls JSON-RPC `getdifficultyhistory`.
func (c *Client) GetDifficultyHistory(limit int64) (*DifficultyHistory, error) {
	params := []interface{}{}
	opt := []struct {
		v   interface{}
		def bool
	}{
		{limit, limit == 20},
	}
	lastKeep := -1
	for i := range opt {
		if !opt[i].def {
			lastKeep = i
		}
	}
	for i := 0; i <= lastKeep; i++ {
		params = append(params, opt[i].v)
	}
	out := new(DifficultyHistory)
	err := c.Call("getdifficultyhistory", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetBlockTimePercentiles calls JSON-RPC `getblocktimepercentiles`.
func (c *Client) GetBlockTimePercentiles(window int64) (*BlockTimePercentiles, error) {
	params := []interface{}{}
	opt := []struct {
		v   interface{}
		def bool
	}{
		{window, window == 100},
	}
	lastKeep := -1
	for i := range opt {
		if !opt[i].def {
			lastKeep = i
		}
	}
	for i := 0; i <= lastKeep; i++ {
		params = append(params, opt[i].v)
	}
	out := new(BlockTimePercentiles)
	err := c.Call("getblocktimepercentiles", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetPools calls JSON-RPC `getpools`.
func (c *Client) GetPools() (*Pools, error) {
	params := []interface{}{}
	out := new(Pools)
	err := c.Call("getpools", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetAttestation calls JSON-RPC `getattestation`.
func (c *Client) GetAttestation(nonce *string) (*AttestationReport, error) {
	params := []interface{}{}
	opt := []struct {
		v   interface{}
		def bool
	}{
		{nonce, nonce == nil},
	}
	lastKeep := -1
	for i := range opt {
		if !opt[i].def {
			lastKeep = i
		}
	}
	for i := 0; i <= lastKeep; i++ {
		params = append(params, opt[i].v)
	}
	out := new(AttestationReport)
	err := c.Call("getattestation", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetBlockTemplate calls JSON-RPC `getblocktemplate`.
func (c *Client) GetBlockTemplate() (*BlockTemplate, error) {
	params := []interface{}{}
	out := new(BlockTemplate)
	err := c.Call("getblocktemplate", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SubmitBlock calls JSON-RPC `submitblock` (WRITE — needs X-API-Key on a non-local node when auth is on).
func (c *Client) SubmitBlock(block string) (*SubmitBlockResult, error) {
	params := []interface{}{block}
	out := new(SubmitBlockResult)
	err := c.Call("submitblock", params, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}
