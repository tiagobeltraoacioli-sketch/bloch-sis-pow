# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
# @generated from docs/openapi.yaml — do not edit by hand.
#
# Typed JSON-RPC 2.0 client for Bloch over the single `POST /` endpoint
# (default port 16210). Normalizes BOTH failure shapes:
#   1. the standard top-level `error` object (transport/auth: -32001/-32002)
#   2. the non-standard string `result.error` (HTTP 200, most method errors)

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Union

from .errors import BlochRpcError, BlochTransportError
from .models import *  # noqa: F401,F403 (typed model names for annotations)
from .signer import Signer  # noqa: F401 (re-export the write-path seam)

DEFAULT_RPC_URL = "http://127.0.0.1:16210"
DEFAULT_RPC_PORT = 16210


def _trim_optionals(pairs: List[Any]) -> List[Any]:
    """pairs: list of (value, default). Drop trailing entries whose value
    equals its default; keep interior ones (they become JSON null / value)."""
    items = list(pairs)
    while items and items[-1][0] == items[-1][1]:
        items.pop()
    return [v for v, _ in items]


class BlochClient:
    """A typed client for the Bloch JSON-RPC surface.

    Every method maps to one node RPC. Reads are public; the only write is
    :meth:`send_raw_transaction` (already-signed raw tx hex). Failures raise
    :class:`BlochRpcError` (both error shapes normalized) or
    :class:`BlochTransportError` (network / malformed response)."""

    def __init__(
        self,
        url: str = DEFAULT_RPC_URL,
        *,
        api_key: Optional[str] = None,
        bearer: bool = False,
        timeout: float = 30.0,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.url = url
        self.api_key = api_key
        self.bearer = bearer
        self.timeout = timeout
        self.static_headers = dict(headers or {})
        self._id = 0

    def call(self, method: str, params: Optional[List[Any]] = None) -> Any:
        """Low-level JSON-RPC call. Prefer the typed wrappers below."""
        self._id += 1
        payload = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": self._id}
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(self.static_headers)
        if self.api_key is not None:
            if self.bearer:
                headers["Authorization"] = f"Bearer {self.api_key}"
            else:
                headers["X-API-Key"] = self.api_key
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        status = 0
        raw = b""
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = getattr(resp, "status", resp.getcode())
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            # Transport/auth failures (401/429) arrive here with a JSON body.
            status = exc.code
            try:
                raw = exc.read()
            except Exception:
                raw = b""
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            raise BlochTransportError(
                f"RPC transport error calling {method}: {exc}", method=method
            ) from exc
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError) as exc:
            raise BlochTransportError(
                f"RPC {method}: response was not valid JSON (HTTP {status})",
                method=method,
                http_status=status,
            ) from exc
        envelope = parsed if isinstance(parsed, dict) else {}
        # Shape 1: standard top-level error object (transport/auth).
        err = envelope.get("error")
        if isinstance(err, dict):
            raise BlochRpcError(
                str(err.get("message", "JSON-RPC error")),
                method=method,
                source="jsonrpc-error",
                code=err.get("code") if isinstance(err.get("code"), int) else None,
                http_status=status,
                data=err.get("data"),
            )
        if status and status >= 400:
            raise BlochTransportError(
                f"RPC {method}: HTTP {status}", method=method, http_status=status
            )
        result = envelope.get("result")
        # Shape 2: non-standard string result.error (HTTP 200).
        if isinstance(result, dict) and isinstance(result.get("error"), str):
            raise BlochRpcError(
                result["error"], method=method, source="result-error", data=result
            )
        return result

    def get_network_info(self) -> "NetworkInfo":
        """JSON-RPC `getnetworkinfo` [chain-state]."""
        return self.call("getnetworkinfo")

    def get_block_count(self) -> "int":
        """JSON-RPC `getblockcount` [chain-state]."""
        return self.call("getblockcount")

    def get_mempool_info(self) -> "MempoolInfo":
        """JSON-RPC `getmempoolinfo` [chain-state]."""
        return self.call("getmempoolinfo")

    def get_dag_info(self) -> "DagInfo":
        """JSON-RPC `getdaginfo` [chain-state]."""
        return self.call("getdaginfo")

    def get_peer_info(self) -> "PeerInfo":
        """JSON-RPC `getpeerinfo` [chain-state]."""
        return self.call("getpeerinfo")

    def get_peers(self) -> "PeersList":
        """JSON-RPC `getpeers` [chain-state]."""
        return self.call("getpeers")

    def get_block_hash(self, height: int) -> "Hex32":
        """JSON-RPC `getblockhash` [blocks]."""
        return self.call("getblockhash", [height])

    def get_block(self, hash: str, verbose: bool = False) -> "Block":
        """JSON-RPC `getblock` [blocks]."""
        params: List[Any] = [hash]
        params.extend(_trim_optionals([(verbose, False)]))
        return self.call("getblock", params)

    def get_block_by_height(self, height: int, verbose: bool = False) -> "Block":
        """JSON-RPC `getblockbyheight` [blocks]."""
        params: List[Any] = [height]
        params.extend(_trim_optionals([(verbose, False)]))
        return self.call("getblockbyheight", params)

    def get_recent_blocks(self, count: int = 10) -> "List[BlockSummary]":
        """JSON-RPC `getrecentblocks` [blocks]."""
        params: List[Any] = []
        params.extend(_trim_optionals([(count, 10)]))
        return self.call("getrecentblocks", params)

    def get_txs_by_block(self, block: Any) -> "TxsByBlock":
        """JSON-RPC `gettxsbyblock` [blocks]."""
        return self.call("gettxsbyblock", [block])

    def get_transaction(self, txid: str) -> "TransactionLookup":
        """JSON-RPC `gettransaction` [transactions]."""
        return self.call("gettransaction", [txid])

    def get_tx_status(self, txid: str) -> "TxStatus":
        """JSON-RPC `gettxstatus` [transactions]."""
        return self.call("gettxstatus", [txid])

    def decode_raw_transaction(self, hex: str) -> "Transaction":
        """JSON-RPC `decoderawtransaction` [transactions]."""
        return self.call("decoderawtransaction", [hex])

    def get_raw_mempool(self, verbose: bool = False) -> "RawMempool":
        """JSON-RPC `getrawmempool` [transactions]."""
        params: List[Any] = []
        params.extend(_trim_optionals([(verbose, False)]))
        return self.call("getrawmempool", params)

    def get_mempool_stats(self) -> "MempoolStats":
        """JSON-RPC `getmempoolstats` [transactions]."""
        return self.call("getmempoolstats")

    def get_balance(self, address: str) -> "Balance":
        """JSON-RPC `getbalance` [addresses]."""
        return self.call("getbalance", [address])

    def get_utxos(self, address: str) -> "UtxoList":
        """JSON-RPC `getutxos` [addresses]."""
        return self.call("getutxos", [address])

    def get_address_info(self, address: str) -> "AddressInfo":
        """JSON-RPC `getaddressinfo` [addresses]."""
        return self.call("getaddressinfo", [address])

    def get_address_balance_at_height(self, address: str, height: int) -> "AddressBalanceAtHeight":
        """JSON-RPC `getaddressbalance_at_height` [addresses]."""
        return self.call("getaddressbalance_at_height", [address, height])

    def get_address_count(self) -> "AddressCount":
        """JSON-RPC `getaddresscount` [addresses]."""
        return self.call("getaddresscount")

    def list_transactions(self, address: str, limit: int = 20, start_height: int = 0, end_height: Optional[int] = None, offset: int = 0) -> "ListTransactionsResult":
        """JSON-RPC `listtransactions` [addresses]."""
        params: List[Any] = [address]
        params.extend(_trim_optionals([(limit, 20), (start_height, 0), (end_height, None), (offset, 0)]))
        return self.call("listtransactions", params)

    def validate_address(self, address: str) -> "AddressValidation":
        """JSON-RPC `validateaddress` [addresses]."""
        return self.call("validateaddress", [address])

    def validate_address_verbose(self, address: str) -> "AddressValidationVerbose":
        """JSON-RPC `validateaddressverbose` [addresses]."""
        return self.call("validateaddressverbose", [address])

    def estimate_fee(self) -> "FeeEstimate":
        """JSON-RPC `estimatefee` [fees]."""
        return self.call("estimatefee")

    def estimate_fee_advanced(self) -> "FeeEstimateAdvanced":
        """JSON-RPC `estimatefeeadvanced` [fees]."""
        return self.call("estimatefeeadvanced")

    def send_raw_transaction(self, hex: str) -> "BroadcastResult":
        """JSON-RPC `sendrawtransaction` [write] (WRITE — needs X-API-Key on a non-local node when auth is on)."""
        return self.call("sendrawtransaction", [hex])

    def get_chain_stats(self) -> "ChainStats":
        """JSON-RPC `getchainstats` [chain-state]."""
        return self.call("getchainstats")

    def get_hashrate(self) -> "HashrateInfo":
        """JSON-RPC `gethashrate` [chain-state]."""
        return self.call("gethashrate")

    def get_supply_distribution(self) -> "SupplyDistribution":
        """JSON-RPC `getsupplydistribution` [chain-state]."""
        return self.call("getsupplydistribution")

    def get_difficulty_history(self, limit: int = 20) -> "DifficultyHistory":
        """JSON-RPC `getdifficultyhistory` [chain-state]."""
        params: List[Any] = []
        params.extend(_trim_optionals([(limit, 20)]))
        return self.call("getdifficultyhistory", params)

    def get_block_time_percentiles(self, window: int = 100) -> "BlockTimePercentiles":
        """JSON-RPC `getblocktimepercentiles` [chain-state]."""
        params: List[Any] = []
        params.extend(_trim_optionals([(window, 100)]))
        return self.call("getblocktimepercentiles", params)

    def get_pools(self) -> "Pools":
        """JSON-RPC `getpools` [chain-state]."""
        return self.call("getpools")

    def get_attestation(self, nonce: Optional[str] = None) -> "AttestationReport":
        """JSON-RPC `getattestation` [chain-state]."""
        params: List[Any] = []
        params.extend(_trim_optionals([(nonce, None)]))
        return self.call("getattestation", params)

    def get_block_template(self) -> "BlockTemplate":
        """JSON-RPC `getblocktemplate` [mining]."""
        return self.call("getblocktemplate")

    def submit_block(self, block: str) -> "SubmitBlockResult":
        """JSON-RPC `submitblock` [mining] (WRITE — needs X-API-Key on a non-local node when auth is on)."""
        return self.call("submitblock", [block])

