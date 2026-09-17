// Public read-only RPC; HTTPS upstream must be provisioned before deployment.
// Shared code bounds bytes/time and preserves exact upstream amount encoding.
import { createRpcProxy } from "../../_shared/rpc-proxy.mjs";

const ALLOWED_METHODS = new Set([
  // Genesis-4 read methods (historical methods below remain available).
  "getchaininfo", "getbuildinfo", "getblockbyslot", "getblockbyid",
  "getvalidator", "getvalidatorcount", "getvalidatorbykey",
  "getvalidatoradmission", "getvalidators", "gettxout", "listunspent",
  // network / chain
  "getnetworkinfo",
  "getdaginfo",
  "getblockcount",
  "getchainstats",
  "gethashrate",
  "getdifficultyhistory",
  "getblocktimepercentiles",
  "getsupplydistribution",
  "getaddresscount",
  // blocks
  "getblockhash",
  "getblock",
  "getblockbyheight",
  "getrecentblocks",
  "gettxsbyblock",
  // transactions
  "gettransaction",
  "gettxstatus",
  "getrawmempool",
  "getmempoolinfo",
  "getmempoolstats",
  "estimatefee",
  "estimatefeeadvanced",
  "decoderawtransaction",
  // addresses / utxo
  "getbalance",
  "getutxos",
  "getaddressinfo",
  "getaddressbalance_at_height",
  "listtransactions",
  "validateaddress",
  "validateaddressverbose",
  // pools / peers / misc
  "getpools",
  "getpeerinfo",
  "getpeers",
  "getattestation",
]);


export const { onRequestOptions, onRequestPost } = createRpcProxy(ALLOWED_METHODS);
