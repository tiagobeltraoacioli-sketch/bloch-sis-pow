// Public read-only RPC; HTTPS upstream must be provisioned before deployment.
// Shared code bounds bytes/time and preserves exact upstream amount encoding.
import { createRpcProxy } from "../../_shared/rpc-proxy.mjs";

const ALLOWED_METHODS = new Set([
  "getnetworkinfo",
  "getdaginfo",
  "getblockcount",
  "getchainstats",
  "gethashrate",
  "getdifficultyhistory",
  "getpools",
  "getpeerinfo",
  "getpeers",
  "getmempoolinfo",
]);


export const { onRequestOptions, onRequestPost } = createRpcProxy(ALLOWED_METHODS);
