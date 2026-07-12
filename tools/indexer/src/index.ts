// SPDX-License-Identifier: MIT OR Apache-2.0
// Entry point: wire config -> transport -> rpc -> store -> indexer + read API.

import { loadConfig } from "./config.js";
import { HttpTransport, RpcClient, type JsonRpcTransport } from "./rpc.js";
import { JsonStore } from "./store.js";
import { Indexer } from "./indexer.js";
import { createReadApi } from "./api.js";
import { encodeAddress } from "./address.js";
import { buildScenario } from "./stubchain.js";

function main(): void {
  const cfg = loadConfig();

  let transport: JsonRpcTransport;
  let onStart: (() => void) | undefined;
  if (cfg.stub) {
    const scenario = buildScenario();
    transport = scenario.transport;
    // Trigger the scripted reorg once, a few seconds in, so operators watching
    // the logs see a real rollback+re-apply happen against the stub chain.
    onStart = () => {
      setTimeout(() => {
        console.log("[bloch-indexer] (stub) triggering scripted reorg at height 3…");
        scenario.doReorg();
      }, cfg.pollMs * 3);
    };
  } else {
    transport = new HttpTransport(cfg.rpcUrl, cfg.rpcApiKey);
  }

  const rpc = new RpcClient(transport);
  const store = JsonStore.open(cfg.dataFile, (spk) => encodeAddress(spk, cfg.network));
  const indexer = new Indexer(rpc, store, (m) => console.log(`[bloch-indexer] ${m}`));

  const api = createReadApi(cfg, store);
  api.listen(cfg.apiPort, cfg.apiHost, () => {
    console.log(`[bloch-indexer] reorg-safe reference indexer (SCAFFOLD, unaudited, testnet-only).`);
    console.log(`[bloch-indexer] read API on http://${cfg.apiHost}:${cfg.apiPort}`);
    console.log(`[bloch-indexer] source: ${cfg.stub ? "OFFLINE STUB CHAIN (scripted reorg)" : cfg.rpcUrl}`);
    console.log(`[bloch-indexer] network: ${cfg.network}; data: ${cfg.dataFile}`);
    console.log(`[bloch-indexer] BLCH is not a security; test BLCH has no value.`);
    onStart?.();
  });

  void indexer.run(cfg.pollMs);
}

main();
