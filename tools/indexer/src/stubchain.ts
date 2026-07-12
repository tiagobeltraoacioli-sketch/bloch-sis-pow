// SPDX-License-Identifier: MIT OR Apache-2.0
// Offline scripted chain that speaks the subset of Bloch JSON-RPC the indexer
// uses (getblockcount / getblockhash / getblockbyheight / getdaginfo), and can
// perform a reorg on command. Lets you exercise the reorg-safe logic with no
// live node (INDEXER_STUB=true), and backs the self-test.
//
// NOT a real node. Blocks/txs are minimal fixtures. Test coins have no value.

import { createHash } from "node:crypto";
import { unwrapResult, type JsonRpcTransport, type Tx, type Block } from "./rpc.js";

export interface StubBlock {
  hash: string;
  parents: string[];
  timestamp: number;
  transactions: Tx[];
}

function h(s: string): string {
  return createHash("sha3-256").update(s).digest("hex");
}

/** Deterministic 20-byte script_pubkey (hash) for a named actor. */
export function actorScript(name: string): string {
  return h("actor:" + name).slice(0, 40);
}

/** Deterministic txid from a label. */
export function txid(label: string): string {
  return h("tx:" + label);
}

export function coinbase(label: string, script: string, value: number): Tx {
  return {
    txid: txid(label),
    coinbase: true,
    inputs: [],
    outputs: [{ index: 0, value, script_pubkey: script }],
  };
}

export function payment(
  label: string,
  spend: { prev_txid: string; prev_index: number },
  outputs: Array<{ script: string; value: number }>,
): Tx {
  return {
    txid: txid(label),
    coinbase: false,
    inputs: [{ prev_txid: spend.prev_txid, prev_index: spend.prev_index, sequence: 0 }],
    outputs: outputs.map((o, i) => ({ index: i, value: o.value, script_pubkey: o.script })),
  };
}

export class StubChainTransport implements JsonRpcTransport {
  private blocks: StubBlock[] = [];

  constructor(initial: StubBlock[]) {
    this.blocks = [...initial];
  }

  /** Replace all blocks at heights >= fromHeight with `newBlocks` (a reorg). */
  reorgFrom(fromHeight: number, newBlocks: StubBlock[]): void {
    this.blocks = [...this.blocks.slice(0, fromHeight), ...newBlocks];
  }

  height(): number {
    return this.blocks.length - 1;
  }

  async call(method: string, params: unknown[]): Promise<unknown> {
    // Mirror the real transport: surface the node's `result.error` quirk as a
    // thrown RpcError so callers (and the not-found guards) behave identically.
    return unwrapResult(await this.dispatch(method, params), method);
  }

  private async dispatch(method: string, params: unknown[]): Promise<unknown> {
    switch (method) {
      case "getblockcount":
        return this.blocks.length;
      case "getdaginfo": {
        const tip = this.blocks[this.blocks.length - 1];
        return {
          tip: tip ? tip.hash : null,
          tip_height: this.blocks.length - 1,
          block_count: this.blocks.length,
          tips: tip ? [tip.hash] : [],
          k: 4,
        };
      }
      case "getblockhash": {
        const hgt = Number(params[0]);
        const b = this.blocks[hgt];
        return b ? b.hash : { error: "height not found" };
      }
      case "getblockbyheight": {
        const hgt = Number(params[0]);
        const b = this.blocks[hgt];
        if (!b) return { error: "height not found" };
        const block: Block = {
          hash: b.hash,
          height: hgt,
          parents: b.parents,
          timestamp: b.timestamp,
          transactions: b.transactions,
        };
        return block;
      }
      default:
        return { error: `stub: unsupported method ${method}` };
    }
  }
}

// ── A canned scenario used by the self-test and INDEXER_STUB runtime ──────────
//
// Chain A (heights 0..4):
//   h0 coinbase -> MINER 50
//   h1 MINER pays ALICE 30 (change 20 back to MINER)
//   h2 ALICE pays BOB 10 (change 20 to ALICE)
//   h3 BOB pays CAROL 5 (change 5 to BOB)     <-- will be reorged away
//   h4 coinbase -> MINER 50                    <-- will be reorged away
//
// Reorg replaces heights 3..4 with:
//   h3' BOB pays DAVE 8 (change 2 to BOB)      <-- CAROL never paid; DAVE paid
//   h4' coinbase -> MINER 50
//
// After the reorg a correct indexer must show CAROL balance 0 (her UTXO gone),
// DAVE balance 8, and no stale CAROL history.

export function buildScenario(): { transport: StubChainTransport; doReorg: () => void } {
  const MINER = actorScript("miner");
  const ALICE = actorScript("alice");
  const BOB = actorScript("bob");
  const CAROL = actorScript("carol");
  const DAVE = actorScript("dave");

  const chainA: StubBlock[] = [
    { hash: h("blkA0"), parents: [], timestamp: 1000, transactions: [coinbase("cb0", MINER, 50)] },
    {
      hash: h("blkA1"),
      parents: [h("blkA0")],
      timestamp: 1001,
      transactions: [
        payment("t1", { prev_txid: txid("cb0"), prev_index: 0 }, [
          { script: ALICE, value: 30 },
          { script: MINER, value: 20 },
        ]),
      ],
    },
    {
      hash: h("blkA2"),
      parents: [h("blkA1")],
      timestamp: 1002,
      transactions: [
        payment("t2", { prev_txid: txid("t1"), prev_index: 0 }, [
          { script: BOB, value: 10 },
          { script: ALICE, value: 20 },
        ]),
      ],
    },
    {
      hash: h("blkA3"),
      parents: [h("blkA2")],
      timestamp: 1003,
      transactions: [
        payment("t3", { prev_txid: txid("t2"), prev_index: 0 }, [
          { script: CAROL, value: 5 },
          { script: BOB, value: 5 },
        ]),
      ],
    },
    { hash: h("blkA4"), parents: [h("blkA3")], timestamp: 1004, transactions: [coinbase("cb4", MINER, 50)] },
  ];

  const transport = new StubChainTransport(chainA);

  const doReorg = () => {
    const chainB3plus: StubBlock[] = [
      {
        hash: h("blkB3"),
        parents: [h("blkA2")],
        timestamp: 1013,
        transactions: [
          payment("t3b", { prev_txid: txid("t2"), prev_index: 0 }, [
            { script: DAVE, value: 8 },
            { script: BOB, value: 2 },
          ]),
        ],
      },
      { hash: h("blkB4"), parents: [h("blkB3")], timestamp: 1014, transactions: [coinbase("cb4b", MINER, 50)] },
    ];
    transport.reorgFrom(3, chainB3plus);
  };

  return { transport, doReorg };
}
