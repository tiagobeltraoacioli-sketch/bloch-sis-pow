#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Save getlcproof replies from a loopback node, once per finalized epoch.

  lcproof-capture.py --rpc-port N --out DIR [--hop K] [--stop-epoch E]

Writes DIR/e<epoch>.json (default set source) and DIR/e<epoch>-hop<K>.json (set
source K epochs back), plus DIR/admission.json. Read-only. Refuses anything but
127.0.0.1: this is for private rehearsal networks.
"""
import argparse
import json
import time
import urllib.request
from pathlib import Path


def call(port, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", body, {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc-port", type=int, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--hop", type=int, default=6)
    ap.add_argument("--stop-epoch", type=int, default=60)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    seen = 0
    while seen < a.stop_epoch:
        time.sleep(5)
        try:
            info = call(a.rpc_port, "getchaininfo", [])["result"]
            if not (a.out / "admission.json").exists():
                adm = call(a.rpc_port, "getvalidatoradmission", [])
                (a.out / "admission.json").write_text(json.dumps(adm))
            fin = info.get("finalized_epoch") or info.get("finality", {}).get("finalized_epoch") or 0
        except (OSError, ValueError, KeyError) as e:
            print(f"waiting: {e}", flush=True)
            continue
        for e in range(max(seen + 1, 1), fin + 1):
            for name, params in ((f"e{e}", [e]), (f"e{e}-hop{a.hop}", [e, max(e - a.hop, 1)])):
                try:
                    r = call(a.rpc_port, "getlcproof", params)
                except (OSError, ValueError) as x:
                    r = {"transport_error": str(x)}
                (a.out / f"{name}.json").write_text(json.dumps(r))
                res = r.get("result") or {}
                print(name, res.get("weights"), res.get("kes"), res.get("votes"), r.get("error"), flush=True)
            seen = e


if __name__ == "__main__":
    main()
