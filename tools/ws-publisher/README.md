<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ws-publisher

The recurring publication pipeline for weak-subjectivity checkpoints —
the machinery that keeps the promise `WS_PUBLICATION_INTERVAL_EPOCHS = 256`
makes (crates/bloch-pos-committee/src/ws.rs:153).

Design, trust assumptions, channels and the third-party verification
runbook: **docs/specs/BLOCH-WS-PUBLICATION-PIPELINE.md**. Deployment
(systemd timer, env, channel fan-out): **deploy/ws-publication/**.

Four stations, one binary (`bloch-ws-publisher`, see `--help`):

| Station | Who runs it | Keys |
|---|---|---|
| `stage` | systemd timer, hourly, unattended | none |
| `sign` | one keyholder, attended, own machine | that keyholder's |
| `seal` | ceremony coordinator, attended | none |
| `verify` | any third party (exchanges) | none |

Everything numeric — the cadence, the 154-byte canonical layout, the
digest, the m-of-n quorum with its external minimum, the freshness window —
is imported from `bloch-pos-committee`; this crate restates none of it, the
tools/genesis4-ceremony rule. Sealing runs the node's own
`ws::verify_envelope` under the real ML-DSA-65 ‖ Falcon-1024 verifier, so
what this tool publishes and what a booting node accepts are the same
judgement.

The checkpoint *payload* (deriving the 154 bytes from chain state) is the
checkpoint tool's job; `stage` invokes it as a pluggable producer
(`--producer 'cmd … --epoch {epoch} --out {out}'`) and byte-validates the
result against the pins and the node's finalized root before staging.

```
cargo build --release -p ws-publisher
cargo test  -p ws-publisher     # includes stage→sign→seal→verify end to end
                                # under the real hybrid suite
```
