# Optional native component persistence

The `native-component-snapshots` Cargo feature connects the committee's bounded
native component codec to a derived `native-component.bin` sidecar in the
existing node data directory. It enables compilation of the native component
implementation; both consensus activation epochs remain `u64::MAX`.

The authoritative durable input remains `blocks.log`. A node writes the sidecar
only after the corresponding log append or reorganization rewrite is durable.
It writes a fresh private temporary file, synchronizes it, atomically renames
it and synchronizes the directory. The existing Store directory lock prevents
two node processes from owning that directory; the engine performs these writes
synchronously. An interrupted temporary file never replaces the last complete file.

On restart the node still replays every canonical block. Only after that replay
does it compare the sidecar's genesis identity, head, slot and state root with
the independently reconstructed state. Stale heads are cache misses. A matching
head with contradictory metadata, malformed bytes or invalid native state is
refused before the node becomes live. Missing sidecars are rebuilt from replay.

Component restoration uses the native commitment already present in replayed
`CommittedState`; it cannot introduce a component where replay found none.
The restored complete state must have the same canonical root. Rehearsal fee
escrow, caller-provided checkpoint authority and external gateway observations
cannot initialize canonical native state through this interface.

The version-1 sidecar header is `BPOSNAT1`, little-endian u32 version, genesis
manifest digest, block ID, state root, little-endian slot u64, payload length u32
and a SHA3-256 digest over the domain tag, preceding header and payload. An empty
payload records component absence. Payload length is checked against metadata
and the 64 MiB codec limit before allocation. Reads refuse symlinks, nonregular
files and multiple hard links on Unix.

This is a durable restoration cross-check, not accelerated boot, fast sync or
a full base-state snapshot format. It adds optional disk/verification work and
does not skip consensus replay. Gateway registration/import dispatch, route
bootstrap, finality proofs and production activation remain separate work.

Validation:

```sh
cargo test --offline -p bloch-pos-node --features native-component-snapshots --bin bloch-pos store::native_snapshot -- --test-threads=1
cargo test --offline -p bloch-pos-committee --features native-dex-rehearsal --lib snapshot_wire
```

Storage tests cover durable replacement, reopen, preserved component absence,
refused bootstrap, stale heads, conflicting identities, corrupt/truncated files,
forged lengths and interrupted writes. Committee tests separately exercise real
populated component restoration and subsequent canonical execution, including
custody indexes and gateway import/release replay protection.
