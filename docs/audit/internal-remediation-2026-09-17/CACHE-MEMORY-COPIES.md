# Local cache memory copies

Date: 2026-09-17. Source correction only; no production deployment or restart SLA.

A successful warm restore now moves the fully validated canonical log prefix
into the engine instead of cloning every `BlockEnvelope`. The input log keeps
only the uncached tail, which the normal replay loop consumes. Both cache
candidates still undergo the complete manifest/build/log/header/state checks
before any envelope is moved. If both candidates fail, the genesis engine and
complete input log remain available for full replay.

This removes one simultaneous deep copy of the cached prefix's signature,
transaction and attestation buffers. It does not make startup constant-memory:
`Store::read_all` still reads the entire log, the engine retains its canonical
block history, and the drained vector can retain its original allocation until
replay consumes it. The existing replay benchmark uses the same move/tail path.

Cache serialization now borrows every committed-state field and serializes
unspent outputs directly as an ordered sequence. It no longer clones the state
maps, queues and output entries into an owned serialization DTO. The serializer
reserves the bounded encoded size and appends directly to the node's cache
header buffer, removing the separate full encoded-state temporary. The small
checksum is written separately to the same staged file, avoiding a final
buffer growth solely to append 32 bytes. Durable private staging, previous-cache
rotation, checksum coverage, file layout and decode validation are unchanged.

The exhaustive `CommittedState` destructuring still forces new fields to be
handled explicitly. A populated-state regression compares the new bytes with
the previous owned serializer retained only under `cfg(test)`. Other tests check
allocation identity of a real block signature, uncached-tail preservation,
continuation equality with full replay, corrupted-cache fallback, and failed
restore preserving every original block. These are copy-elimination and
correctness evidence, not peak-RSS measurements.

An ignored, bounded `local_cache_serializer_memory_measurement` fixture can
compare the old and new serializers in separate compiled-test processes using
`BLOCH_CACHE_SERIALIZER=owned|borrowed` and `BLOCH_CACHE_BENCH_UTXOS` (default
100,000; maximum 200,000). Run the test executable directly under the platform
RSS tool, excluding Cargo/compiler processes. It prints serialized length,
checksum and serialization time. Whole-process peak RSS also includes identical
fixture/state construction and can hide or amplify allocation effects; it is
not an exchange recovery-time qualification.
