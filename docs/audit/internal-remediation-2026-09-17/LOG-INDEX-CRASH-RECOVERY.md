# Derived log index recovery across reorg publication

The block log is authoritative; the slot index is disposable. Previously a reorg
published its rewritten log before clearing the old index. A crash between those
operations could leave an index with valid magic, offsets and covered length
that nevertheless described the losing branch. For equal-size old slots `[1,2]`
and replacement slots `[100,200]`, a request after slot 50 returned no blocks:
the index's `Nothing` fast path bypassed the existing header-mismatch fallback.
This exact residue was reproduced before the correction.

The store now durably invalidates the index before publishing a rewritten log.
Startup also rebuilds the index from the actual log, recovering residue left by
older binaries instead of treating covered length as proof of log identity.
A per-canonical-directory read/write guard keeps in-process serving threads from
combining an index from one log generation with a replacement log. The weak
registry shares path aliases and removes entries without live users; unrelated
stores retain independent guards. Staging the replacement log happens before
acquiring the write guard. Readers hold their shared guard only through one
bounded page request; rebuilding/publishing holds the exclusive guard.

Lock-taking entry points are `Store::open`, `Store::rewrite`, and
`Store::blocks_after`. The internal index/scan helpers take no generation lock,
so those entry points do not recursively acquire it. A poisoned guard refuses
serving and requires restart. This coordinates the node owning `DirLock` and its
reader threads; it is not an inter-process transaction protocol for external
programs bypassing the store lock and directly editing/reading live files.

## Recovery cost and limits

Every startup now performs one additional header/index reconstruction pass over
N complete frames. Explicit frame reads are `N × (4 + 304)` bytes, plus a final
EOF check; buffered read-ahead and actual device I/O may read more. Bodies are
skipped rather than decoded for this pass. The rebuilt index writes `8 + 20N`
bytes and is fsynced. At 100,000 frames this is 30.8 MB of explicit header/prefix
reads and approximately 2 MB of index output. Reconstruction remains O(N) in
work and temporary index memory. It does not add consensus state replay or PQ
signature verification. This is a cost bound, not a measured fleet restart SLA.

The existing per-request page count/byte caps and indexed past-tip fast path
remain. Tests retain those bounds, reproduce the old crash residue, force an
index-invalidation failure through a real read-only descriptor to prove the log
is not replaced first, and check guard identity across aliases and unrelated
stores. Per-frame checksums and policy for consensus-invalid log contents remain
separate open recovery work; this change neither repairs nor trusts such data.

## Index append failures

A separate reproduced failure affected a live process: after indexing slot1,
slot2's log append succeeded while its index write failed; the next successful
index write added slot3. Serving after slot1 then returned only slot3, because the
index looked fully covered while containing a hole. The node now disables further
index appends after their first failure, retaining the known contiguous prefix.
Readers scan its unindexed tail, so later log entries cannot hide the missing
frame. A successful reorg rebuild or restart restores normal indexing. The
regression forces the failure with a real read-only descriptor, verifies slots2
and3 are both served, then verifies indexing resumes after rebuild.

Tail scanning after an index failure can be O(tail length) per request until
rebuild; this deliberately preserves availability and correctness of the durable
log instead of claiming the index failure is cost-free.

## Private replacement staging

Block-log rewrites and restart-cache writes now stream into exclusively created
0600 staging files. They no longer truncate predictable `blocks.log.tmp` or
`state.cache.tmp` paths. A prepositioned symlink at either legacy path is ignored,
and its target is unchanged. Shared staging cleanup removes only its own
successfully created path and is disarmed immediately after successful rename.
The staged file and published directory entry are fsynced. Cache staging is synced
before moving the old cache to its previous-generation name. Crash leftovers are
not swept by wildcard cleanup. Regression fixtures retain the unrelated target,
private output mode, previous cache bytes and successful cache restoration.

## Writer/reader frame ceiling

Append and rewrite now reject an encoded envelope exceeding the existing 8 MiB
log-reader ceiling before changing the authoritative log or its index. This does
not lower a reader or consensus limit. Previously the writer could successfully
persist bytes that its own next startup refused to read. The regression rejects
an oversized append and a rewrite containing a valid prefix followed by an
oversized frame, checks both original files are unchanged and owned staging is
cleaned, then persists and reopens an envelope exactly at the existing limit.
The check follows encoding; it is not a new bound on callers' in-memory objects.
