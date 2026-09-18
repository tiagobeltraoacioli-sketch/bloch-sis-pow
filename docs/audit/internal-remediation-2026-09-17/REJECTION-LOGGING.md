# Bounded rejection diagnostics (NET-04, partial)

Date: 2026-09-17. Local observability policy only; validation results, peer
scores, signature verification, wire formats and consensus gates are unchanged.

Repeated rejected attestations and malformed/forged blocks previously wrote a
stderr line on every rejection, even when the exact failed signature came from
the negative cache. Libp2p decoding failures and sync refusals likewise emitted
one line per request. These writes run on engine/swarm paths, so cheap repeated
failures could still amplify log volume and synchronous output work.

The shared logger keeps exactly five static windows: block, attestation,
transaction, sync and connection. Each admits eight diagnostic calls per ten
monotonic seconds. Lower-level identifiers or attacker-controlled messages do
not allocate map entries. Formatting executes only for admitted calls, and the
logger releases its mutex before stderr output. A new window emits a summary of
prior suppressed calls before the first admitted diagnostic, if any. That is
up to eight admitted diagnostic calls plus one optional summary line per class
window. Existing diagnostic text may itself contain multiple lines.

`bloch_pos_rejection_logs_suppressed_total` counts every suppressed diagnostic
call cumulatively, saturating only at `u64::MAX`. Scrapes do not reset it, so
suppression remains observable even if no subsequent event triggers a summary.
This is a diagnostic-call count, not a count of distinct invalid transactions or
peers. Existing validation counters and all verdict/report paths still execute.

Fatal storage, signing and checkpoint errors are not throttled. This change does
not establish an asynchronous logging subsystem or a whole-process stderr bound:
a single admitted write can still block on the output destination, ordinary
operational diagnostics remain outside these classes, and explicitly enabled
`BLOCH_P2P_TRACE` still provides verbose tracing. Unique invalid signatures still
consume verification work. Static classes prevent unbounded per-source logging
state but do not guarantee every reason or peer receives an individual log line.

Regression coverage checks burst suppression, exact cumulative counts,
independent classes, recovery at the original monotonic deadline despite steady
input, and absence of formatting callbacks for suppressed events. An actual
engine fixture ingests the same forged block 100 times and verifies 100 rejection
verdicts, 100 rejected-signature counter increments, no stored/parked block and an
increased suppression counter.

Qualification: the targeted `rejection_logging` node selection passed **3 tests**
with no failures or ignored tests in
`/private/tmp/bloch-wave8-rejection-logging-final.log`. Metrics exposition is
checked separately in `/private/tmp/bloch-wave8-rejection-metrics.log`; broader
integration and hardened checks are recorded by the release owner.
