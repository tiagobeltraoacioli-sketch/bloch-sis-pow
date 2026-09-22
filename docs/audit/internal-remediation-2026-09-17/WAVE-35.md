# Internal audit remediation, thirty-fifth wave — 2026-09-18

Base: `e5b2305`; branch `fix/internal-audit-20260917`. This wave reconciles
existing doppelgänger controls and their remaining boundary.

## Doppelgänger detection

KS-18 remains directionally correct: the detector is process-local, observes a
finite startup window and has a deliberate operator opt-out. Its generic open
ledger entry, however, omitted the protections added since the audit:

- observation begins only after replay and the weak-subjectivity boot gate, so
  a long restart still receives a complete live window;
- only duties signed at or after the observation start are evidence, preventing
  an old self-attestation replay from permanently halting the validator;
- accepted held attestations and authenticated proposals traverse the same
  duplicate-sighting hook;
- duties stay blocked during observation and remain blocked indefinitely once
  a current duplicate is detected;
- the environment opt-out now requires explicit `1`/`true`; `0`/`false` stay
  off and ambiguous values refuse startup.

All nine focused doppelgänger tests pass, covering the old-duty/current-duty
distinction, replay timing, proposal replay, observation gating, other
validator identities and permanent post-detection halt.

KS-18 moves to partial, not implemented. A process restart forgets the detector
state, no cross-host lease/fencing authority proves key singularity, the window
eventually closes and an explicit opt-out remains supported. The ledger retains
all 200 rows: 66 implemented, 83 partial, 37 open, seven base-changed, four
protocol decisions, one unarmed candidate, one refuted by the original audit
and one verified positive.
