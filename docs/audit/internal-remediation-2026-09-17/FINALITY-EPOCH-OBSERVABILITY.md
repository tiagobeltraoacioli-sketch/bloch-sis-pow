# FC-09: rejected finality epoch feeds

The epoch transition previously discarded `FinalityState::process_epoch` errors.
It now increments a saturating process-wide `FINALITY_EPOCH_ORDER_FAILURES`
counter and writes a structured `finality_epoch_order` diagnostic containing the
received epoch, expected epoch and occurrence count. Logging occurs for the first
eight occurrences and subsequent powers of two; even an enormous replay cannot
produce one warning per rejected epoch indefinitely. A failed stderr write does
not panic or alter the transition.

This is an observability correction. It does not reset the finality cursor,
reject a formerly accepted block, change the returned post-state, introduce an
activation, or resolve why a cursor became desynchronized. The existing finality
no-op on `OutOfOrderEpoch` is deliberately preserved pending separate protocol
analysis. FC-09 therefore remains partial. The counter is process-local and is
not persisted or included in a state root; the structured warning is available
in node stderr logs.

The regression deliberately advances the committed state's epoch while leaving
its finality cursor behind, then closes two real epochs. Both failures increment
the counter while the finality engine remains unchanged and the surrounding
epoch transition still progresses, proving that diagnosis neither silently
resets the cursor nor turns the historical behavior into a transition refusal.
