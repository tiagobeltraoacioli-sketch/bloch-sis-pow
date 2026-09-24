# Historical observation analytics

The monitor's analytics section operates on the last 15, 30, 60 or all retained rounds. It uses the same validated observations as the source cards and works in live sessions and unverified local replay. It issues no additional network requests.

## Outcome map and shared failures

The source-by-round map records whether each read was valid or failed at capture time. It is a historical view, not current freshness. Select a cell or use the source selector and round slider to inspect the exact recorded observation. Failed reads stay in the denominator of the sampled success fraction. These are sampled attempts, not an uptime measurement.

An episode groups adjacent rounds where at least three of the five RPC methods failed. The methods share one gateway; concurrent failures cannot establish independent outages or a root cause. A gap above 2.5 times the selected polling interval splits an episode. A later round below the threshold ends the pattern, without claiming full recovery. Reaching the window end is labeled separately. The indexer's valid-read count is included as separate context, not as proof that the chain was operating.

## Rates and statistics

Head progress is the height difference between adjacent valid observations divided by their actual elapsed time, expressed as observed blocks per minute. Failed reads, non-increasing times, polling gaps, height/slot regressions and conflicting equal-height block IDs break the series. Missing rates remain unavailable; an observed unchanged head is zero. This does not measure transaction throughput or chain-wide performance.

The matrix calculates pairwise-complete Pearson coefficients for RPC latency, finality distance, observer lag, indexer lag, node queue and reported connections. At least eight rounds with both values are required. Constant signals have no defined coefficient. Each cell exposes its paired sample count. No significance test or causal interpretation is offered: temporal dependence, shared sources and small samples can distort correlations.

Distribution quantiles use linear interpolation at sorted position `(n - 1) * p`. The table shows valid and missing counts, minimum, median, P95 and maximum for every signal. Source latency statistics elsewhere retain their documented nearest-rank P95 definition.

## Portable analysis

The analysis JSON includes descriptive results, method notes and the selected normalized source evidence. Opening it through the monitor's local import enters unverified replay and recomputes all calculations; stored analysis conclusions are not trusted. The same 8 MiB and 180-round limits apply. Only explicit downloads persist data, and no private data, keys, browser signing or value-moving operations are involved.
