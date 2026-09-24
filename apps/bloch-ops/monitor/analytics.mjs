import {SOURCES, metrics, statistics} from './model.mjs';

export const SIGNALS = Object.freeze([
  ['latency', 'RPC latency', 'ms'],
  ['finality_gap', 'Finality distance', 'blocks'],
  ['sync_lag', 'Observer lag', 'slots'],
  ['indexer_lag', 'Indexer lag', 'slots'],
  ['mempool', 'Node queue', 'transactions'],
  ['connections', 'Connections', 'reported connections'],
]);
const rpcSources = Object.keys(SOURCES).filter(key => SOURCES[key].method);
const finite = value => typeof value === 'number' && Number.isFinite(value);

export function quantile(values, fraction) {
  const ordered = values.filter(finite).toSorted((a, b) => a - b);
  if (!ordered.length) return null;
  const position = (ordered.length - 1) * fraction;
  const low = Math.floor(position), high = Math.ceil(position);
  return ordered[low] + (ordered[high] - ordered[low]) * (position - low);
}

export function pearson(pairs, minimum = 8) {
  const valid = pairs.filter(([x, y]) => finite(x) && finite(y));
  if (valid.length < minimum) return {n: valid.length, r: null, reason: 'Insufficient paired samples'};
  const n = valid.length;
  const meanX = valid.reduce((sum, [x]) => sum + x, 0) / n;
  const meanY = valid.reduce((sum, [, y]) => sum + y, 0) / n;
  let xx = 0, yy = 0, xy = 0;
  for (const [x, y] of valid) { xx += (x - meanX) ** 2; yy += (y - meanY) ** 2; xy += (x - meanX) * (y - meanY); }
  if (!xx || !yy) return {n, r: null, reason: 'A signal is constant'};
  return {n, r: Math.max(-1, Math.min(1, xy / Math.sqrt(xx * yy))), reason: null};
}

export function progress(rounds, interval) {
  return rounds.map((round, index) => {
    const previous = rounds[index - 1]?.observations.chain;
    const current = round.observations.chain;
    const result = {at: current.at, per_minute: null, reason: 'No adjacent valid chain pair'};
    if (previous?.status !== 'valid' || current.status !== 'valid') return result;
    const elapsed = Date.parse(current.at) - Date.parse(previous.at);
    if (elapsed <= 0 || elapsed > interval * 2500) return {...result, reason: 'Sampling gap or non-increasing time'};
    const blocks = current.data.height - previous.data.height;
    if (blocks < 0 || current.data.slot < previous.data.slot || blocks === 0 && current.data.block_id !== previous.data.block_id) return {...result, reason: 'Contradictory or regressed chain observation'};
    return {...result, per_minute: blocks * 60000 / elapsed, reason: null};
  });
}

export function failureEpisodes(rounds, interval) {
  const episodes = [];
  let open = null, previousAt = null;
  const close = reason => { if (open) episodes.push({...open, end_reason: reason}); open = null; };
  for (const round of rounds) {
    const at = Date.parse(round.finished_at);
    if (previousAt !== null && at - previousAt > interval * 2500) close('sampling_gap');
    const failed = rpcSources.filter(source => round.observations[source].status === 'failed');
    if (failed.length >= 3) {
      if (!open) open = {first_at: round.finished_at, last_at: round.finished_at, rounds: 0, peak_failed_methods: 0, indexer_valid_rounds: 0, sources: []};
      open.last_at = round.finished_at;
      open.rounds++;
      open.peak_failed_methods = Math.max(open.peak_failed_methods, failed.length);
      open.indexer_valid_rounds += Number(round.observations.indexer.status === 'valid');
      open.sources = [...new Set([...open.sources, ...failed])];
    } else close('threshold_not_met');
    previousAt = at;
  }
  close('window_end');
  return episodes;
}

export function analyze(rounds, config) {
  const rows = rounds.map(metrics), stats = statistics(rounds);
  const total = rounds.length * Object.keys(SOURCES).length;
  const valid = Object.values(stats).reduce((sum, source) => sum + source.valid, 0);
  const signals = SIGNALS.map(([key, name, unit]) => {
    const values = rows.map(row => row[key]).filter(finite);
    return {key, name, unit, n: values.length, missing: rows.length - values.length,
      min: values.length ? Math.min(...values) : null, median: quantile(values, .5),
      p95: quantile(values, .95), max: values.length ? Math.max(...values) : null};
  });
  const correlations = SIGNALS.map(([a]) => SIGNALS.map(([b]) => ({a, b, ...pearson(rows.map(row => [row[a], row[b]]))})));
  const rates = progress(rounds, config.interval), usableRates = rates.map(r => r.per_minute).filter(finite);
  return {rounds: rounds.length, reads: total, valid_reads: valid, failed_reads: total - valid,
    valid_fraction: total ? valid / total : null, first_at: rounds[0]?.started_at ?? null,
    last_at: rounds.at(-1)?.finished_at ?? null, signals, correlations, rates,
    median_progress: quantile(usableRates, .5), progress_pairs: usableRates.length,
    episodes: failureEpisodes(rounds, config.interval), source_statistics: stats};
}

export function analysisReport(rounds, config) {
  return {schema: 'bloch-ops-analysis/1', generated_at: new Date().toISOString(),
    interpretation: 'Historical browser samples; not uptime, consensus attestation, causal inference or independent source verification.',
    methods: {correlation: 'Pairwise-complete Pearson; at least eight pairs; constants are unavailable.',
      quantiles: 'Linear interpolation between ordered sample positions (n - 1) × p.',
      progress: 'Adjacent valid, non-regressed chain observations; gaps above 2.5 times the selected interval are excluded.',
      failure_episode: 'At least three of five RPC methods failed in a round; sampling gaps split episodes.'},
    analysis: analyze(rounds, config),
    evidence: {schema: 'bloch-ops-monitor/1', settings: {...config}, rounds: structuredClone(rounds)}};
}
