import {SOURCES} from './model.mjs';
import {SIGNALS, analyze, analysisReport} from './analytics.mjs';

const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const number = value => value == null ? '—' : value.toLocaleString('en-US', {maximumFractionDigits: 2});
const time = value => new Date(value).toLocaleTimeString('en-GB', {timeZone:'UTC'}) + ' UTC';
const svg = (tag, attrs = {}) => { const element = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [key,value] of Object.entries(attrs)) element.setAttribute(key,value); return element; };

export function mountAnalytics(root, download) {
  root.innerHTML = `<div class="section-label"><div><p class="eyebrow">OBSERVATION ANALYTICS / HISTORICAL SAMPLES</p><h2>Find the pattern.<br>Keep the context.</h2></div><div class="analytics-controls"><label>Analysis window<select id="analysis-window"><option value="15">Last 15 rounds</option><option value="30" selected>Last 30 rounds</option><option value="60">Last 60 rounds</option><option value="180">All retained rounds</option></select></label><button id="analysis-export" type="button" disabled>Analysis JSON ↓</button></div></div>
    <p class="scope-note">These calculations describe the selected observations. Missing values are excluded, never replaced with zero. A shared failure pattern does not establish its cause.</p>
    <div class="headline-metrics" id="analysis-metrics"></div>
    <article class="analysis-panel"><div class="section-label"><div><p class="eyebrow">SOURCE × ROUND</p><h3>Read outcome map</h3></div><span id="analysis-range"></span></div><div class="analysis-legend"><span>■ Valid reply at capture</span><span>■ Failed read</span><span>Click a cell or use the controls to inspect a sample.</span></div><div class="analysis-svg-scroll"><svg id="analysis-heatmap" viewBox="0 0 900 270" role="group" aria-label="Historical source read outcomes"></svg></div><div class="sample-controls"><label>Source<select id="analysis-source">${Object.entries(SOURCES).map(([key,meta])=>`<option value="${key}">${meta.name}</option>`).join('')}</select></label><label>Recorded round <span id="analysis-sample-label"></span><input type="range" id="analysis-sample" min="0" max="0" value="0" disabled></label></div><p id="analysis-sample-detail" class="scope-note" aria-live="polite"></p><details><summary>Inspect this historical source observation</summary><pre id="analysis-sample-json">No samples.</pre></details></article>
    <div class="analysis-grid"><article class="analysis-panel"><p class="eyebrow">ADJACENT OBSERVATIONS</p><h3>Observed head progress</h3><p class="scope-note">Blocks per minute between adjacent valid chain reads. Regressions, anchor conflicts and sampling gaps break the line. This is not transaction throughput.</p><svg id="analysis-progress" viewBox="0 0 620 205" role="img" aria-label="Observed chain head progress per minute"></svg></article><article class="analysis-panel"><p class="eyebrow">SHARED GATEWAY / FIVE METHODS</p><h3>Shared RPC failure episodes</h3><div id="analysis-episodes"></div></article></div>
    <article class="analysis-panel"><p class="eyebrow">PAIRWISE-COMPLETE PEARSON / MINIMUM EIGHT PAIRS</p><h3>Do the sampled signals move together?</h3><p class="scope-note">Each cell uses rounds where both values exist. Constant signals and smaller samples are unavailable. Correlation does not establish causation; time dependence and a shared gateway can distort it.</p><div class="table-scroll"><table id="analysis-correlation"></table></div><div id="analysis-pair-detail" class="scope-note" aria-live="polite">Select a coefficient for its paired sample count.</div><div class="table-scroll"><table><thead><tr><th>Signal</th><th>Valid / missing</th><th>Minimum</th><th>Median</th><th>P95</th><th>Maximum</th></tr></thead><tbody id="analysis-distributions"></tbody></table></div><p class="scope-note">Quantiles use linear interpolation between sorted sample positions. Statistics apply only to this window, not continuous availability. <a href="./ANALYTICS.md">Methods and limits ↗</a></p></article>`;
  const $ = id => root.querySelector('#' + id);
  let retained = [], config, selectedId = null, selectedSource = 'chain', selectedPair = [0,1];
  const window = () => retained.slice(-Number($('analysis-window').value));
  const selectedRound = () => { const rows = window(); return rows.find(r => r.id === selectedId) ?? rows.at(-1); };

  function inspect() {
    const rows = window(), round = selectedRound();
    $('analysis-sample').disabled = !rows.length;
    $('analysis-sample').max = String(Math.max(0, rows.length - 1));
    $('analysis-sample').value = String(Math.max(0, rows.indexOf(round)));
    $('analysis-source').value = selectedSource;
    $('analysis-sample-label').textContent = round ? `${rows.indexOf(round)+1} / ${rows.length}` : 'No samples';
    const observation = round?.observations[selectedSource];
    $('analysis-sample-detail').textContent = observation ? `${SOURCES[selectedSource].name} · ${time(observation.at)} · recorded ${observation.status} · ${number(observation.round_trip_ms)} ms${observation.error ? ' · ' + observation.error : ''}. Historical evidence, not a current availability claim.` : 'Waiting for the first observation round.';
    $('analysis-sample-json').textContent = observation ? JSON.stringify(observation, null, 2) : 'No samples.';
  }

  function heatmap(rows) {
    const graphic = $('analysis-heatmap'); graphic.replaceChildren();
    const cellWidth = Math.min(42, 690 / Math.max(1, rows.length));
    for (const [sourceIndex, source] of Object.keys(SOURCES).entries()) {
      const label = svg('text', {x:0,y:30+sourceIndex*35,class:'chart-label'}); label.textContent = SOURCES[source].name; graphic.append(label);
      rows.forEach((round,index) => {
        const observation = round.observations[source];
        const cell = svg('rect', {x:180+index*cellWidth,y:13+sourceIndex*35,width:Math.max(1,cellWidth-2),height:25,rx:2,class:'heat-cell','data-state':observation.status,'data-source':source,'data-round':String(index),role:'button','aria-label':`${SOURCES[source].name}, round ${index+1}, ${observation.status}. Use source and round controls for keyboard inspection.`});
        const title = svg('title'); title.textContent = `${time(observation.at)} · ${observation.status} · ${observation.round_trip_ms} ms`; cell.append(title);
        cell.addEventListener('click',()=>{selectedId=round.id;selectedSource=source;inspect();}); graphic.append(cell);
      });
    }
    const label=svg('text',{x:180,y:249,class:'chart-label'});label.textContent=rows.length?`${time(rows[0].finished_at)} → ${time(rows.at(-1).finished_at)} · oldest to newest`:'No observations yet';graphic.append(label);
  }

  function rates(points) {
    const graphic = $('analysis-progress'); graphic.replaceChildren();
    const valid = points.filter(p=>p.per_minute!==null);
    if (!valid.length) { const label=svg('text',{x:25,y:95,class:'chart-label'});label.textContent='Need two adjacent, consistent chain observations.';graphic.append(label);return; }
    const high=Math.max(...valid.map(p=>p.per_minute)),first=Date.parse(points[0].at),last=Date.parse(points.at(-1).at);
    const x=p=>last===first?330:60+(Date.parse(p.at)-first)/(last-first)*530,y=p=>high?165-p.per_minute/high*135:165;
    for(const tick of [0,.5,1]){const py=165-tick*135;graphic.append(svg('line',{x1:60,x2:590,y1:py,y2:py,class:'chart-grid'}));const label=svg('text',{x:2,y:py+4,class:'chart-label'});label.textContent=number(high*tick);if(high||!tick)graphic.append(label);}
    let segment=[];const flush=()=>{if(segment.length>1)graphic.append(svg('path',{d:segment.map((p,i)=>`${i?'L':'M'}${x(p)} ${y(p)}`).join(' '),class:'chart-line'}));segment=[];};
    for(const point of points){if(point.per_minute===null){flush();continue;}segment.push(point);const dot=svg('circle',{cx:x(point),cy:y(point),r:3,class:'chart-dot'}),title=svg('title');title.textContent=`${time(point.at)} · ${number(point.per_minute)} observed blocks/min`;dot.append(title);graphic.append(dot);}flush();
    const label=svg('text',{x:60,y:195,class:'chart-label'});label.textContent=`${time(points[0].at)} → ${time(points.at(-1).at)}`;graphic.append(label);
  }

  function pairDetail(analysis) {
    const [a,b]=selectedPair, cell=analysis.correlations[a][b];
    $('analysis-pair-detail').textContent=`${SIGNALS[a][1]} × ${SIGNALS[b][1]} · ${cell.n} paired samples · ${cell.r===null?cell.reason:'Pearson r = '+cell.r.toFixed(4)}.`;
  }

  function render() {
    const rows=window(), analysis=analyze(rows,config);
    $('analysis-export').disabled=!rows.length;
    $('analysis-metrics').innerHTML=[['Valid sampled reads',analysis.valid_fraction==null?'—':number(analysis.valid_fraction*100)+'%',`${analysis.valid_reads} / ${analysis.reads} attempts`],['Failed sampled reads',analysis.failed_reads,'Failures remain in the denominator'],['Shared failure episodes',analysis.episodes.length,'At least 3 / 5 RPC methods failed'],['Median observed progress',number(analysis.median_progress),`${analysis.progress_pairs} adjacent pairs · blocks/min`]].map(([label,value,note])=>`<article class="headline-metric"><span>${label}</span><strong>${value}</strong><small>${note}</small></article>`).join('');
    $('analysis-range').textContent=rows.length?`${rows.length} historical rounds · ${time(analysis.first_at)} → ${time(analysis.last_at)}`:'Waiting for observations';
    heatmap(rows);inspect();rates(analysis.rates);
    $('analysis-episodes').innerHTML=analysis.episodes.length?analysis.episodes.slice().reverse().map(e=>`<div class="failure-episode"><strong>${time(e.first_at)} → ${time(e.last_at)}</strong><p>${e.rounds} sampled rounds · peak ${e.peak_failed_methods} / 5 failed methods · indexer replied in ${e.indexer_valid_rounds} / ${e.rounds} rounds.</p><span>${{window_end:'Reaches selected window end',sampling_gap:'Split by a sampling gap',threshold_not_met:'Threshold not met in the next observed round'}[e.end_reason]}</span></div>`).join(''):'<p class="scope-note">No round in this window has three or more failed RPC reads. This is not a continuous availability measurement.</p>';
    $('analysis-correlation').innerHTML=`<thead><tr><th>Signal</th>${SIGNALS.map(([,name])=>`<th>${name}</th>`).join('')}</tr></thead><tbody>${analysis.correlations.map((row,a)=>`<tr><th>${SIGNALS[a][1]}</th>${row.map((cell,b)=>`<td><button class="correlation-cell" data-pair="${a},${b}" data-band="${cell.r===null?'unknown':Math.abs(cell.r)<.3?'low':cell.r>0?'positive':'negative'}" type="button" aria-label="${SIGNALS[a][1]} and ${SIGNALS[b][1]}: ${cell.r===null?cell.reason:cell.r.toFixed(2)}, ${cell.n} pairs">${cell.r===null?'—':cell.r.toFixed(2)}<small>n=${cell.n}</small></button></td>`).join('')}</tr>`).join('')}</tbody>`;
    for(const button of root.querySelectorAll('[data-pair]'))button.onclick=()=>{selectedPair=button.dataset.pair.split(',').map(Number);pairDetail(analysis);};
    pairDetail(analysis);
    $('analysis-distributions').innerHTML=analysis.signals.map(s=>`<tr><th>${escape(s.name)}<small class="signal-unit">${s.unit}</small></th><td>${s.n} / ${s.missing}</td><td>${number(s.min)}</td><td>${number(s.median)}</td><td>${number(s.p95)}</td><td>${number(s.max)}</td></tr>`).join('');
  }
  $('analysis-window').onchange=render;
  $('analysis-source').onchange=()=>{selectedSource=$('analysis-source').value;inspect();};
  $('analysis-sample').oninput=()=>{selectedId=window()[Number($('analysis-sample').value)]?.id;inspect();};
  $('analysis-export').onclick=()=>download(JSON.stringify(analysisReport(window(),config),null,2),'application/json','analysis.json');
  return {update(rounds,settings){retained=rounds;config=settings;render();}};
}
