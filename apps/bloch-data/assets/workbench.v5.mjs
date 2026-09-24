import { createReport, resultsCSV, MAX_BYTES } from './reconcile.v1.mjs';
import { samplesFor } from './samples.v1.mjs';
import { MODULES, INSTITUTIONS, REGIONS, defaultConfig, validateConfig, getModule } from './modules.v1.mjs';
import {newReview,appendReview,reviewExport,validateReview,readExport,latestReviews,REVIEW_STATES,MAX_REVIEW_BYTES} from './audit.v1.mjs';
import {setupVerification} from './verification.v1.mjs';
import {setupCaseFiles} from './case-workbench.v1.mjs';
import {setupCaseComparison} from './diff-workbench.v1.mjs';
import {buildQueue,selectQueue,queueSummary,queueCSV,defaultQueueFilter,QUEUE_REVIEW_STATES,QUEUE_SORTS} from './queue.v1.mjs';
const $ = id => document.getElementById(id);
const names = {matched:'Matched',different:'Different fields',left_only:'Only in A',right_only:'Only in B',duplicate:'Duplicate key'};
const colors = {matched:'#6b9046',different:'#b08943',left_only:'#638695',right_only:'#89a4b0',duplicate:'#b3654c'};
let sources=[null,null], mode='synthetic_example', current=null, page=0, computeId=0, loads=[0,0], pending=[false,false];
let config=defaultConfig('trades','br','exchange');
let review=null,selectedKey=null,reviewGeneration=0;
let queueIndex=null;
let caseFiles=null;
const pageSize=50;
function status(message,error=false) { $('workbench-status').textContent=message; $('workbench-status').classList.toggle('error',error); }
function invalidate() { computeId++; reviewGeneration++; current=null; review=null; selectedKey=null; queueIndex=null; caseFiles?.invalidateExport(); resetQueueFilters(); $('review-editor').hidden=true; $('reviewer').value=''; $('review-note').value=''; $('import-review').value=''; for(const id of ['result-rows','review-history','review-key','report-digest','field-chart','review-chart','queue-summary'])$(id).replaceChildren(); $('review-status').textContent=''; $('review-io-status').textContent='Download the evidence and review journal before clearing, loading files or rerunning. Resume retained reports with Verify below.'; $('results').hidden=true; $('run').disabled=!sources.every(Boolean)||pending.some(Boolean); }
function clearInputs() { loads=loads.map(v=>v+1); pending=[false,false]; sources=[null,null]; $('source-a').value=''; $('source-b').value=''; $('name-a').textContent='No file selected'; $('name-b').textContent='No file selected'; invalidate(); }
function updateMode() { $('mode-label').textContent=mode==='synthetic_example'?'SYNTHETIC EXAMPLE':'YOUR FILES / LOCAL ONLY'; }

async function run() {
  invalidate(); const request=computeId;
  if(!sources.every(Boolean)||pending.some(Boolean)) { status('Choose both source files before running the comparison.',true); return; }
  $('run').disabled=true; status('Comparing exact values and generating the local evidence manifest…');
  try {
    const result=await createReport(sources[0],sources[1],mode,config);
    if(request!==computeId)return;
    current=result; review=newReview(result.digest); page=0; $('status-filter').value='all'; render();
    const {key_count,counts}=current.report.result;
    status(`${mode==='synthetic_example'?'Synthetic example':'Local files'} · ${key_count} unique keys · ${counts.matched} matched · ${key_count-counts.matched} require review. No files were uploaded. No transaction was submitted.`);
  } catch(error) { if(request===computeId)status(error.message,true); }
  finally { if(request===computeId)$('run').disabled=false; }
}
async function selectFile(index) {
  if(mode==='synthetic_example') {
    sources=[null,null]; loads=loads.map(v=>v+1); pending=[false,false];
    $('name-a').textContent='No file selected'; $('name-b').textContent='No file selected';
    mode='local_files'; updateMode();
  }
  const input=$(index?'source-b':'source-a'), file=input.files[0], token=++loads[index];
  sources[index]=null; pending[index]=!!file; invalidate();
  $(index?'name-b':'name-a').textContent=file?file.name:'No file selected';
  if(!file) { status('Choose both source files to start.'); return; }
  status('Reading the selected file locally…');
  try {
    if(file.size>MAX_BYTES)throw new Error('Each CSV must be at most 2 MiB.');
    const bytes=await file.arrayBuffer();
    const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
    if(token!==loads[index])return;
    sources[index]={name:file.name,text};
    status('Files are kept in browser memory. Select both sources, then run reconciliation.');
  } catch(error) { if(token===loads[index])status(error instanceof TypeError?'Use a valid UTF-8 CSV file.':error.message,true); }
  finally { if(token===loads[index]) { pending[index]=false; invalidate(); } }
}
function loadSample() {
  clearInputs(); mode='synthetic_example'; updateMode();
  const pair=samplesFor(config);
  sources=pair.map((text,i)=>({name:`example-${config.module}-${i?'b':'a'}.csv`,text}));
  $('name-a').textContent=sources[0].name; $('name-b').textContent=sources[1].name;
  run();
}
function node(tag,text,className) { const n=document.createElement(tag); if(text!==undefined)n.textContent=text; if(className)n.className=className; return n; }
function svgNode(tag,attrs,text) { const n=document.createElementNS('http://www.w3.org/2000/svg',tag); Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,String(v))); if(text!==undefined)n.textContent=text; return n; }
function renderChart(result) {
  const svg=$('outcome-chart'); svg.replaceChildren();
  svg.append(svgNode('title',{},Object.keys(names).map(k=>`${names[k]}: ${result.counts[k]}`).join('; ')));
  const max=Math.max(...Object.values(result.counts),1);
  Object.keys(names).forEach((key,i)=>{const y=10+i*42;svg.append(svgNode('text',{x:0,y:y+19,fill:'#4a5b40','font-size':13},names[key]),svgNode('rect',{x:145,y,width:365,height:27,fill:'#ecf0e6',rx:2}),svgNode('rect',{x:145,y,width:365*result.counts[key]/max,height:27,fill:colors[key],rx:2}),svgNode('text',{x:530,y:y+19,fill:'#283a1e','font-size':14},result.counts[key]));});
}
function render() {
  const result=current.report.result;
  $('metric-keys').textContent=result.key_count; $('metric-matched').textContent=result.counts.matched;
  $('metric-review').textContent=result.key_count-result.counts.matched; $('metric-rows').textContent=`${result.left_rows} / ${result.right_rows}`;
  $('report-digest').textContent=current.digest; renderChart(result); renderReview(); renderTable(); $('results').hidden=false;
}
function renderTable() {
  if(!current)return;
  const latestByKey=latestReviews(review);
  let rows;
  try {rows=selectQueue(queueIndex,queueFilter()).entries.map(entry=>entry.item);}
  catch(error){$('result-rows').replaceChildren();$('queue-summary').textContent=error.message;$('export-queue').disabled=true;$('table-count').textContent='Invalid filter';$('previous-page').disabled=true;$('next-page').disabled=true;return;}
  const exceptions=rows.filter(item=>item.status!=='matched').length;
  $('queue-summary').textContent=`${rows.length} of ${current.report.result.key_count} keys selected · ${exceptions} exceptions · ${rows.length-exceptions} matched. Graphs summarize the full report.`;
  $('export-queue').disabled=rows.length===0;
  syncChartSelection();
  page=Math.min(page,Math.max(0,Math.ceil(rows.length/pageSize)-1));
  const tbody=$('result-rows'); tbody.replaceChildren();
  for(const item of rows.slice(page*pageSize,(page+1)*pageSize)) {
    const tr=node('tr'), key=node('td');
    key.append(node('strong',item.key.join(' · ')),node('small',current.report.matching_key.join(' / ')));
    const outcome=node('td'); outcome.append(node('span',names[item.status],`outcome ${item.status}`));
    const latest=latestByKey.get(JSON.stringify(item.key));
    if(item.status!=='matched')outcome.append(node('small',latest?REVIEW_STATES[latest.state]:'Not reviewed','review-badge'));
    if(latest){const annotation=node('details'),summary=node('summary',`Latest review · #${latest.sequence}`);annotation.append(summary,node('small',`${latest.reviewer} · ${latest.recorded_at} · local clock`),node('p',latest.note,'queue-note'));outcome.append(annotation);}
    const refs=node('td',`${item.left.map(r=>r.row).join(', ')||'—'} / ${item.right.map(r=>r.row).join(', ')||'—'}`);
    const detail=node('td');
    if(item.status==='matched') detail.textContent='All compared fields agree.';
    else if(item.status==='different') {
      const details=node('details'), summary=node('summary',`${item.differences.length} field difference${item.differences.length===1?'':'s'}`), list=node('ul');
      for(const field of item.differences)list.append(node('li',`${field}\nA: ${item.left[0].values[field]}\nB: ${item.right[0].values[field]}`));
      details.append(summary,list); detail.append(details);
    } else detail.textContent=item.status==='duplicate'?'Repeated key in a source; no automatic match.':`No matching key in source ${item.status==='left_only'?'B':'A'}.`;
    const records=node('details'), title=node('summary','View source records'), list=node('ul');
    for(const [side,entries] of [['A',item.left],['B',item.right]]){
      for(const record of entries.slice(0,20))list.append(node('li',`${side} · row ${record.row}\n`+Object.entries(record.values).map(([k,v])=>`${k}: ${v}`).join('\n')));
      if(entries.length>20)list.append(node('li',`${side}: ${entries.length-20} additional source records are retained in the full evidence JSON. Preview limited to 20 rows per source.`));
    }
    records.append(title,list);detail.append(records);
    if(item.status!=='matched') {const button=node('button','Review exception','review-record');button.type='button';button.addEventListener('click',()=>selectReview(item));detail.append(button);}
    tr.append(key,outcome,refs,detail);tbody.append(tr);
  }
  if(!rows.length){const tr=node('tr'),td=node('td','No keys match this filter.');td.colSpan=4;tr.append(td);tbody.append(tr);}
  $('table-count').textContent=`${rows.length? page*pageSize+1:0}–${Math.min((page+1)*pageSize,rows.length)} of ${rows.length} keys`;
  $('previous-page').disabled=page===0; $('next-page').disabled=(page+1)*pageSize>=rows.length;
}
function download(name,bytes,type) { const url=URL.createObjectURL(new Blob([bytes],{type}));const a=node('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000); }
$('source-a').addEventListener('change',()=>selectFile(0));$('source-b').addEventListener('change',()=>selectFile(1));
$('run').addEventListener('click',run);$('sample').addEventListener('click',loadSample);
$('clear').addEventListener('click',()=>{clearInputs();mode='local_files';updateMode();status('Comparison files, report and review journal cleared. Verification has a separate Clear button. Downloads remain on your device.');});
$('status-filter').addEventListener('change',()=>{page=0;renderTable();});
for(const id of ['review-filter','field-filter','queue-sort'])$(id).addEventListener('change',()=>{page=0;renderTable();});
$('queue-search').addEventListener('input',()=>{page=0;renderTable();});
$('reset-queue').addEventListener('click',()=>{resetQueueFilters();renderTable();});
$('previous-page').addEventListener('click',()=>{page--;renderTable();});$('next-page').addEventListener('click',()=>{page++;renderTable();});
$('export-json').addEventListener('click',()=>{if(current)download('bloch-data-evidence.json',current.bytes,'application/json');});
$('export-csv').addEventListener('click',()=>{if(current)download('bloch-data-results.csv',resultsCSV(current.report.result),'text/csv');});
$('export-hash').addEventListener('click',()=>{if(current)download('bloch-data-evidence.json.sha256',`${current.digest}  bloch-data-evidence.json\n`,'text/plain');});
function setConfigurationControls() {
  for(const [id,field] of [['module-select','module'],['institution-select','institution'],['region-select','region'],['date-format','date_format'],['decimal-format','decimal_format'],['csv-separator','separator'],['policy-purpose','purpose'],['policy-jurisdiction','jurisdiction'],['policy-retention','retention_policy'],['policy-region','processing_region']])$(id).value=config[field];
  $('gdpr-scope').checked=config.gdpr_in_scope; $('column-mapping').value=JSON.stringify(config.column_mapping,null,2);
}
function renderModule() {
  const module=getModule(config.module);
  $('module-title').textContent=module.name.toUpperCase()+' / V1';
  $('source-label-a').textContent=module.labels[0];$('source-label-b').textContent=module.labels[1];
  $('module-schema').textContent=module.fields.map(f=>config.column_mapping[f]??f).join(config.separator);
  $('module-key').textContent=module.keys.join(' + ');$('module-note').textContent=module.note;
  $('module-region-note').textContent=REGIONS[config.region].note;
  $('module-format-note').textContent=`${config.date_format==='dmy'?'DD/MM/YYYY':'YYYY-MM-DD'} dates · ${config.decimal_format==='comma'?'comma':'dot'} decimal mark · ${config.separator===';'?'semicolon':'comma'} delimiter · no thousands separators`;
  $('manifest-rule').textContent=module.version;
}
function acceptConfiguration(next) {
  const wasSample=mode==='synthetic_example';config=validateConfig(next);setConfigurationControls();renderModule();clearInputs();
  if(wasSample)loadSample();else status('Configuration applied. Select two files using the displayed module schema.');
  $('config-status').textContent='Configuration applied locally. Policy references are declarations; institutional enforcement remains external.';
}
for(const [id,registry] of [['module-select',MODULES],['institution-select',INSTITUTIONS],['region-select',REGIONS]])for(const [value,entry] of Object.entries(registry)){const option=node('option',entry.name);option.value=value;$(id).append(option);}
$('institution-select').addEventListener('change',()=>{$('module-select').value=INSTITUTIONS[$('institution-select').value].module;});
$('region-select').addEventListener('change',()=>{const region=REGIONS[$('region-select').value];$('date-format').value=region.format;$('decimal-format').value=region.decimal;$('csv-separator').value=region.separator;});
$('apply-config').addEventListener('click',()=>{
  try {const mappingText=$('column-mapping').value;if(mappingText.length>10000)throw new Error('Column mapping is too large.');acceptConfiguration({schema:'bloch.data.module-config.v1',module:$('module-select').value,institution:$('institution-select').value,region:$('region-select').value,date_format:$('date-format').value,decimal_format:$('decimal-format').value,separator:$('csv-separator').value,column_mapping:JSON.parse(mappingText),purpose:$('policy-purpose').value.trim(),jurisdiction:$('policy-jurisdiction').value.trim(),retention_policy:$('policy-retention').value.trim(),processing_region:$('policy-region').value.trim(),gdpr_in_scope:$('gdpr-scope').checked});}
  catch(error){$('config-status').textContent='Configuration not applied: '+error.message;}
});
$('export-config').addEventListener('click',()=>download('bloch-data-module-config.json',JSON.stringify(config,null,2)+'\n','application/json'));
$('import-config').addEventListener('change',async event=>{const file=event.target.files[0];if(!file)return;try{if(file.size>16384)throw new Error('Configuration must be at most 16 KiB.');acceptConfiguration(JSON.parse(await file.text()));}catch(error){$('config-status').textContent='Configuration not imported: '+error.message;}finally{event.target.value='';}});
for(const [id,index] of [['download-a',0],['download-b',1]])$(id).addEventListener('click',event=>{event.preventDefault();download(`example-${config.module}-${index?'b':'a'}.csv`,samplesFor(config)[index],'text/csv');});

function renderReview() {
  caseFiles?.invalidateExport();
  const latest=latestReviews(review),counts={investigating:0,explained:0,follow_up:0,reopened:0};
  for(const event of latest.values())counts[event.state]++;
  const total=current.report.result.key_count-current.report.result.counts.matched;
  $('review-unstarted').textContent=total-latest.size;
  $('review-explained').textContent=counts.explained;
  $('review-active').textContent=counts.investigating+counts.follow_up+counts.reopened;
  $('review-entry-count').textContent=review.events.length;
  renderDesk();
  if(selectedKey)renderReviewHistory();
}
function selectReview(item) {
  selectedKey=JSON.stringify(item.key);$('review-editor').hidden=false;
  $('review-key').textContent=item.key.join(' · ');$('review-outcome').textContent=names[item.status];
  $('review-state').value='investigating';$('review-note').value='';$('review-status').textContent='Record a local annotation. The original comparison outcome stays unchanged.';
  renderReviewHistory();$('review-editor').scrollIntoView({block:'center'});$('reviewer').focus({preventScroll:true});
}
function renderReviewHistory() {
  const list=$('review-history');list.replaceChildren();
  const entries=review.events.filter(event=>JSON.stringify(event.record_key)===selectedKey);
  for(const event of entries.slice(-20).reverse()) {
    const li=node('li');li.append(node('strong',`#${event.sequence} · ${REVIEW_STATES[event.state]} · ${event.reviewer}`),node('small',`${event.recorded_at} · local clock`),node('p',event.note));list.append(li);
  }
  $('review-history-count').textContent=entries.length>20?`Showing the latest 20 of ${entries.length} entries. The export retains all entries.`:`${entries.length} entries for this exception.`;
}
for(const [value,label] of Object.entries(REVIEW_STATES)){const option=node('option',label);option.value=value;$('review-state').append(option);}
$('save-review').addEventListener('click',()=>{
  if(!current||!selectedKey)return;
  try {
    const item=current.report.result.items.find(item=>JSON.stringify(item.key)===selectedKey);
    review=appendReview(review,current.report,current.digest,{record_key:item.key,original_outcome:item.status,state:$('review-state').value,reviewer:$('reviewer').value,note:$('review-note').value});
    reviewGeneration++;$('review-note').value='';renderReview();renderTable();
    $('review-status').textContent='Entry added in memory. Download the journal to retain it. Comparison outcomes are unchanged.';
  }catch(error){$('review-status').textContent=error.message;}
});
$('export-review').addEventListener('click',async()=>{
  if(!current)return;const token=reviewGeneration;
  const output=await reviewExport(review,current.report,current.digest);
  if(token===reviewGeneration)download('bloch-data-review.json',output.bytes,'application/json');
});
$('export-review-hash').addEventListener('click',async()=>{
  if(!current)return;const token=reviewGeneration;
  const output=await reviewExport(review,current.report,current.digest);
  if(token===reviewGeneration)download('bloch-data-review.json.sha256',`${output.digest}  bloch-data-review.json\n`,'text/plain');
});
$('import-review').addEventListener('change',async event=>{
  const file=event.target.files[0],token=++reviewGeneration;if(!file||!current)return;
  try {
    if(file.size>MAX_REVIEW_BYTES)throw new Error('Review journal must be at most 8 MiB.');
    const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer());
    if(token!==reviewGeneration)return;
    const next=validateReview(readExport(text,MAX_REVIEW_BYTES),current.report,current.digest);
    if(next.events.length<review.events.length||review.events.some((entry,i)=>JSON.stringify(entry)!==JSON.stringify(next.events[i])))throw new Error('Import would replace existing history. Open the original evidence in the verifier to start a separate review session.');
    review=next;renderReview();renderTable();$('review-io-status').textContent=`Imported ${review.events.length} entries bound to this evidence report. Reviewer identities are self-declared.`;
  }catch(error){if(token===reviewGeneration)$('review-io-status').textContent='Review not imported: '+error.message;}
  finally {if(token===reviewGeneration)event.target.value='';}
});
function openVerifiedReport({evidence,sources:originals,review:journal}) {
  clearInputs();config=validateConfig(evidence.report.configuration);setConfigurationControls();renderModule();
  sources=originals;mode=evidence.report.mode;updateMode();
  $('name-a').textContent=originals[0].name;$('name-b').textContent=originals[1].name;
  current=evidence;review=journal??newReview(evidence.digest);page=0;$('status-filter').value='review';
  $('review-io-status').textContent='Verified report opened. Download any new review entries before clearing or rerunning.';
  $('run').disabled=false;render();status('Opened a verified report for review. Its original bytes and outcomes are preserved. Running reconciliation again creates a new report.');
  $('results').scrollIntoView({block:'start'});
}
setupVerification(openVerifiedReport,download);
caseFiles=setupCaseFiles(()=>current&&review&&sources.every(Boolean)?{evidence:current,sources,review}:null,openVerifiedReport,download);
setupCaseComparison(openVerifiedReport,download);

function queueFilter() {return {query:$('queue-search').value,outcome:$('status-filter').value,review:$('review-filter').value,field:$('field-filter').value,sort:$('queue-sort').value};}
function resetQueueFilters() {
  const defaults=defaultQueueFilter();page=0;
  for(const [id,key] of [['queue-search','query'],['status-filter','outcome'],['review-filter','review'],['field-filter','field'],['queue-sort','sort']])$(id).value=defaults[key];
}
function chartButton(label,count,max,onClick) {
  const button=node('button',undefined,'desk-bar');button.type='button';button.disabled=count===0;
  const svg=svgNode('svg',{viewBox:'0 0 100 8','aria-hidden':'true',preserveAspectRatio:'none'});
  svg.append(svgNode('rect',{x:0,y:0,width:100,height:8,rx:2,fill:'#e1e8d8'}),svgNode('rect',{x:0,y:0,width:max?100*count/max:0,height:8,rx:2,fill:'#658849'}));
  button.append(node('span',label),svg,node('b',count));button.setAttribute('aria-pressed','false');button.addEventListener('click',onClick);return button;
}
function renderDesk() {
  queueIndex=buildQueue(current.report,review);const summary=queueSummary(queueIndex);
  const previousField=$('field-filter').value,any=node('option','Any differing field');any.value='';$('field-filter').replaceChildren(any);
  for(const {field,count} of summary.fields){const option=node('option',`${field} · ${count}`);option.value=field;$('field-filter').append(option);}
  $('field-filter').value=summary.fields.some(entry=>entry.field===previousField)?previousField:'';
  const fields=$('field-chart');fields.replaceChildren();
  for(const {field,count} of summary.fields){
    const button=chartButton(field,count,summary.fields[0].count,()=>{resetQueueFilters();$('field-filter').value=field;renderTable();$('queue-controls').scrollIntoView({block:'center'});$('field-filter').focus({preventScroll:true});});
    button.dataset.field=field;fields.append(button);
  }
  if(!summary.fields.length)fields.append(node('p','No comparable field differences. Missing records and duplicate keys are separate outcomes.','desk-empty'));
  const reviews=$('review-chart');reviews.replaceChildren();
  for(const [state,count] of Object.entries(summary.reviews)){
    const button=chartButton(QUEUE_REVIEW_STATES[state],count,Math.max(...Object.values(summary.reviews),1),()=>{resetQueueFilters();$('status-filter').value='review';$('review-filter').value=state;renderTable();$('queue-controls').scrollIntoView({block:'center'});$('review-filter').focus({preventScroll:true});});
    button.dataset.review=state;reviews.append(button);
  }
  $('desk-report-total').textContent=`${summary.keys} keys · ${summary.exceptions} exceptions · full report`;
}
function syncChartSelection() {
  for(const button of $('field-chart').querySelectorAll('button'))button.setAttribute('aria-pressed',String(button.dataset.field===$('field-filter').value));
  for(const button of $('review-chart').querySelectorAll('button'))button.setAttribute('aria-pressed',String(button.dataset.review===$('review-filter').value));
}
for(const [value,label] of Object.entries(QUEUE_REVIEW_STATES)){const option=node('option',label);option.value=value;$('review-filter').append(option);}
for(const [value,label] of Object.entries(QUEUE_SORTS)){const option=node('option',label);option.value=value;$('queue-sort').append(option);}
$('export-queue').addEventListener('click',async()=>{
  if(!current||!queueIndex)return;
  const token=computeId,journalToken=reviewGeneration,index=queueIndex,filter=queueFilter(),evidenceDigest=current.digest;
  try {
    const {digest}=await reviewExport(review,current.report,evidenceDigest);
    if(token!==computeId||journalToken!==reviewGeneration)return;
    download('bloch-data-filtered-queue.csv',queueCSV(index,filter,evidenceDigest,digest),'text/csv');
  }catch(error){if(token===computeId)$('queue-summary').textContent='Queue export failed: '+error.message;}
});
setConfigurationControls();renderModule();loadSample();
