import {compareCaseFiles,caseComparisonCSV,selectChanges,defaultDiffFilter,CHANGE_LABELS,OUTCOME_LABELS} from './case-diff.v1.mjs';
import {MAX_CASE_BYTES} from './case-file.v1.mjs';
import {exampleCasePair} from './diff-samples.v1.mjs';

export function setupCaseComparison(openForReview,download) {
  const $=id=>document.getElementById(id),pageSize=50;
  let generation=0,current=null,page=0;
  const node=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
  const status=(text,error=false)=>{$('diff-status').textContent=text;$('diff-status').classList.toggle('error',error);};
  function resetFilters(){const f=defaultDiffFilter();for(const [id,key] of [['diff-query','query'],['diff-category','category'],['diff-before','before'],['diff-after','after']])$(id).value=f[key];page=0;}
  function invalidate(){generation++;current=null;page=0;resetFilters();$('diff-results').hidden=true;for(const id of ['diff-counts','diff-matrix','diff-rows','diff-identities','diff-digest','diff-table-count','diff-summary'])$(id).replaceChildren();$('diff-run').disabled=false;$('diff-example').disabled=false;}
  for(const id of ['diff-baseline','diff-candidate'])$(id).addEventListener('change',()=>{invalidate();status('Selection changed. Both cases must be verified again before comparison.');});
  for(const id of ['diff-baseline-pin','diff-candidate-pin'])$(id).addEventListener('input',()=>{invalidate();status('Retained digest changed. Run comparison again.');});
  $('diff-clear').addEventListener('click',()=>{invalidate();for(const id of ['diff-baseline','diff-candidate','diff-baseline-pin','diff-candidate-pin'])$(id).value='';status('Comparison inputs and results cleared. Other workbench sessions and downloads remain separate.');});
  async function read(file){if(!file)throw new Error('Choose a baseline and a candidate case.');if(file.size>MAX_CASE_BYTES)throw new Error('Each case must be at most 64 MiB.');return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer());}
  async function run(example=false){
    invalidate();const token=generation,pins=[$('diff-baseline-pin').value.trim().toLowerCase(),$('diff-candidate-pin').value.trim().toLowerCase()],files=[$('diff-baseline').files[0],$('diff-candidate').files[0]];
    if(example)for(const id of ['diff-baseline','diff-candidate','diff-baseline-pin','diff-candidate-pin'])$(id).value='';
    $('diff-run').disabled=true;$('diff-example').disabled=true;status(example?'Building and verifying two labelled synthetic cases locally…':'Verifying both cases, then comparing normalized records and per-key review histories locally…');
    try {
      let texts;
      if(example)texts=await exampleCasePair();
      else {const a=await read(files[0]);if(token!==generation)return;texts=[a,await read(files[1])];}
      if(token!==generation)return;
      const result=await compareCaseFiles(texts[0],texts[1],...(example?['','']:pins));
      if(token!==generation)return;
      current=result;render();$('diff-results').hidden=false;
      status(`${result.report.mode==='synthetic_example'?'Synthetic cases':'Local-file cases'} · both verified · ${result.report.key_count} keys compared. Baseline/candidate order is your selection, not verified chronology. No review entries were transferred.`);
    }catch(error){if(token===generation)status('Comparison failed: '+(error instanceof TypeError?'Use valid UTF-8 case files.':error.message),true);}
    finally{if(token===generation){$('diff-run').disabled=false;$('diff-example').disabled=false;}}
  }
  function render(){
    const r=current.report;
    for(const [category,label] of Object.entries(CHANGE_LABELS)){
      const button=node('button');button.type='button';button.dataset.category=category;button.append(node('strong',r.counts[category]),node('span',label));button.setAttribute('aria-pressed','false');
      button.addEventListener('click',()=>{resetFilters();$('diff-category').value=category;renderTable();});$('diff-counts').append(button);
    }
    const head=node('thead'),hr=node('tr');hr.append(node('th','Baseline ↓ / Candidate →'));
    for(const label of Object.values(OUTCOME_LABELS)){const th=node('th',label);th.scope='col';hr.append(th);}head.append(hr);
    const body=node('tbody');
    for(const [from,label] of Object.entries(OUTCOME_LABELS)){
      const row=node('tr'),th=node('th',label);th.scope='row';row.append(th);
      for(const [to,toLabel] of Object.entries(OUTCOME_LABELS)){
        const count=r.transitions[from][to],td=node('td'),button=node('button',count);button.type='button';button.disabled=count===0;button.dataset.before=from;button.dataset.after=to;button.setAttribute('aria-pressed','false');button.setAttribute('aria-label',`${label} to ${toLabel}: ${count} keys`);
        button.addEventListener('click',()=>{resetFilters();$('diff-before').value=from;$('diff-after').value=to;renderTable();});td.append(button);row.append(td);
      }body.append(row);
    }$('diff-matrix').append(head,body);
    for(const [label,snapshot] of [['Baseline',r.baseline],['Candidate',r.candidate]]){
      const card=node('div');card.append(node('strong',label),node('code',snapshot.case_sha256),node('small',snapshot.retained_case_digest_check==='matched'?'Retained case digest matched':'No independent case digest supplied'));$('diff-identities').append(card);
    }
    $('diff-digest').textContent=current.digest;
    $('diff-summary').textContent=`${r.key_count} keys in the union · ${r.review_changed_keys} with changed review history · ${r.row_reference_moved_keys} with row moves on an otherwise unchanged source side. Original bytes changed: evidence ${r.snapshot_changes.evidence_bytes?'yes':'no'}, journal ${r.snapshot_changes.review_bytes?'yes':'no'}, source A ${r.snapshot_changes.source_bytes.A?'yes':'no'}, source B ${r.snapshot_changes.source_bytes.B?'yes':'no'}.`;
    renderTable();
  }
  function filters(){return {query:$('diff-query').value,category:$('diff-category').value,before:$('diff-before').value,after:$('diff-after').value};}
  function sourcePreview(item){
    const details=node('details');details.append(node('summary','Inspect retained records and review history'));const list=node('ul');
    for(const [label,record,history] of [['Baseline',item.before,item.before_review],['Candidate',item.after,item.after_review]]){
      if(!record)list.append(node('li',`${label}: key absent.`));
      else for(const [side,rows] of [['A',record.left],['B',record.right]]){
        for(const row of rows.slice(0,10))list.append(node('li',`${label} / ${side} / row ${row.row}\n`+Object.entries(row.values).map(([k,v])=>`${k}: ${v}`).join('\n')));
        if(rows.length>10)list.append(node('li',`${label} / ${side}: ${rows.length-10} additional records are retained in the comparison JSON.`));
      }
      for(const event of history.slice(-10))list.append(node('li',`${label} review #${event.sequence} · ${event.state} · ${event.reviewer}\n${event.recorded_at} (local clock)\n${event.note}`));
      if(history.length>10)list.append(node('li',`${label}: ${history.length-10} earlier review entries are retained in the comparison JSON.`));
    }details.append(list);return details;
  }
  function renderTable(){
    if(!current)return;let items;
    try {items=selectChanges(current.report,filters());}catch(error){$('diff-rows').replaceChildren();$('diff-table-count').textContent=error.message;$('diff-previous').disabled=true;$('diff-next').disabled=true;return;}
    page=Math.min(page,Math.max(0,Math.ceil(items.length/pageSize)-1));const rows=$('diff-rows');rows.replaceChildren();
    for(const item of items.slice(page*pageSize,(page+1)*pageSize)){
      const tr=node('tr'),key=node('td',item.key.join(' · ')),category=node('td',CHANGE_LABELS[item.category]),transition=node('td',`${OUTCOME_LABELS[item.before_outcome]} → ${OUTCOME_LABELS[item.after_outcome]}`),detail=node('td');
      for(const [side,change] of Object.entries(item.source_changes))if(change.records_changed)detail.append(node('p',`${side}: ${change.fields.length?'changed field values: '+change.fields.join(', '):'record combinations changed; individual field value counts agree'}.`));
      if(item.review_changed)detail.append(node('p','Per-key review history changed.'));
      if(item.row_references_moved)detail.append(node('p','Source row references moved while normalized values agree.'));
      if(item.category==='unchanged'&&!item.row_references_moved)detail.append(node('p','Normalized records, outcome and per-key annotations agree.'));
      detail.append(sourcePreview(item));tr.append(key,category,transition,detail);rows.append(tr);
    }
    if(!items.length){const tr=node('tr'),td=node('td','No keys match these filters.');td.colSpan=4;tr.append(td);rows.append(tr);}
    $('diff-table-count').textContent=`${items.length?page*pageSize+1:0}–${Math.min((page+1)*pageSize,items.length)} of ${items.length} selected keys`;
    $('diff-previous').disabled=page===0;$('diff-next').disabled=(page+1)*pageSize>=items.length;
    for(const button of $('diff-counts').querySelectorAll('button'))button.setAttribute('aria-pressed',String(button.dataset.category===$('diff-category').value));
    for(const button of $('diff-matrix').querySelectorAll('button'))button.setAttribute('aria-pressed',String(button.dataset.before===$('diff-before').value&&button.dataset.after===$('diff-after').value));
  }
  for(const [value,label] of Object.entries(CHANGE_LABELS)){const option=node('option',label);option.value=value;$('diff-category').append(option);}
  for(const id of ['diff-before','diff-after'])for(const [value,label] of Object.entries(OUTCOME_LABELS)){const option=node('option',label);option.value=value;$(id).append(option);}
  for(const id of ['diff-category','diff-before','diff-after'])$(id).addEventListener('change',()=>{page=0;renderTable();});
  $('diff-query').addEventListener('input',()=>{page=0;renderTable();});$('diff-reset').addEventListener('click',()=>{resetFilters();renderTable();});
  $('diff-run').addEventListener('click',()=>run());$('diff-example').addEventListener('click',()=>run(true));
  $('diff-previous').addEventListener('click',()=>{page--;renderTable();});$('diff-next').addEventListener('click',()=>{page++;renderTable();});
  $('diff-json').addEventListener('click',()=>{if(current)download('bloch-data-case-comparison.json',current.bytes,'application/json');});
  $('diff-csv').addEventListener('click',()=>{if(current)download('bloch-data-case-comparison.csv',caseComparisonCSV(current.report),'text/csv');});
  $('diff-hash').addEventListener('click',()=>{if(current)download('bloch-data-case-comparison.json.sha256',`${current.digest}  bloch-data-case-comparison.json\n`,'text/plain');});
  $('diff-open-baseline').addEventListener('click',()=>{if(current)openForReview(current.baseline);});$('diff-open-candidate').addEventListener('click',()=>{if(current)openForReview(current.candidate);});
}
