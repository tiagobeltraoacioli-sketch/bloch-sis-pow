import {MODULES,REGIONS,INSTITUTIONS} from './modules.v1.mjs';
import {buildCaseOverview,validateOverviewSelection,selectOverview,overviewTotals,caseOverviewExport,caseOverviewCSV,OVERVIEW_OUTCOMES,OVERVIEW_REVIEWS} from './case-overview.v1.mjs';
import {overviewExample} from './overview-samples.v1.mjs';

const $=id=>document.getElementById(id);
const node=(tag,text)=>{const element=document.createElement(tag);if(text!==undefined)element.textContent=text;return element;};
const colors={matched:'#6b9046',different:'#b08943',left_only:'#638695',right_only:'#89a4b0',duplicate:'#b3654c'};
export function setupCaseOverview(openForReview,download){
  let generation=0,overview=null,exported=null,selected=null;
  const status=(text,error=false)=>{$('co-status').textContent=text;$('co-status').classList.toggle('error',error);};
  function invalidate(){generation++;overview=null;exported=null;selected=null;$('co-results').hidden=true;$('co-detail').replaceChildren();$('co-detail').hidden=true;for(const id of ['co-chart','co-review-rows','co-metrics','co-summary','co-set-digest'])$(id).replaceChildren();$('co-run').disabled=false;$('co-open').disabled=true;$('co-case').disabled=true;}
  function resetFilters(){for(const id of ['co-module','co-region','co-review'])$(id).value='all';}
  function selectedEntry(){return overview?.entries.find(entry=>entry.summary.case_sha256===selected);}
  function showDetails(){
    const entry=selectedEntry(),panel=$('co-detail');panel.replaceChildren();panel.hidden=!entry;$('co-open').disabled=!entry;$('co-case').disabled=!entry;
    for(const button of document.querySelectorAll('[data-overview-case]'))button.setAttribute('aria-pressed',String(button.dataset.overviewCase===selected));
    if(!entry)return;const s=entry.summary,config=entry.verified.evidence.report.configuration;
    panel.append(node('h4',s.selected_name),node('p',`${MODULES[s.module].name} · ${INSTITUTIONS[s.institution].name} · ${REGIONS[s.region].name}`),node('p',`${s.keys} compared keys · ${s.exceptions} exceptions · ${s.review_entries} retained journal entries. An explained exception remains a discrepancy.`));
    panel.append(node('p',`Independent case reference: ${s.retained_case_digest_check==='matched'?'matched':'not supplied; internal consistency only'}.`));
    for(const [label,digest] of [['Case',s.case_sha256],['Evidence',s.evidence_sha256],['Review journal',s.review_sha256],['Configuration',s.configuration_sha256]]){const p=node('p',label+' SHA-256');p.append(node('code',digest));panel.append(p);}
    panel.append(node('p',`Retained configuration: ${config.date_format} dates · ${config.decimal_format} decimals. Retained comparison CSVs and component bytes remain in the case. The dashboard does not establish common cutoffs, chronology or comparable economic scope.`));
  }
  function selectButton(text,digest){const button=node('button',text);button.type='button';button.dataset.overviewCase=digest;button.addEventListener('click',()=>{selected=digest;showDetails();});return button;}
  function render(){
    if(!overview)return;const entries=selectOverview(overview,{module:$('co-module').value,region:$('co-region').value,review:$('co-review').value}),totals=overviewTotals(entries);
    if(!entries.some(entry=>entry.summary.case_sha256===selected))selected=entries[0]?.summary.case_sha256??null;
    $('co-metrics').replaceChildren();for(const [value,label] of [[totals.cases,'Visible cases'],[totals.keys,'Key observations'],[totals.exceptions,'Exception observations'],[totals.review_states.unreviewed,'Not reviewed']]){const cell=node('div');cell.append(node('strong',String(value)),node('span',label));$('co-metrics').append(cell);}
    $('co-summary').textContent=`${overview.mode==='synthetic_example'?'SYNTHETIC EXAMPLE':'LOCAL FILES'} · ${entries.length} of ${overview.entries.length} cases visible · charts follow the filters · exports retain all ${overview.entries.length} cases`;
    $('co-chart').replaceChildren();$('co-review-rows').replaceChildren();
    for(const {summary:s} of entries){
      const button=selectButton('',s.case_sha256);button.className='co-bar';button.setAttribute('aria-label',`${s.selected_name}: ${Object.entries(OVERVIEW_OUTCOMES).map(([key,label])=>`${label} ${s.outcomes[key]}`).join(', ')}. Select case details.`);
      const title=node('span',s.selected_name),svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 100 12');svg.setAttribute('preserveAspectRatio','none');svg.setAttribute('aria-hidden','true');let x=0;
      for(const key of Object.keys(OVERVIEW_OUTCOMES)){const width=s.keys?s.outcomes[key]/s.keys*100:0,rect=document.createElementNS(svg.namespaceURI,'rect');rect.setAttribute('x',String(x));rect.setAttribute('y','0');rect.setAttribute('width',String(width));rect.setAttribute('height','12');rect.setAttribute('fill',colors[key]);svg.append(rect);x+=width;}
      button.append(title,svg,node('b',`${s.exceptions} / ${s.keys}`),node('small',Object.entries(OVERVIEW_OUTCOMES).map(([key,label])=>`${label}: ${s.outcomes[key]}`).join(' · ')));$('co-chart').append(button);
      const row=node('tr'),heading=node('th');heading.scope='row';heading.append(selectButton(s.selected_name,s.case_sha256));row.append(heading);for(const key of Object.keys(OVERVIEW_REVIEWS))row.append(node('td',String(s.review_states[key])));row.append(node('td',String(s.review_entries)));$('co-review-rows').append(row);
    }
    if(!entries.length){$('co-chart').append(node('p','No cases match these filters. Reset filters to see the complete selection.'));const row=node('tr'),cell=node('td','No matching cases.');cell.colSpan=7;row.append(cell);$('co-review-rows').append(row);}
    showDetails();
  }
  for(const [id,items] of [['co-module',MODULES],['co-region',REGIONS]])for(const [value,item] of Object.entries(items)){const option=node('option',item.name);option.value=value;$(id).append(option);}
  for(const id of ['co-module','co-region','co-review'])$(id).addEventListener('change',render);
  $('co-reset').addEventListener('click',()=>{resetFilters();render();});
  $('co-files').addEventListener('change',()=>{
    invalidate();$('co-input-list').replaceChildren();const files=Array.from($('co-files').files);
    try{validateOverviewSelection(files.map(file=>({name:file.name,size:file.size})));for(const [index,file] of files.entries()){const label=node('label',`${index+1}. ${file.name}`);label.append(node('small',`${file.size.toLocaleString('en-US')} bytes · independent case SHA-256 (optional)`));const input=node('input');input.maxLength=64;input.autocomplete='off';input.spellcheck=false;input.dataset.overviewPin=String(index);input.placeholder='64 hexadecimal characters';input.addEventListener('input',()=>{invalidate();status('Reference changed. Verify the complete selection again.');});label.append(input);$('co-input-list').append(label);}status('Selection changed. Every case and reference must pass before the dashboard is shown.');}
    catch(error){status(error.message,true);}
  });
  async function finish(inputs,token){const result=await buildCaseOverview(inputs);if(token!==generation)return;const output=await caseOverviewExport(result);if(token!==generation)return;overview=result;exported=output;resetFilters();$('co-set-digest').textContent=result.setDigest;$('co-results').hidden=false;render();status('All selected cases verified. Charts summarize retained snapshots; opening a case does not change this dashboard.');}
  $('co-run').addEventListener('click',async()=>{
    invalidate();const token=generation,files=Array.from($('co-files').files),pins=Array.from(document.querySelectorAll('[data-overview-pin]'),input=>input.value.trim().toLowerCase());
    try{validateOverviewSelection(files.map(file=>({name:file.name,size:file.size})));$('co-run').disabled=true;status('Reading and verifying all selected cases locally…');const inputs=[];
      for(const [index,file] of files.entries()){const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer());if(token!==generation)return;inputs.push({name:file.name,text,expectedDigest:pins[index]??''});}
      await finish(inputs,token);
    }catch(error){if(token===generation)status('Overview failed: '+(error instanceof TypeError?'Use valid UTF-8 case files.':error.message),true);}
    finally{if(token===generation)$('co-run').disabled=false;}
  });
  $('co-example').addEventListener('click',async()=>{invalidate();const token=generation;$('co-files').value='';$('co-input-list').replaceChildren();status('Building five labelled synthetic case snapshots…');try{const inputs=await overviewExample();if(token===generation)await finish(inputs,token);}catch(error){if(token===generation)status('Example failed: '+error.message,true);}});
  $('co-clear').addEventListener('click',()=>{invalidate();$('co-files').value='';$('co-input-list').replaceChildren();resetFilters();status('Overview inputs and results cleared. Other workspaces and saved downloads remain separate.');});
  $('co-json').addEventListener('click',()=>{if(exported)download('bloch-data-case-overview.json',exported.bytes,'application/json');});
  $('co-hash').addEventListener('click',()=>{if(exported)download('bloch-data-case-overview.json.sha256',`${exported.digest}  bloch-data-case-overview.json\n`,'text/plain');});
  $('co-csv').addEventListener('click',()=>{if(overview)download('bloch-data-case-overview.csv',caseOverviewCSV(overview),'text/csv');});
  $('co-case').addEventListener('click',()=>{const entry=selectedEntry();if(entry)download('bloch-data-selected-case.bloch.json',entry.text,'application/json');});
  $('co-open').addEventListener('click',()=>{const entry=selectedEntry();if(entry)openForReview(structuredClone(entry.verified));});
}
