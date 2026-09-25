import {emptyWorkspace,readBackup,formatAmount,localDate,storeWorkspace,STORAGE_KEY} from './model.mjs';
import {BATCH_LIMITS,previewReconciliation,applyReconciliation,csvTemplate,reconciliationCsv} from './reconciliation.mjs';
import {setupPwa} from './pwa.mjs';
const $=id=>document.getElementById(id),escape=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const labels={ready:'New / ready',duplicate:'Identical / skipped',blocked:'Blocked'},statuses={open:'Open',partial:'Partial',matched:'Matched records','over-recorded':'Over-recorded'};
let state=emptyWorkspace(),serialized=null,preview=null,applied=false,stale=false,unavailable=false,page=0,generation=0,busy=false,timer;
function notice(message){$('storage-notice').hidden=false;$('storage-notice').textContent=message;}
try{serialized=localStorage.getItem(STORAGE_KEY);if(serialized)state=readBackup(serialized);}catch{unavailable=true;notice('Invoice storage cannot be read. Open the invoice workspace to export and recover your data before importing records.');}
function ledger(){ $('batch-ledger-count').textContent=`${state.invoices.length} invoices`;$('batch-revision').textContent=`Revision ${state.revision} · ${state.receipts.length} saved records`;$('batch-preview').disabled=unavailable||stale||busy; }
function notify(message){clearTimeout(timer);$('batch-toast').textContent=message;$('batch-toast').hidden=false;timer=setTimeout(()=>$('batch-toast').hidden=true,7000);}
function download(name,content,type){const url=URL.createObjectURL(new Blob([content],{type})),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1500);}
function eligible(){return preview&&!applied&&!stale&&!unavailable&&!preview.batchError&&!preview.counts.blocked&&preview.counts.ready>0;}
function actions(){ $('batch-apply').disabled=!eligible()||!$('batch-ack').checked;$('batch-ack').disabled=!eligible();$('batch-state').textContent=applied?'IMPORTED · REVIEW SNAPSHOT':stale?'STALE · RELOAD REQUIRED':preview?`PREVIEW · REVISION ${preview.revision}`:'NO FILE REVIEWED'; }
function rows(){
  if(!preview)return;
  const query=$('batch-search').value.trim().toLowerCase(),filter=$('batch-filter').value;
  const selected=preview.rows.filter(r=>(filter==='all'||r.status===filter)&&(!query||`${r.reference} ${r.invoice} ${r.message}`.toLowerCase().includes(query)));
  const pages=Math.max(1,Math.ceil(selected.length/50));page=Math.min(page,pages-1);
  $('batch-row-count').textContent=`${selected.length} of ${preview.rows.length} CSV records · 50 per page. Blank records are ignored; quoted multiline fields remain one record.`;
  $('batch-rows').innerHTML=selected.slice(page*50,(page+1)*50).map(r=>`<tr><td>${r.row}</td><td><strong>${escape(r.reference)}</strong><small>${escape(r.invoice)}</small></td><td class="amount">${escape(r.amount)}</td><td><span class="badge ${r.status}">${labels[r.status]}</span></td><td>${escape(r.message)}</td></tr>`).join('')||'<tr><td colspan="5">No records match these filters.</td></tr>';
  $('batch-page').textContent=`Page ${page+1} of ${pages}`;$('batch-previous').disabled=page===0;$('batch-next').disabled=page>=pages-1;
}
function render(){
  ledger();$('batch-results').hidden=!preview;$('batch-empty').hidden=!!preview;$('batch-actions').hidden=!preview;
  if(preview){
    const c=preview.counts;
    $('batch-metrics').innerHTML=[['NEW RECORDS',c.ready,'Append after confirmation'],['IDENTICAL',c.duplicate,'Skipped without changes'],['BLOCKED',c.blocked,'Resolve before importing'],['INVOICES',preview.impacts.length,'Affected by new records']].map(([label,value,note])=>`<article class="metric"><span class="metric-label">${label}</span><strong>${value}</strong><small>${note}</small></article>`).join('');
    $('batch-chart').innerHTML=['ready','duplicate','blocked'].map(key=>`<div class="chart-row ${key}"><div class="chart-label"><span>${labels[key]}</span><span>${c[key]} / ${preview.rows.length}</span></div><svg viewBox="0 0 100 9" preserveAspectRatio="none" role="img" aria-label="${labels[key]}: ${c[key]} of ${preview.rows.length} records"><rect class="track" width="100" height="9"/><rect width="${c[key]*100/preview.rows.length}" height="9"/></svg></div>`).join('');
    $('batch-blocker').textContent=preview.batchError|| (c.blocked?'This batch is blocked. Correct the invalid rows in the source file and preview it again. No records will be imported.':'');
    $('batch-impact-note').textContent=`Proposed additions: ${formatAmount(preview.totals.receivable)} BLCH against receivables · ${formatAmount(preview.totals.payable)} BLCH against payables. ${c.blocked||preview.batchError?'Provisional impact only; the batch is blocked.':'Identical rows are excluded.'}`;
    $('batch-impacts').innerHTML=preview.impacts.length?`<div class="table-wrap"><table><thead><tr><th>Invoice / direction</th><th>Added · BLCH</th><th>Current → proposed</th><th>Outstanding · BLCH</th><th>Excess · BLCH</th></tr></thead><tbody>${preview.impacts.map(i=>`<tr><td><strong>${escape(i.reference)}</strong><small>${i.direction}</small></td><td class="amount">${formatAmount(i.added)}</td><td>${statuses[i.before]} → ${statuses[i.after]}</td><td class="amount">${formatAmount(i.outstanding)}</td><td class="amount">${formatAmount(i.excess)}${i.newExcess?'<small>Excess increases</small>':''}</td></tr>`).join('')}</tbody></table></div><div class="batch-impact-cards">${preview.impacts.map(i=>`<article class="panel"><h3>${escape(i.reference)}</h3><p>${i.direction} · ${statuses[i.before]} → ${statuses[i.after]}</p><dl><div><dt>Added · BLCH</dt><dd>${formatAmount(i.added)}</dd></div><div><dt>Outstanding · BLCH</dt><dd>${formatAmount(i.outstanding)}</dd></div><div><dt>Excess · BLCH</dt><dd>${formatAmount(i.excess)}${i.newExcess?' · increases':''}</dd></div></dl></article>`).join('')}</div>`:'<p class="section-description">No new records affect invoice balances.</p>';
    const excess=preview.impacts.filter(i=>i.newExcess).length;$('batch-excess').textContent=excess?`${excess} invoice(s) would have increased excess amounts. Check the allocation and source amounts before confirming.`:'Existing records will be retained. Export a backup before importing if you need a copy of the prior ledger.';
    rows();
  }else{$('batch-impacts').replaceChildren();$('batch-impact-note').textContent='Preview a batch to compare its new records with current invoice balances.';}
  actions();
}
function clear(){generation++;preview=null;applied=false;page=0;$('batch-ack').checked=false;$('batch-confirm').close();$('batch-status').textContent='';render();}
$('batch-file').addEventListener('change',clear);
$('batch-clear').onclick=()=>{$('batch-form').reset();clear();};
$('batch-template').onclick=()=>download('bloch-pay-record-template.csv',csvTemplate(),'text/csv;charset=utf-8');
$('batch-form').onsubmit=async event=>{
  event.preventDefault();const file=$('batch-file').files[0];if(!file)return;clear();const active=generation;busy=true;ledger();
  try{
    if(unavailable||stale)throw new Error('Reload the current workspace before reviewing this file.');
    if(file.size>BATCH_LIMITS.bytes)throw new Error('Choose a CSV no larger than 2 MB.');
    const raw=await file.text();if(active!==generation)return;
    if(localStorage.getItem(STORAGE_KEY)!==serialized){stale=true;throw new Error('The workspace changed in another tab. Reload before reviewing.');}
    preview=previewReconciliation(raw,state);$('batch-search').value='';$('batch-filter').value='all';render();$('batch-status').textContent=`Reviewed ${preview.rows.length} records locally. ${preview.counts.blocked||preview.batchError?'Resolve the blocked batch before importing.':'Review the proposed invoice impact below.'}`;
  }catch(error){if(active===generation)$('batch-status').textContent='Preview refused: '+error.message;}finally{busy=false;ledger();}
};
$('batch-filters').onsubmit=event=>event.preventDefault();$('batch-filters').oninput=()=>{page=0;rows();};
$('batch-previous').onclick=()=>{page--;rows();};$('batch-next').onclick=()=>{page++;rows();};$('batch-ack').onchange=actions;
$('batch-report').onclick=()=>{if(preview)download(`bloch-pay-reconciliation-${localDate()}.csv`,reconciliationCsv(preview),'text/csv;charset=utf-8');};
$('batch-backup').onclick=()=>download(`bloch-pay-workspace-revision-${state.revision}-${localDate()}.json`,JSON.stringify(state,null,2),'application/json');
$('batch-apply').onclick=()=>{
  if(!eligible()||!$('batch-ack').checked)return;
  $('batch-confirm-copy').textContent=`Append ${preview.counts.ready} new records to ${preview.impacts.length} invoices? ${preview.counts.duplicate} identical rows will be skipped. ${preview.impacts.filter(i=>i.newExcess).length} invoices have increased excess amounts. This updates local records only.`;
  $('batch-confirm-error').textContent='';$('batch-confirm').showModal();
};
$('batch-cancel').onclick=()=>$('batch-confirm').close();
$('batch-confirm-save').onclick=()=>{
  try{
    if(!eligible()||!$('batch-ack').checked)throw new Error('This preview is no longer eligible. Reload and review the file again.');
    const next=applyReconciliation(preview,state),saved=storeWorkspace(localStorage,serialized,next);state=saved.data;serialized=saved.serialized;applied=true;$('batch-file').value='';$('batch-confirm').close();render();$('batch-status').textContent=`Imported ${preview.counts.ready} new records. ${preview.counts.duplicate} identical rows skipped. Revision ${state.revision} saved locally. The review below is the pre-import snapshot.`;notify('Batch imported. Invoice balances now include the new records.');
  }catch(error){$('batch-confirm-error').textContent=error.message;}
};
window.addEventListener('storage',event=>{if(event.key===STORAGE_KEY||event.key===null){stale=true;generation++;notice('The invoice workspace changed in another tab. Reload before reviewing or importing a batch.');render();}});
const pending=()=>!applied&&(!!preview||!!$('batch-file').files.length||busy);
window.addEventListener('beforeunload',event=>{if(pending()){event.preventDefault();event.returnValue='';}});
function connection(){$('batch-connection').textContent=navigator.onLine?'Online':'Offline · local mode';}
window.addEventListener('online',connection);window.addEventListener('offline',connection);
setupPwa({notify,canReload:()=>!pending()&&!$('batch-confirm').open});connection();render();
