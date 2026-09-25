import {STUDIO_KEY,emptyStudio,readStudio} from './studio-model.mjs';
import {REVIEW_STAGES,EVIDENCE_LIMITS,publicEvidencePage,validatePacket,createEvidenceCase,reviseEvidenceCase,validateEvidenceCase,validateVault,vaultBundle,selectRecords,recordTotals} from './evidence-model.mjs';
import {openEvidenceStore} from './evidence-store.mjs';
import {setupPwa} from './pwa.mjs';
const $=id=>document.getElementById(id);
const escape=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=value=>value.length>26?value.slice(0,12)+'…'+value.slice(-10):value;
let studio=emptyStudio(),store=null,snapshot={generation:0,records:[]},records=[],healthy=false,packet=null,current=null,acquisition=null,dirty=false,requestId=0,controller=null,working=false,writing=false,page=0,block='',toastTimer;
const channel=typeof BroadcastChannel==='function'?new BroadcastChannel('bloch-pay-evidence-changes'):null;
const reviewForm=$('evidence-review-form');
const reviewValue=()=>Object.fromEntries(new FormData(reviewForm));
const notify=message=>{clearTimeout(toastTimer);$('evidence-toast').textContent=message;$('evidence-toast').hidden=false;toastTimer=setTimeout(()=>$('evidence-toast').hidden=true,6500);};
const warn=message=>{$('evidence-storage-warning').textContent=message;$('evidence-storage-warning').hidden=false;};
const download=(filename,value)=>{const url=URL.createObjectURL(new Blob([JSON.stringify(value)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1500);};
const canDiscard=()=>!dirty||confirm('Discard the open unsaved sample or review changes? Saved evidence records will remain.');
function readParticipants(){try{const raw=localStorage.getItem(STUDIO_KEY);studio=raw?readStudio(raw):emptyStudio();}catch{studio=emptyStudio();warn('The integration workspace could not be read. Recover it in the integration studio to link new evidence. Saved evidence reviews remain separate.');}}
function participants(){return studio.partners.filter(p=>p.modules.enabled.length);}
function contexts(){
  const before=$('capture-participant').value,asset=$('capture-asset').value,route=$('capture-route').value;
  $('capture-participant').innerHTML=participants().length?participants().map(p=>`<option value="${p.id}">${escape(p.name)} · ${p.id}</option>`).join(''):'<option value="">Configure a participant module first</option>';
  if(participants().some(p=>p.id===before))$('capture-participant').value=before;
  if(current&&!participants().some(p=>p.id===current.context.participant_reference))$('capture-participant').insertAdjacentHTML('beforeend',`<option value="${current.context.participant_reference}">${escape(current.context.participant_name)} · saved association</option>`);
  if(current)$('capture-participant').value=current.context.participant_reference;
  const partner=studio.partners.find(p=>p.id===$('capture-participant').value),assets=current?[current.packet.dataset.asset]:partner?.modules.assets||[];
  $('capture-asset').innerHTML=assets.length?assets.map(a=>`<option>${a}</option>`).join(''):'<option value="">No configured asset</option>';if(assets.includes(asset))$('capture-asset').value=asset;
  const routes=studio.routes.filter(r=>[r.draft.source,r.draft.destination].some(leg=>leg.partner_reference.toLowerCase()===$('capture-participant').value));
  $('capture-route').innerHTML='<option value="">Participant context only</option>'+routes.map(r=>`<option value="${r.draft.id}">${escape(r.draft.payment_reference)}${r.archived?' · archived draft':''}</option>`).join('');if(routes.some(r=>r.draft.id===route))$('capture-route').value=route;
  if(current?.context.route_id){if(!routes.some(r=>r.draft.id===current.context.route_id))$('capture-route').insertAdjacentHTML('beforeend',`<option value="${current.context.route_id}">${escape(current.context.payment_reference)} · saved association</option>`);$('capture-route').value=current.context.route_id;}
  controls();
}
function controls(){
  $('capture-public').disabled=working||writing||!!current||!$('capture-asset').value;
  $('capture-cancel').hidden=!controller;
  $('import-evidence-packet').disabled=writing||!!current||!$('capture-asset').value;
  for(const id of ['capture-participant','capture-asset','capture-route'])$(id).disabled=writing||!!current;
  for(const input of reviewForm.elements)input.disabled=writing;
  $('save-evidence').disabled=working||writing||!healthy||!packet;
  $('export-evidence-packet').disabled=!packet||writing;
  $('new-evidence').disabled=$('reload-evidence').disabled=writing;
  $('import-evidence-vault').disabled=!store||writing;
  $('export-evidence-vault').disabled=!store||writing;
  $('archive-evidence').hidden=$('delete-evidence').hidden=!current;
  if(current)$('archive-evidence').textContent=current.archived?'Restore review':'Archive review';
}
function cancel(message='Capture canceled. The previous sample, if any, is retained.'){
  requestId++;controller?.abort();controller=null;working=false;$('capture-status').textContent=message;controls();
}
function reset(message='Ready for a new review. No source request has been made.'){
  cancel(message);packet=null;current=null;acquisition=null;dirty=false;page=0;block='';reviewForm.reset();$('evidence-review-error').textContent='';$('evidence-result').hidden=true;readParticipants();contexts();
}
function contextChanged(event){
  if(writing)return;
  if(!canDiscard()){contexts();return;}
  cancel('Review context changed. Capture or import a new sample.');packet=null;current=null;acquisition=null;dirty=false;reviewForm.reset();$('evidence-result').hidden=true;if(event.target.id==='capture-participant')contexts();controls();
}
// Remember selection so canceled context changes restore the prior target.
let previousContext={};
function rememberContext(){previousContext=Object.fromEntries(['capture-participant','capture-asset','capture-route'].map(id=>[id,$(id).value]));}
for(const id of ['capture-participant','capture-asset','capture-route'])$(id).addEventListener('change',event=>{if(dirty&&!confirm('Discard the unsaved sample or review before changing its context?')){for(const[key,value]of Object.entries(previousContext))$(key).value=value;return;}dirty=false;contextChanged(event);rememberContext();});
$('new-evidence').addEventListener('click',()=>{if(canDiscard()){reset();rememberContext();$('capture').scrollIntoView({block:'start'});}});
$('capture-cancel').addEventListener('click',()=>cancel());
$('capture-form').addEventListener('submit',async event=>{
  event.preventDefault();if(current||working||writing||!$('capture-asset').value)return;
  if(packet&&!canDiscard())return;
  const asset=$('capture-asset').value,id=++requestId,active=new AbortController();controller=active;working=true;controls();$('capture-status').textContent=`Reading one bounded ${asset} source page. No participant or route data is sent…`;
  const timer=setTimeout(()=>active.abort(),45000);
  try{const candidate=await publicEvidencePage(asset,{signal:active.signal});if(id!==requestId)return;if(active.signal.aborted)throw new Error('Source request timed out.');packet=candidate;reviewForm.reset();$('evidence-review-error').textContent='';acquisition='public_capture';dirty=true;page=0;clearFilters();renderPacket();$('capture-status').textContent=`Captured ${packet.diagnostics.records} records from ${packet.dataset.source}. Save the review to retain this sample across reloads.`;}
  catch(error){if(id===requestId)$('capture-status').textContent=`${active.signal.aborted?'Source request timed out.':error.message==='Failed to fetch'?'The public source could not be read from this browser. Check connectivity and retry the capture.':error.message} ${packet?'The previous sample remains available.':'No source sample was committed.'}`;}
  finally{clearTimeout(timer);if(id===requestId){controller=null;working=false;controls();}}
});
$('import-evidence-packet').addEventListener('click',()=>$('evidence-packet-file').click());
$('evidence-packet-file').addEventListener('change',async event=>{
  const file=event.target.files[0];event.target.value='';if(!file||current||writing)return;if(!canDiscard())return;
  cancel('Validating imported Graphus packet…');const id=requestId,asset=$('capture-asset').value;working=true;controls();
  try{if(file.size>EVIDENCE_LIMITS.packetBytes)throw new Error('Graphus packet exceeds 6 MB.');const candidate=await validatePacket(JSON.parse(await file.text()));if(id!==requestId)return;if(candidate.dataset.asset!==asset)throw new Error('The packet asset differs from the configured review asset.');packet=candidate;reviewForm.reset();$('evidence-review-error').textContent='';acquisition='imported_packet';dirty=true;page=0;clearFilters();renderPacket();$('capture-status').textContent='Imported packet validated against its dataset digest. The digest identifies bytes, not source truth. Save the review to retain it.';}
  catch(error){if(id===requestId)$('capture-status').textContent=`Import refused: ${error.message} ${packet?'The previous sample remains available.':''}`;}
  finally{if(id===requestId){working=false;controls();}}
});
function clearFilters(){for(const id of ['evidence-search','evidence-minimum','evidence-maximum'])$(id).value='';$('evidence-kind').value='all';block='';page=0;}
function chart(id,rows,select){
  const host=$(id),max=Math.max(1,...rows.map(([,value])=>value));host.replaceChildren();
  for(const [label,count]of rows){const row=document.createElement('div');row.className='evidence-bar';const button=document.createElement('button');button.textContent=label.replaceAll('_',' ');button.addEventListener('click',()=>select(label));const meter=document.createElement('meter');meter.max=max;meter.value=count;meter.setAttribute('aria-label',`${label}: ${count} returned records`);const value=document.createElement('strong');value.textContent=count;row.append(button,meter,value);host.append(row);}
  if(!rows.length)host.textContent='No records in this sample.';
}
function renderPacket(){
  if(!packet)return;const {dataset:d,diagnostics:q}=packet;$('evidence-result').hidden=false;
  $('evidence-metrics').innerHTML=[['RETURNED RECORDS',q.records],['REFERENCES',q.references],['TRANSACTIONS',q.transactions],['MISSING TIMESTAMPS',q.records_without_timestamp]].map(([label,value])=>`<article class="metric"><span class="metric-label">${label}</span><strong>${value}</strong><small>Within this sample</small></article>`).join('');
  $('evidence-source').innerHTML=`<span class="tag">${acquisition==='imported_packet'?'IMPORTED PACKET':'PUBLIC SOURCE CAPTURE'}</span><h3>${escape(d.asset)} / ${escape(d.network)}</h3><p>Source: ${escape(d.source)}<br>Source retrieval time: ${escape(d.retrieved_at)} · ${q.source_pages} source pages</p><p>${escape(d.coverage)}</p><p>Highest sampled anchor: ${d.anchor.height}. Finality: ${escape(d.anchor.finality||'Not supplied')}.</p><p class="source-hash">${escape(d.anchor.hash)}</p><p class="small">Missing records or timestamps remain unknown. This sample is not matched to a payment or attributed to a participant.</p>`;
  const counts=new Map();for(const edge of d.edges)counts.set(String(edge.block_number),(counts.get(String(edge.block_number))||0)+1);
  const prior=$('evidence-kind').value;$('evidence-kind').innerHTML='<option value="all">All record types</option>'+Object.keys(q.record_types).map(kind=>`<option value="${kind}">${kind.replaceAll('_',' ')}</option>`).join('');if(Object.hasOwn(q.record_types,prior))$('evidence-kind').value=prior;
  chart('evidence-type-chart',Object.entries(q.record_types),kind=>{$('evidence-kind').value=kind;page=0;ledger();});chart('evidence-block-chart',[...counts].sort((a,b)=>Number(a[0])-Number(b[0])).slice(-16),height=>{block=height;page=0;ledger();});
  $('evidence-provenance').textContent=JSON.stringify({dataset_sha256:packet.dataset_sha256,digest_encoding:packet.digest_encoding,diagnostics:q,snapshots:d.snapshots,selection:packet.selection,aml_score_included:false,identity_attribution_included:false},null,2);
  const c=current?.context,participant=studio.partners.find(p=>p.id===(c?.participant_reference||$('capture-participant').value)),route=studio.routes.find(r=>r.draft.id===(c?.route_id||$('capture-route').value));
  $('evidence-association').textContent=`Local context: ${c?.participant_name||participant?.name||'Unknown participant'} · ${c?.payment_reference||route?.draft.payment_reference||'No route selected'}.${current&&!participant?' The participant is no longer in the integration directory.':''}${c?.route_id&&!route?' The linked draft is no longer in the route library.':''} This association does not establish ownership or settlement.`;
  $('evidence-saved-state').textContent=current?`REVISION ${current.revision}${current.archived?' / ARCHIVED':''}`:'UNSAVED SAMPLE';
  $('evidence-history').innerHTML=current?current.history.slice().reverse().map(row=>`<div class="evidence-history-item"><strong>Revision ${row.revision} · ${escape(REVIEW_STAGES[row.stage])}${row.archived?' · archived':''}</strong><p>${escape(row.at)} · ${escape(row.owner||'No owner entered')}</p><p>${escape(row.note||'No note entered')}</p></div>`).join(''):'<p class="small">The first saved review creates revision 1.</p>';
  ledger();controls();
}
function ledger(){
  if(!packet)return;const d=packet.dataset;let rows;
  try{rows=selectRecords(packet,{query:$('evidence-search').value,kind:$('evidence-kind').value,minimum:$('evidence-minimum').value,maximum:$('evidence-maximum').value,minBlock:block,maxBlock:block}).rows;}
  catch(error){$('evidence-filter-status').textContent=error.message;$('evidence-ledger').replaceChildren();$('evidence-totals').replaceChildren();$('evidence-page').textContent='Correct the filters to inspect records.';$('evidence-prev').disabled=$('evidence-next').disabled=true;return;}
  $('evidence-filter-status').textContent=`${rows.length} / ${d.edges.length} records match${block?' · block '+block:''}. Values are exact base units; record types are totaled separately, not combined into transfer volume.`;
  const totals=recordTotals(rows);$('evidence-totals').innerHTML=totals.map(t=>`<div><span>${t.kind.replaceAll('_',' ')}</span><strong>${t.amount}</strong></div>`).join('');
  const pages=Math.max(1,Math.ceil(rows.length/20));page=Math.min(page,pages-1);const nodes=new Map(d.nodes.map(n=>[n.id,n]));
  const endpoint=id=>{const n=nodes.get(id),ref=n.address||n.txid;return `<button data-evidence-reference="${escape(ref)}" title="${escape(ref)}">${escape(short(ref))}</button>`;};
  const origin=d.asset==='BLCH'?'https://blochl1.com':d.asset==='BTC'?'https://blockstream.info':'https://etherscan.io';
  $('evidence-ledger').innerHTML=rows.slice(page*20,page*20+20).map(row=>`<tr><td>${row.block_number}<a href="${origin}/tx/${encodeURIComponent(row.txid)}" target="_blank" rel="noopener noreferrer" title="${escape(row.txid)}">${escape(short(row.txid))} ↗</a></td><td>${endpoint(row.from)}<span>→</span>${endpoint(row.to)}</td><td>${row.kind.replaceAll('_',' ')}</td><td>${row.amount_base_units}</td></tr>`).join('');
  $('evidence-page').textContent=`Page ${page+1} / ${pages}`;$('evidence-prev').disabled=page===0;$('evidence-next').disabled=page===pages-1;
}
for(const id of ['evidence-search','evidence-kind','evidence-minimum','evidence-maximum'])$(id).addEventListener('input',()=>{page=0;ledger();});
$('evidence-reset-filters').addEventListener('click',()=>{clearFilters();ledger();});$('evidence-prev').addEventListener('click',()=>{page--;ledger();});$('evidence-next').addEventListener('click',()=>{page++;ledger();});
$('evidence-ledger').addEventListener('click',event=>{const button=event.target.closest('[data-evidence-reference]');if(button){$('evidence-search').value=button.dataset.evidenceReference;page=0;ledger();}});
reviewForm.addEventListener('input',()=>{dirty=true;});
function committed(next,generation){records=next;snapshot={records,generation};healthy=true;$('evidence-storage-warning').hidden=true;channel?.postMessage({generation});renderLibrary();}
reviewForm.addEventListener('submit',async event=>{
  event.preventDefault();if(writing||working||!packet||!healthy)return;const value=reviewValue();writing=true;controls();$('evidence-review-error').textContent='';
  try{let candidate;if(current){candidate=reviseEvidenceCase(current,value);if(candidate===current){dirty=false;notify('No review changes to save.');return;}candidate=await validateEvidenceCase(candidate);}else{readParticipants();const participant=studio.partners.find(p=>p.id===$('capture-participant').value),routeId=$('capture-route').value,route=studio.routes.find(r=>r.draft.id===routeId);if(routeId&&!route)throw new Error('The selected draft is no longer in the integration workspace.');candidate=await createEvidenceCase({packet,participant,route,review:value,acquisition});}
    const generation=await store.save(snapshot.generation,candidate,!current);committed(current?records.map(r=>r.id===candidate.id?candidate:r):[...records,candidate],generation);current=candidate;packet=candidate.packet;dirty=false;contexts();renderPacket();notify('Evidence packet and local review saved.');
  }catch(error){$('evidence-review-error').textContent=error.message;}
  finally{writing=false;controls();}
});
$('archive-evidence').addEventListener('click',async()=>{
  if(!current||writing)return;if(dirty)return notify('Save or discard your review changes before archiving.');writing=true;controls();
  try{const candidate=await validateEvidenceCase(reviseEvidenceCase(current,current.review,!current.archived));const generation=await store.save(snapshot.generation,candidate,false);committed(records.map(r=>r.id===candidate.id?candidate:r),generation);current=candidate;renderPacket();notify(candidate.archived?'Review archived; its evidence is retained.':'Review restored.');}catch(error){notify(error.message);}finally{writing=false;controls();}
});
$('delete-evidence').addEventListener('click',async()=>{
  if(!current||writing||!confirm('Remove this saved review, its packet and local history from this browser? Export an evidence backup first to retain a copy.'))return;writing=true;controls();
  try{const id=current.id,generation=await store.remove(snapshot.generation,id);committed(records.filter(r=>r.id!==id),generation);reset('Saved review removed from this browser.');}catch(error){notify(error.message);}finally{writing=false;controls();}
});
function renderLibrary(){
  const query=$('evidence-library-search').value.trim().toLowerCase(),view=$('evidence-library-view').value,stage=$('evidence-library-stage').value;
  const visible=records.filter(r=>(view==='all'||r.archived===(view==='archived'))&&(stage==='all'||r.review.stage===stage)&&`${r.context.participant_name} ${r.context.participant_reference} ${r.context.payment_reference||''} ${r.packet.dataset_sha256} ${r.packet.dataset.asset}`.toLowerCase().includes(query)).sort((a,b)=>b.updated_at.localeCompare(a.updated_at));
  $('evidence-library-list').innerHTML=visible.length?visible.map(r=>`<article class="evidence-library-card"><div><span class="tag">${escape(REVIEW_STAGES[r.review.stage])}${r.archived?' / ARCHIVED':''}</span><h3>${escape(r.context.participant_name)} · ${r.packet.dataset.asset}</h3><p>${escape(r.context.payment_reference||'Participant context only')} · ${r.packet.diagnostics.records} records · ${escape(r.review.owner||'No owner entered')}</p><code>SHA-256 ${r.packet.dataset_sha256.slice(0,16)}…</code><p>Revision ${r.revision} · ${escape(r.updated_at)}</p></div><button data-open-evidence="${r.id}">Open review</button></article>`).join(''):'<div class="empty"><h3>No saved reviews in this view</h3><p>Capture or import a Graphus packet, then save a review to retain it here.</p></div>';
  $('evidence-library-count').textContent=`${visible.length} of ${records.length} saved reviews · vault generation ${snapshot.generation}`;
}
for(const id of ['evidence-library-search','evidence-library-view','evidence-library-stage'])$(id).addEventListener('input',renderLibrary);
$('evidence-library-list').addEventListener('click',event=>{const button=event.target.closest('[data-open-evidence]');if(!button||writing||!canDiscard())return;const record=records.find(r=>r.id===button.dataset.openEvidence);cancel('Opened saved evidence. No source request was made.');current=record;packet=record.packet;acquisition=record.acquisition;dirty=false;for(const[key,value]of Object.entries(record.review))reviewForm.elements[key].value=value;clearFilters();contexts();renderPacket();$('evidence-result').scrollIntoView({block:'start'});});
$('export-evidence-packet').addEventListener('click',()=>{if(packet)download(`graphus-${packet.dataset.asset}-${packet.dataset_sha256.slice(0,12)}.json`,packet);});
$('export-evidence-vault').addEventListener('click',()=>download('bloch-pay-evidence-vault.json',vaultBundle(snapshot.records)));
$('import-evidence-vault').addEventListener('click',()=>$('evidence-vault-file').click());
$('evidence-vault-file').addEventListener('change',async event=>{
  const file=event.target.files[0];event.target.value='';if(!file||!store||writing)return;writing=true;controls();
  try{if(file.size>EVIDENCE_LIMITS.bytes)throw new Error('Evidence backup exceeds 20 MB.');const candidate=await validateVault(JSON.parse(await file.text()));if(!confirm(`Replace all saved evidence with ${candidate.records.length} reviews and discard the open unsaved review? Export a backup first. Invoice and integration data will stay unchanged.`))return;cancel();const generation=await store.replace(snapshot.generation,candidate.records);committed(candidate.records,generation);reset('Evidence backup imported. Invoice and integration records were not changed.');notify('Evidence vault replaced.');}
  catch(error){notify('Import refused: '+error.message);}finally{writing=false;controls();}
});
async function loadVault(){
  try{if(!store)store=await openEvidenceStore();snapshot=await store.snapshot();const validated=await validateVault(vaultBundle(snapshot.records));records=validated.records;healthy=true;$('evidence-storage-warning').hidden=true;renderLibrary();}
  catch(error){healthy=false;warn(`Evidence storage could not be loaded: ${error.message} Export the original evidence backup if available, or import a valid backup to recover.`);}finally{controls();}
}
$('reload-evidence').addEventListener('click',async()=>{if(writing||!canDiscard())return;reset();writing=true;controls();await loadVault();writing=false;controls();rememberContext();});
channel?.addEventListener('message',event=>{if(event.data?.generation!==snapshot.generation)warn('Evidence changed in another tab. Reload saved reviews before writing. Your open changes remain in this tab.');});
window.addEventListener('storage',event=>{if(event.key===STUDIO_KEY||event.key===null)warn('The integration workspace changed in another tab. Start a new review or reload to update participant and route choices. Existing evidence links remain local annotations.');});
window.addEventListener('beforeunload',event=>{if(dirty||working||writing){event.preventDefault();event.returnValue='';}});
const connection=()=>{$('connection').textContent=navigator.onLine?'Online · explicit captures only':'Offline · saved evidence available';};window.addEventListener('online',connection);window.addEventListener('offline',connection);connection();
$('evidence-review-stage').innerHTML=Object.entries(REVIEW_STAGES).map(([key,label])=>`<option value="${key}">${label}</option>`).join('');$('evidence-library-stage').insertAdjacentHTML('beforeend',Object.entries(REVIEW_STAGES).map(([key,label])=>`<option value="${key}">${label}</option>`).join(''));
readParticipants();contexts();
const query=new URL(location.href).searchParams,requestedRoute=studio.routes.find(r=>r.draft.id===query.get('route'));
const requestedPartner=participants().find(p=>p.id===query.get('participant'))||participants().find(p=>requestedRoute&&[requestedRoute.draft.source,requestedRoute.draft.destination].some(leg=>leg.partner_reference.toLowerCase()===p.id));
if(requestedPartner){$('capture-participant').value=requestedPartner.id;contexts();const asset=query.get('asset');if(requestedPartner.modules.assets.includes(asset))$('capture-asset').value=asset;if(requestedRoute&&[...$('capture-route').options].some(option=>option.value===requestedRoute.draft.id))$('capture-route').value=requestedRoute.draft.id;}
rememberContext();await loadVault();
setupPwa({canReload:()=>!dirty&&!working&&!writing,notify});
