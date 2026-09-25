import './graphus-analytics.mjs';
const A=globalThis.GraphusAnalytics;
const NETWORK={BTC:'bitcoin-mainnet',ETH:'ethereum-mainnet',USDT:'ethereum-mainnet',USDC:'ethereum-mainnet',BLCH:'bloch-mainnet'};
const hash=value=>typeof value==='string'&&/^(0x)?[a-f0-9]{64}$/i.test(value);
const check=(condition,message)=>{if(!condition)throw new Error(message);};
export const COLLECTION_LIMITS={pages:8,nodes:1200,records:4000,bytes:3_000_000};
const cursorValid=(asset,value)=>value===null||typeof value==='string'&&(asset==='BLCH'?/^[0-9]{1,12}-[a-f0-9]{64}-[0-9]{1,12}$/i:/^(0|[1-9][0-9]{0,11})$/).test(value);

export async function evidencePacket(raw,asset,{cursor=null}={}) {
  check(raw?.status==='source-reported'&&raw.asset===asset&&raw.network===NETWORK[asset],'Source asset or network mismatch.');
  check(typeof raw.source==='string'&&raw.source.length>0&&raw.source.length<=300&&Number.isFinite(Date.parse(raw.retrieved_at)),'Missing source provenance.');
  check(Number.isSafeInteger(raw.anchor?.height)&&raw.anchor.height>=0&&hash(raw.anchor.hash),'Missing source block anchor.');
  const nextCursor=raw.next_cursor??null;
  check(cursorValid(asset,cursor)&&cursorValid(asset,nextCursor),'Invalid source cursor.');
  check(nextCursor===null||nextCursor!==cursor,'Source cursor repeated.');
  if(cursor!==null){const parts=cursor.split('-');check(raw.anchor.height===Number(parts[0])&&(asset!=='BLCH'||raw.anchor.hash.toLowerCase()===parts[1].toLowerCase()),'Source cursor anchor mismatch.');}
  if(nextCursor!==null&&asset!=='BLCH')check(Number(nextCursor)<raw.anchor.height,'Source cursor must select an earlier block.');
  const normalized=A.normalize(raw),blocks=new Map([[raw.anchor.height,raw.anchor.hash.toLowerCase()]]);
  check(raw.edges.every(edge=>typeof edge.event_id==='string'&&edge.event_id.length>0),'Missing event identity.');
  const nodes=raw.nodes.map(node=>{
    const reference=node.kind==='transaction'?node.txid:node.address;
    check(node.kind==='transaction'?hash(reference):typeof reference==='string'&&/^[a-zA-Z0-9]{14,100}$/.test(reference),'Invalid public reference.');
    check(node.id===`${asset}:${node.kind}:${reference}`,'Reference identity mismatch.');
    return {id:node.id,kind:node.kind,...(node.kind==='transaction'?{txid:reference}:{address:reference})};
  });
  const edges=normalized.edges.map(edge=>{
    check(hash(edge.txid)&&hash(edge.block_hash)&&Number.isSafeInteger(edge.block)&&edge.block>=0,'Record lacks transaction or block provenance.');
    check(edge.block<=raw.anchor.height,'Record is newer than the source anchor.');
    const blockHash=edge.block_hash.toLowerCase();check(!blocks.has(edge.block)||blocks.get(edge.block)===blockHash,'Conflicting source block hashes.');blocks.set(edge.block,blockHash);
    return {event_id:edge.id,from:edge.from,to:edge.to,kind:edge.kind,amount_base_units:edge.amount,txid:edge.txid,block_number:edge.block,block_hash:blockHash,
      ...(edge.position!==undefined?{position:edge.position}:{}),...(edge.block_time?{block_time:edge.block_time}:{}),...(edge.outpoint?{outpoint:edge.outpoint}:{})};
  });
  const anchor=normalized.anchor,scopeKeys=['transactions_returned','transactions_in_block','transactions_in_page','endpoint_records_omitted','selection','candidates_checked','successful_transfers','failed_transactions_omitted','internal_calls_included','from_block','to_block','contract','source_logs','returned_logs','truncated','not_finalized_omitted','has_more','finality_available'];
  const scope=Object.fromEntries(Object.entries(normalized.scope||{}).filter(([key])=>scopeKeys.includes(key)));
  const dataset={status:'source-reported',asset,network:NETWORK[asset],source:raw.source,retrieved_at:raw.retrieved_at,anchor,coverage:normalized.coverage,scope,independent_verification:false,nodes,edges,
    snapshots:[{source:raw.source,retrieved_at:raw.retrieved_at,anchor,scope,coverage:normalized.coverage,records:edges.length,requested_cursor:cursor}]};
  return packageDataset(dataset,{pagination:{next_cursor:nextCursor,requested_cursors:[cursor]}});
}

async function packageDataset(dataset,extra={}) {
  const {nodes,edges}=dataset,counts={};for(const edge of edges)counts[edge.kind]=(counts[edge.kind]||0)+1;
  const diagnostics={references:nodes.length,records:edges.length,transactions:new Set(edges.map(e=>e.txid)).size,blocks:new Set(edges.map(e=>e.block_number)).size,
    source_pages:dataset.snapshots.length,records_with_timestamp:edges.filter(e=>Number.isFinite(Date.parse(e.block_time))).length,records_without_timestamp:edges.filter(e=>!Number.isFinite(Date.parse(e.block_time))).length,record_types:counts,complete_chain_history:false,independent_verification:false};
  const bytes=new TextEncoder().encode(JSON.stringify(dataset));check(bytes.byteLength<=3_000_000,'Evidence packet exceeds the 3 MB limit.');
  const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
  return {kind:'graphus_network_collection',schema_version:1,exported_at:new Date().toISOString(),dataset,dataset_sha256:digest,digest_encoding:'SHA-256 of UTF-8 JSON.stringify(dataset), preserving field and array order',diagnostics,
    purpose:'Public-chain evidence preparation',aml_score_included:false,identity_attribution_included:false,...extra};
}

export async function fetchEvidence(asset,{fetcher=fetch,signal,cursor=null}={}) {
  check(Object.hasOwn(NETWORK,asset),'Unsupported asset.');
  check(cursorValid(asset,cursor),'Invalid source cursor.');
  const query=new URLSearchParams({asset});if(cursor!==null)query.set('cursor',cursor);
  const response=await fetcher(`/api/chain/network?${query}`,{headers:{accept:'application/json'},signal,redirect:'error'});
  if(!response.ok)throw new Error(`Source unavailable (HTTP ${response.status}). Retry the capture.`);
  const reader=response.body.getReader(),chunks=[];let size=0;
  try{while(true){const result=await reader.read();if(result.done)break;size+=result.value.byteLength;if(size>3_000_000)throw new Error('Source response exceeds the 3 MB limit.');chunks.push(result.value);}}
  catch(error){await reader.cancel().catch(()=>{});throw error;}
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  return evidencePacket(JSON.parse(new TextDecoder().decode(bytes)),asset,{cursor});
}

function sameSource(a,b){check(a.asset===b.asset&&a.network===b.network&&a.source===b.source,'Cannot combine different assets, networks or sources.');}
function blockMap(dataset){const blocks=new Map();for(const item of [...dataset.snapshots.map(s=>({block_number:s.anchor.height,block_hash:s.anchor.hash})),...dataset.edges]){const hash=item.block_hash.toLowerCase();check(!blocks.has(item.block_number)||blocks.get(item.block_number)===hash,'Conflicting source block hashes.');blocks.set(item.block_number,hash);}return blocks;}
const eventValue=edge=>JSON.stringify([edge.from,edge.to,edge.kind,edge.amount_base_units,edge.txid,edge.block_number,edge.block_hash.toLowerCase(),edge.position??null,edge.block_time??null,edge.outpoint?.txid??null,edge.outpoint?.vout??null]);

export async function mergeEvidence(previous,page){
  if(!previous)return page;
  check(!previous.selection&&!page.selection,'Filtered packets cannot be extended.');
  const before=previous.dataset,next=page.dataset;sameSource(before,next);
  check(page.pagination?.requested_cursors.length===1&&previous.pagination?.next_cursor!==null&&page.pagination.requested_cursors[0]===previous.pagination.next_cursor,'Unexpected source page cursor.');
  const requested=[...previous.pagination.requested_cursors,...page.pagination.requested_cursors];
  check(new Set(requested).size===requested.length&&(page.pagination.next_cursor===null||!requested.includes(page.pagination.next_cursor)),'Source cursor cycle detected.');
  check(requested.length<=COLLECTION_LIMITS.pages,'Collection capacity reached: eight source pages.');
  const blocks=blockMap(before);for(const[height,hash]of blockMap(next))check(!blocks.has(height)||blocks.get(height)===hash,'Conflicting source block hashes.');
  const nodes=new Map(before.nodes.map(n=>[n.id,n])),edges=new Map(before.edges.map(e=>[e.event_id,e]));let duplicates=0;
  for(const node of next.nodes){check(!nodes.has(node.id)||JSON.stringify(nodes.get(node.id))===JSON.stringify(node),'Conflicting source reference.');nodes.set(node.id,node);}
  for(const edge of next.edges){const prior=edges.get(edge.event_id);check(!prior||eventValue(prior)===eventValue(edge),'Conflicting source event.');if(prior)duplicates++;else edges.set(edge.event_id,edge);}
  check(nodes.size<=COLLECTION_LIMITS.nodes&&edges.size<=COLLECTION_LIMITS.records,'Collection capacity reached: 1,200 references / 4,000 records.');
  const snapshots=[...before.snapshots,...next.snapshots],dataset={...before,retrieved_at:next.retrieved_at,anchor:next.anchor.height>before.anchor.height?next.anchor:before.anchor,
    nodes:[...nodes.values()],edges:[...edges.values()],snapshots,scope:{source_pages:snapshots.length,unique_records:edges.size,complete_chain_history:false},
    coverage:`${edges.size} unique records from ${snapshots.length} bounded source pages. Unreturned history and sampling gaps remain unknown.`};
  return packageDataset(dataset,{pagination:{next_cursor:page.pagination.next_cursor,requested_cursors:requested},collection:{last_page_added:next.edges.length-duplicates,duplicate_records_omitted:(previous.collection?.duplicate_records_omitted||0)+duplicates}});
}

function unsigned(value,name,maxLength=78){if(value===''||value===null||value===undefined)return null;check(typeof value==='string'&&new RegExp(`^(0|[1-9][0-9]{0,${maxLength-1}})$`).test(value),`${name} must be an unsigned integer.`);return BigInt(value);}
const sensitive=(value,asset,kind)=>asset==='BTC'&&kind==='address'&&/^[13]/.test(value);
const match=(value,query,asset,kind,exact=false)=>{const a=sensitive(value,asset,kind)?value:value.toLowerCase(),b=sensitive(value,asset,kind)?query:query.toLowerCase();return exact?a===b:a.includes(b);};
export function selectRecords(packet,options={}){
  const {dataset}=packet,query=String(options.query||'').trim(),kind=options.kind||'all',direction=options.direction||'all';
  check(query.length<=200,'Reference query is too long.');check(['all','incoming','outgoing'].includes(direction),'Invalid direction filter.');
  check(kind==='all'||A.KINDS[dataset.asset].includes(kind),'Invalid record type.');
  const minBlock=unsigned(options.minBlock,'First block',16),maxBlock=unsigned(options.maxBlock,'Last block',16),minimum=unsigned(options.minimum,'Minimum base units'),maximum=unsigned(options.maximum,'Maximum base units');
  for(const value of [minBlock,maxBlock])check(value===null||value<=BigInt(Number.MAX_SAFE_INTEGER),'Block number exceeds the supported range.');
  check(minBlock===null||maxBlock===null||minBlock<=maxBlock,'First block must not exceed last block.');check(minimum===null||maximum===null||minimum<=maximum,'Minimum amount must not exceed maximum amount.');
  const nodes=new Map(dataset.nodes.map(n=>[n.id,n])),target=direction==='all'?null:dataset.nodes.find(n=>match(n.address||n.txid,query,dataset.asset,n.kind,true));
  check(direction==='all'||Boolean(query&&target),'Direction filtering requires an exact graph reference.');
  const rows=dataset.edges.filter(e=>{
    const from=nodes.get(e.from),to=nodes.get(e.to),value=BigInt(e.amount_base_units);
    return (kind==='all'||e.kind===kind)&&(minBlock===null||BigInt(e.block_number)>=minBlock)&&(maxBlock===null||BigInt(e.block_number)<=maxBlock)&&(minimum===null||value>=minimum)&&(maximum===null||value<=maximum)
      &&(target?(direction==='incoming'?e.to===target.id:e.from===target.id):!query||match(e.txid,query,dataset.asset,'transaction')||[from,to].some(n=>match(n.address||n.txid,query,dataset.asset,n.kind)));
  });
  return {rows,filters:{query,kind,direction,minBlock:minBlock?.toString()??'',maxBlock:maxBlock?.toString()??'',minimum:minimum?.toString()??'',maximum:maximum?.toString()??''}};
}
export async function filteredEvidence(packet,options={}){
  const{rows,filters}=selectRecords(packet,options),ids=new Set(rows.flatMap(e=>[e.from,e.to])),original=packet.dataset;
  const dataset={...original,nodes:original.nodes.filter(n=>ids.has(n.id)),edges:rows,scope:{filtered_records:rows.length,source_records:original.edges.length,complete_chain_history:false},coverage:`Filtered subset: ${rows.length} of ${original.edges.length} collected records. Source snapshots describe the original sampled pages.`};
  return packageDataset(dataset,{selection:{parent_dataset_sha256:packet.dataset_sha256,filters}});
}

export function compareEvidence(baseline,current){
  sameSource(baseline.dataset,current.dataset);check(!baseline.selection&&!current.selection,'Compare full collections, not filtered subsets.');
  const a=new Map(baseline.dataset.edges.map(e=>[e.event_id,e])),b=new Map(current.dataset.edges.map(e=>[e.event_id,e]));
  const onlyCurrent=[],onlyBaseline=[],changed=[],shared=[];
  for(const[id,edge]of b){const before=a.get(id);if(!before)onlyCurrent.push(id);else if(eventValue(before)!==eventValue(edge))changed.push(id);else shared.push(id);}
  for(const id of a.keys())if(!b.has(id))onlyBaseline.push(id);
  const oldBlocks=blockMap(baseline.dataset),newBlocks=blockMap(current.dataset),conflicts=[];
  for(const[height,hash]of oldBlocks)if(newBlocks.has(height)&&newBlocks.get(height)!==hash)conflicts.push({height,baseline_hash:hash,current_hash:newBlocks.get(height)});
  return {kind:'graphus_evidence_comparison',schema_version:1,asset:current.dataset.asset,network:current.dataset.network,source:current.dataset.source,baseline_sha256:baseline.dataset_sha256,current_sha256:current.dataset_sha256,
    baseline:{retrieved_at:baseline.dataset.retrieved_at,records:a.size,source_pages:baseline.dataset.snapshots.length},current:{retrieved_at:current.dataset.retrieved_at,records:b.size,source_pages:current.dataset.snapshots.length},
    counts:{only_current:onlyCurrent.length,only_baseline:onlyBaseline.length,changed:changed.length,shared:shared.length},event_ids:{only_current:onlyCurrent,only_baseline:onlyBaseline,changed,shared},conflicting_blocks:conflicts,
    interpretation:conflicts.length?'Source block hashes diverge at overlapping heights. Review anchors before combining observations.':'Differences describe these sampled datasets. A missing record is not proof of a deleted transaction or inactivity. These counts are not a time-based activity delta.'};
}

const stable=value=>JSON.stringify(value,(_,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.entries(item).sort(([a],[b])=>a.localeCompare(b))):item);
function fields(value,allowed,label){check(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>allowed.includes(key)),`Unexpected ${label} fields.`);}
export async function validateEvidenceCollection(packet){
  check(new TextEncoder().encode(JSON.stringify(packet)).byteLength<=6_000_000,'Collection file exceeds 6 MB.');
  fields(packet,['kind','schema_version','exported_at','dataset','dataset_sha256','digest_encoding','diagnostics','purpose','aml_score_included','identity_attribution_included','pagination','collection','selection'],'packet');
  check(packet.kind==='graphus_network_collection'&&packet.schema_version===1&&/^[a-f0-9]{64}$/.test(packet.dataset_sha256||''),'Open a System Map evidence collection with a dataset digest.');
  check(packet.aml_score_included===false&&packet.identity_attribution_included===false&&typeof packet.exported_at==='string'&&packet.exported_at.length<=100&&Number.isFinite(Date.parse(packet.exported_at)),'Invalid evidence packet metadata.');
  const d=packet.dataset;
  fields(d,['status','asset','network','source','retrieved_at','anchor','coverage','scope','independent_verification','nodes','edges','snapshots'],'dataset');
  check(d.independent_verification===false&&typeof d.coverage==='string'&&d.coverage.length<=1000,'Invalid source coverage.');
  check(Array.isArray(d.snapshots)&&d.snapshots.length>0&&d.snapshots.length<=COLLECTION_LIMITS.pages,'Expected one to eight source snapshots.');
  const scopeKeys=['transactions_returned','transactions_in_block','transactions_in_page','endpoint_records_omitted','selection','candidates_checked','successful_transfers','failed_transactions_omitted','internal_calls_included','from_block','to_block','contract','source_logs','returned_logs','truncated','not_finalized_omitted','has_more','finality_available','source_pages','unique_records','complete_chain_history','filtered_records','source_records'];
  function metadata(value){
    fields(value.anchor,['height','hash','time','finality','finalized_height'],'anchor');
    fields(value.scope,scopeKeys,'scope');
    check(typeof value.retrieved_at==='string'&&value.retrieved_at.length<=100&&Number.isFinite(Date.parse(value.retrieved_at)),'Invalid source retrieval time.');
    check(value.anchor.finality===undefined||typeof value.anchor.finality==='string'&&value.anchor.finality.length<=300,'Invalid source finality text.');
    check(value.anchor.time===undefined||typeof value.anchor.time==='string'&&Number.isFinite(Date.parse(value.anchor.time)),'Invalid source block time.');
    check(value.anchor.finalized_height===undefined||Number.isSafeInteger(value.anchor.finalized_height)&&value.anchor.finalized_height>=0,'Invalid source finalized height.');
    check(Object.values(value.scope).every(v=>typeof v==='boolean'||Number.isSafeInteger(v)||typeof v==='string'&&v.length<=500),'Invalid scope values.');
  }
  metadata(d);const checked=await evidencePacket({...d,next_cursor:null},d.asset);
  check(stable(d.nodes)===stable(checked.dataset.nodes)&&stable(d.edges)===stable(checked.dataset.edges)&&stable(d.anchor)===stable(checked.dataset.anchor),'Unexpected or invalid reference, event or anchor fields.');
  for(const [i,s]of d.snapshots.entries()){
    fields(s,['source','retrieved_at','anchor','scope','coverage','records','requested_cursor'],'snapshot');metadata(s);
    check(s.source===d.source&&Number.isSafeInteger(s.records)&&s.records>=0&&s.records<=COLLECTION_LIMITS.records&&typeof s.coverage==='string'&&s.coverage.length<=1000,'Invalid source snapshot.');
    check(i===0?s.requested_cursor===null:typeof s.requested_cursor==='string','Invalid snapshot cursor sequence.');
    await evidencePacket({...s,status:'source-reported',asset:d.asset,network:d.network,nodes:[],edges:[],next_cursor:null},d.asset,{cursor:s.requested_cursor});
  }
  check(new Set(d.snapshots.map(s=>s.requested_cursor)).size===d.snapshots.length,'Repeated snapshot cursor.');
  check(Math.max(...d.snapshots.map(s=>s.anchor.height))===d.anchor.height&&d.snapshots.some(s=>s.anchor.height===d.anchor.height&&s.anchor.hash.toLowerCase()===d.anchor.hash.toLowerCase()),'Collection anchor differs from source snapshots.');
  check(d.snapshots.reduce((sum,s)=>sum+s.records,0)>=d.edges.length,'Snapshot record counts cannot cover this collection.');
  blockMap(d);
  const expected=await packageDataset(d);
  check(expected.dataset_sha256===packet.dataset_sha256,'Dataset digest mismatch. The saved records have changed.');
  check(packet.purpose===expected.purpose&&packet.digest_encoding===expected.digest_encoding&&stable(packet.diagnostics)===stable(expected.diagnostics),'Dataset diagnostics or digest encoding mismatch.');
  if(packet.pagination){
    fields(packet.pagination,['next_cursor','requested_cursors'],'pagination');
    check(!packet.selection&&cursorValid(d.asset,packet.pagination.next_cursor)&&stable(packet.pagination.requested_cursors)===stable(d.snapshots.map(s=>s.requested_cursor)),'Invalid collection pagination.');
  }
  if(packet.collection){fields(packet.collection,['last_page_added','duplicate_records_omitted'],'collection');check(Object.values(packet.collection).every(v=>Number.isSafeInteger(v)&&v>=0&&v<=32000),'Invalid collection counts.');}
  if(packet.selection){
    fields(packet.selection,['parent_dataset_sha256','filters'],'selection');fields(packet.selection.filters,['query','kind','direction','minBlock','maxBlock','minimum','maximum'],'filters');
    check(/^[a-f0-9]{64}$/.test(packet.selection.parent_dataset_sha256||''),'Missing parent dataset digest.');
    const selected=selectRecords(packet,packet.selection.filters);check(selected.rows.length===d.edges.length&&stable(selected.filters)===stable(packet.selection.filters),'Records do not match the saved filters.');
  }
  return structuredClone(packet);
}
