// Bounded public-source observations. No writes, keys, or consensus decisions.
export const SOURCES=Object.freeze({
  chain:{name:'Chain observer',method:'getchaininfo',url:'https://posternlabs.com/g4rpc',route:'/rpc/',scope:'Gateway chain view; corroboration is source-reported.'},
  validators:{name:'Validator registry',method:'getvalidatorcount',url:'https://posternlabs.com/g4rpc',route:'/validators/',scope:'Aggregate validators reported by the answering observer.'},
  admission:{name:'Funded admission',method:'getvalidatoradmission',url:'https://posternlabs.com/g4rpc',route:'/validators/',scope:'Admission only; no exit, withdrawal or delegation qualification.'},
  mempool:{name:'Node mempool',method:'getmempoolinfo',url:'https://posternlabs.com/g4rpc',route:'/rpc/',scope:'One observer’s queue, not a network-wide mempool.'},
  build:{name:'Build identity',method:'getbuildinfo',url:'https://posternlabs.com/g4rpc',route:'/rpc/',scope:'Self-reported source/build identity, not remote attestation.'},
  indexer:{name:'Historical indexer',relay:'/api/indexer-health',url:'https://blochl1.com/indexer/health',route:'/wallets/',scope:'Separate indexed-chain snapshot reported by Bloch Explorer, read through a fixed same-origin relay.'}
});
export const MAX_ROUNDS=180;
export const DEFAULTS=Object.freeze({interval:30,finalityGap:128,syncLag:8,indexerLag:16,latency:4000,stall:180,expectedDomain:'',expectedDigest:''});
const fail=message=>{throw new Error(message);};
const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const uint=(v,name,optional=false)=>v==null&&optional?null:Number.isSafeInteger(v)&&v>=0?v:fail(`Invalid ${name}.`);
const bool=(v,name,optional=false)=>v==null&&optional?null:typeof v==='boolean'?v:fail(`Invalid ${name}.`);
const hex=(v,name,optional=false)=>v==null&&optional?null:typeof v==='string'&&/^[a-f0-9]{64}$/i.test(v)?v.toLowerCase():fail(`Invalid ${name}.`);
const amount=(v,name)=>typeof v==='string'&&/^(0|[1-9][0-9]{0,49})$/.test(v)?v:fail(`Invalid ${name}.`);
const string=(v,max=200)=>typeof v==='string'?v.replace(/[\x00-\x1f\x7f]/g,' ').slice(0,max):null;
const time=v=>typeof v==='string'&&v.length<=40&&Number.isFinite(Date.parse(v))?v:fail('Invalid observation time.');
function registry(r){const total=uint(r?.total,'validator total'),active=uint(r?.active,'active validators');if(active>total)fail('Active validators exceed total.');return {total,active};}
function corroboration(c={}){
  if(!object(c))fail('Invalid corroboration.');
  const plane=object(c.plane)?c.plane:{},witness=object(c.witness)?c.witness:{};
  return {level:string(c.level,60),source_node:string(c.source_node,80),archival_witnesses:uint(c.archival_witnesses,'witness count',true),of:uint(c.of,'witness total',true),
    plane:{certified:bool(plane.certified,'plane certification',true),agree_on_head:bool(plane.agree_on_head,'plane agreement',true),age_ms:uint(plane.age_ms,'plane age',true)},
    witness:{available:bool(witness.available,'witness availability',true),age_ms:uint(witness.age_ms,'witness age',true)}};
}
export function normalize(source,raw){
  if(!Object.hasOwn(SOURCES,source)||!object(raw))fail('Unknown or malformed source.');
  const c=source==='indexer'?null:corroboration(raw.corroboration??{});let data;
  if(source==='chain'){
    const height=uint(raw.height,'height'),slot=uint(raw.slot,'slot'),finalized_height=uint(raw.finalized_height,'finalized height',true);if(height>slot||finalized_height!=null&&finalized_height>height)fail('Inconsistent chain heights.');
    const finalized=raw.finalized==null?null:{epoch:uint(raw.finalized.epoch,'finalized epoch'),root:hex(raw.finalized.root,'finalized root')};
    data={height,slot,block_id:hex(raw.block_id,'block ID'),finalized_height,finalized,epoch:uint(raw.epoch,'epoch'),behind_by_slots:uint(raw.behind_by_slots,'sync lag',true),validators:registry(raw.validators),total_active_stake_sat:amount(raw.total_active_stake_sat,'active stake'),
      transport:{peers:{devnet:uint(raw.transport?.peers?.devnet,'devnet connections',true),libp2p:uint(raw.transport?.peers?.libp2p,'libp2p connections',true)}}};
  }else if(source==='validators')data={...registry(raw),total_active_stake_sat:amount(raw.total_active_stake_sat,'active stake')};
  else if(source==='admission'){
    data={active:bool(raw.active,'admission state'),epoch:uint(raw.epoch,'admission epoch'),activation_epoch:uint(raw.activation_epoch,'activation epoch',true),network_domain:hex(raw.network_domain,'network domain',true),minimum_stake_sat:amount(raw.minimum_stake_sat,'minimum stake'),maximum_stake_sat:amount(raw.maximum_stake_sat,'maximum stake'),activation_delay_epochs:uint(raw.activation_delay_epochs,'activation delay'),exit_delay_epochs:uint(raw.exit_delay_epochs,'exit delay'),withdrawal_delay_epochs:uint(raw.withdrawal_delay_epochs,'withdrawal delay')};
    if(BigInt(data.minimum_stake_sat)>BigInt(data.maximum_stake_sat))fail('Inconsistent stake bounds.');
  }else if(source==='mempool'){
    data={size:uint(raw.size,'queue size'),max:uint(raw.max,'queue limit'),bytes:uint(raw.bytes,'queue bytes'),barred:uint(raw.barred,'barred count',true),barred_hits:uint(raw.barred_hits,'barred hits',true),expired:uint(raw.expired,'expired count',true),evicted_low_fee:uint(raw.evicted_low_fee,'eviction count',true),next_base_fee_millisat_per_gas:amount(raw.next_base_fee_millisat_per_gas,'base fee')};
  }else if(source==='build'){
    const version=string(raw.package_version??raw.build_version);if(!version)fail('Missing build version.');
    data={package_version:version,build_version:string(raw.build_version),commit:string(raw.commit,80),commit_source:string(raw.commit_source,80),tree_state:string(raw.tree_state,80),source_digest:hex(raw.source_digest,'source digest',true),source_digest_alg:string(raw.source_digest_alg,40),target:string(raw.target,100),rustc:string(raw.rustc,150)};
  }else{
    data={ok:bool(raw.ok,'indexer state'),indexed_to_height:uint(raw.indexed_to_height,'indexed height'),indexed_to_slot:uint(raw.indexed_to_slot,'indexed slot'),finalized_height:uint(raw.finalized_height,'indexed finalized height',true),lag_slots:uint(raw.lag_slots,'indexer lag',true),transactions:uint(raw.transactions,'indexed transaction count'),chain_tip:hex(raw.chain_tip,'indexed tip'),live_head_available:bool(raw.live_head_available,'indexer live head',true),source:string(raw.source),verification:string(raw.verification),lag_basis:string(raw.lag_basis)};
    if(data.indexed_to_height>data.indexed_to_slot||data.finalized_height!=null&&data.finalized_height>data.indexed_to_height)fail('Inconsistent indexer heights.');
  }
  return c?{...data,corroboration:c}:data;
}
export function settings(raw={}){
  const result={...DEFAULTS};for(const key of ['interval','finalityGap','syncLag','indexerLag','latency','stall']){const value=raw[key]??result[key];if(!Number.isInteger(value)||value<1||value>1000000)fail(`Invalid ${key} setting.`);result[key]=value;}
  if(![30,60,120].includes(result.interval)||result.stall<60)fail('Choose a supported interval and a stall threshold of at least 60 seconds.');
  for(const key of ['expectedDomain','expectedDigest']){result[key]=raw[key]??'';if(result[key]!==''&&!/^[a-f0-9]{64}$/i.test(result[key]))fail('Expected identity values must contain 64 hexadecimal characters.');result[key]=result[key].toLowerCase();}return result;
}
export function validateObservation(o,source){
  if(!object(o)||o.source!==source||!['valid','failed'].includes(o.status)||typeof o.id!=='string'||o.id.length>80)fail('Invalid source observation.');
  const data=o.status==='valid'?normalize(source,o.data):null;
  return {id:o.id,source,at:time(o.at),round_trip_ms:uint(o.round_trip_ms,'round trip'),status:o.status,error:o.status==='failed'?string(o.error,200)||'Source unavailable.':null,data};
}
export function validateBundle(raw){
  if(raw?.schema!=='bloch-ops-monitor/1'||!Array.isArray(raw.rounds)||raw.rounds.length>MAX_ROUNDS)fail('Unsupported or oversized monitor evidence.');
  const ids=new Set();let previous=0;
  const rounds=raw.rounds.map(r=>{if(!object(r)||typeof r.id!=='string'||r.id.length>80||ids.has(r.id)||!object(r.observations)||Object.keys(r.observations).length!==6)fail('Invalid observation round.');ids.add(r.id);
    const started_at=time(r.started_at),finished_at=time(r.finished_at),start=Date.parse(started_at),end=Date.parse(finished_at);if(start<previous||end<start||end-start>120000)fail('Inconsistent observation ordering.');previous=end;
    const observations={};for(const source of Object.keys(SOURCES)){const o=validateObservation(r.observations[source],source),at=Date.parse(o.at);if(at<start||at>end)fail('Observation lies outside its round.');if(ids.has(o.id))fail('Duplicate observation ID.');ids.add(o.id);observations[source]=o;}return {id:r.id,started_at,finished_at,observations};
  });return {schema:raw.schema,settings:settings(raw.settings),rounds};
}
export function freshness(observation,now=Date.now(),config=DEFAULTS){if(!observation)return 'unknown';if(observation.status!=='valid')return 'failed';const age=now-Date.parse(observation.at);return age<0||age>Math.max(90000,config.interval*3000)?'stale':'valid';}
export function stake(value){const n=BigInt(value),part=(n%100000000n).toString().padStart(8,'0').replace(/0+$/,'');return `${(n/100000000n).toLocaleString('en-US')}${part?'.'+part:''}`;}
export function metrics(round){const o=round?.observations||{},d=s=>o[s]?.status==='valid'?o[s].data:null,c=d('chain'),v=d('validators'),m=d('mempool'),i=d('indexer');return {
  height:c?.height??null,finalized:c?.finalized_height??null,finality_gap:c?.finalized_height==null?null:c.height-c.finalized_height,sync_lag:c?.behind_by_slots??null,
  active:v?.active??null,validators:v?.total??null,mempool:m?.size??null,indexer_lag:i?.lag_slots??null,connections:c?.transport.peers.devnet??null,
  latency:o.chain?.status==='valid'?o.chain.round_trip_ms:null,indexer_delta:c&&i?c.height-i.indexed_to_height:null};}
function rule(source,code,title,detail,state,severity='review'){return {id:`${source}:${code}`,source,code,title,detail,state:state===null?'unknown':state?'active':'clear',severity};}
export function evaluate(rounds,config=DEFAULTS,now=Date.now()){
  const latest=rounds.at(-1),result=[];if(!latest)return result;
  const fresh={},valid={};for(const source of Object.keys(SOURCES)){const o=latest.observations[source],state=freshness(o,now,config);fresh[source]=state==='valid';valid[source]=o.status==='valid'?o.data:null;
    result.push(rule(source,'availability',`${SOURCES[source].name}: ${state==='stale'?'observation is stale':'read unavailable'}`,o.error||'The latest observation is outside the freshness window.',!fresh[source]));
    result.push(rule(source,'latency',`${SOURCES[source].name}: slow round trip`,`Browser round trip exceeds ${config.latency} ms. This includes network and gateway time.`,fresh[source]?o.round_trip_ms>config.latency:null));
  }
  const c=valid.chain,m=valid.mempool,i=valid.indexer,a=valid.admission,b=valid.build,fc=fresh.chain;
  result.push(rule('chain','finality_gap','Finality distance above local threshold',`Threshold: ${config.finalityGap} blocks. This is an operator setting, not a protocol safety limit.`,fc&&c.finalized_height!=null?c.height-c.finalized_height>config.finalityGap:null));
  result.push(rule('chain','sync_lag','Observer reports slot lag',`Reported lag exceeds ${config.syncLag} slots.`,fc&&c.behind_by_slots!=null?c.behind_by_slots>config.syncLag:null));
  const corroborated=c?.corroboration;
  result.push(rule('chain','corroboration','Review reported corroboration','The gateway does not report all three: head agreement, plane certification and an available witness.',fc?!(corroborated.plane.certified===true&&corroborated.plane.agree_on_head===true&&corroborated.witness.available===true):null));
  result.push(rule('indexer','lag','Indexer lag above local threshold',`Reported lag exceeds ${config.indexerLag} slots.`,fresh.indexer&&i.lag_slots!=null?i.lag_slots>config.indexerLag:null));
  result.push(rule('indexer','state','Indexer reports unavailable state','The source reports an unhealthy index or no live comparison head.',fresh.indexer?i.ok!==true||i.live_head_available===false:null));
  result.push(rule('mempool','capacity','Node queue above 85% capacity','This applies only to the answering node’s configured queue.',fresh.mempool&&m.max>0?m.size/m.max>.85:null));
  result.push(rule('admission','inactive','Node reports admission inactive','This flag concerns funded admission only.',fresh.admission?!a.active:null));
  if(config.expectedDomain)result.push(rule('admission','domain','Network domain differs from the supplied expectation','The expected value was supplied locally; its independent trust is not established by this portal.',fresh.admission&&a.network_domain!=null?a.network_domain!==config.expectedDomain:null));
  if(config.expectedDigest)result.push(rule('build','digest','Source digest differs from the supplied expectation','Build identity is self-reported; matching a digest is not remote attestation.',fresh.build&&b.source_digest!=null?b.source_digest!==config.expectedDigest:null));
  const previous=rounds.slice(0,-1).findLast(r=>r.observations.chain.status==='valid')?.observations.chain.data;
  if(previous){
    result.push(rule('chain','regression','Chain observation regressed','Height or slot fell relative to the prior valid gateway observation. Compare independent sources before drawing a chain conclusion.',fc?c.height<previous.height||c.slot<previous.slot:null));
    result.push(rule('chain','finality_regression','Finality observation regressed','Reported finalized height or epoch fell. A cached or inconsistent gateway view is possible.',fc&&c.finalized_height!=null&&previous.finalized_height!=null?c.finalized_height<previous.finalized_height||c.finalized!=null&&previous.finalized!=null&&c.finalized.epoch<previous.finalized.epoch:null));
    result.push(rule('chain','anchor_changed','Reported chain anchor changed','Equal-height block IDs or equal-epoch finalized roots disagree between source observations.',fc?c.height===previous.height&&c.block_id!==previous.block_id||c.finalized!=null&&previous.finalized!=null&&c.finalized.epoch===previous.finalized.epoch&&c.finalized.root!==previous.finalized.root:null));
  }
  // A polling gap or failed read breaks the stall observation window.
  let first=latest.observations.chain,count=0,lastAt=Date.parse(first.at);
  for(let n=rounds.length-1;n>=0;n--){const o=rounds[n].observations.chain,at=Date.parse(o.at);if(o.status!=='valid'||!c||o.data.height!==c.height||o.data.block_id!==c.block_id||lastAt-at>config.interval*2500)break;first=o;count++;lastAt=at;}
  result.push(rule('chain','no_progress','No head progress in the observed window',`At least three consecutive valid reads report the same head over ${config.stall} seconds. Hidden tabs and missing polls break this window.`,fc?count>=3&&Date.parse(latest.observations.chain.at)-Date.parse(first.at)>=config.stall*1000:null));
  return result;
}
export function transitionAlerts(previous,rules,at){
  const next=new Map(previous),events=[];const seen=new Set();
  for(const r of rules){seen.add(r.id);const old=next.get(r.id);if(r.state==='active'){const changed=!old||old.state==='resolved';next.set(r.id,{...r,opened_at:changed?at:old.opened_at,updated_at:at,acknowledged:changed?false:old.acknowledged});if(changed)events.push({at,id:r.id,action:'opened',title:r.title});}
    else if(old&&old.state!=='resolved'){const state=r.state==='unknown'?'unknown':'resolved';next.set(r.id,{...old,...r,state,updated_at:at});if(old.state!==state)events.push({at,id:r.id,action:state==='resolved'?'cleared':'observation_unavailable',title:r.title});}}
  for(const [id,old]of next)if(!seen.has(id)&&old.state!=='resolved')next.set(id,{...old,state:'unknown'});
  return {alerts:next,events};
}
export function statistics(rounds){return Object.fromEntries(Object.keys(SOURCES).map(source=>{const all=rounds.map(r=>r.observations[source]),valid=all.filter(o=>o.status==='valid'),times=valid.map(o=>o.round_trip_ms).sort((a,b)=>a-b);return [source,{attempts:all.length,valid:valid.length,successRatio:all.length?valid.length/all.length:null,median:times.length?(times[Math.floor((times.length-1)/2)]+times[Math.floor(times.length/2)])/2:null,p95:times.length?times[Math.ceil(times.length*.95)-1]:null}];}));}
export function csv(rounds){const keys=['height','finalized','finality_gap','sync_lag','active','validators','mempool','indexer_lag','connections','latency','indexer_delta'],rows=[['round_id','observed_at',...keys,...Object.keys(SOURCES).map(k=>`${k}_status`)],...rounds.map(r=>{const m=metrics(r);return [r.id,r.finished_at,...keys.map(k=>m[k]),...Object.keys(SOURCES).map(k=>r.observations[k].status)];})];return rows.map(row=>row.map(v=>{const text=String(v??'');return '"'+(/^[\s]*[=+\-@]/.test(text)?"'":'')+text.replaceAll('"','""')+'"';}).join(',')).join('\r\n');}
