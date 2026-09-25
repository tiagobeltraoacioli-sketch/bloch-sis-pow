import {ASSETS,GRAPHUS_ORIGIN,validateModules} from './participant-modules.mjs';
import {validateEvidenceCollection,fetchEvidence,selectRecords} from './evidence-vendor/graphus-evidence.mjs';
export {selectRecords};
export const EVIDENCE_LIMITS=Object.freeze({cases:50,bytes:20_000_000,packetBytes:6_000_000,revisions:50});
export const REVIEW_STAGES=Object.freeze({unreviewed:'Unreviewed',in_review:'In review',follow_up:'Follow-up needed',reviewed:'Review recorded'});
const check=(condition,message)=>{if(!condition)throw new Error(message);};
const bytes=value=>new TextEncoder().encode(JSON.stringify(value)).length;
const reference=value=>typeof value==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,79}$/.test(value);
const timestamp=value=>typeof value==='string'&&/^20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
const text=(value,max)=>typeof value==='string'&&value.length<=max&&!/[\u0000-\u0008\u000b-\u001f]/.test(value);
export function validateReview(input){
  check(input&&typeof input.stage==='string'&&Object.hasOwn(REVIEW_STAGES,input.stage)&&text(input.owner,120)&&text(input.note,1000),'Invalid local review fields.');
  const owner=input.owner.trim(),note=input.note.trim();
  check(input.stage==='unreviewed'||owner.length>0,'Record an owner for this review stage.');
  check(input.stage!=='reviewed'||note.length>0,'Add a review note before recording completion.');
  return {stage:input.stage,owner,note};
}
export async function validatePacket(packet){check(bytes(packet)<=EVIDENCE_LIMITS.packetBytes,'Graphus packet exceeds 6 MB.');return validateEvidenceCollection(packet);}
export async function publicEvidencePage(asset,{fetcher=fetch,signal}={}){
  check(ASSETS.includes(asset),'Unsupported evidence asset.');
  const packet=await fetchEvidence(asset,{signal,fetcher:(path,options)=>{
    check(path==='/api/chain/network?'+new URLSearchParams({asset}),'Unexpected public source request.');
    return fetcher(GRAPHUS_ORIGIN+path,{...options,method:'GET',credentials:'omit',cache:'no-store',redirect:'error'});
  }});
  return validatePacket(packet);
}
export async function createEvidenceCase({packet,participant,route=null,review,acquisition},now=new Date().toISOString(),id=crypto.randomUUID()){
  const checked=await validatePacket(packet),plan=validateModules(participant?.modules);
  check(participant&&reference(participant.id)&&plan.enabled.length&&plan.assets.includes(checked.dataset.asset),'Select a participant with a module configured for this asset.');
  check(!route||[route.draft.source,route.draft.destination].some(leg=>leg.partner_reference.toLowerCase()===participant.id),'The selected route does not contain this participant.');
  const reviewValue=validateReview(review);
  return validateEvidenceCase({schema:'bloch-pay-evidence-case',version:1,id,created_at:now,updated_at:now,revision:1,
    acquisition,context:{participant_reference:participant.id,participant_name:participant.name,route_id:route?.draft.id||null,payment_reference:route?.draft.payment_reference||null,association:'local_context_only'},
    packet:checked,review:reviewValue,archived:false,history:[{revision:1,at:now,...reviewValue,archived:false}]});
}
export function reviseEvidenceCase(previous,review,archived=previous.archived,now=new Date().toISOString()){
  check(previous.history.length<EVIDENCE_LIMITS.revisions,'The 50-revision limit is reached. Export this record before starting a new review.');
  check(timestamp(now)&&now>=previous.updated_at,'Review timestamp predates the saved record.');
  const next=validateReview(review);check(typeof archived==='boolean','Invalid archive state.');
  if(JSON.stringify(next)===JSON.stringify(previous.review)&&archived===previous.archived)return previous;
  const revision=previous.revision+1;
  return {...previous,revision,updated_at:now,review:next,archived,history:[...previous.history,{revision,at:now,...next,archived}]};
}
export async function validateEvidenceCase(input){
  check(input&&input.schema==='bloch-pay-evidence-case'&&input.version===1&&reference(input.id)&&timestamp(input.created_at)&&timestamp(input.updated_at)&&input.updated_at>=input.created_at,'Invalid evidence review record.');
  check(['public_capture','imported_packet'].includes(input.acquisition),'Invalid evidence acquisition mode.');
  const c=input.context;
  check(c&&reference(c.participant_reference)&&text(c.participant_name,120)&&c.participant_name.trim()&&c.association==='local_context_only','Invalid participant association.');
  check(c.route_id===null&&c.payment_reference===null||reference(c.route_id)&&reference(c.payment_reference),'Invalid route association.');
  const review=validateReview(input.review);check(typeof input.archived==='boolean','Invalid archived state.');
  check(Number.isSafeInteger(input.revision)&&input.revision>=1&&input.revision<=EVIDENCE_LIMITS.revisions&&Array.isArray(input.history)&&input.history.length===input.revision,'Invalid review revision history.');
  let prior=input.created_at;
  const history=input.history.map((row,index)=>{check(row&&row.revision===index+1&&timestamp(row.at)&&row.at>=prior&&typeof row.archived==='boolean','Invalid review history order.');prior=row.at;return {revision:row.revision,at:row.at,...validateReview(row),archived:row.archived};});
  check(history[0].at===input.created_at&&history.at(-1).at===input.updated_at&&history.at(-1).archived===input.archived&&JSON.stringify(validateReview(history.at(-1)))===JSON.stringify(review),'Review history does not match the current record.');
  return {schema:'bloch-pay-evidence-case',version:1,id:input.id,created_at:input.created_at,updated_at:input.updated_at,revision:input.revision,acquisition:input.acquisition,context:{participant_reference:c.participant_reference,participant_name:c.participant_name,route_id:c.route_id,payment_reference:c.payment_reference,association:'local_context_only'},packet:await validatePacket(input.packet),review,archived:input.archived,history};
}
export async function validateVault(input){
  check(input&&input.schema==='bloch-pay-evidence-vault'&&input.version===1&&Array.isArray(input.records)&&input.records.length<=EVIDENCE_LIMITS.cases,'Unsupported evidence backup or more than 50 records.');
  check(bytes(input)<=EVIDENCE_LIMITS.bytes,'Evidence vault exceeds 20 MB.');
  const seen=new Set(),records=[];
  for(const row of input.records){const record=await validateEvidenceCase(row);check(!seen.has(record.id),'Duplicate evidence review identifier.');seen.add(record.id);records.push(record);}
  return {schema:'bloch-pay-evidence-vault',version:1,records};
}
export function vaultBundle(records){return {schema:'bloch-pay-evidence-vault',version:1,records};}
export function capacityCheck(records){check(records.length<=EVIDENCE_LIMITS.cases&&bytes(vaultBundle(records))<=EVIDENCE_LIMITS.bytes,'Evidence capacity reached: 50 records / 20 MB. Export and remove a retained record before adding another.');}
export function recordTotals(rows){const totals=new Map();for(const row of rows)totals.set(row.kind,(totals.get(row.kind)||0n)+BigInt(row.amount_base_units));return [...totals].map(([kind,value])=>({kind,amount:value.toString()}));}
