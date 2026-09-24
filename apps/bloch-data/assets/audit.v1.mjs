import {createReport, sha256} from './reconcile.v1.mjs';

export const MAX_EVIDENCE_BYTES = 24 * 1024 * 1024;
export const MAX_REVIEW_BYTES = 8 * 1024 * 1024;
export const MAX_REVIEW_EVENTS = 1000;
export const REVIEW_STATES = Object.freeze({investigating:'Investigating',explained:'Explained',follow_up:'Follow-up required',reopened:'Reopened'});
const encode = value => JSON.stringify(value,null,2)+'\n';
const digestPattern = /^[0-9a-f]{64}$/;
const reviewMetadata = {clock_source:'local_browser_untrusted',reviewer_identity:'self_declared',approval:'not_an_authorized_approval'};

// Workbench exports have a single byte format. Requiring it also rejects duplicate
// JSON keys, ambiguous numbers and edits made by spreadsheet/text formatters.
export function readExport(text,limit=MAX_EVIDENCE_BYTES) {
  if(typeof text!=='string'||new TextEncoder().encode(text).length>limit)throw new Error('JSON export exceeds its size limit.');
  let value;
  try { value=JSON.parse(text); if(encode(value)!==text)throw new Error(); }
  catch {throw new Error('Use the original workbench JSON export, including its formatting. Duplicate fields or reformatted JSON are not accepted.');}
  return value;
}
function stable(value,depth=0) {
  if(depth>24)throw new Error('JSON nesting exceeds the supported export schema.');
  if(Array.isArray(value))return '['+value.map(v=>stable(v,depth+1)).join(',')+']';
  if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+stable(value[k],depth+1)).join(',')+'}';
  return JSON.stringify(value);
}
function equal(a,b) {return stable(a)===stable(b);}
function timestamp(value) {return typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;}
function textField(value,max,multiline=false) {
  return typeof value==='string'&&value.length>0&&value.length<=max&&value===value.trim()&&!(multiline?/[\u0000-\u0008\u000b-\u001f\u007f]/:/[\u0000-\u001f\u007f]/).test(value);
}
function exactKeys(value,keys) {return value&&typeof value==='object'&&!Array.isArray(value)&&equal(Object.keys(value).sort(),[...keys].sort());}

export async function verifyEvidence(text,left,right,expectedDigest='') {
  const report=readExport(text),digest=await sha256(text);
  if(expectedDigest!==''&&(!digestPattern.test(expectedDigest)||expectedDigest!==digest))throw new Error('The report does not match the independently retained SHA-256.');
  if(!report||report.schema!=='bloch.data.financial-evidence.v1')throw new Error('Unsupported evidence schema.');
  if(!['synthetic_example','local_files'].includes(report.mode)||!timestamp(report.generated_at))throw new Error('Invalid report mode or local timestamp.');
  if(!Array.isArray(report.sources)||report.sources.length!==2||report.sources.some(s=>!s||typeof s.name!=='string'||s.name.length>1024))throw new Error('Invalid source declarations.');
  // Names can change during retention; byte content and A/B ordering must agree.
  const rebuilt=await createReport({name:report.sources[0].name,text:left.text},{name:report.sources[1].name,text:right.text},report.mode,report.configuration);
  rebuilt.report.generated_at=report.generated_at;
  if(!equal(report.sources,rebuilt.report.sources))throw new Error('Source bytes do not match the report. Supply the original files in A/B order.');
  if(!equal(report.result,rebuilt.report.result))throw new Error('Recomputed outcomes or source rows differ from the report.');
  if(!equal(report,rebuilt.report))throw new Error('Report rules, metadata or assurance fields differ from the supported schema.');
  return {report,bytes:text,digest,pinned:expectedDigest!==''};
}

export function newReview(evidenceDigest) {
  if(!digestPattern.test(evidenceDigest))throw new Error('Invalid evidence digest.');
  return {schema:'bloch.data.exception-review.v1',evidence_sha256:evidenceDigest,...reviewMetadata,events:[]};
}
export function validateReview(review,report,evidenceDigest) {
  if(!exactKeys(review,['schema','evidence_sha256',...Object.keys(reviewMetadata),'events'])||review.schema!=='bloch.data.exception-review.v1'||review.evidence_sha256!==evidenceDigest||!digestPattern.test(evidenceDigest))throw new Error('Review journal is not bound to this exact evidence report.');
  for(const [key,value] of Object.entries(reviewMetadata))if(review[key]!==value)throw new Error('Unsupported review assurance declaration.');
  if(!Array.isArray(review.events)||review.events.length>MAX_REVIEW_EVENTS)throw new Error(`Review journal supports at most ${MAX_REVIEW_EVENTS} entries.`);
  const records=new Map(report.result.items.map(item=>[JSON.stringify(item.key),item]));
  review.events.forEach((event,index)=>{
    if(!exactKeys(event,['sequence','record_key','original_outcome','state','reviewer','note','recorded_at']))throw new Error('Unexpected review entry fields.');
    const item=records.get(JSON.stringify(event.record_key));
    if(!item||item.status==='matched'||event.original_outcome!==item.status)throw new Error('Review entry does not identify an exception in this report.');
    if(event.sequence!==index+1||!Object.hasOwn(REVIEW_STATES,event.state)||!textField(event.reviewer,120)||!textField(event.note,2000,true)||!timestamp(event.recorded_at))throw new Error('Invalid review sequence, state, reviewer, note or local timestamp.');
  });
  return structuredClone(review);
}
export function appendReview(review,report,evidenceDigest,entry) {
  const next=validateReview(review,report,evidenceDigest);
  next.events.push({sequence:next.events.length+1,record_key:entry.record_key,original_outcome:entry.original_outcome,state:entry.state,reviewer:entry.reviewer.trim(),note:entry.note.trim(),recorded_at:new Date().toISOString()});
  return validateReview(next,report,evidenceDigest);
}
export async function reviewExport(review,report,evidenceDigest) {
  const bytes=encode(validateReview(review,report,evidenceDigest));
  return {bytes,digest:await sha256(bytes)};
}
export function latestReviews(review) {
  const latest=new Map();
  for(const event of review.events)latest.set(JSON.stringify(event.record_key),event);
  return latest;
}
export async function verificationExport(evidence,review=null) {
  const report={
    schema:'bloch.data.local-verification.v1',verified_at:new Date().toISOString(),
    clock_source:'local_browser_untrusted',evidence_sha256:evidence.digest,
    retained_digest_check:evidence.pinned?'matched':'not_provided',
    source_bytes:'matched',comparison:'recomputed_and_matched',rules_and_metadata:'matched_supported_schema',
    module:evidence.report.configuration.module,mode:evidence.report.mode,
    counts:evidence.report.result.counts,
    review:review?{sha256:(await reviewExport(review,evidence.report,evidence.digest)).digest,events:review.events.length,binding:'matched'}:null,
    assurance:{scope:'local_consistency_only',source_authentication:'not_verified',reviewer_identity:'not_verified',auditor_signature:'absent',rollback_protection:'absent',onchain:'not_verified',regulatory_compliance:'not_certified'}
  };
  const bytes=encode(report);return {bytes,digest:await sha256(bytes)};
}
