import {verifyCaseFile,MAX_CASE_BYTES} from './case-file.v1.mjs';
import {sha256} from './reconcile.v1.mjs';
import {latestReviews} from './audit.v1.mjs';
import {MODULES,REGIONS} from './modules.v1.mjs';

export const MAX_OVERVIEW_CASES=12;
export const MAX_OVERVIEW_BYTES=96*1024*1024;
export const OVERVIEW_OUTCOMES=Object.freeze({matched:'Matched',different:'Different fields',left_only:'Only in A',right_only:'Only in B',duplicate:'Duplicate key'});
export const OVERVIEW_REVIEWS=Object.freeze({unreviewed:'Not reviewed',investigating:'Investigating',explained:'Explained',follow_up:'Follow-up required',reopened:'Reopened'});
const encode=value=>JSON.stringify(value,null,2)+'\n';
const counts=labels=>Object.fromEntries(Object.keys(labels).map(key=>[key,0]));
const hex=/^[0-9a-f]{64}$/;
function validName(name){return typeof name==='string'&&name.isWellFormed()&&name.trim()!==''&&name.length<=255&&!/\p{Cc}/u.test(name);}

export function validateOverviewSelection(files){
  if(!Array.isArray(files)||files.length<1||files.length>MAX_OVERVIEW_CASES)throw new Error('Select 1–12 case files.');
  let total=0;
  for(const file of files){
    if(!file||!validName(file.name))throw new Error('Case filenames must be valid single-line Unicode text of at most 255 characters.');
    if(!Number.isSafeInteger(file.size)||file.size<1||file.size>MAX_CASE_BYTES)throw new Error('Each case must be nonempty and at most 64 MiB.');
    total+=file.size;
  }
  if(total>MAX_OVERVIEW_BYTES)throw new Error('Selected case files must total at most 96 MiB.');
  return total;
}

export async function buildCaseOverview(inputs){
  if(!Array.isArray(inputs)||inputs.length<1||inputs.length>MAX_OVERVIEW_CASES)throw new Error('Select 1–12 case files.');
  // Snapshot every input and reference before the first asynchronous verification.
  const files=inputs.map(input=>{
    if(!input||typeof input.text!=='string'||input.text.length>MAX_CASE_BYTES||!input.text.isWellFormed())throw new Error('Use valid UTF-8 case files within the 64 MiB limit.');
    const pin=input.expectedDigest??'';
    if(typeof pin!=='string'||(pin!==''&&!hex.test(pin)))throw new Error('Independent case references must be 64 lowercase hexadecimal characters.');
    return {name:input.name,text:input.text,expectedDigest:pin,size:new TextEncoder().encode(input.text).length};
  });
  const totalBytes=validateOverviewSelection(files),entries=[],seenCases=new Set(),seenEvidence=new Set();let mode=null;
  for(const file of files){
    const verified=await verifyCaseFile(file.text,file.expectedDigest),report=verified.evidence.report;
    if(seenCases.has(verified.digest))throw new Error('The same case was selected more than once. Select it only once.');
    if(seenEvidence.has(verified.evidence.digest))throw new Error('Multiple snapshots share the same evidence. Select one review snapshot per exact report.');
    if(mode!==null&&mode!==report.mode)throw new Error('Synthetic examples and local-file cases must use separate overviews.');
    mode=report.mode;seenCases.add(verified.digest);seenEvidence.add(verified.evidence.digest);
    const outcomes=counts(OVERVIEW_OUTCOMES),reviews=counts(OVERVIEW_REVIEWS),latest=latestReviews(verified.review);
    for(const item of report.result.items){outcomes[item.status]++;if(item.status!=='matched')reviews[latest.get(JSON.stringify(item.key))?.state??'unreviewed']++;}
    const config=report.configuration;
    const summary={selected_name:file.name,bytes:file.size,case_sha256:verified.digest,evidence_sha256:verified.evidence.digest,review_sha256:verified.caseFile.review_sha256,configuration_sha256:verified.caseFile.components[4].sha256,retained_case_digest_check:verified.pinned?'matched':'not_provided',module:config.module,institution:config.institution,region:config.region,keys:report.result.key_count,outcomes,exceptions:report.result.key_count-outcomes.matched,review_states:reviews,active_reviews:reviews.investigating+reviews.follow_up+reviews.reopened,review_entries:verified.review.events.length};
    entries.push({summary,verified,text:file.text});
  }
  const setDigest=await sha256(encode([...seenCases].sort()));
  return {mode,totalBytes,setDigest,entries};
}

export function defaultOverviewFilter(){return {module:'all',region:'all',review:'all'};}
export function selectOverview(overview,filter=defaultOverviewFilter()){
  if(!filter||typeof filter!=='object'||Array.isArray(filter)||Object.keys(filter).sort().join(',')!=='module,region,review'||Object.values(filter).some(value=>typeof value!=='string')||(filter.module!=='all'&&!Object.hasOwn(MODULES,filter.module))||(filter.region!=='all'&&!Object.hasOwn(REGIONS,filter.region))||!['all','unreviewed','active'].includes(filter.review))throw new Error('Unsupported case overview filter.');
  return overview.entries.filter(({summary:s})=>(filter.module==='all'||s.module===filter.module)&&(filter.region==='all'||s.region===filter.region)&&(filter.review==='all'||(filter.review==='unreviewed'?s.review_states.unreviewed>0:s.active_reviews>0)));
}

export function overviewTotals(entries){
  const total={cases:entries.length,keys:0,exceptions:0,review_entries:0,outcomes:counts(OVERVIEW_OUTCOMES),review_states:counts(OVERVIEW_REVIEWS)};
  for(const {summary:s} of entries){for(const key of ['keys','exceptions','review_entries'])total[key]+=s[key];for(const key of Object.keys(total.outcomes))total.outcomes[key]+=s.outcomes[key];for(const key of Object.keys(total.review_states))total.review_states[key]+=s.review_states[key];}
  return total;
}

export async function caseOverviewExport(overview){
  const value={schema:'bloch.data.case-overview.v1',generated_at:new Date().toISOString(),clock_source:'local_browser_untrusted',mode:overview.mode,scope:'all_selected_cases_filters_not_applied',ordering:'file_selection_not_chronology',case_set_sha256:overview.setDigest,input_bytes:overview.totalBytes,totals:overviewTotals(overview.entries),cases:overview.entries.map(entry=>structuredClone(entry.summary)),assurance:{scope:'local_consistency_only',counting:'sum_of_case_observations_not_unique_records',amounts:'not_aggregated',source_authentication:'not_verified',source_completeness:'not_verified',reviewer_identity:'not_verified',approval:'not_determined',chronology:'not_established',rollback_protection:'absent',onchain:'not_verified',regulatory_compliance:'not_certified',encryption:'none',signatures:'absent'}};
  const bytes=encode(value);return {value,bytes,digest:await sha256(bytes)};
}

export function caseOverviewCSV(overview){
  const header=['export_schema','mode','case_set_sha256','scope','counting','selected_name','case_sha256','evidence_sha256','review_sha256','configuration_sha256','retained_case_digest_check','module','institution','region','keys','exceptions',...Object.keys(OVERVIEW_OUTCOMES),...Object.keys(OVERVIEW_REVIEWS).map(key=>'review_'+key),'review_entries'];
  const rows=overview.entries.map(({summary:s})=>['bloch.data.case-overview-csv.v1',overview.mode,overview.setDigest,'all_selected_cases_filters_not_applied','case_observations_not_unique_records',s.selected_name,s.case_sha256,s.evidence_sha256,s.review_sha256,s.configuration_sha256,s.retained_case_digest_check,s.module,s.institution,s.region,s.keys,s.exceptions,...Object.keys(OVERVIEW_OUTCOMES).map(k=>s.outcomes[k]),...Object.keys(OVERVIEW_REVIEWS).map(k=>s.review_states[k]),s.review_entries]);
  const safe=value=>{let text=String(value);if(/^\s*[=+\-@]/.test(text))text="'"+text;return '"'+text.replaceAll('"','""')+'"';};
  return [header,...rows].map(row=>row.map(safe).join(',')).join('\r\n')+'\r\n';
}
