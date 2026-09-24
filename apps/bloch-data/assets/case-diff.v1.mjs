import {verifyCaseFile} from './case-file.v1.mjs';
import {sha256} from './reconcile.v1.mjs';

export const CHANGE_LABELS=Object.freeze({added:'Added keys',removed:'Removed keys',changed:'Changed records',review_only:'Review changes only',unchanged:'Unchanged'});
export const OUTCOME_LABELS=Object.freeze({matched:'Matched',different:'Different fields',left_only:'Only in A',right_only:'Only in B',duplicate:'Duplicate key',absent:'Absent'});
const encode=value=>JSON.stringify(value,null,2)+'\n';
const stable=value=>Array.isArray(value)?'['+value.map(stable).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+stable(value[k])).join(',')+'}':JSON.stringify(value);
const equal=(a,b)=>stable(a)===stable(b);
const bag=values=>values.map(value=>JSON.stringify(value)).sort();
const fold=text=>text.normalize('NFKD').replace(/\p{M}/gu,'').toLowerCase();
function historyByKey(review) {
  const result=new Map();
  for(const event of review.events){const key=JSON.stringify(event.record_key);if(!result.has(key))result.set(key,[]);result.get(key).push(event);}
  return result;
}
function historyContent(events) {
  // A sequence number orders the whole journal. Inserting an event for another
  // key may renumber this key without changing its own ordered annotations.
  return events.map(({state,reviewer,note,recorded_at,original_outcome})=>({state,reviewer,note,recorded_at,original_outcome}));
}
function sideChanges(before,after,side,fields) {
  const a=before?.[side]??[],b=after?.[side]??[];
  const values=records=>bag(records.map(record=>fields.map(field=>record.values[field])));
  const changed=!equal(values(a),values(b));
  const changedFields=fields.filter(field=>!equal(bag(a.map(r=>r.values[field])),bag(b.map(r=>r.values[field]))));
  const references=records=>bag(records.map(r=>[r.row,...fields.map(field=>r.values[field])]));
  return {records_changed:changed,fields:changedFields,row_references_moved:!changed&&!equal(references(a),references(b))};
}
function snapshot(verified) {
  return {case_sha256:verified.digest,evidence_sha256:verified.evidence.digest,review_sha256:verified.caseFile.review_sha256,retained_case_digest_check:verified.pinned?'matched':'not_provided',case_created_at:verified.caseFile.created_at,evidence_generated_at:verified.evidence.report.generated_at,source_sha256:verified.evidence.report.sources.map(source=>source.sha256)};
}

export async function compareCaseFiles(baselineText,candidateText,baselinePin='',candidatePin='') {
  // Verify separately, without inferring chronology or source authority from a
  // filename, timestamp, journal sequence or an internal checksum.
  const baseline=await verifyCaseFile(baselineText,baselinePin);
  const candidate=await verifyCaseFile(candidateText,candidatePin);
  const a=baseline.evidence.report,b=candidate.evidence.report;
  if(a.mode!==b.mode)throw new Error('Synthetic examples and local-file cases cannot be compared together.');
  if(a.rule_version!==b.rule_version||!equal(a.configuration,b.configuration)||!equal(a.matching_key,b.matching_key)||!equal(a.compared_fields,b.compared_fields)||!equal(a.rules,b.rules))throw new Error('Case comparison requires the same module, matching rules and complete applied configuration.');
  const left=new Map(a.result.items.map(item=>[JSON.stringify(item.key),item])),right=new Map(b.result.items.map(item=>[JSON.stringify(item.key),item]));
  const oldHistory=historyByKey(baseline.review),newHistory=historyByKey(candidate.review);
  const counts=Object.fromEntries(Object.keys(CHANGE_LABELS).map(key=>[key,0]));
  const transitions=Object.fromEntries(Object.keys(OUTCOME_LABELS).map(from=>[from,Object.fromEntries(Object.keys(OUTCOME_LABELS).map(to=>[to,0]))]));
  let moved=0,reviewChanges=0;
  const items=[...new Set([...left.keys(),...right.keys()])].sort().map(key=>{
    const before=left.get(key)??null,after=right.get(key)??null;
    const beforeReview=oldHistory.get(key)??[],afterReview=newHistory.get(key)??[];
    const sourceChanges={A:sideChanges(before,after,'left',a.compared_fields),B:sideChanges(before,after,'right',a.compared_fields)};
    const reviewChanged=!equal(historyContent(beforeReview),historyContent(afterReview));
    const outcomeChanged=before?.status!==after?.status;
    const category=!before?'added':!after?'removed':sourceChanges.A.records_changed||sourceChanges.B.records_changed||outcomeChanged?'changed':reviewChanged?'review_only':'unchanged';
    const rowsMoved=sourceChanges.A.row_references_moved||sourceChanges.B.row_references_moved;
    counts[category]++;transitions[before?.status??'absent'][after?.status??'absent']++;if(rowsMoved)moved++;if(reviewChanged)reviewChanges++;
    return {key:JSON.parse(key),category,before_outcome:before?.status??'absent',after_outcome:after?.status??'absent',source_changes:sourceChanges,review_changed:reviewChanged,row_references_moved:rowsMoved,before,after,before_review:beforeReview,after_review:afterReview};
  });
  const oldSnapshot=snapshot(baseline),newSnapshot=snapshot(candidate);
  const report={schema:'bloch.data.case-comparison.v1',generated_at:new Date().toISOString(),clock_source:'local_browser_untrusted',ordering:'user_selected_baseline_and_candidate',module:a.configuration.module,mode:a.mode,configuration:a.configuration,matching_key:a.matching_key,compared_fields:a.compared_fields,baseline:oldSnapshot,candidate:newSnapshot,
    snapshot_changes:{case_bytes:baseline.digest!==candidate.digest,evidence_bytes:baseline.evidence.digest!==candidate.evidence.digest,review_bytes:oldSnapshot.review_sha256!==newSnapshot.review_sha256,source_bytes:{A:oldSnapshot.source_sha256[0]!==newSnapshot.source_sha256[0],B:oldSnapshot.source_sha256[1]!==newSnapshot.source_sha256[1]}},
    comparison_rules:{matching:'exact_composite_key',source_sides:'A_to_A_and_B_to_B',records:'multiset_of_all_normalized_fields',duplicates:'retain_multiplicity_no_pairing',field_changes:'per_side_value_multiset',row_references:'reported_separately_when_values_agree',review:'ordered_per_key_history_ignoring_global_sequence',timestamps:'compared_as_declared_text_not_trusted_time',renamed_keys:'removed_plus_added',automatic_review_transfer:false},
    key_count:items.length,counts,review_changed_keys:reviewChanges,row_reference_moved_keys:moved,transitions,items,
    assurance:{scope:'local_snapshot_comparison_only',chronology:'not_verified',source_authentication:'not_verified',source_scope_alignment:'operator_responsibility',reviewer_identity:'not_verified',auditor_signature:'absent',rollback_protection:'absent',settlement:'not_determined',onchain:'not_verified',regulatory_compliance:'not_certified'}};
  const bytes=encode(report);return {report,bytes,digest:await sha256(bytes),baseline,candidate};
}

export function defaultDiffFilter() {return {query:'',category:'all',before:'all',after:'all'};}
export function selectChanges(report,filter=defaultDiffFilter()) {
  const keys=['query','category','before','after'];
  if(!filter||Object.keys(filter).length!==keys.length||!keys.every(key=>Object.hasOwn(filter,key))||typeof filter.query!=='string'||filter.query.length>160||/[\u0000-\u001f\u007f]/.test(filter.query)||!['all','changes',...Object.keys(CHANGE_LABELS)].includes(filter.category)||!['all',...Object.keys(OUTCOME_LABELS)].includes(filter.before)||!['all',...Object.keys(OUTCOME_LABELS)].includes(filter.after))throw new Error('Invalid case-comparison filter.');
  const words=fold(filter.query).trim().split(/\s+/u).filter(Boolean);
  return report.items.filter(item=>(filter.category==='all'||(filter.category==='changes'?item.category!=='unchanged':item.category===filter.category))&&(filter.before==='all'||filter.before===item.before_outcome)&&(filter.after==='all'||filter.after===item.after_outcome)&&words.every(word=>fold(item.key.join('\n')).includes(word)));
}

export function caseComparisonCSV(report) {
  const safe=value=>{let text=String(value);if(/^[\s]*[=+\-@]/.test(text))text="'"+text;return '"'+text.replaceAll('"','""')+'"';};
  const header=['export_schema','baseline_case_sha256','candidate_case_sha256','category',...report.matching_key,'baseline_outcome','candidate_outcome','source_a_changed_fields','source_b_changed_fields','source_a_records_changed','source_b_records_changed','review_history_changed','row_references_moved','baseline_latest_review_state','candidate_latest_review_state'];
  const rows=report.items.map(item=>['bloch.data.case-comparison-csv.v1',report.baseline.case_sha256,report.candidate.case_sha256,item.category,...item.key,item.before_outcome,item.after_outcome,item.source_changes.A.fields.join(' | '),item.source_changes.B.fields.join(' | '),item.source_changes.A.records_changed,item.source_changes.B.records_changed,item.review_changed,item.row_references_moved,item.before_review.at(-1)?.state??'',item.after_review.at(-1)?.state??'']);
  return [header,...rows].map(row=>row.map(safe).join(',')).join('\r\n')+'\r\n';
}
