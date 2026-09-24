import {latestReviews,REVIEW_STATES} from './audit.v1.mjs';

export const QUEUE_REVIEW_STATES=Object.freeze({unreviewed:'Not reviewed',...REVIEW_STATES,not_applicable:'Matched / no exception'});
export const QUEUE_SORTS=Object.freeze({key:'Record key',follow_up:'Follow-up first',differences:'Most differing fields',latest_review:'Latest journal entry'});
const outcomes=['all','review','matched','different','left_only','right_only','duplicate'];
const reviewStates=['all','active',...Object.keys(QUEUE_REVIEW_STATES)];
const fold=value=>value.normalize('NFKD').replace(/\p{M}/gu,'').toLowerCase();
const priority={follow_up:0,reopened:1,unreviewed:2,investigating:3,explained:4,not_applicable:5};

export function defaultQueueFilter() {return {query:'',outcome:'all',review:'all',field:'',sort:'key'};}
export function validateQueueFilter(input,fields) {
  if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).sort().join(',')!=='field,outcome,query,review,sort')throw new Error('Unsupported queue filter.');
  if(typeof input.query!=='string'||input.query.length>160||/[\u0000-\u001f\u007f]/.test(input.query))throw new Error('Search must be a single line of at most 160 characters.');
  if(!outcomes.includes(input.outcome)||!reviewStates.includes(input.review)||typeof input.field!=='string'||(input.field!==''&&!fields.includes(input.field))||typeof input.sort!=='string'||!Object.hasOwn(QUEUE_SORTS,input.sort))throw new Error('Unknown queue filter value.');
  return {...input,query:input.query.trim()};
}

// Build once per report/journal revision. Search is a presentation-only index;
// no search normalization enters the comparison or evidence rules.
export function buildQueue(report,review) {
  const latest=latestReviews(review);
  const entries=report.result.items.map((item,index)=>{
    const annotation=latest.get(JSON.stringify(item.key))??null;
    const reviewState=item.status==='matched'?'not_applicable':annotation?.state??'unreviewed';
    const values=[...item.key,...[...item.left,...item.right].flatMap(record=>Object.values(record.values)),annotation?.reviewer??'',annotation?.note??''];
    return {item,index,latest:annotation,reviewState,search:fold(values.join('\n'))};
  });
  return {fields:[...report.compared_fields],keyFields:[...report.matching_key],entries};
}

export function selectQueue(index,filter=defaultQueueFilter()) {
  const applied=validateQueueFilter(filter,index.fields),words=fold(applied.query).split(/\s+/u).filter(Boolean);
  const entries=index.entries.filter(entry=>{
    const {item,reviewState}=entry;
    return (applied.outcome==='all'||(applied.outcome==='review'?item.status!=='matched':item.status===applied.outcome))
      &&(applied.review==='all'||(applied.review==='active'?['investigating','follow_up','reopened'].includes(reviewState):reviewState===applied.review))
      &&(!applied.field||item.differences.includes(applied.field))
      &&words.every(word=>entry.search.includes(word));
  });
  entries.sort((a,b)=>{
    let result=0;
    if(applied.sort==='follow_up')result=priority[a.reviewState]-priority[b.reviewState];
    if(applied.sort==='differences')result=b.item.differences.length-a.item.differences.length;
    if(applied.sort==='latest_review')result=(b.latest?.sequence??0)-(a.latest?.sequence??0);
    return result||a.index-b.index;
  });
  return {filter:applied,entries};
}

export function queueSummary(index) {
  const reviews=Object.fromEntries(Object.keys(QUEUE_REVIEW_STATES).filter(state=>state!=='not_applicable').map(state=>[state,0]));
  const fields=new Map();
  let exceptions=0;
  for(const entry of index.entries){
    if(entry.item.status!=='matched'){exceptions++;reviews[entry.reviewState]++;}
    if(entry.item.status==='different')for(const field of new Set(entry.item.differences))fields.set(field,(fields.get(field)??0)+1);
  }
  return {keys:index.entries.length,exceptions,reviews,fields:[...fields].map(([field,count])=>({field,count})).sort((a,b)=>b.count-a.count||index.fields.indexOf(a.field)-index.fields.indexOf(b.field))};
}

// A filtered convenience export, not a replacement for evidence or its journal.
// Formula-like values are neutralized, including values in private review notes.
export function queueCSV(index,filter,evidenceDigest,reviewDigest) {
  if(!/^[0-9a-f]{64}$/.test(evidenceDigest)||!/^[0-9a-f]{64}$/.test(reviewDigest))throw new Error('Queue export requires exact evidence and journal digests.');
  const selection=selectQueue(index,filter),f=selection.filter;
  const safe=value=>{let text=String(value);if(/^[\s]*[=+\-@]/.test(text))text="'"+text;return '"'+text.replaceAll('"','""')+'"';};
  const header=['export_schema','evidence_sha256','review_sha256','filter_query','filter_outcome','filter_review','filter_field','sort_order','original_outcome',...index.keyFields,'differing_fields','source_a_rows','source_b_rows','review_state','latest_review_sequence','reviewer_label_self_declared','recorded_at_local_untrusted','latest_review_note'];
  const rows=selection.entries.map(({item,reviewState,latest})=>[
    'bloch.data.queue-csv.v1',evidenceDigest,reviewDigest,f.query,f.outcome,f.review,f.field,f.sort,item.status,...item.key,item.differences.join(' | '),item.left.map(r=>r.row).join(' | '),item.right.map(r=>r.row).join(' | '),reviewState,latest?.sequence??'',latest?.reviewer??'',latest?.recorded_at??'',latest?.note??''
  ]);
  return [header,...rows].map(row=>row.map(safe).join(',')).join('\r\n')+'\r\n';
}
