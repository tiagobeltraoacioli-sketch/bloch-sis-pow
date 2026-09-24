import test from 'node:test';
import assert from 'node:assert/strict';
import {defaultConfig,MODULES} from '../apps/bloch-data/assets/modules.v1.mjs';
import {samplesFor} from '../apps/bloch-data/assets/samples.v1.mjs';
import {createReport} from '../apps/bloch-data/assets/reconcile.v1.mjs';
import {newReview,appendReview,reviewExport} from '../apps/bloch-data/assets/audit.v1.mjs';
import {buildQueue,selectQueue,queueSummary,queueCSV,defaultQueueFilter,validateQueueFilter} from '../apps/bloch-data/assets/queue.v1.mjs';
const filters=overrides=>({...defaultQueueFilter(),...overrides});
async function fixture(module='cash') {
  const config=defaultConfig(module,'br','bank'),sources=samplesFor(config).map((text,i)=>({text,name:`source-${i}.csv`}));
  const evidence=await createReport(...sources,'synthetic_example',config);
  return {evidence,review:newReview(evidence.digest)};
}
function add(review,evidence,item,state,note='Investigate this discrepancy.',reviewer='Operator A') {
  return appendReview(review,evidence.report,evidence.digest,{record_key:item.key,original_outcome:item.status,state,note,reviewer});
}
for(const module of Object.keys(MODULES))test(`${module}: full-report counts distinguish field changes from missing and duplicate keys`,async()=>{
  const {evidence,review}=await fixture(module),index=buildQueue(evidence.report,review),summary=queueSummary(index);
  assert.equal(summary.keys,8);assert.equal(summary.exceptions,5);assert.equal(summary.reviews.unreviewed,5);
  assert.equal(selectQueue(index,filters({outcome:'review'})).entries.length,5);
  assert.equal(selectQueue(index,filters({review:'not_applicable'})).entries.length,3);
  assert.equal(summary.fields.reduce((n,f)=>n+f.count,0),evidence.report.result.items.filter(i=>i.status==='different').reduce((n,i)=>n+i.differences.length,0));
  for(const {field,count} of summary.fields)assert.equal(selectQueue(index,filters({field})).entries.length,count);
});
test('search folds accents and case only in the queue, combines literal terms and includes the latest annotation',async()=>{
  let {evidence,review}=await fixture();const item=evidence.report.result.items.find(i=>i.status==='different');
  review=add(review,evidence,item,'investigating','Conciliação São Paulo: compare [cutoff].','Álvaro');
  const index=buildQueue(evidence.report,review),before=JSON.stringify(evidence.report);
  assert.equal(selectQueue(index,filters({query:'ALVARO conciliacao sao [cutoff]'})).entries.length,1);
  assert.equal(selectQueue(index,filters({query:'ALVARO absent-token'})).entries.length,0);
  assert.equal(selectQueue(index,filters({query:'.*'})).entries.length,0,'Search is literal, not a regular expression');
  assert.equal(selectQueue(index,filters({query:item.key.at(-1),outcome:'different',review:'investigating',field:item.differences[0]})).entries.length,1);
  assert.equal(selectQueue(index,filters({query:'Álvaro',review:'unreviewed'})).entries.length,0);
  assert.equal(JSON.stringify(evidence.report),before);
});
test('all duplicate source values are searchable, including rows beyond the preview limit',async()=>{
  const {evidence,review}=await fixture(),report=structuredClone(evidence.report),duplicate=report.result.items.find(i=>i.status==='duplicate');
  duplicate.left=Array.from({length:25},(_,i)=>({row:i+2,values:{...duplicate.left[0].values,account:`account-${i}`}}));
  duplicate.left[24].values.reference='HIDDEN-BEYOND-PREVIEW';
  const matches=selectQueue(buildQueue(report,review),filters({query:'hidden-beyond-preview',outcome:'duplicate'}));
  assert.equal(matches.entries.length,1);assert.deepEqual(matches.entries[0].item.key,duplicate.key);
});
test('new journal states and search text replace the previous index without changing comparison counts',async()=>{
  let {evidence,review}=await fixture();const item=evidence.report.result.items.find(i=>i.status==='different');
  review=add(review,evidence,item,'investigating','Old private note.');
  review=add(review,evidence,item,'explained','Replacement explanation.');
  const index=buildQueue(evidence.report,review),summary=queueSummary(index);
  assert.equal(summary.reviews.unreviewed,4);assert.equal(summary.reviews.explained,1);assert.equal(summary.reviews.investigating,0);
  assert.equal(selectQueue(index,filters({query:'Old private'})).entries.length,0);
  assert.equal(selectQueue(index,filters({query:'replacement',review:'explained',outcome:'different'})).entries.length,1);
  assert.equal(evidence.report.result.counts.matched,3);
  assert.equal(selectQueue(index,filters({outcome:'matched',review:'explained'})).entries.length,0);
});
test('follow-up ordering and latest-entry ordering use declared state and sequence, never local time',async()=>{
  let {evidence,review}=await fixture();const items=evidence.report.result.items.filter(i=>i.status!=='matched');
  review=add(review,evidence,items[0],'explained');review=add(review,evidence,items[1],'follow_up');review=add(review,evidence,items[2],'reopened');review=add(review,evidence,items[3],'investigating');
  review.events[0].recorded_at='2099-01-01T00:00:00.000Z';review.events[3].recorded_at='2000-01-01T00:00:00.000Z';
  const index=buildQueue(evidence.report,review);
  assert.deepEqual(selectQueue(index,filters({sort:'follow_up'})).entries.map(e=>e.reviewState),['follow_up','reopened','unreviewed','investigating','explained','not_applicable','not_applicable','not_applicable']);
  assert.equal(selectQueue(index,filters({sort:'latest_review'})).entries[0].latest.sequence,4);
  assert.equal(selectQueue(index,filters({review:'active'})).entries.length,3);
  const sorted=selectQueue(index,filters({sort:'differences'})).entries;
  for(let i=1;i<sorted.length;i++)assert.ok(sorted[i-1].item.differences.length>=sorted[i].item.differences.length);
  assert.deepEqual(selectQueue(index).entries.map(e=>e.index),[0,1,2,3,4,5,6,7]);
});
test('invalid, oversized and ambiguous filters fail closed',()=>{
  for(const f of [null,{},filters({extra:'x'}),filters({query:'x'.repeat(161)}),filters({query:'line\nbreak'}),filters({field:'unknown'}),filters({review:'approved'}),filters({sort:'__proto__'}),filters({outcome:'certified'}),filters({query:[]})])assert.throws(()=>validateQueueFilter(f,['amount']));
  assert.equal(validateQueueFilter(filters({query:'  São  Paulo  '}),['amount']).query,'São  Paulo');
});
test('CSV captures applied filters, exact report/journal digests and all selected pages with stable ordering',async()=>{
  const {evidence,review}=await fixture(),index=buildQueue(evidence.report,review);
  const base=index.entries.find(e=>e.item.status==='different');
  index.entries=Array.from({length:125},(_,i)=>({...base,index:i,item:{...base.item,key:[`key-${i}`]}}));index.keyFields=['record_id'];
  const digest=(await reviewExport(review,evidence.report,evidence.digest)).digest;
  const csv=queueCSV(index,filters({outcome:'different'}),evidence.digest,digest);
  assert.equal(csv.split('\r\n').length,127);assert.ok(csv.includes('"key-124"'));assert.ok(csv.includes(evidence.digest));assert.ok(csv.includes(digest));assert.ok(csv.includes('"bloch.data.queue-csv.v1"'));
  assert.ok(csv.includes('"filter_query","filter_outcome","filter_review","filter_field","sort_order"'));
  assert.throws(()=>queueCSV(index,filters(),evidence.digest,'bad'),/digests/);
});
test('CSV neutralizes formulas in source keys, queries and review text, and escapes quoted multiline notes',async()=>{
  let {evidence,review}=await fixture();const item=evidence.report.result.items.find(i=>i.status==='different');
  review=add(review,evidence,item,'follow_up','=HYPERLINK("x")\nFollow up with "A".','+1+1');
  const index=buildQueue(evidence.report,review),digest=(await reviewExport(review,evidence.report,evidence.digest)).digest;
  const csv=queueCSV(index,filters({query:'=HYPERLINK',review:'follow_up'}),evidence.digest,digest);
  assert.ok(csv.includes('"\'=HYPERLINK"'));assert.ok(csv.includes('"\'+1+1"'));assert.ok(csv.includes('"\'=HYPERLINK(""x"")\nFollow up with ""A""."'));
  const candidate=index.entries.find(e=>e.item.status==='different');candidate.item={...candidate.item,key:['  @FORMULA']};index.keyFields=['record_id'];
  const unfiltered=queueCSV(index,filters({review:'follow_up'}),evidence.digest,digest);assert.ok(unfiltered.includes('"\'  @FORMULA"'));
});
test('empty queues and reports with only matched keys contain no invented exceptions',async()=>{
  const {evidence,review}=await fixture(),report=structuredClone(evidence.report);report.result.items=report.result.items.filter(i=>i.status==='matched');
  const index=buildQueue(report,review),summary=queueSummary(index);
  assert.equal(summary.exceptions,0);assert.deepEqual(summary.fields,[]);assert.equal(Object.values(summary.reviews).reduce((a,b)=>a+b,0),0);
  assert.equal(selectQueue(index,filters({outcome:'review'})).entries.length,0);
});
