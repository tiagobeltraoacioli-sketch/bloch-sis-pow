import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {MODULES,defaultConfig} from '../apps/bloch-data/assets/modules.v1.mjs';
import {samplesFor} from '../apps/bloch-data/assets/samples.v1.mjs';
import {createReport} from '../apps/bloch-data/assets/reconcile.v1.mjs';
import {readExport,verifyEvidence,newReview,appendReview,validateReview,reviewExport,latestReviews,verificationExport,MAX_REVIEW_EVENTS} from '../apps/bloch-data/assets/audit.v1.mjs';
const encode=x=>JSON.stringify(x,null,2)+'\n';
async function fixture(module='cash',region='br') {
  const config=defaultConfig(module,region,'bank'),sources=samplesFor(config).map((text,i)=>({name:`source-${i}.csv`,text}));
  const evidence=await createReport(...sources,'local_files',config);
  return {sources,evidence};
}
function entry(report,state='investigating') {
  const item=report.result.items.find(item=>item.status!=='matched');
  return {record_key:item.key,original_outcome:item.status,state,reviewer:'Operator A',note:'Investigate the source discrepancy.'};
}
for(const module of Object.keys(MODULES))test(`${module}: exported evidence independently recomputes with retained digest`,async()=>{
  const {sources,evidence}=await fixture(module);
  const verified=await verifyEvidence(evidence.bytes,...sources,evidence.digest);
  assert.equal(verified.pinned,true);assert.equal(verified.bytes,evidence.bytes);assert.deepEqual(verified.report,evidence.report);
});
test('renamed retained files are allowed; exact raw bytes, BOM and source order matter',async()=>{
  const {sources}=await fixture();sources[0].text='\uFEFF'+sources[0].text;
  const evidence=await createReport(...sources,'local_files',defaultConfig('cash','br','bank'));
  assert.equal((await verifyEvidence(evidence.bytes,...sources.map(s=>({...s,name:'renamed.csv'})))).pinned,false);
  await assert.rejects(verifyEvidence(evidence.bytes,...[...sources].reverse()),/Source bytes/);
  await assert.rejects(verifyEvidence(evidence.bytes,{...sources[0],text:sources[0].text.slice(1)},sources[1]),/Source bytes/);
  await assert.rejects(verifyEvidence(evidence.bytes,...sources,'0'.repeat(64)),/retained SHA/);
});
test('changed outcomes, row references, configuration, rules and assurances fail',async()=>{
  const {sources,evidence}=await fixture();
  const edits=[
    r=>r.result.counts.matched++,r=>r.result.items[0].left[0].row++,
    r=>r.result.items[0].left[0].values.amount='123',r=>r.rules.tolerance='1',
    r=>r.assurance.auditor_signature='verified',r=>r.configuration.unexpected=true,
    r=>r.extra='unexpected',r=>r.sources[0].side='B',r=>r.generated_at='2026-02-30T00:00:00.000Z',
    r=>r.mode='certified',r=>r.rule_version='future.v9'
  ];
  for(const edit of edits){const report=structuredClone(evidence.report);edit(report);await assert.rejects(verifyEvidence(encode(report),...sources));}
});
test('reformatted, duplicate-key, non-finite and over-limit JSON fails closed',()=>{
  assert.throws(()=>readExport('{"x":1}'),/original workbench/);
  assert.throws(()=>readExport('{\n  "x": 1,\n  "x": 2\n}\n'),/original workbench/);
  assert.throws(()=>readExport('{\n  "x": 1e999\n}\n'),/original workbench/);
  assert.throws(()=>readExport('null\n',3),/size limit/);
});
test('no retained digest means consistency only; replacing coherent metadata remains detectable with a pin',async()=>{
  const {sources,evidence}=await fixture(),report=structuredClone(evidence.report);
  report.configuration.purpose='Another declared purpose';report.generated_at='2026-01-01T00:00:00.000Z';
  const verified=await verifyEvidence(encode(report),...sources);
  assert.equal(verified.pinned,false);
  await assert.rejects(verifyEvidence(encode(report),...sources,evidence.digest),/retained SHA/);
});
test('review history appends without changing the evidence; latest state is explicit',async()=>{
  const {evidence}=await fixture(),original=encode(evidence.report),empty=newReview(evidence.digest);
  const first=appendReview(empty,evidence.report,evidence.digest,entry(evidence.report));
  const next=appendReview(first,evidence.report,evidence.digest,{...entry(evidence.report,'explained'),note:'Statement cutoff explains the difference.\nCompare again after the next extract.'});
  assert.equal(empty.events.length,0);assert.equal(first.events.length,1);assert.equal(next.events.length,2);
  assert.equal(latestReviews(next).values().next().value.state,'explained');assert.equal(encode(evidence.report),original);
  const output=await reviewExport(next,evidence.report,evidence.digest);
  assert.equal(output.digest,createHash('sha256').update(output.bytes).digest('hex'));
  assert.deepEqual(validateReview(readExport(output.bytes),evidence.report,evidence.digest),next);
});
test('reviews reject another report, matched or unknown keys, fake assurances and changed sequences',async()=>{
  const {evidence}=await fixture();
  const journal=appendReview(newReview(evidence.digest),evidence.report,evidence.digest,entry(evidence.report));
  const edits=[r=>r.evidence_sha256='0'.repeat(64),r=>r.events[0].sequence=9,r=>r.events[0].state='approved',r=>r.events[0].record_key=['unknown'],r=>r.events[0].original_outcome='matched',r=>r.events[0].reviewer='',r=>r.events[0].note=' ',r=>r.events[0].note='\u0000',r=>r.events[0].note='x'.repeat(2001),r=>r.events[0].recorded_at='tomorrow',r=>r.events[0].extra='secret',r=>r.approval='authorized',r=>r.extra='bad'];
  for(const edit of edits){const next=structuredClone(journal);edit(next);assert.throws(()=>validateReview(next,evidence.report,evidence.digest));}
  const matched=evidence.report.result.items.find(i=>i.status==='matched');
  assert.throws(()=>appendReview(journal,evidence.report,evidence.digest,{...entry(evidence.report),record_key:matched.key,original_outcome:'matched'}),/exception/);
});
test('review event bound is enforced and user-provided text stays literal',async()=>{
  const {evidence}=await fixture(),input={...entry(evidence.report),reviewer:'<img src=x>',note:'=SUM(A1:A5) <script>alert(1)</script>'};
  const journal=appendReview(newReview(evidence.digest),evidence.report,evidence.digest,input);
  assert.equal(journal.events[0].reviewer,input.reviewer);assert.equal(journal.events[0].note,input.note);
  const many={...journal,events:Array.from({length:MAX_REVIEW_EVENTS},(_,i)=>({...journal.events[0],sequence:i+1}))};
  assert.equal(validateReview(many,evidence.report,evidence.digest).events.length,MAX_REVIEW_EVENTS);
  assert.throws(()=>appendReview(many,evidence.report,evidence.digest,input),/at most 1000/);
});
test('verification receipt separates consistency from authenticity and binds the optional journal',async()=>{
  const {evidence,sources}=await fixture(),verified=await verifyEvidence(evidence.bytes,...sources,evidence.digest);
  const journal=appendReview(newReview(evidence.digest),evidence.report,evidence.digest,entry(evidence.report));
  const output=await verificationExport(verified,journal),receipt=readExport(output.bytes);
  assert.equal(receipt.retained_digest_check,'matched');assert.equal(receipt.review.events,1);
  assert.equal(receipt.review.sha256,(await reviewExport(journal,evidence.report,evidence.digest)).digest);
  assert.equal(receipt.assurance.scope,'local_consistency_only');assert.equal(receipt.assurance.rollback_protection,'absent');assert.equal(receipt.assurance.onchain,'not_verified');
  assert.equal((readExport((await verificationExport(verified)).bytes)).review,null);
});
