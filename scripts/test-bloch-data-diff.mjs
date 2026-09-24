import test from 'node:test';
import assert from 'node:assert/strict';
import {MODULES,defaultConfig,getModule} from '../apps/bloch-data/assets/modules.v1.mjs';
import {samplesFor} from '../apps/bloch-data/assets/samples.v1.mjs';
import {parseCSV,createReport,sha256} from '../apps/bloch-data/assets/reconcile.v1.mjs';
import {newReview,appendReview} from '../apps/bloch-data/assets/audit.v1.mjs';
import {createCaseFile} from '../apps/bloch-data/assets/case-file.v1.mjs';
import {exampleCasePair} from '../apps/bloch-data/assets/diff-samples.v1.mjs';
import {compareCaseFiles,selectChanges,defaultDiffFilter,caseComparisonCSV} from '../apps/bloch-data/assets/case-diff.v1.mjs';
const config=defaultConfig('cash','global','bank');
const records=c=>samplesFor(c).map(text=>parseCSV(text,c).map(row=>row.values));
async function makeCase(books=records(config),configuration=config,mode='local_files') {
  const fields=getModule(configuration.module).fields;
  const csv=rows=>[fields,...rows.map(row=>fields.map(field=>row[field]))].map(row=>row.map(value=>'"'+value.replaceAll('"','""')+'"').join(configuration.separator)).join('\n')+'\n';
  const sources=books.map((rows,i)=>({name:`book-${i}.csv`,text:csv(rows)}));
  const evidence=await createReport(...sources,mode,configuration),review=newReview(evidence.digest),output=await createCaseFile(evidence.bytes,...sources,review);
  return {sources,evidence,review,output};
}
const filters=values=>({...defaultDiffFilter(),...values});
for(const module of Object.keys(MODULES))test(`${module}: identical verified cases retain every key without changes`,async()=>{
  const c=defaultConfig(module,'global','bank'),{output}=await makeCase(records(c),c),diff=await compareCaseFiles(output.bytes,output.bytes,output.digest,output.digest);
  assert.deepEqual(diff.report.counts,{added:0,removed:0,changed:0,review_only:0,unchanged:8});
  assert.equal(diff.report.baseline.retained_case_digest_check,'matched');assert.equal(diff.report.candidate.retained_case_digest_check,'matched');
  assert.equal(diff.report.snapshot_changes.case_bytes,false);assert.equal(diff.report.row_reference_moved_keys,0);assert.equal(diff.digest,await sha256(diff.bytes));
});
test('synthetic comparison has additions, removals, source changes and a separate review-only change',async()=>{
  const diff=await compareCaseFiles(...await exampleCasePair());
  assert.deepEqual(diff.report.counts,{added:1,removed:1,changed:3,review_only:1,unchanged:3});assert.equal(diff.report.key_count,9);
  assert.equal(diff.report.transitions.matched.different,1);assert.equal(diff.report.transitions.different.matched,1);assert.equal(diff.report.transitions.left_only.matched,1);
  assert.equal(diff.report.transitions.absent.matched,1);assert.equal(diff.report.transitions.matched.absent,1);
  assert.equal(Object.values(diff.report.transitions).flatMap(Object.values).reduce((a,b)=>a+b,0),9);
});
test('row reordering changes byte identity and row references, not normalized record categories',async()=>{
  const books=records(config),before=await makeCase(books),after=await makeCase(books.map(rows=>[...rows].reverse())),diff=await compareCaseFiles(before.output.bytes,after.output.bytes);
  assert.equal(diff.report.counts.unchanged,8);assert.equal(diff.report.counts.changed,0);assert.ok(diff.report.row_reference_moved_keys>0);
  assert.deepEqual(diff.report.snapshot_changes.source_bytes,{A:true,B:true});
});
test('duplicate record combinations differ even when each field multiset agrees',async()=>{
  const row=records(config)[0][0],a={...row,amount:'100',reference:'REF-A'},b={...row,amount:'200',reference:'REF-B'};
  const before=await makeCase([[a,b],[a]]),after=await makeCase([[{...a,reference:'REF-B'},{...b,reference:'REF-A'}],[a]]);
  const item=(await compareCaseFiles(before.output.bytes,after.output.bytes)).report.items[0];
  assert.equal(item.category,'changed');assert.equal(item.before_outcome,'duplicate');assert.equal(item.after_outcome,'duplicate');assert.equal(item.source_changes.A.records_changed,true);assert.deepEqual(item.source_changes.A.fields,[]);
});
test('duplicate multiplicity and exact fractional amount changes are preserved',async()=>{
  const row=records(config)[0][0],before=await makeCase([[row,row],[row]]),after=await makeCase([[row,row,row],[row]]);
  assert.equal((await compareCaseFiles(before.output.bytes,after.output.bytes)).report.counts.changed,1);
  const precise={...row,amount:'9007199254740993.00000001'},a=await makeCase([[precise],[precise]]),b=await makeCase([[{...precise,amount:'9007199254740993.00000002'}],[precise]]);
  const item=(await compareCaseFiles(a.output.bytes,b.output.bytes)).report.items[0];assert.deepEqual(item.source_changes.A.fields,['amount']);assert.equal(item.after.left[0].values.amount,'9007199254740993.00000002');
});
test('a changed composite key is removal plus addition, never a guessed continuation',async()=>{
  const row=records(config)[0][0],renamed={...row,entry_id:'RENAMED'},before=await makeCase([[row],[row]]),after=await makeCase([[renamed],[renamed]]);
  assert.deepEqual((await compareCaseFiles(before.output.bytes,after.output.bytes)).report.counts,{added:1,removed:1,changed:0,review_only:0,unchanged:0});
});
function annotate(fixture,items) {
  let journal=fixture.review;
  for(const [item,note] of items){journal=appendReview(journal,fixture.evidence.report,fixture.evidence.digest,{record_key:item.key,original_outcome:item.status,state:'investigating',reviewer:'LOCAL LABEL',note});journal.events.at(-1).recorded_at='2026-09-24T12:00:00.000Z';}
  return journal;
}
test('earlier review history changes are detected even when the latest annotation is identical',async()=>{
  const f=await makeCase(),item=f.evidence.report.result.items.find(i=>i.status==='different');
  const old=annotate(f,[[item,'Original explanation'],[item,'Latest note']]),updated=annotate(f,[[item,'Changed earlier explanation'],[item,'Latest note']]);
  const a=await createCaseFile(f.evidence.bytes,...f.sources,old),b=await createCaseFile(f.evidence.bytes,...f.sources,updated),diff=await compareCaseFiles(a.bytes,b.bytes);
  assert.equal(diff.report.counts.review_only,1);assert.equal(diff.report.counts.changed,0);assert.equal(diff.report.items.filter(i=>i.review_changed).length,1);
});
test('global journal renumbering leaves each unchanged ordered key history intact',async()=>{
  const f=await makeCase(),[a,b]=f.evidence.report.result.items.filter(i=>i.status==='different');
  const old=annotate(f,[[a,'A first'],[b,'B first'],[a,'A second']]),next=annotate(f,[[b,'B first'],[a,'A first'],[a,'A second']]);
  const before=await createCaseFile(f.evidence.bytes,...f.sources,old),after=await createCaseFile(f.evidence.bytes,...f.sources,next),diff=await compareCaseFiles(before.bytes,after.bytes);
  assert.equal(diff.report.counts.unchanged,8);assert.equal(diff.report.snapshot_changes.review_bytes,true);assert.equal(diff.report.review_changed_keys,0);
});
test('dropped review entries are visible without asserting which snapshot is chronologically newer',async()=>{
  const f=await makeCase(),item=f.evidence.report.result.items.find(i=>i.status==='different'),journal=annotate(f,[[item,'Retained note']]);
  const withNote=await createCaseFile(f.evidence.bytes,...f.sources,journal),diff=await compareCaseFiles(withNote.bytes,f.output.bytes);
  const changed=diff.report.items.find(i=>i.category==='review_only');assert.equal(changed.before_review.length,1);assert.equal(changed.after_review.length,0);
  assert.equal(diff.report.assurance.chronology,'not_verified');assert.equal(diff.report.assurance.rollback_protection,'absent');assert.equal(diff.report.comparison_rules.automatic_review_transfer,false);
});
test('incompatible configurations, modules and synthetic/local modes cannot be compared',async()=>{
  const a=await makeCase(),differentPurpose=await makeCase(records(config),{...config,purpose:'Another purpose'}),synthetic=await makeCase(records(config),config,'synthetic_example');
  const c=defaultConfig('positions','global','bank'),positions=await makeCase(records(c),c);
  await assert.rejects(compareCaseFiles(a.output.bytes,differentPurpose.output.bytes),/configuration/);await assert.rejects(compareCaseFiles(a.output.bytes,positions.output.bytes),/module/);await assert.rejects(compareCaseFiles(a.output.bytes,synthetic.output.bytes),/cannot be compared/);
});
test('each case and each retained digest must verify before a delta is returned',async()=>{
  const f=await makeCase(),tampered=JSON.parse(f.output.bytes);tampered.components[1].content+='changed';
  await assert.rejects(compareCaseFiles(f.output.bytes,JSON.stringify(tampered,null,2)+'\n'),/mismatch/);
  await assert.rejects(compareCaseFiles(f.output.bytes,f.output.bytes,'0'.repeat(64)),/retained SHA/);
  await assert.rejects(compareCaseFiles(f.output.bytes,f.output.bytes,'','0'.repeat(64)),/retained SHA/);
});
test('category, outcome-transition and literal key search filters combine without mutating the comparison',async()=>{
  const diff=await compareCaseFiles(...await exampleCasePair()),bytes=JSON.stringify(diff.report);
  assert.equal(selectChanges(diff.report,filters({category:'changes'})).length,6);
  assert.equal(selectChanges(diff.report,filters({before:'matched',after:'different'})).length,1);
  assert.equal(selectChanges(diff.report,filters({query:'demo-new',category:'added',before:'absent'})).length,1);
  assert.equal(selectChanges(diff.report,filters({query:'.*'})).length,0);
  for(const filter of [filters({category:'approved'}),filters({query:'x'.repeat(161)}),filters({after:'unknown'}),filters({extra:true})])assert.throws(()=>selectChanges(diff.report,filter),/Invalid/);
  assert.equal(JSON.stringify(diff.report),bytes);
});
test('CSV exports the full union with both case bindings and neutralizes formula-like keys',async()=>{
  const row={...records(config)[0][0],entry_id:'=1+1'},f=await makeCase([[row],[row]]),diff=await compareCaseFiles(f.output.bytes,f.output.bytes),csv=caseComparisonCSV(diff.report);
  assert.ok(csv.includes('"\'=1+1"'));assert.ok(csv.includes(f.output.digest));assert.ok(csv.includes('"baseline_case_sha256","candidate_case_sha256"'));
  assert.equal(csv.split('\r\n').length,3);
});
