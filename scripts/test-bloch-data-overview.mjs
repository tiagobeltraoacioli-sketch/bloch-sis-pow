import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {defaultConfig,MODULES} from '../apps/bloch-data/assets/modules.v1.mjs';
import {samplesFor} from '../apps/bloch-data/assets/samples.v1.mjs';
import {createReport,sha256} from '../apps/bloch-data/assets/reconcile.v1.mjs';
import {newReview,appendReview} from '../apps/bloch-data/assets/audit.v1.mjs';
import {createCaseFile,MAX_CASE_BYTES} from '../apps/bloch-data/assets/case-file.v1.mjs';
import {buildCaseOverview,selectOverview,overviewTotals,caseOverviewExport,caseOverviewCSV,validateOverviewSelection,MAX_OVERVIEW_BYTES,defaultOverviewFilter} from '../apps/bloch-data/assets/case-overview.v1.mjs';
import {overviewExample} from '../apps/bloch-data/assets/overview-samples.v1.mjs';
const encode=value=>JSON.stringify(value,null,2)+'\n';
async function fixture(module='cash',mode='local_files',region='br',singleMatch=false){
  const config=defaultConfig(module,region,'bank'),sources=samplesFor(config).map((text,index)=>({name:`private-source-${index}.csv`,text:singleMatch?samplesFor(config)[0].split('\n').slice(0,2).join('\n')+'\n':text}));
  const evidence=await createReport(...sources,mode,config);let review=newReview(evidence.digest);
  if(!singleMatch){const items=evidence.report.result.items.filter(item=>item.status!=='matched');
    for(const [index,state] of [[0,'investigating'],[1,'follow_up'],[0,'explained'],[2,'reopened']])review=appendReview(review,evidence.report,evidence.digest,{record_key:items[index].key,original_outcome:items[index].status,state,reviewer:'Private reviewer sentinel',note:'Private note sentinel <script>alert(1)</script>'});
  }
  const output=await createCaseFile(evidence.bytes,...sources,review);
  return {input:{name:`${module}.bloch.json`,text:output.bytes,expectedDigest:output.digest},output,evidence,review,sources};
}
for(const module of Object.keys(MODULES))test(`${module}: overview counts recomputed outcomes and latest exception states`,async()=>{
  const f=await fixture(module),overview=await buildCaseOverview([f.input]),s=overview.entries[0].summary;
  assert.equal(s.keys,8);assert.equal(s.exceptions,5);assert.deepEqual(s.outcomes,{matched:3,different:2,left_only:1,right_only:1,duplicate:1});
  assert.deepEqual(s.review_states,{unreviewed:2,investigating:0,explained:1,follow_up:1,reopened:1});assert.equal(s.review_entries,4);assert.equal(s.active_reviews,2);
  assert.equal(s.module,module);assert.equal(s.region,'br');assert.equal(s.retained_case_digest_check,'matched');assert.equal(s.case_sha256,f.output.digest);assert.equal(s.evidence_sha256,f.evidence.digest);
  assert.equal(overview.entries[0].text,f.input.text);assert.equal(overview.entries[0].verified.evidence.bytes,f.evidence.bytes);assert.deepEqual(overview.entries[0].verified.review,f.review);
});
test('fully matched cases have no invented exceptions or review progress',async()=>{
  const f=await fixture('cash','local_files','global',true),overview=await buildCaseOverview([f.input]);assert.equal(overview.entries[0].summary.keys,1);assert.equal(overview.entries[0].summary.exceptions,0);assert.equal(overviewTotals(overview.entries).review_states.unreviewed,0);
});
test('mixed module/region counts sum observations without adding financial amounts',async()=>{
  const a=await fixture('cash'),b=await fixture('positions','local_files','mx'),overview=await buildCaseOverview([a.input,b.input]),total=overviewTotals(overview.entries);
  assert.equal(total.cases,2);assert.equal(total.keys,16);assert.equal(total.exceptions,10);assert.equal(total.outcomes.matched,6);assert.equal(total.review_states.explained,2);
  const output=await caseOverviewExport(overview);assert.equal(output.value.assurance.amounts,'not_aggregated');assert.equal(output.value.assurance.counting,'sum_of_case_observations_not_unique_records');
});
test('all files must verify before returning a collection, including a malformed later case',async()=>{
  const a=await fixture(),b=await fixture('positions');const value=JSON.parse(b.input.text);value.components[1].content+=' ';
  await assert.rejects(buildCaseOverview([a.input,{name:'invalid.json',text:encode(value)}]),/mismatch/);
});
test('each independent case pin gates verification and is reported separately',async()=>{
  const a=await fixture(),b=await fixture('positions');const inputs=[a.input,{...b.input,expectedDigest:''}],overview=await buildCaseOverview(inputs);
  assert.deepEqual(overview.entries.map(e=>e.summary.retained_case_digest_check),['matched','not_provided']);
  await assert.rejects(buildCaseOverview([a.input,{...b.input,expectedDigest:'0'.repeat(64)}]),/does not match/);
  await assert.rejects(buildCaseOverview([{...a.input,expectedDigest:'bad'}]),/Independent case references/);
});
test('duplicate whole cases and alternate review snapshots of one exact report are rejected',async()=>{
  const f=await fixture();await assert.rejects(buildCaseOverview([f.input,{...f.input,name:'renamed.json'}]),/same case/);
  const alternative=await createCaseFile(f.evidence.bytes,...f.sources,newReview(f.evidence.digest));assert.notEqual(alternative.digest,f.output.digest);
  await assert.rejects(buildCaseOverview([f.input,{name:'alternative.json',text:alternative.bytes}]),/same evidence/);
});
test('synthetic and local-file cases cannot be combined',async()=>{
  const a=await fixture(),b=await fixture('positions','synthetic_example');await assert.rejects(buildCaseOverview([a.input,b.input]),/separate overviews/);
});
test('module, region and active/unreviewed filters combine without mutating snapshots',async()=>{
  const a=await fixture(),b=await fixture('positions','local_files','mx'),overview=await buildCaseOverview([a.input,b.input]),before=JSON.stringify(overview.entries.map(e=>e.summary));
  assert.equal(selectOverview(overview).length,2);assert.equal(selectOverview(overview,{module:'positions',region:'mx',review:'active'}).length,1);
  assert.equal(selectOverview(overview,{module:'positions',region:'br',review:'unreviewed'}).length,0);assert.equal(overviewTotals([]).keys,0);
  assert.equal(JSON.stringify(overview.entries.map(e=>e.summary)),before);assert.deepEqual(defaultOverviewFilter(),{module:'all',region:'all',review:'all'});
});
test('invalid filter fields and types fail closed',async()=>{
  const overview=await buildCaseOverview([(await fixture()).input]);
  for(const filter of [null,[],{}, {...defaultOverviewFilter(),extra:true},{...defaultOverviewFilter(),module:'bad'},{...defaultOverviewFilter(),module:['cash']},{...defaultOverviewFilter(),region:'__proto__'},{...defaultOverviewFilter(),review:'approved'}])assert.throws(()=>selectOverview(overview,filter),/Unsupported/);
});
test('case-set identity is independent of selection order while rows preserve that order',async()=>{
  const a=await fixture(),b=await fixture('positions'),one=await buildCaseOverview([a.input,b.input]),two=await buildCaseOverview([b.input,a.input]);
  assert.equal(one.setDigest,two.setDigest);assert.equal(one.setDigest,await sha256(encode([a.output.digest,b.output.digest].sort())));assert.equal(two.entries[0].summary.case_sha256,b.output.digest);
  assert.notEqual(one.setDigest,(await buildCaseOverview([a.input])).setDigest);
});
test('summary exports include all cases, exact references and counts but no records or private notes',async()=>{
  const a=await fixture(),b=await fixture('positions'),overview=await buildCaseOverview([a.input,b.input]);selectOverview(overview,{module:'cash',region:'all',review:'all'});
  const output=await caseOverviewExport(overview);assert.equal(output.value.cases.length,2);assert.equal(output.value.scope,'all_selected_cases_filters_not_applied');assert.equal(output.digest,createHash('sha256').update(output.bytes).digest('hex'));
  for(const text of ['Private reviewer sentinel','Private note sentinel','private-source-','record_key','source-a.csv','"components"'])assert.equal(output.bytes.includes(text),false,text);
  assert.equal(output.value.cases[0].review_sha256,a.output.caseFile.review_sha256);assert.equal(output.value.assurance.encryption,'none');assert.equal(output.value.assurance.regulatory_compliance,'not_certified');
});
test('CSV preserves full selection and neutralizes formula-like filenames',async()=>{
  const a=await fixture(),overview=await buildCaseOverview([{...a.input,name:' =SUM(1,2).bloch.json'}]),csv=caseOverviewCSV(overview);
  assert.ok(csv.includes('"\' =SUM(1,2).bloch.json"'));assert.ok(csv.includes(a.output.digest));assert.ok(csv.includes('all_selected_cases_filters_not_applied'));assert.equal(csv.split('\r\n').length,3);assert.equal(csv.includes('Private note sentinel'),false);
});
test('file count, individual/combined bytes, names and invalid Unicode are bounded',async()=>{
  for(const files of [[],Array.from({length:13},()=>({name:'x',size:1})),[{name:'x',size:0}],[{name:'x',size:MAX_CASE_BYTES+1}],[{name:'a',size:MAX_CASE_BYTES},{name:'b',size:MAX_CASE_BYTES}],[{name:'bad\nname',size:1}],[{name:'x'.repeat(256),size:1}],[{name:'\ud800',size:1}],[{name:'x',size:1.5}]])assert.throws(()=>validateOverviewSelection(files));
  assert.equal(validateOverviewSelection([{name:'a',size:MAX_CASE_BYTES},{name:'b',size:MAX_OVERVIEW_BYTES-MAX_CASE_BYTES}]),MAX_OVERVIEW_BYTES);
  await assert.rejects(buildCaseOverview([{name:'x',text:'\ud800'}]),/valid UTF-8/);await assert.rejects(buildCaseOverview([{name:'x',text:'x'.repeat(MAX_CASE_BYTES+1)}]),/64 MiB/);
});
test('caller mutation during asynchronous verification cannot replace the input snapshots',async()=>{
  const f=await fixture(),inputs=[{...f.input}],pending=buildCaseOverview(inputs);inputs[0].text='invalid';inputs[0].name='changed';inputs[0].expectedDigest='0'.repeat(64);inputs.push({name:'unexpected',text:'invalid'});
  const result=await pending;assert.equal(result.entries.length,1);assert.equal(result.entries[0].summary.selected_name,f.input.name);assert.equal(result.entries[0].text,f.input.text);
});
test('five synthetic cases cover all four modules and explicitly retain synthetic mode',async()=>{
  const inputs=await overviewExample(),overview=await buildCaseOverview(inputs);assert.equal(overview.entries.length,5);assert.equal(overview.mode,'synthetic_example');assert.deepEqual(new Set(overview.entries.map(e=>e.summary.module)),new Set(Object.keys(MODULES)));assert.equal(overviewTotals(overview.entries).keys,40);
});
