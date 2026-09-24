import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {MODULES,defaultConfig} from '../apps/bloch-data/assets/modules.v1.mjs';
import {samplesFor} from '../apps/bloch-data/assets/samples.v1.mjs';
import {createReport,sha256,MAX_BYTES} from '../apps/bloch-data/assets/reconcile.v1.mjs';
import {newReview,appendReview,reviewExport} from '../apps/bloch-data/assets/audit.v1.mjs';
import {createCaseFile,verifyCaseFile,caseVerificationExport,CASE_COMPONENTS,MAX_CASE_BYTES} from '../apps/bloch-data/assets/case-file.v1.mjs';
const encode=value=>JSON.stringify(value,null,2)+'\n';
async function fixture(module='cash',customSources=null) {
  const configuration=defaultConfig(module,'br','bank');
  const sources=(customSources??samplesFor(configuration)).map((text,i)=>({name:`original-${i}.csv`,text}));
  const evidence=await createReport(...sources,'synthetic_example',configuration);
  let review=newReview(evidence.digest);const item=evidence.report.result.items.find(i=>i.status!=='matched');
  review=appendReview(review,evidence.report,evidence.digest,{record_key:item.key,original_outcome:item.status,state:'investigating',reviewer:'Local reviewer',note:'Review the statement cutoff.'});
  const output=await createCaseFile(evidence.bytes,...sources,review);
  return {sources,evidence,review,output};
}
async function changePart(caseFile,index,content) {
  const part=caseFile.components[index];part.content=content;part.bytes=new TextEncoder().encode(content).length;part.sha256=await sha256(content);
}
for(const module of Object.keys(MODULES))test(`${module}: a case round-trips original evidence, sources, review and configuration`,async()=>{
  const {sources,evidence,review,output}=await fixture(module),verified=await verifyCaseFile(output.bytes,output.digest);
  assert.equal(output.digest,createHash('sha256').update(output.bytes).digest('hex'));
  assert.equal(verified.pinned,true);assert.equal(verified.evidence.pinned,false,'Internal digest is not an independent evidence pin');
  assert.equal(verified.evidence.bytes,evidence.bytes);assert.equal(verified.evidence.digest,evidence.digest);assert.deepEqual(verified.review,review);
  assert.deepEqual(verified.sources.map(s=>s.text),sources.map(s=>s.text));
  assert.equal(verified.caseFile.components[4].content,encode(evidence.report.configuration));
  assert.deepEqual(verified.caseFile.components.map(p=>p.name),CASE_COMPONENTS.map(p=>p.name));
  assert.equal(JSON.parse(verified.caseFile.components[5].content).retained_digest_check,'not_provided');
});
test('raw UTF-8 source bytes, BOM, CRLF, quotes and accents survive the JSON container',async()=>{
  const texts=samplesFor(defaultConfig('cash','br','bank')).map(text=>'\uFEFF'+text.replaceAll('\n','\r\n').replaceAll('ACCOUNT-DEMO','Conta São Paulo'));
  const {output,sources}=await fixture('cash',texts),verified=await verifyCaseFile(output.bytes);
  for(let i=0;i<2;i++)assert.equal(await sha256(verified.sources[i].text),await sha256(sources[i].text));
  assert.ok(verified.sources[0].text.startsWith('\uFEFF'));assert.ok(verified.sources[0].text.includes('\r\n'));
});
test('an unreviewed case retains every exception with an empty bound journal',async()=>{
  const {sources,evidence}=await fixture(),empty=newReview(evidence.digest);
  const verified=await verifyCaseFile((await createCaseFile(evidence.bytes,...sources,empty)).bytes);
  assert.equal(verified.review.events.length,0);assert.equal(verified.evidence.report.result.key_count,8);assert.equal(verified.evidence.report.result.counts.matched,3);
  assert.equal(JSON.parse(verified.caseFile.components[5].content).review.events,0);
});
test('creation independently recomputes rather than trusting a report status or supplied review',async()=>{
  const {sources,evidence,review}=await fixture();
  const tampered=structuredClone(evidence.report);tampered.result.counts.matched++;
  await assert.rejects(createCaseFile(encode(tampered),...sources,review),/Recomputed outcomes/);
  await assert.rejects(createCaseFile(evidence.bytes,...sources,{...review,evidence_sha256:'0'.repeat(64)}),/bound/);
  await assert.rejects(createCaseFile(evidence.bytes,sources[1],sources[0],review),/Source bytes/);
});
test('case preparation snapshots the journal before asynchronous work',async()=>{
  const {sources,evidence,review}=await fixture();
  const pending=createCaseFile(evidence.bytes,...sources,review);review.events[0].note='Changed after preparation started.';
  const verified=await verifyCaseFile((await pending).bytes);
  assert.equal(verified.review.events[0].note,'Review the statement cutoff.');
});
test('manifest rejects missing, extra, duplicate, reordered and path-like components',async()=>{
  const {output}=await fixture();
  const edits=[c=>c.components.pop(),c=>c.components.push(c.components[0]),c=>c.components[1].name='evidence.json',c=>c.components.reverse(),c=>c.components[0].name='../evidence.json',c=>c.components[0].media_type='text/html',c=>c.components[0].extra='value',c=>c.extra='value',c=>c.schema='other',c=>c.encoding='base64',c=>c.created_at='2026-02-30T00:00:00.000Z',c=>c.assurance.signatures='verified',c=>c.assurance.encryption='encrypted'];
  for(const edit of edits){const changed=structuredClone(output.caseFile);edit(changed);await assert.rejects(verifyCaseFile(encode(changed)));}
});
test('every component hash and UTF-8 byte count is checked',async()=>{
  const {output}=await fixture();
  for(let i=0;i<6;i++){
    const badHash=structuredClone(output.caseFile);badHash.components[i].sha256='0'.repeat(64);await assert.rejects(verifyCaseFile(encode(badHash)),/mismatch/);
    const badSize=structuredClone(output.caseFile);badSize.components[i].bytes++;await assert.rejects(verifyCaseFile(encode(badSize)),/mismatch/);
  }
});
test('consistent component hashes cannot conceal changed outcomes, configuration or receipt claims',async()=>{
  const {output}=await fixture();
  const reportCase=structuredClone(output.caseFile),report=JSON.parse(reportCase.components[0].content);report.result.counts.matched++;
  await changePart(reportCase,0,encode(report));reportCase.evidence_sha256=reportCase.components[0].sha256;
  await assert.rejects(verifyCaseFile(encode(reportCase)),/Recomputed outcomes/);
  const configCase=structuredClone(output.caseFile),configuration=JSON.parse(configCase.components[4].content);configuration.purpose='Different purpose';await changePart(configCase,4,encode(configuration));
  await assert.rejects(verifyCaseFile(encode(configCase)),/configuration differs/);
  const receiptCase=structuredClone(output.caseFile),receipt=JSON.parse(receiptCase.components[5].content);receipt.assurance.source_authentication='verified';await changePart(receiptCase,5,encode(receipt));
  await assert.rejects(verifyCaseFile(encode(receiptCase)),/receipt differs/);
});
test('review binding, sequence and packaged receipt must agree with the same journal',async()=>{
  const {output}=await fixture();
  const changed=structuredClone(output.caseFile),journal=JSON.parse(changed.components[3].content);journal.events[0].note='Another explanation';await changePart(changed,3,encode(journal));changed.review_sha256=changed.components[3].sha256;
  await assert.rejects(verifyCaseFile(encode(changed)),/receipt differs/);
  journal.events[0].sequence=999;await changePart(changed,3,encode(journal));changed.review_sha256=changed.components[3].sha256;
  await assert.rejects(verifyCaseFile(encode(changed)),/sequence/);
});
test('a replaced but coherent manifest requires an external digest to detect its changed identity',async()=>{
  const {output}=await fixture(),changed=structuredClone(output.caseFile);changed.created_at='2000-01-01T00:00:00.000Z';
  assert.equal((await verifyCaseFile(encode(changed))).pinned,false);
  await assert.rejects(verifyCaseFile(encode(changed),output.digest),/retained SHA/);
  await assert.rejects(verifyCaseFile(output.bytes,'bad'),/retained SHA/);
});
test('duplicate JSON keys, malformed exports and text size bounds fail closed',async()=>{
  const {output}=await fixture();
  await assert.rejects(verifyCaseFile(output.bytes.replace('"schema":','"schema": "duplicate",\n  "schema":')),/original workbench/);
  await assert.rejects(verifyCaseFile(JSON.stringify(output.caseFile)),/original workbench/);
  await assert.rejects(verifyCaseFile(' '.repeat(MAX_CASE_BYTES+1)),/size limit/);
  const oversized=structuredClone(output.caseFile);oversized.components[1].content='x'.repeat(MAX_BYTES+1);await assert.rejects(verifyCaseFile(encode(oversized)),/size limit/);
  const unicode=structuredClone(output.caseFile);unicode.components[1].content='\ud800';await assert.rejects(verifyCaseFile(encode(unicode)),/valid Unicode/);
});
test('a case verification receipt records exact component digests and scoped assurance',async()=>{
  const {output,evidence,review}=await fixture(),verified=await verifyCaseFile(output.bytes,output.digest),receipt=JSON.parse((await caseVerificationExport(verified)).bytes);
  assert.equal(receipt.case_sha256,output.digest);assert.equal(receipt.evidence_sha256,evidence.digest);assert.equal(receipt.review_sha256,(await reviewExport(review,evidence.report,evidence.digest)).digest);
  assert.equal(receipt.retained_case_digest_check,'matched');assert.equal(receipt.review_entries,1);assert.equal(receipt.components.length,6);assert.ok(receipt.components.every(c=>c.check==='matched'));
  assert.equal(receipt.assurance.encryption,'none');assert.equal(receipt.assurance.source_authentication,'not_verified');assert.equal(receipt.assurance.onchain,'not_verified');
});
