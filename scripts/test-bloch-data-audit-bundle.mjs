import test from 'node:test';
import assert from 'node:assert/strict';
import {defaultConfig} from '../apps/bloch-data/assets/modules.v1.mjs';
import {sha256,createReport,MAX_BYTES} from '../apps/bloch-data/assets/reconcile.v1.mjs';
import {newReview,appendReview} from '../apps/bloch-data/assets/audit.v1.mjs';
import {createCaseFile} from '../apps/bloch-data/assets/case-file.v1.mjs';
import {preparationExample} from '../apps/bloch-data/assets/preparation-samples.v1.mjs';
import {auditBundleExample} from '../apps/bloch-data/assets/audit-bundle-samples.v1.mjs';
import {createAuditBundle,verifyAuditBundle,auditBundleVerificationExport,MAX_AUDIT_BUNDLE_BYTES} from '../apps/bloch-data/assets/audit-bundle.v1.mjs';

const encode=value=>JSON.stringify(value,null,2)+'\n';
async function fixture(module='cash'){
  const input=await preparationExample(defaultConfig(module,'br','bank')),report=JSON.parse(input.evidenceText),digest=await sha256(input.evidenceText),exception=report.result.items.find(item=>item.status!=='matched');
  const review=appendReview(newReview(digest),report,digest,{record_key:exception.key,original_outcome:exception.status,state:'follow_up',reviewer:'Local reviewer',note:'Retain both references. <img src=x onerror=alert(1)>'});
  const caseFile=await createCaseFile(input.evidenceText,input.prepared[0],input.prepared[1],review);
  return {caseText:caseFile.bytes,preparationText:input.receiptText,originals:input.originals,caseDigest:caseFile.digest,preparationDigest:await sha256(input.receiptText)};
}
async function replacePart(bundle,index,text){const part=bundle.components[index];part.content=text;part.bytes=new TextEncoder().encode(text).length;part.sha256=await sha256(text);}

for(const module of ['trades','cash','positions','onchain'])test(`${module}: full audit bundle preserves exact original, preparation, case and review bytes`,async()=>{
  const input=await fixture(module),created=await createAuditBundle(input),verified=await verifyAuditBundle(created.bytes,created.digest);
  assert.equal(verified.pinned,true);assert.equal(verified.bytes,created.bytes);assert.equal(verified.bundle.components.length,5);
  assert.equal(verified.bundle.components[0].content,input.caseText);assert.equal(verified.bundle.components[1].content,input.preparationText);
  assert.deepEqual(verified.originals.map(file=>file.text),input.originals.map(file=>file.text));assert.equal(verified.case.review.events.length,1);assert.equal(verified.case.review.events[0].state,'follow_up');
  assert.deepEqual(verified.case.evidence.report.result.counts,{matched:3,different:2,left_only:1,right_only:1,duplicate:1});
  assert.equal(verified.preparation.receipt.sources[0].lineage[0].source_row,3);assert.equal(verified.bundle.module,module);assert.equal(verified.bundle.case_sha256,input.caseDigest);
});
test('internal references are never reported as independently retained pins',async()=>{
  const input=await fixture(),created=await createAuditBundle(input),verified=await verifyAuditBundle(created.bytes,created.digest),packaged=JSON.parse(verified.bundle.components[4].content);
  assert.equal(verified.case.pinned,false);assert.equal(verified.preparation.pinned,false);assert.equal(verified.preparation.evidence.pinned,false);
  assert.equal(packaged.retained_preparation_digest_check,'not_provided');assert.equal(packaged.evidence.retained_digest_check,'not_provided');
});
test('retained case and preparation pins gate creation and external bundle pin gates reopening',async()=>{
  const input=await fixture();for(const field of ['caseDigest','preparationDigest'])await assert.rejects(createAuditBundle({...input,[field]:'0'.repeat(64)}),/independently retained/);
  const created=await createAuditBundle(input);for(const pin of ['0'.repeat(64),'bad','A'.repeat(64)])await assert.rejects(verifyAuditBundle(created.bytes,pin),/independently retained/);
});
test('replaced excluded cells and swapped originals cannot be attached to an existing case',async()=>{
  const input=await fixture();for(const originals of [[...input.originals].reverse(),input.originals.map((file,index)=>index?file:{...file,text:file.text.replace('Synthetic extraction note','different excluded contents')})])await assert.rejects(createAuditBundle({...input,originals}));
});
test('a valid unrelated case with different configuration or prepared bytes is rejected',async()=>{
  const input=await fixture(),caseFile=JSON.parse(input.caseText),report=JSON.parse(caseFile.components[0].content),sources=[{text:caseFile.components[1].content,name:'a.csv'},{text:caseFile.components[2].content,name:'b.csv'}];
  for(const variant of ['policy','data','mode']){
    const pair=structuredClone(sources);if(variant==='data')pair[0].text=pair[0].text.replace('"125.5"','"125.6"');
    const evidence=await createReport(pair[0],pair[1],variant==='mode'?'local_files':report.mode,variant==='policy'?{...report.configuration,purpose:'Different purpose'}:report.configuration);
    const changed=await createCaseFile(evidence.bytes,pair[0],pair[1],newReview(evidence.digest));await assert.rejects(createAuditBundle({...input,caseText:changed.bytes,caseDigest:changed.digest}));
  }
});
test('fixed components reject missing, extra, duplicate, reordered and path-like names',async()=>{
  const original=await createAuditBundle(await fixture());
  for(const mutate of [b=>b.components.pop(),b=>b.components.push(b.components[0]),b=>b.components.reverse(),b=>b.components[1]=b.components[0],b=>b.components[0].name='../case.json',b=>b.components[0].media_type='text/html',b=>b.components[0].extra=true]){const bundle=structuredClone(original.bundle);mutate(bundle);await assert.rejects(verifyAuditBundle(encode(bundle)));}
});
test('component sizes and digests are checked before trusting embedded declarations',async()=>{
  const original=await createAuditBundle(await fixture());for(let index=0;index<5;index++)for(const field of ['content','bytes','sha256']){const bundle=structuredClone(original.bundle);if(field==='content')bundle.components[index].content+=' ';else if(field==='bytes')bundle.components[index].bytes++;else bundle.components[index].sha256='0'.repeat(64);await assert.rejects(verifyAuditBundle(encode(bundle)),/size or SHA-256 mismatch/);}
});
test('rehashed original and preparation changes still fail semantic recomputation',async()=>{
  const original=await createAuditBundle(await fixture());
  const changedOriginal=structuredClone(original.bundle);await replacePart(changedOriginal,2,changedOriginal.components[2].content.replace('Synthetic extraction note','changed excluded cell'));await assert.rejects(verifyAuditBundle(encode(changedOriginal)),/Original source A/);
  const changedPreparation=structuredClone(original.bundle),preparation=JSON.parse(changedPreparation.components[1].content);preparation.sources[0].lineage[0].source_row++;await replacePart(changedPreparation,1,encode(preparation));changedPreparation.preparation_sha256=changedPreparation.components[1].sha256;await assert.rejects(verifyAuditBundle(encode(changedPreparation)),/lineage/);
});
test('rehashed nested case outcomes cannot bypass independent reconciliation',async()=>{
  const original=await createAuditBundle(await fixture()),bundle=structuredClone(original.bundle),nested=JSON.parse(bundle.components[0].content),evidence=JSON.parse(nested.components[0].content);evidence.result.counts.matched++;
  await replacePart(nested,0,encode(evidence));nested.evidence_sha256=nested.components[0].sha256;await replacePart(bundle,0,encode(nested));bundle.case_sha256=bundle.components[0].sha256;bundle.evidence_sha256=nested.evidence_sha256;
  await assert.rejects(verifyAuditBundle(encode(bundle)),/Recomputed outcomes/);
});
test('packaged preparation receipt cannot assert external pins, approvals or altered counts',async()=>{
  const original=await createAuditBundle(await fixture());for(const mutate of [r=>r.retained_preparation_digest_check='matched',r=>r.evidence.retained_digest_check='matched',r=>r.sources[0].lineage_rows++,r=>r.assurance.signature='verified',r=>r.extra=true,r=>r.verified_at='not-a-time']){const bundle=structuredClone(original.bundle),receipt=JSON.parse(bundle.components[4].content);mutate(receipt);await replacePart(bundle,4,encode(receipt));await assert.rejects(verifyAuditBundle(encode(bundle)),/verification|timestamp/);}
});
test('manifest bindings, supported schema and assurance fields must agree',async()=>{
  const original=await createAuditBundle(await fixture());for(const mutate of [b=>b.schema='future',b=>b.case_sha256='0'.repeat(64),b=>b.preparation_sha256='0'.repeat(64),b=>b.evidence_sha256='0'.repeat(64),b=>b.review_sha256='0'.repeat(64),b=>b.module='positions',b=>b.mode='local_files',b=>b.assurance.encryption='encrypted',b=>b.assurance.signatures='present',b=>b.created_at='2026-02-30T00:00:00.000Z',b=>b.extra='unsupported']){const bundle=structuredClone(original.bundle);mutate(bundle);await assert.rejects(verifyAuditBundle(encode(bundle)));}
});
test('coherent replacement requires an external digest to detect changed identity',async()=>{
  const original=await createAuditBundle(await fixture()),replacement=structuredClone(original.bundle);replacement.created_at='2000-01-01T00:00:00.000Z';const text=encode(replacement);assert.equal((await verifyAuditBundle(text)).pinned,false);await assert.rejects(verifyAuditBundle(text,original.digest),/independently retained/);
});
test('source snapshots remain stable while asynchronous verification runs',async()=>{
  const input=await fixture(),originalA=input.originals[0].text,originalB=input.originals[1].text,promise=createAuditBundle(input);input.originals[0].text='changed';input.originals.reverse();const output=await promise;assert.equal(output.bundle.components[2].content,originalA);assert.equal(output.bundle.components[3].content,originalB);
});
test('unreviewed cases are retained without inventing history',async()=>{
  const source=await preparationExample(),report=JSON.parse(source.evidenceText),empty=newReview(await sha256(source.evidenceText)),caseFile=await createCaseFile(source.evidenceText,...source.prepared,empty),bundle=await createAuditBundle({caseText:caseFile.bytes,preparationText:source.receiptText,originals:source.originals});const verified=await verifyAuditBundle(bundle.bytes);assert.equal(verified.case.review.events.length,0);assert.deepEqual(verified.case.evidence.report.result,report.result);
});
test('original bytes retain UTF-8 BOM, CRLF, private excluded columns and literal source names',async()=>{
  const input=await fixture();assert.ok(input.originals[0].text.startsWith('\uFEFF\r\n'));const bundle=await createAuditBundle(input),verified=await verifyAuditBundle(bundle.bytes);assert.equal(verified.originals[0].text,input.originals[0].text);assert.ok(verified.originals[0].text.includes('Synthetic extraction note'));assert.ok(verified.case.review.events[0].note.includes('<img'));assert.equal(verified.bundle.assurance.encryption,'none');
});
test('invalid Unicode, source counts, raw source bounds and noncanonical JSON fail closed',async()=>{
  const input=await fixture();for(const originals of [[],null,[{text:'\ud800'},input.originals[1]],[{text:'x'.repeat(MAX_BYTES+1)},input.originals[1]]])await assert.rejects(createAuditBundle({...input,originals}));
  const bundle=await createAuditBundle(input);for(const text of ['\ud800','null\n','[]\n',JSON.stringify(bundle.bundle),bundle.bytes.replace('  "schema":','  "schema": "duplicate",\n  "schema":'),' '.repeat(MAX_AUDIT_BUNDLE_BYTES+1)])await assert.rejects(verifyAuditBundle(text));
});
test('verification export binds whole bundle, inner identities and complete review count',async()=>{
  const bundle=await createAuditBundle(await fixture()),verified=await verifyAuditBundle(bundle.bytes,bundle.digest),output=await auditBundleVerificationExport(verified),report=output.report;
  assert.equal(output.digest,await sha256(output.bytes));assert.equal(report.audit_bundle_sha256,bundle.digest);assert.equal(report.retained_bundle_digest_check,'matched');assert.equal(report.case_sha256,verified.case.digest);assert.equal(report.preparation_sha256,verified.preparation.digest);assert.equal(report.evidence_sha256,verified.case.evidence.digest);assert.equal(report.review_sha256,verified.case.caseFile.review_sha256);assert.equal(report.review_entries,1);assert.equal(report.components.length,5);assert.equal(report.original_rows[0].lineage_rows,8);assert.equal(report.assurance.reviewer_identity,'not_verified');assert.equal(output.bytes.includes('Local reviewer'),false);assert.equal(output.bytes.includes('Synthetic extraction note'),false);
});
test('synthetic example is explicitly labelled and carries one illustrative review entry',async()=>{
  const example=await auditBundleExample(defaultConfig('positions','global','manager')),verified=await verifyAuditBundle(example.bytes);assert.equal(verified.bundle.mode,'synthetic_example');assert.equal(verified.bundle.module,'positions');assert.equal(verified.case.review.events.length,1);assert.equal(verified.case.review.events[0].reviewer,'Synthetic reviewer');
});
