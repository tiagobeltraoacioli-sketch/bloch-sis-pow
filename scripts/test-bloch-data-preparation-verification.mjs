import test from 'node:test';
import assert from 'node:assert/strict';
import {defaultConfig} from '../apps/bloch-data/assets/modules.v1.mjs';
import {sha256,createReport,MAX_BYTES} from '../apps/bloch-data/assets/reconcile.v1.mjs';
import {preparationExample} from '../apps/bloch-data/assets/preparation-samples.v1.mjs';
import {verifyPreparation,preparationVerificationExport,MAX_PREPARATION_BYTES} from '../apps/bloch-data/assets/preparation-verification.v1.mjs';
import {inspectSource,machineCSV,prepareSources} from '../apps/bloch-data/assets/preparation.v1.mjs';

const encode=value=>JSON.stringify(value,null,2)+'\n';
const fixture=()=>preparationExample();
function changedReceipt(input,mutate){const receipt=JSON.parse(input.receiptText);mutate(receipt);return {...input,receiptText:encode(receipt)};}

for(const module of ['trades','cash','positions','onchain'])test(`${module}: retained preparation reproduces exact originals, outputs, lineage and evidence`,async()=>{
  const input=await preparationExample(defaultConfig(module,'br','bank'));
  input.expectedDigest=await sha256(input.receiptText);input.expectedEvidenceDigest=await sha256(input.evidenceText);
  const checked=await verifyPreparation(input);
  assert.equal(checked.bytes,input.receiptText);assert.equal(checked.pinned,true);assert.equal(checked.evidence.pinned,true);
  assert.deepEqual(checked.sources,input.prepared);assert.deepEqual(checked.evidence.report.result.counts,{matched:3,different:2,left_only:1,right_only:1,duplicate:1});
  assert.equal(checked.receipt.sources[0].lineage[0].source_row,3);assert.equal(checked.receipt.sources[0].lineage[0].prepared_row,2);
  assert.equal(checked.receipt.module,module);assert.equal(checked.evidence.bytes,input.evidenceText);
});
test('files may be renamed without changing retained declarations or exact bytes',async()=>{
  const input=await fixture();input.originals.forEach(source=>source.name='renamed.csv');input.prepared.forEach(source=>source.name='renamed.csv');
  const checked=await verifyPreparation(input);assert.equal(checked.receipt.sources[0].input.name,'synthetic-original-a.csv');assert.equal(checked.sources[0].name,'prepared-a.csv');
});
test('changes to excluded cells or BOM fail even when mapped output is unchanged',async()=>{
  for(const mutate of [text=>text.replace('Synthetic extraction note','Different extraction note'),text=>text.replace(/^\uFEFF/,''),text=>text.replaceAll('\r\n','\n')]){
    const input=await fixture();input.originals[0].text=mutate(input.originals[0].text);await assert.rejects(verifyPreparation(input),/Original source A/);
  }
});
test('A/B swaps fail on both original and prepared sources',async()=>{
  for(const field of ['originals','prepared']){const input=await fixture();input[field].reverse();await assert.rejects(verifyPreparation(input));}
});
test('equivalent prepared CSV formatting and record reordering are rejected',async()=>{
  for(const mutate of [text=>text.replaceAll('\r\n','\n'),text=>'\uFEFF'+text,text=>{const lines=text.trimEnd().split('\r\n');return [lines[0],...lines.slice(1).reverse()].join('\r\n')+'\r\n';},text=>text.replace('"125.5"','"125.50000000"')]){
    const input=await fixture(),before=input.prepared[0].text;input.prepared[0].text=mutate(before);assert.notEqual(input.prepared[0].text,before);await assert.rejects(verifyPreparation(input),/Prepared source A/);
  }
});
test('lineage, counts, profiles, output descriptors and assurance mutations fail closed',async()=>{
  const input=await fixture();
  for(const mutate of [
    receipt=>receipt.sources[0].lineage[0].source_row++,receipt=>receipt.sources[0].lineage[0].prepared_row++,
    receipt=>receipt.sources[0].lineage[0].changed_fields=[],receipt=>receipt.sources[0].changed_cells_by_field.amount++,
    receipt=>receipt.sources[0].output.sha256='0'.repeat(64),receipt=>receipt.sources[0].output.rows++,
    receipt=>receipt.sources[0].profile.excluded_columns=[],receipt=>receipt.sources[0].profile.column_mapping.account='book_entity',
    receipt=>receipt.rules.tolerance='0.01',receipt=>receipt.assurance.source_authentication='verified',
    receipt=>receipt.sources.reverse(),receipt=>receipt.sources[0].side='B',receipt=>receipt.sources[0].input.bytes++,
    receipt=>receipt.configuration.date_format='dmy',receipt=>receipt.configuration.column_mapping={account:'unexpected'},
    receipt=>receipt.extra='unexpected',receipt=>receipt.validation_rule='new-rule',receipt=>receipt.module='trades',
  ])await assert.rejects(verifyPreparation(changedReceipt(input,mutate)));
});
test('independent receipt and evidence digests detect mismatched retained identities',async()=>{
  const input=await fixture();for(const field of ['expectedDigest','expectedEvidenceDigest'])for(const value of ['0'.repeat(64),'bad','A'.repeat(64)])await assert.rejects(verifyPreparation({...input,[field]:value}),/independently retained/);
});
test('no evidence is allowed but cannot be paired with an evidence digest',async()=>{
  const input=await fixture(),checked=await verifyPreparation({...input,evidenceText:null});assert.equal(checked.evidence,null);
  const exported=await preparationVerificationExport(checked);assert.equal(exported.report.evidence,null);
  await assert.rejects(verifyPreparation({...input,evidenceText:null,expectedEvidenceDigest:await sha256(input.evidenceText)}),/requires the corresponding evidence/);
});
test('evidence outcomes, original source bindings and byte digests are independently recomputed',async()=>{
  const input=await fixture();
  for(const mutate of [report=>report.result.counts.matched++,report=>report.sources[0].sha256='0'.repeat(64),report=>report.result.items[0].status='different',report=>report.assurance.onchain='verified']){
    const evidence=JSON.parse(input.evidenceText);mutate(evidence);await assert.rejects(verifyPreparation({...input,evidenceText:encode(evidence)}));
  }
});
test('a valid report with different policy configuration or mode is not linked',async()=>{
  const input=await fixture(),config=JSON.parse(input.receiptText).configuration;
  for(const [configuration,mode] of [[{...config,purpose:'Other purpose'},'synthetic_example'],[config,'local_files']]){
    const other=await createReport(input.prepared[0],input.prepared[1],mode,configuration);await assert.rejects(verifyPreparation({...input,evidenceText:other.bytes}),/configuration and data mode/);
  }
});
test('a coherent declaration replacement is consistent without a pin, not authenticated',async()=>{
  const original=await fixture();let replacement=changedReceipt(original,receipt=>{receipt.generated_at='2000-01-01T00:00:00.000Z';receipt.sources[0].input.name='another-declared-name.csv';receipt.mode='local_files';});replacement.evidenceText=null;
  const verified=await verifyPreparation(replacement);assert.equal(verified.pinned,false);assert.equal(verified.mode,'local_files');assert.equal(verified.receipt.assurance.source_authentication,'not_verified');
  await assert.rejects(verifyPreparation({...replacement,expectedDigest:await sha256(original.receiptText)}),/independently retained/);
});
test('reformatted, duplicate-key, invalid or oversized JSON is rejected',async()=>{
  const input=await fixture();for(const text of [JSON.stringify(JSON.parse(input.receiptText)),input.receiptText.replace('  "schema":','  "schema": "duplicate",\n  "schema":'),'null\n','[1]\n','{invalid',' '.repeat(MAX_PREPARATION_BYTES+1)])await assert.rejects(verifyPreparation({...input,receiptText:text}));
});
test('unknown schemas, modes, invalid timestamps and incomplete manifests are rejected',async()=>{
  const input=await fixture();for(const mutate of [r=>r.schema='future',r=>r.mode='live',r=>r.generated_at='2026-02-30T00:00:00.000Z',r=>r.generated_at='yesterday',r=>r.sources.pop(),r=>delete r.sources[0].profile,r=>r.sources[0].input.name='\ud800'])await assert.rejects(verifyPreparation(changedReceipt(input,mutate)));
});
test('source count, text, Unicode and byte bounds apply to both pairs',async()=>{
  const input=await fixture();for(const field of ['originals','prepared'])for(const pair of [[],[input[field][0]],null,[{text:'\ud800'},input[field][1]],[{text:'a'.repeat(MAX_BYTES+1)},input[field][1]],[{text:42},input[field][1]]])await assert.rejects(verifyPreparation({...input,[field]:pair}),/two valid UTF-8 CSVs/);
});
test('caller mutations during hashing do not alter the verified source snapshots',async()=>{
  const input=await fixture(),originalPrepared=input.prepared[1].text,promise=verifyPreparation(input);input.originals[1].text='changed';input.prepared[1].text='changed';input.originals.reverse();const result=await promise;assert.equal(result.sources[1].text,originalPrepared);
});
test('verification receipt binds exact hashes and explicit scoped checks without raw data',async()=>{
  const input=await fixture(),checked=await verifyPreparation({...input,expectedDigest:await sha256(input.receiptText)}),output=await preparationVerificationExport(checked),report=output.report;
  assert.equal(output.digest,await sha256(output.bytes));assert.equal(report.preparation_sha256,await sha256(input.receiptText));assert.equal(report.retained_preparation_digest_check,'matched');
  assert.equal(report.evidence.sha256,await sha256(input.evidenceText));assert.equal(report.evidence.retained_digest_check,'not_provided');assert.equal(report.sources[0].original.sha256,await sha256(input.originals[0].text));assert.equal(report.sources[1].prepared.sha256,await sha256(input.prepared[1].text));
  assert.equal(report.assurance.mapping_authorization,'not_authenticated');assert.equal(report.assurance.review_journal,'not_supplied_or_verified');assert.equal(report.assurance.onchain,'not_verified');assert.equal(output.bytes.includes('ACCOUNT-DEMO'),false);assert.equal(output.bytes.includes('Synthetic extraction note'),false);
});
test('every retained lineage row is checked beyond the UI preview',async()=>{
  const input=await fixture(),retained=JSON.parse(input.receiptText);
  const originals=input.originals.map((source,index)=>{const profile=retained.sources[index].profile,table=inspectSource(source.text,profile.separator),position=table.headers.indexOf(profile.column_mapping.entry_id);const rows=Array.from({length:125},(_,row)=>{const values=[...table.records[0].values];values[position]=`BULK-${row}`;return values;});return {...source,text:machineCSV([table.headers,...rows],profile.separator),profile};});
  const prepared=await prepareSources(originals,retained.configuration,'synthetic_example');const inputs={receiptText:prepared.bytes,originals,prepared:prepared.sources};const verified=await verifyPreparation(inputs);assert.equal(verified.receipt.sources[0].lineage.length,125);assert.equal((await preparationVerificationExport(verified)).report.sources[1].lineage_rows,125);
  await assert.rejects(verifyPreparation(changedReceipt(inputs,r=>r.sources[0].lineage[124].source_row++)),/lineage/);
});
