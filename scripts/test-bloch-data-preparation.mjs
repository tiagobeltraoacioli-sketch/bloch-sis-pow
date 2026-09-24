import test from 'node:test';
import assert from 'node:assert/strict';
import {defaultConfig,getModule} from '../apps/bloch-data/assets/modules.v1.mjs';
import {parseCSV,compare,sha256,MAX_BYTES} from '../apps/bloch-data/assets/reconcile.v1.mjs';
import {samplesFor} from '../apps/bloch-data/assets/samples.v1.mjs';
import {inspectSource,prepareSources,machineCSV} from '../apps/bloch-data/assets/preparation.v1.mjs';

function fixture(module='cash') {
  const config=defaultConfig(module,'br','bank');
  config.purpose='Local reconciliation';config.jurisdiction='BR';config.retention_policy='POL-7';
  const sources=[0,1].map(index=>{
    const format={separator:index?',':';',date_format:index?'iso':'dmy',decimal_format:index?'dot':'comma'};
    const table=inspectSource(samplesFor({...config,...format})[index],format.separator);
    const mapping=Object.fromEntries(table.headers.map(header=>[header,`${index?'external':'internal'}_${header}`]));
    return {name:`original-${index}.csv`,text:machineCSV([[...Object.values(mapping),'unused'],...table.records.map(row=>[...row.values,'secret-not-exported'])],format.separator),profile:{...format,column_mapping:mapping,excluded_columns:['unused']}};
  });
  return {config,sources};
}
function change(source,field,value,row=0) {
  const table=inspectSource(source.text,source.profile.separator);
  table.records[row].values[table.headers.indexOf(source.profile.column_mapping[field])]=value;
  source.text=machineCSV([table.headers,...table.records.map(record=>record.values)],source.profile.separator);
}

for(const module of ['trades','cash','positions','onchain'])test(`${module}: unlike source headers and conventions preserve comparison outcomes`,async()=>{
  const {config,sources}=fixture(module),prepared=await prepareSources(sources,config,'synthetic_example');
  const actual=compare(...prepared.sources.map(source=>parseCSV(source.text,prepared.configuration)),module);
  const expected=compare(...samplesFor(config).map(text=>parseCSV(text,config)),module);
  assert.deepEqual(actual.counts,expected.counts);assert.deepEqual(actual.items.map(item=>[item.key,item.status,item.differences]),expected.items.map(item=>[item.key,item.status,item.differences]));
  assert.equal(prepared.mode,'synthetic_example');assert.equal(prepared.configuration.retention_policy,'POL-7');assert.deepEqual(prepared.configuration.column_mapping,{});
  assert.equal(prepared.configuration.date_format,'iso');assert.equal(prepared.configuration.decimal_format,'dot');assert.equal(prepared.configuration.separator,',');
  assert.equal(prepared.receipt.sources[0].output.rows,8);assert.equal(actual.counts.duplicate,1);
});
test('receipt binds exact BOM, line endings, originals, outputs and declared exclusions',async()=>{
  const {config,sources}=fixture();sources[0].text='\uFEFF\r\n'+sources[0].text;
  const result=await prepareSources(sources,config),a=result.receipt.sources[0];
  assert.equal(a.input.sha256,await sha256(sources[0].text));assert.equal(a.output.sha256,await sha256(result.sources[0].text));
  assert.equal(result.digest,await sha256(result.bytes));assert.equal(a.input.bytes,new TextEncoder().encode(sources[0].text).length);
  assert.deepEqual(a.lineage[0],{source_row:3,prepared_row:2,changed_fields:['booking_date','value_date','amount']});
  assert.equal(a.changed_cells_by_field.booking_date,8);assert.equal(a.profile.excluded_columns[0],'unused');
  assert.equal(result.bytes.includes('secret-not-exported'),false);assert.equal(result.sources[0].text.includes('secret-not-exported'),false);
  assert.equal(result.receipt.assurance.evidence_source_binding,'prepared_csv_only');
});
test('lineage counts quoted excluded multiline cells, CRLF and blank lines',async()=>{
  const {config,sources}=fixture();const table=inspectSource(sources[0].text,';');
  table.records[0].values[table.headers.length-1]='one\r\ntwo\rthree\nfour';
  sources[0].text='\r\n'+machineCSV([table.headers,...table.records.map(row=>row.values)],';');
  const result=await prepareSources(sources,config);assert.equal(result.receipt.sources[0].lineage[0].source_row,3);assert.equal(result.receipt.sources[0].lineage[1].source_row,7);
});
test('missing or duplicate mappings and unacknowledged exclusions fail closed',async()=>{
  for(const mutate of [p=>delete p.column_mapping.account,p=>p.column_mapping.account=p.column_mapping.entity,p=>p.column_mapping.account='absent',p=>p.excluded_columns=[],p=>p.excluded_columns=['unused','invented'],p=>p.excluded_columns=['unused','unused'],p=>p.extra=true]){
    const {config,sources}=fixture();mutate(sources[0].profile);await assert.rejects(prepareSources(sources,config));
  }
});
test('explicitly mapped extra columns cannot also be declared excluded',async()=>{
  const {config,sources}=fixture();sources[0].profile.excluded_columns.push('internal_account');await assert.rejects(prepareSources(sources,config),/acknowledge/);
});
test('strict source parser rejects duplicate, empty, excessive or malformed headers and ragged rows',()=>{
  for(const text of ['a,a\n1,2',' a ,a\n1,2',',b\n1,2','a,b\n1','a\n"x"oops','a\n"unclosed','a\nva"lue','a\n',`${'a'.repeat(81)}\nx`,Array.from({length:65},(_,i)=>'c'+i).join(',')+'\n'+Array(65).fill('1').join(',')])assert.throws(()=>inspectSource(text));
});
test('byte, row, delimiter and invalid Unicode limits apply before processing',()=>{
  assert.throws(()=>inspectSource('a\n'+'x'.repeat(MAX_BYTES)),/2 MiB/);
  assert.throws(()=>inspectSource('a\n'+Array(5001).fill('x').join('\n')),/5000/);
  assert.equal(inspectSource('a\n'+Array(5000).fill('x').join('\n')).records.length,5000);
  assert.throws(()=>inspectSource('a\n\ud800'),/UTF-8/);assert.throws(()=>inspectSource('a\nx','\t'),/delimiter/);
});
test('all-empty mapped fields cannot disappear when an excluded column is populated',async()=>{
  const {config,sources}=fixture(),table=inspectSource(sources[0].text,';');table.records[0].values=table.headers.map((_,index)=>index===table.headers.length-1?'extra':'');sources[0].text=machineCSV([table.headers,...table.records.map(row=>row.values)],';');await assert.rejects(prepareSources(sources,config),/Source row 2: all mapped fields are empty/);
});
test('invalid dates, signs, localized enums and ambiguous/grouped decimals are rejected',async()=>{
  for(const [field,value,expected] of [['booking_date','31/02/2026',/booking_date/],['amount','1.000,00',/amount/],['amount','-1',/sign/],['amount','1,000000001',/amount/],['direction','DEBITO',/direction/],['amount','1e3',/amount/],['currency','R$',/currency/]]) {
    const {config,sources}=fixture();change(sources[0],field,value);await assert.rejects(prepareSources(sources,config),expected);
  }
});
test('error row references point to the original extract after excluded multiline rows',async()=>{
  const {config,sources}=fixture(),table=inspectSource(sources[0].text,';');table.records[0].values[table.headers.length-1]='x\ny';table.records[1].values[table.headers.indexOf('internal_amount')]='bad';sources[0].text='\n'+machineCSV([table.headers,...table.records.map(row=>row.values)],';');await assert.rejects(prepareSources(sources,config),/Source row 5: invalid amount/);
});
test('exact decimals beyond Number precision and formula-like identifiers stay exact',async()=>{
  const {config,sources}=fixture();change(sources[0],'amount','999999999999999999999999,12345678');change(sources[0],'entry_id','=LOCAL()');change(sources[0],'account','001234');
  const result=await prepareSources(sources,config),first=parseCSV(result.sources[0].text,result.configuration)[0].values;
  assert.equal(first.amount,'999999999999999999999999.12345678');assert.equal(first.entry_id,'=LOCAL()');assert.equal(first.account,'001234');assert.equal(result.receipt.rules.csv_formula_escaping,false);
});
test('trimmed text, uppercase enums/currencies and numeric normalization are counted',async()=>{
  const {config,sources}=fixture();change(sources[0],'account','  ACC-001  ');change(sources[0],'currency','brl');change(sources[0],'direction','credit');change(sources[0],'amount','10,00000000');
  const result=await prepareSources(sources,config),line=result.receipt.sources[0].lineage[0];for(const field of ['account','currency','direction','amount'])assert.ok(line.changed_fields.includes(field));
  assert.equal(parseCSV(result.sources[0].text,result.configuration)[0].values.amount,'10');
});
test('Bloch uint64, hash casing and imported network assertions stay bounded',async()=>{
  const {config,sources}=fixture('onchain');change(sources[0],'value_sat','18446744073709551615');change(sources[0],'txid','A'.repeat(64));const result=await prepareSources(sources,config);const values=parseCSV(result.sources[0].text,result.configuration)[0].values;assert.equal(values.value_sat,'18446744073709551615');assert.equal(values.txid,'a'.repeat(64));
  change(sources[0],'value_sat','18446744073709551616');await assert.rejects(prepareSources(sources,config),/unsigned integer/);
});
test('source header prototype names are mapped as literal data',async()=>{
  const {config,sources}=fixture(),table=inspectSource(sources[0].text,';'),position=table.headers.indexOf('internal_account');table.headers[position]='__proto__';sources[0].profile.column_mapping.account='__proto__';sources[0].text=machineCSV([table.headers,...table.records.map(row=>row.values)],';');const result=await prepareSources(sources,config);assert.equal(parseCSV(result.sources[0].text,result.configuration)[0].values.account,'ACCOUNT-DEMO');
});
test('configuration and inputs are snapshotted across hashing awaits',async()=>{
  const {config,sources}=fixture(),original=sources[1].text,promise=prepareSources(sources,config);sources[1].text='bad';sources[1].profile.column_mapping.account='bad';config.purpose='Mutated';const result=await promise;assert.equal(result.receipt.sources[1].input.sha256,await sha256(original));assert.equal(result.configuration.purpose,'Local reconciliation');
});
test('invalid modes, source counts, filenames and configuration fail closed',async()=>{
  const {config,sources}=fixture();await assert.rejects(prepareSources(sources,config,'guessed'));await assert.rejects(prepareSources(sources.slice(0,1),config));sources[0].name='line\nbreak';await assert.rejects(prepareSources(sources,config),/filename/);await assert.rejects(prepareSources(sources,{...config,module:'unknown'}));
});
test('CSV serialization round-trips embedded quotes, separators and non-ASCII metadata',()=>{
  const input=[['name','memo'],['ação','a,"quoted";value'],['value','a\r\nb']];assert.deepEqual(inspectSource(machineCSV(input)).records.map(row=>row.values),input.slice(1));
});
