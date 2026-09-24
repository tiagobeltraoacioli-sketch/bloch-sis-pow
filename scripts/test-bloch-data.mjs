import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { MODULES, REGIONS, defaultConfig, validateConfig } from '../apps/bloch-data/assets/modules.v1.mjs';
import { parseCSV, compare, decimal, createReport, resultsCSV, MAX_ROWS, MAX_BYTES } from '../apps/bloch-data/assets/reconcile.v1.mjs';
import { samplesFor } from '../apps/bloch-data/assets/samples.v1.mjs';
const config=defaultConfig('trades','global');
const samples=samplesFor(config);
const fixture=()=>parseCSV(samples[0],config);
for(const module of Object.keys(MODULES))test(`${module}: all regional formats produce identical outcomes`,()=>{
  for(const region of Object.keys(REGIONS)){
    const c=defaultConfig(module,region),s=samplesFor(c),result=compare(parseCSV(s[0],c),parseCSV(s[1],c),module);
    assert.deepEqual(result.counts,{matched:3,different:2,left_only:1,right_only:1,duplicate:1});
    assert.equal(result.left_rows,8);assert.equal(result.right_rows,7);assert.equal(result.key_count,8);
  }
});
test('amount comparison preserves differences beyond IEEE-754 integer precision',()=>{
  const a=fixture().slice(0,1),b=structuredClone(a);a[0].values.net_amount=decimal('9007199254740993.00000001').text;b[0].values.net_amount=decimal('9007199254740993.00000002').text;
  assert.equal(compare(a,b).counts.different,1);assert.equal(decimal('9007199254740993.00000001').value,900719925474099300000001n);
});
test('decimal representation changes do not create discrepancies',()=>{
  const a=samples[0],b=a.replace('"1250"','"1250.00000000"');assert.equal(compare(parseCSV(a),parseCSV(b)).counts.different,0);assert.equal(decimal('-0.000').text,'0');
});
test('duplicate keys are never consumed as matches',()=>{const a=fixture().slice(0,1),b=structuredClone(a);a.push(structuredClone(a[0]));assert.equal(compare(a,b).counts.duplicate,1);assert.equal(compare(a,b).counts.matched,0);});
test('same record id under another member never cross-matches',()=>{const a=fixture().slice(0,1),b=structuredClone(a);b[0].values.member='DIFFERENT';assert.equal(compare(a,b).counts.left_only,1);assert.equal(compare(a,b).counts.right_only,1);});
test('currency differences are retained rather than converted',()=>{const a=fixture().slice(0,1),b=structuredClone(a);b[0].values.currency='EUR';assert.deepEqual(compare(a,b).items[0].differences,['currency']);});
test('malformed quoting, duplicate/unknown/missing headers fail closed',()=>{
  assert.throws(()=>parseCSV(samples[0].replace('"DEMO-001"','"DEMO-001"x')),/quoting/);
  assert.throws(()=>parseCSV(samples[0]+'"'),/quote/);
  assert.throws(()=>parseCSV(samples[0].replace('"account"','"member"')),/columns/);
  assert.throws(()=>parseCSV(samples[0].replace('"account"','"secret"')),/columns/);
  assert.throws(()=>parseCSV(samples[0].replace('"account",','')),/columns/);
});
test('invalid dates, signed quantities and excess precision are rejected',()=>{
  for(const [from,to] of [['2026-09-24','2026-02-30'],['"100"','"-100"'],['"12.5"','"12.500000001"'],['"12.5"','"1e3"']])assert.throws(()=>parseCSV(samples[0].replace(from,to)));
});
test('wrong date conventions are not guessed',()=>{const c=defaultConfig('trades','br');assert.throws(()=>parseCSV(samplesFor(c)[0].replace('24/09/2026','2026-09-24'),c),/DD\/MM\/YYYY/);});
test('decimal comma accepts exact decimals and rejects grouped or mixed separators',()=>{
  const c=defaultConfig('trades','br'),s=samplesFor(c)[0];assert.equal(parseCSV(s,c)[0].values.price,'12.5');
  assert.throws(()=>parseCSV(s.replace('"12,5"','"1.234,50"'),c),/decimal/);assert.throws(()=>parseCSV(s.replace('"12,5"','"12.5"'),c),/decimal/);
});
test('column mapping supports local field names and rejects collisions',()=>{
  const c=defaultConfig('cash','br','bank');c.column_mapping={account:'conta',amount:'valor',entry_id:'id_lancamento'};
  assert.equal(parseCSV(samplesFor(c)[0],c)[0].values.account,'ACCOUNT-DEMO');
  c.column_mapping.amount='conta';assert.throws(()=>validateConfig(c),/unique/);
});
test('field order can vary while values remain associated with their fields',()=>{
  const line=samples[0].trim().split('\n').map(l=>l.split(',').reverse().join(',')).join('\n');assert.deepEqual(parseCSV(line),fixture());
});
test('blank lines and CRLF preserve physical source row references',()=>{
  const input='\n'+samples[0].replace('\n','\n\n').replaceAll('\n','\r\n');assert.equal(parseCSV(input)[0].row,4);
});
test('quoted commas and Unicode are retained safely as identifiers',()=>{
  const input=samples[0].replaceAll('ACCOUNT-DEMO','Conta, São Paulo');assert.equal(parseCSV(input)[0].values.account,'Conta, São Paulo');
});
test('unrecognized fields, control characters and oversized values are rejected',()=>{
  assert.throws(()=>parseCSV(samples[0].replace('ACCOUNT-DEMO','BAD\u0000ACCOUNT')));
  assert.throws(()=>parseCSV(samples[0].replace('ACCOUNT-DEMO','x'.repeat(161))));
  assert.throws(()=>parseCSV(samples[0].replace('"USD"','"USDX"')));
});
test('file and row bounds fail before generating a partial report',()=>{
  assert.throws(()=>parseCSV('x'.repeat(MAX_BYTES+1)),/MiB/);
  const [header,row]=samples[0].split('\n');assert.throws(()=>parseCSV(header+'\n'+(row+'\n').repeat(MAX_ROWS+1)),/Maximum/);
});
test('cash value dates may precede booking; negative unsigned amounts do not pass',()=>{
  const c=defaultConfig('cash'),s=samplesFor(c)[0];assert.doesNotThrow(()=>parseCSV(s.replace('"2026-09-24","2026-09-24"','"2026-09-24","2026-09-23"'),c));
  assert.throws(()=>parseCSV(s.replace('"125.50"','"-125.50"'),c),/sign/);
});
test('position snapshots retain short quantities and isolate currencies',()=>{
  const c=defaultConfig('positions'),s=samplesFor(c)[0].replace('"100"','"-100"');const a=parseCSV(s,c).slice(0,1),b=structuredClone(a);assert.equal(a[0].values.quantity,'-100');b[0].values.currency='EUR';assert.equal(compare(a,b,'positions').counts.left_only,1);
});
test('Bloch observations preserve uint64 satoshis and detect changed blocks',()=>{
  const c=defaultConfig('onchain'),s=samplesFor(c),a=parseCSV(s[0].replace('"100000000"','"18446744073709551615"'),c);assert.equal(a[0].values.value_sat,'18446744073709551615');
  const result=compare(parseCSV(s[0],c),parseCSV(s[1],c),'onchain');assert.ok(result.items.some(item=>item.differences.includes('block_id')));
  assert.throws(()=>parseCSV(s[0].replace('"100000000"','"18446744073709551616"'),c),/bound/);
  assert.throws(()=>parseCSV(s[0].replace('bloch-genesis4','ethereum'),c),/network/);
  assert.throws(()=>parseCSV(s[0].replace('"INCLUDED"','"SETTLED"'),c),/status/);
  assert.throws(()=>parseCSV(s[0].replace('a'.repeat(64),'a'.repeat(63)),c),/hexadecimal/);
});
test('evidence digest binds the exact JSON, original source bytes and applied configuration',async()=>{
  const source='\uFEFF'+samples[0],r=await createReport({name:'a.csv',text:source},{name:'b.csv',text:samples[1]},'local_files',config);
  const hash=s=>createHash('sha256').update(s).digest('hex');assert.equal(r.digest,hash(r.bytes));assert.equal(r.report.sources[0].sha256,hash(source));assert.equal(r.report.sources[0].bytes,Buffer.byteLength(source));assert.deepEqual(r.report.configuration,config);assert.equal(r.report.assurance.onchain,'not_submitted');assert.equal(r.report.assurance.regulatory_compliance,'not_certified');
});
test('CSV exports neutralize spreadsheet formulas in untrusted identifiers',()=>{
  const a=fixture().slice(0,1);a[0].values.record_id='=HYPERLINK("https://invalid.test")';const csv=resultsCSV(compare(a,[]));assert.ok(csv.includes("'=HYPERLINK"));assert.ok(csv.includes('""https://invalid.test""'));
});
test('configuration rejects unknown fields, modules and invalid formats',()=>{
  assert.throws(()=>validateConfig({...config,broadcast:true}));assert.throws(()=>validateConfig({...config,module:'toString'}));assert.throws(()=>validateConfig({...config,module:undefined}));assert.throws(()=>validateConfig({...config,separator:'|'}));assert.throws(()=>validateConfig({...config,column_mapping:{private_key:'secret'}}));
});
