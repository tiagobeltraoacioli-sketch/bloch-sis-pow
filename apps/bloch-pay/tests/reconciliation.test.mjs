import test from 'node:test';
import assert from 'node:assert/strict';
import {emptyWorkspace,validateWorkspace,receiptsCSV,csvCell,storeWorkspace,STORAGE_KEY} from '../app/model.mjs';
import {parseRecordCsv,previewReconciliation,applyReconciliation,reconciliationCsv,CSV_COLUMNS} from '../app/reconciliation.mjs';
const now='2026-09-24T12:00:00.000Z';
const invoice=(changes={})=>({id:'invoice-1',reference:'INV-001',counterparty:'Fixture Ltd',direction:'receivable',amount:'10000000000',issued:'2026-09-01',due:'2026-09-20',recipient:'',note:'',state:'active',createdAt:now,...changes});
const workspace=(invoices=[invoice()],receipts=[])=>({...emptyWorkspace(),invoices,receipts});
const row=(changes={})=>({reference:'PAY-001',invoice_reference:'INV-001',amount_BLCH:'25.00000001',record_date:'2026-09-22',txid:'',block_id:'',output_index:'',note:'',...changes});
const csv=(rows,columns=CSV_COLUMNS)=>[columns,...rows.map(r=>columns.map(key=>r[key]||''))].map(r=>r.map(csvCell).join(',')).join('\r\n');
const review=(rows,state=workspace())=>previewReconciliation(csv(rows),state,{now});

test('quoted CSV handles BOM, embedded newlines, commas, quotes and empty optional fields',()=>{
  const note='One, two\r\n"quoted"';const rows=parseRecordCsv('\uFEFF'+csv([row({note})])+'\r\n\r\n');assert.equal(rows.length,1);assert.equal(rows[0].values.note,note);
  assert.equal(review([row({note})]).additions[0].note,note);
});
test('malformed CSV and unsupported headers fail before producing any additions',()=>{
  for(const raw of ['',CSV_COLUMNS.join(','),csv([row()]).replace('"PAY-001"','"PAY-001"x'),'reference,reference,amount_BLCH,record_date\na,a,1,2026-09-22','reference;invoice_reference;amount_BLCH;record_date\na;b;1;2026-09-22',csv([row()])+'\n"unclosed',csv([row()]).replace('PAY-001','PAY\u0000001'),csv([row()]).replace('PAY-001','PAY\uFFFD001')])assert.throws(()=>parseRecordCsv(raw));
  assert.equal(previewReconciliation(CSV_COLUMNS.join(',')+'\nonly,three,columns',workspace(),{now}).counts.blocked,1);
});
test('limits reject oversized input and more than 3000 records',()=>{
  assert.throws(()=>parseRecordCsv('x'.repeat(2_000_001)),/2 MB/);
  assert.throws(()=>parseRecordCsv('reference,invoice_reference,amount_BLCH,record_date\n'+('p,i,1,2026-09-22\n').repeat(3001)),/3,000/);
});
test('one-satoshi and large values preserve exact amounts and split receivables from payables',()=>{
  const state=workspace([invoice({amount:'2700000000000000001'}),invoice({id:'invoice-2',reference:'INV-002',direction:'payable',amount:'1'})]);
  const preview=review([row({amount_BLCH:'27000000000.00000001'}),row({reference:'PAY-002',invoice_reference:'INV-002',amount_BLCH:'0.00000001'})],state);
  assert.deepEqual(preview.totals,{receivable:'2700000000000000001',payable:'1'});assert.equal(preview.impacts[0].after,'matched');assert.equal(preview.impacts[1].after,'matched');assert.equal(state.receipts.length,0);
});
test('multiple records for the same invoice produce one aggregate impact and visible excess',()=>{
  const p=review([row({amount_BLCH:'60'}),row({reference:'PAY-002',amount_BLCH:'50'})]);
  assert.equal(p.impacts.length,1);assert.equal(p.impacts[0].added,'11000000000');assert.equal(p.impacts[0].excess,'1000000000');assert.equal(p.impacts[0].newExcess,true);assert.equal(p.impacts[0].after,'over-recorded');
  assert.equal(review([row()]).impacts[0].after,'partial');
});
test('identical records are idempotent within the file and across repeat imports',()=>{
  const state=workspace(),first=review([row(),row()],state);assert.deepEqual(first.counts,{ready:1,duplicate:1,blocked:0});
  const saved=applyReconciliation(first,state),second=review([row({reference:'pay-001',invoice_reference:'inv-001'})],saved);assert.equal(second.counts.duplicate,1);assert.equal(second.impacts.length,0);assert.throws(()=>applyReconciliation(second,saved),/no new records/);
  const exported=previewReconciliation(receiptsCSV(saved),saved,{now});assert.equal(exported.counts.duplicate,1);
});
test('conflicting duplicate references block all additions, including valid rows',()=>{
  const state=workspace(),p=review([row(),row({amount_BLCH:'5'}),row({reference:'PAY-003'})],state);assert.equal(p.counts.blocked,1);assert.equal(p.counts.ready,2);assert.throws(()=>applyReconciliation(p,state),/blocked/);assert.equal(state.receipts.length,0);
});
test('reused transaction outputs are rejected across invoices and saved records',()=>{
  const a=row({txid:'a'.repeat(64),block_id:'b'.repeat(64),output_index:'0'}),state=workspace([invoice(),invoice({id:'second',reference:'INV-002'})]);
  const p=review([a,row({...a,reference:'OTHER',invoice_reference:'INV-002'})],state);assert.equal(p.counts.blocked,1);assert.match(p.rows[1].message,/already allocated/);
  const saved=applyReconciliation(review([a],state),state);assert.equal(review([row({...a,reference:'OTHER'})],saved).counts.blocked,1);
});
test('missing, void and direction-mismatched invoices cannot receive batch records',()=>{
  assert.equal(review([row({invoice_reference:'unknown'})]).counts.blocked,1);
  assert.equal(review([row()],workspace([invoice({state:'void'})])).counts.blocked,1);
  const p=previewReconciliation(csv([row({direction:'payable'})],[...CSV_COLUMNS,'direction']),workspace(),{now});assert.equal(p.counts.blocked,1);
});
test('invalid dates, amounts and incomplete transaction references are row-level exceptions',()=>{
  for(const change of [{record_date:'2026-02-30'},{record_date:'2026-08-31'},{record_date:'2099-01-01'},{amount_BLCH:'0'},{amount_BLCH:'1e3'},{amount_BLCH:'1,000'},{amount_BLCH:'0.000000001'},{txid:'a'.repeat(64)},{output_index:'-1'},{output_index:'1e1'},{txid:'a'.repeat(64),block_id:'b'.repeat(64),output_index:'4294967296'}])assert.equal(review([row(change)]).counts.blocked,1,JSON.stringify(change));
});
test('preview is bound to the complete invoice workspace, not just its revision',()=>{
  const state=workspace(),p=review([row()],state);const changed=structuredClone(state);changed.invoices[0].amount='1';assert.throws(()=>applyReconciliation(p,changed),/changed after preview/);
});
test('stale persistence and quota failures leave the existing ledger intact',()=>{
  const state=workspace(),p=review([row()],state),next=applyReconciliation(p,state),saved=JSON.stringify(state);let value=saved;
  const storage={getItem:key=>{assert.equal(key,STORAGE_KEY);return value;},setItem:()=>{throw new Error('Quota exceeded');}};
  assert.throws(()=>storeWorkspace(storage,saved,next),/Quota/);assert.equal(value,saved);value='different';assert.throws(()=>storeWorkspace(storage,saved,next),/another tab/);assert.equal(value,'different');assert.equal(state.receipts.length,0);
});
test('receipt capacity blocks the complete batch while retaining its diagnostic rows',()=>{
  const state=workspace(),full=applyReconciliation(review(Array.from({length:3000},(_,i)=>row({reference:'P-'+i,amount_BLCH:'0.00000001'})),state),state);
  const p=review([row()],full);assert.match(p.batchError,/3,000/);assert.throws(()=>applyReconciliation(p,full),/blocked/);
});
test('a valid CSV cannot push the combined ledger beyond its byte capacity',()=>{
  const p=review(Array.from({length:2800},(_,i)=>row({reference:'SIZE-'+i,note:'x'.repeat(500)})));
  assert.equal(p.counts.blocked,0);assert.match(p.batchError,/2 MB/);assert.throws(()=>applyReconciliation(p,workspace()),/blocked/);
});
test('review report escapes formula prefixes and never labels imported evidence verified',()=>{
  const p=previewReconciliation(csv([row({reference:'=1+1',evidence:'chain-verified'})],[...CSV_COLUMNS,'evidence']),workspace(),{now});assert.equal(p.counts.ready,1);
  assert.match(reconciliationCsv(p),/"'=1\+1"/);assert.match(reconciliationCsv(p),/not chain-verified/);assert.equal(p.additions[0].evidence,undefined);validateWorkspace(applyReconciliation(p,workspace()));
});
