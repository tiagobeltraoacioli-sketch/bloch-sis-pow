import test from 'node:test';
import assert from 'node:assert/strict';
import {emptyWorkspace,parseAmount,formatAmount,validateWorkspace,readBackup,invoiceSummary,analytics,invoicesCSV,receiptsCSV,storeWorkspace,STORAGE_KEY,validDate,chartPercent} from '../app/model.mjs';
import {buildRoute,minorAmount,applySampleEvent,RAILS} from '../app/integrations.mjs';
const invoice=(changes={})=>({id:'invoice-1',reference:'INV-001',counterparty:'Example Ltd',direction:'receivable',amount:'10000000000',issued:'2026-09-01',due:'2026-09-20',recipient:'',note:'',state:'active',createdAt:'2026-09-01T12:00:00.000Z',...changes});
const receipt=(changes={})=>({id:'receipt-1',invoiceId:'invoice-1',reference:'REC-001',amount:'2500000000',date:'2026-09-22',txid:'',blockId:'',output:null,note:'',createdAt:'2026-09-22T12:00:00.000Z',...changes});
const workspace=(invoices=[invoice()],receipts=[])=>({...emptyWorkspace(),invoices,receipts});
test('exact BLCH values survive large holdings and one-satoshi round trips',()=>{
  for(const value of ['0.00000001','0.07','27000000000.00000001','100000000000'])assert.equal(formatAmount(parseAmount(value),false),value);
  assert.equal(parseAmount('27000000000.00000001'),'2700000000000000001');
  for(const value of ['0','-1','1e3','1,000','0.000000001','100000000001','1.','01.1','NaN'])assert.throws(()=>parseAmount(value));
});
test('partial, exact, excess and overdue records retain distinct balances',()=>{
  const i=invoice();
  assert.deepEqual(invoiceSummary(i,[receipt()],'2026-09-24'),{recorded:2500000000n,remaining:7500000000n,excess:0n,status:'partial',overdue:true});
  assert.equal(invoiceSummary(i,[receipt({amount:i.amount})]).status,'matched');
  const excess=invoiceSummary(i,[receipt({amount:'11000000000'})]);assert.equal(excess.status,'over-recorded');assert.equal(excess.remaining,0n);assert.equal(excess.excess,1000000000n);
  assert.equal(invoiceSummary(invoice({state:'void'}),[]).remaining,0n);
});
test('dates reject nonexistent days and backup records cannot be future-dated',()=>{
  assert.equal(validDate('2026-02-29'),false);assert.equal(validDate('2024-02-29'),true);assert.equal(validDate('2026-13-01'),false);
  assert.throws(()=>validateWorkspace(workspace([invoice({due:'2026-08-31'})])));
  assert.throws(()=>validateWorkspace(workspace([invoice()],[receipt({date:'2099-01-01'})])));
  assert.throws(()=>validateWorkspace(workspace([invoice()],[receipt({date:'2026-08-31'})])));
});
test('backup validation rejects duplicates, orphans and receipts against void invoices',()=>{
  assert.throws(()=>validateWorkspace(workspace([invoice(),invoice({id:'second',reference:'inv-001'})])));
  assert.throws(()=>validateWorkspace(workspace([],[receipt()])));
  assert.throws(()=>validateWorkspace(workspace([invoice({state:'void'})],[receipt()])));
  assert.throws(()=>validateWorkspace(workspace([invoice()],[receipt(),receipt({id:'second'})])));
});
test('transaction evidence requires a full output reference and rejects double counting',()=>{
  const linked=receipt({txid:'a'.repeat(64),blockId:'b'.repeat(64),output:0});
  assert.equal(validateWorkspace(workspace([invoice()],[linked])).receipts[0].output,0);
  assert.throws(()=>validateWorkspace(workspace([invoice()],[receipt({txid:'a'.repeat(64)})])));
  assert.throws(()=>validateWorkspace(workspace([invoice()],[linked,{...linked,id:'r2',reference:'REC-002'}])));
});
test('analytics keeps directions, aging buckets, excess and void states separate',()=>{
  const invoices=[invoice(),invoice({id:'i2',reference:'INV-002',direction:'payable',due:'2026-09-24',amount:'5000000000'}),invoice({id:'i3',reference:'INV-003',due:'2026-10-20',amount:'1000000000'}),invoice({id:'i4',reference:'INV-004',state:'void'})];
  const stats=analytics(invoices,[receipt()],'2026-09-24');
  assert.equal(stats.receivable,8500000000n);assert.equal(stats.payable,5000000000n);assert.equal(stats.overdue,7500000000n);assert.equal(stats.inflow,2500000000n);
  assert.deepEqual(stats.aging,[6000000000n,7500000000n,0n,0n]);assert.equal(stats.schedule[1].payable,5000000000n);assert.equal(stats.schedule[4].receivable,1000000000n);
  assert.equal(chartPercent(2700000000000000001n,5400000000000000002n),50);
});
test('CSV keeps decimal precision and neutralizes spreadsheet formulas',()=>{
  const w=workspace([invoice({counterparty:'=HYPERLINK("bad")',amount:'2700000000000000001',note:'+123'})],[receipt()]);
  const csv=invoicesCSV(w);assert(csv.includes('27000000000.00000001'));assert(csv.includes("'=HYPERLINK"));assert(csv.includes("'+123"));
  assert(receiptsCSV(w).includes('manually entered; not chain-verified'));
});
test('backup imports are bounded, typed, and discard undeclared properties',()=>{
  assert.throws(()=>readBackup('{bad'));assert.throws(()=>readBackup(' '.repeat(2_000_001)));assert.throws(()=>validateWorkspace({...emptyWorkspace(),asset:'USD'}));
  assert.throws(()=>validateWorkspace(workspace([invoice({amount:100})])));
  const restored=readBackup(JSON.stringify({...workspace(),untrusted:'ignored'}));assert.equal(restored.untrusted,undefined);
  assert.deepEqual(restored,workspace());
});
test('storage refuses stale writes, preserves quota failures and permits confirmed recovery',()=>{
  let data=null;const storage={getItem:key=>(assert.equal(key,STORAGE_KEY),data),setItem:(key,value)=>{data=value;}};
  const first=storeWorkspace(storage,null,workspace());assert.equal(first.data.revision,1);
  assert.throws(()=>storeWorkspace(storage,null,emptyWorkspace()),/another tab/);assert.equal(data,first.serialized);
  storage.setItem=()=>{throw new Error('QuotaExceededError');};assert.throws(()=>storeWorkspace(storage,first.serialized,emptyWorkspace()),/Quota/);assert.equal(data,first.serialized);
  storage.setItem=(key,value)=>{data=value;};data='{corrupt';assert.equal(storeWorkspace(storage,data,workspace()).data.invoices.length,1);
});
const routeForm=()=>({sourceRail:'pix',sourceRole:'psav',sourcePartner:'origin-psav',sourceCurrency:'BRL',sourceCustom:'',destinationRail:'sepa',destinationRole:'bank',destinationPartner:'destination-bank',destinationCurrency:'EUR',destinationCustom:'',amount:'1234.56',destinationAmount:'',quote:'',reference:'payment-001'});
test('partner drafts preserve exact amounts and never activate rail execution',()=>{
  const draft=buildRoute(routeForm(),'route-id','2026-09-24T12:00:00.000Z');assert.equal(draft.source.amount_minor,'123456');assert.equal(draft.destination.expected_amount_minor,null);assert.equal(draft.conversion.status,'quote_required');assert.equal(draft.execution_enabled,false);assert.equal(draft.source.connection_status,'not_connected');assert.equal(draft.source.rail_access,'via_qualified_financial_institution');assert.equal(draft.settlement.status,'not_observed');
});
test('all rail families and VASP/PSAV roles remain available with declared currencies',()=>{
  for(const key of Object.keys(RAILS)){const f={...routeForm(),sourceRail:key,sourceRole:'vasp',sourceCustom:'custom-rail',sourceCurrency:'JPY',amount:key==='other'?'1000':'1000.00'};if(key==='blch')f.amount='0.00000001';const draft=buildRoute(f);assert.equal(draft.source.rail,key);assert.equal(draft.source.partner_role,'vasp');}
  assert.equal(minorAmount('1000',0),'1000');assert.throws(()=>minorAmount('1000.1',0));assert.throws(()=>minorAmount('0.001',2));
});
test('cross-currency amounts require a quote reference without inventing an FX rate',()=>{
  assert.throws(()=>buildRoute({...routeForm(),destinationAmount:'200.00'}),/quote reference/);
  const d=buildRoute({...routeForm(),destinationAmount:'200.00',quote:'quote-provider-001'});assert.equal(d.destination.expected_amount_minor,'20000');assert.equal(d.conversion.status,'reference_supplied_unverified');assert.equal(d.conversion.rate,undefined);
  assert.throws(()=>buildRoute({...routeForm(),sourceRole:'__proto__'}));assert.throws(()=>buildRoute({...routeForm(),sourceRail:'constructor'}));
});
test('sample lifecycle enforces event order, idempotency, conflicts and post-settlement returns',()=>{
  let state=buildRoute(routeForm());assert.throws(()=>applySampleEvent(state,{id:'event-1',type:'settled'}));
  for(const type of ['accepted','submitted','settled','credited','returned'])state=applySampleEvent(state,{id:'event-'+type,type});
  assert.equal(state.sample_state,'returned');assert.equal(state.status,'draft');assert.equal(state.settlement.status,'not_observed');assert.equal(state.execution_enabled,false);
  assert.equal(applySampleEvent(state,{id:'event-returned',type:'returned'}),state);assert.throws(()=>applySampleEvent(state,{id:'event-returned',type:'failed'}),/conflict/);assert.throws(()=>applySampleEvent(state,{id:'another-event',type:'submitted'}));
});
