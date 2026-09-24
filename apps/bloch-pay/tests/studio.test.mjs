import test from 'node:test';
import assert from 'node:assert/strict';
import {buildRoute,applySampleEvent} from '../app/integrations.mjs';
import {STUDIO_KEY,CHECKS,emptyStudio,emptyReview,validatePartner,validateDraft,validateStudio,readStudio,saveStudio,planningGaps,studioSummary,replayRoute,routeForm} from '../app/studio-model.mjs';
const time='2026-09-24T12:00:00.000Z';
const partner=(changes={})=>({id:'origin-psav',name:'Example partner',role:'psav',jurisdiction:'Brazil',owner:'Operations',stage:'discovery',rails:['pix'],review:emptyReview(),note:'Local planning record',created_at:time,updated_at:time,...changes});
const documented=()=>Object.fromEntries(Object.keys(CHECKS).map(key=>[key,{state:'documented',reference:'evidence-'+key}]));
const form=(changes={})=>({sourceRail:'pix',sourceRole:'psav',sourcePartner:'origin-psav',sourceCurrency:'BRL',sourceCustom:'',destinationRail:'sepa',destinationRole:'bank',destinationPartner:'destination-bank',destinationCurrency:'EUR',destinationCustom:'',amount:'1000.01',destinationAmount:'200.01',quote:'quote-001',reference:'payment-001',...changes});
const draft=(changes={},id='draft-001')=>buildRoute(form(changes),id,time);
const route=(changes={})=>({draft:draft(),events:[],archived:false,updated_at:time,...changes});
const state=(changes={})=>({...emptyStudio(),partners:[partner()],routes:[route()],...changes});
test('directory records validate roles, declared rails and documentation references',()=>{
  assert.equal(validatePartner(partner({id:'Origin-PSAV'})).id,'origin-psav');
  assert.throws(()=>validatePartner(partner({review:{...emptyReview(),entity:{state:'documented',reference:''}}})),/evidence reference/);
  for(const value of [{rails:[]},{rails:['pix','pix']},{rails:['wire-fake']},{role:'licensed_by_bloch'},{stage:'live'},{updated_at:'2026-09-23T12:00:00.000Z'}])assert.throws(()=>validatePartner(partner(value)));
  assert.equal(Object.values(validatePartner(partner({review:documented()})).review).filter(r=>r.state==='documented').length,5);
});
test('canonical draft validation is independent of JSON property order',()=>{
  const original=draft();const reordered=Object.fromEntries(Object.entries(original).reverse());
  assert.deepEqual(validateDraft(reordered),original);assert.deepEqual(buildRoute(routeForm(original),original.id,original.created_at),original);
});
test('import rejects execution, settlement, currency and precision tampering',()=>{
  for(const change of [d=>d.execution_enabled=true,d=>d.settlement.status='settled',d=>d.source.currency='USD',d=>d.source.decimals=8,d=>d.source.amount_minor=100,d=>d.source.connection_status='connected',d=>d.destination.expected_amount_minor='0',d=>d.conversion.required=false]){const d=draft();change(d);assert.throws(()=>validateDraft(d));}
});
test('scenario persistence replays valid events while retaining design-only settlement',()=>{
  let sample=draft();for(const type of ['accepted','submitted','settled','credited','returned'])sample=applySampleEvent(sample,{id:'evt-'+type,type});
  const saved=validateStudio(state({routes:[route({events:sample.events})]}));const restored=replayRoute(saved.routes[0]);assert.equal(restored.sample_state,'returned');assert.equal(restored.settlement.status,'not_observed');assert.equal(restored.execution_enabled,false);
  assert.throws(()=>validateStudio(state({routes:[route({events:[{id:'evt-settled',type:'settled',authentication:'sample_only'}]})]})));
  assert.throws(()=>validateStudio(state({routes:[route({events:[{id:'evt-accepted',type:'accepted',authentication:'bank_verified'}]})]})));
});
test('planning gaps use case-insensitive references and expose role, rail and review mismatch',()=>{
  const d=draft({sourcePartner:'ORIGIN-PSAV',destinationAmount:'',quote:''});
  const gaps=planningGaps(d,[partner({role:'vasp',rails:['ach'],stage:'paused'})]);
  for(const code of ['role','rail','paused','entity','access','security','funding','operations','missing_partner','quote'])assert(gaps.some(g=>g.code===code),code);
  const good=[partner({review:documented()}),partner({id:'destination-bank',role:'bank',rails:['sepa'],review:documented()})];assert.equal(planningGaps(draft(),good).length,0);assert.equal(draft().execution_enabled,false);
});
test('connection summaries retain currency separation and exact large planned amounts',()=>{
  const routes=[route(),route({draft:draft({sourceRail:'blch',amount:'27000000000.00000001'},'draft-002')}),route({draft:draft({sourcePartner:'third-party'},'draft-003')})];
  const summary=studioSummary(state({routes}));assert.equal(summary.active,3);assert.equal(summary.edges.length,2);assert.equal(summary.edges.find(e=>e.source==='origin-psav').count,2);assert.equal(summary.nodes.length,3);assert.deepEqual(summary.currencies,[{currency:'BRL',minor:'200002'},{currency:'BLCH',minor:'2700000000000000001'}]);
});
test('archived drafts remain recoverable and stop contributing to active totals',()=>{
  const s=validateStudio(state({routes:[route({archived:true})]}));const summary=studioSummary(s);assert.equal(summary.active,0);assert.equal(summary.archived,1);assert.deepEqual(summary.edges,[]);assert.equal(s.routes[0].draft.payment_reference,'payment-001');
});
test('integration backup validation is bounded and excludes duplicate references',()=>{
  assert.throws(()=>readStudio(' '.repeat(2_000_001)));assert.throws(()=>readStudio('{broken'));assert.throws(()=>readStudio(JSON.stringify({schema:'bloch-pay-workspace'})));
  assert.throws(()=>validateStudio(state({partners:[partner(),partner({id:'ORIGIN-PSAV'})]})));assert.throws(()=>validateStudio(state({routes:[route(),route()]})));
  assert.throws(()=>validateStudio(state({partners:Array(201).fill(partner())})));assert.throws(()=>validateStudio(state({environment:'production'})));
  assert.equal(validateStudio({...state(),untrusted:'ignored'}).untrusted,undefined);
});
test('studio persistence refuses stale writes and keeps invoice storage untouched',()=>{
  const values=new Map([['bloch-pay-workspace-v1','invoice-content']]);const storage={getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value)};
  const first=saveStudio(storage,null,state());assert.equal(first.data.revision,1);assert.equal(values.get('bloch-pay-workspace-v1'),'invoice-content');
  assert.throws(()=>saveStudio(storage,null,emptyStudio()),/another tab/);assert.equal(values.get(STUDIO_KEY),first.serialized);
  storage.setItem=()=>{throw new Error('quota exceeded');};assert.throws(()=>saveStudio(storage,first.serialized,emptyStudio()),/quota/);assert.equal(values.get(STUDIO_KEY),first.serialized);
});
test('a confirmed valid import can recover corrupt studio storage',()=>{
  let data='{corrupt';const storage={getItem:()=>data,setItem:(key,value)=>{data=value;}};
  const saved=saveStudio(storage,data,state());assert.equal(saved.data.partners.length,1);assert.deepEqual(readStudio(data),saved.data);
});
