import test from 'node:test';
import assert from 'node:assert/strict';
import {buildRoute} from '../app/integrations.mjs';
import {emptyStudio,emptyReview,validateStudio} from '../app/studio-model.mjs';
import {emptyModules,validateModules,integrationManifest,moduleLinks,validateRegistry,fetchRegistry,REGISTRY_URL} from '../app/participant-modules.mjs';
import {routeRows,actionQueue,networkView,corridorRows,operationsCsv} from '../app/operations.mjs';
const date='2026-09-24T12:00:00.000Z';
const partner=(id='origin-psav')=>({id,name:'Example participant',role:'psav',jurisdiction:'Brazil',owner:'Review team',stage:'discovery',rails:['pix'],review:emptyReview(),modules:emptyModules(),note:'',created_at:date,updated_at:date});
const route=(id,source='origin-psav',destination='destination-bank',changes={})=>({draft:buildRoute({reference:id,sourceRail:'pix',sourceRole:'psav',sourcePartner:source,sourceCurrency:'BRL',sourceCustom:'',destinationRail:'sepa',destinationRole:'bank',destinationPartner:destination,destinationCurrency:'EUR',destinationCustom:'',amount:'1000.01',destinationAmount:'',quote:'',...changes},id,date),archived:false,events:[],updated_at:date});
const state=(routes=[route('draft-001')])=>({...emptyStudio(),partners:[partner()],routes});
const registry=()=>({schema_version:1,registry_version:'test-1',source:'https://bloch-graphus.xyz/map',modules:[{id:'scores',title:'Private observations',description:'Descriptive indices',limits:'No AML verdict',status:'available',access:'private',assets:['BLCH'],links_by_asset:{BLCH:[{href:'https://untrusted.example/collect'}]}}]});
test('v1 backups migrate to v2 with all participant modules unselected',()=>{const old=state();old.version=1;old.partners[0].modules={enabled:['aml'],private_profile:'collect'};const migrated=validateStudio(old);assert.equal(migrated.version,2);assert.deepEqual(migrated.partners[0].modules,emptyModules());assert.deepEqual(migrated.routes,old.routes);});
test('module configuration requires purpose and scoped private access without granting it',()=>{
  assert.deepEqual(validateModules(),emptyModules());
  for(const change of [{enabled:['unknown']},{enabled:[['aml']]},{assets:[]},{assets:['ETH','ETH']},{enabled:['graphus']},{private_profile:['none']},{private_profile:'collect'},{enabled:['aml'],purpose:'Review',private_profile:'read'}])assert.throws(()=>validateModules({...emptyModules(),...change}));
  const p=partner();p.modules=validateModules({enabled:['aml','graphus','constellation','system_map'],assets:['BLCH','USDT'],purpose:'Public observations and authorized review',organization_reference:'org-ref',private_profile:'collect'});
  const manifest=integrationManifest(p);assert.equal(manifest.execution_enabled,false);assert.equal(manifest.private_access.authorization_status,'not_verified');assert.deepEqual(manifest.private_access.requested_scopes,['data:read','analyses:write','analyses:read','scores:read']);assert.equal(manifest.private_access.operations.at(-1).method,'POST');assert.equal(manifest.boundaries.automatic_screening,false);
  for(const group of manifest.launchers)for(const a of group.assets)for(const link of a.links){assert(!link.href.includes(p.id));assert(!link.href.includes('org-ref'));assert(!link.href.includes('scores:read'));}
  assert.equal(integrationManifest({...p,modules:{...p.modules,private_profile:'none'}}).private_access.operations.length,0);
});
test('fixed module links separate public evidence from private portal and reject unknown assets',()=>{assert.deepEqual(moduleLinks('constellation','SOL'),[]);assert.deepEqual(moduleLinks('injected','ETH'),[]);assert.equal(moduleLinks('aml','ETH').length,1);assert(moduleLinks('aml','ETH','read').some(x=>x.href==='https://rednblue.space/portal/?view=analyses'));});
test('registry parsing keeps availability separate from access and discards supplied navigation',()=>{const parsed=validateRegistry(registry());assert.equal(parsed.modules[0].access,'private');assert.equal(parsed.modules[0].links_by_asset,undefined);for(const altered of [{schema_version:2},{source:'https://evil.example'},{modules:[...registry().modules,...registry().modules]},{modules:[{...registry().modules[0],status:'connected'}]}])assert.throws(()=>validateRegistry({...registry(),...altered}));});
test('public capability reads omit credentials, refuse bad responses and bound bytes',async()=>{
  let request;const data=await fetchRegistry({fetcher:async(url,options)=>{request={url,options};return new Response(JSON.stringify(registry()),{headers:{'Content-Type':'application/json'}});}});assert.equal(data.modules.length,1);assert.equal(request.url,REGISTRY_URL);assert.equal(request.options.credentials,'omit');assert.equal(request.options.redirect,'error');assert.deepEqual(request.options.headers,{Accept:'application/json'});
  await assert.rejects(fetchRegistry({fetcher:async()=>new Response('{}',{status:502,headers:{'Content-Type':'application/json'}})}),/502/);
  await assert.rejects(fetchRegistry({fetcher:async()=>new Response('x'.repeat(1_000_001),{headers:{'Content-Type':'application/json'}})}),/1 MB/);
});
test('shared action queue deduplicates a participant requirement across both legs and drafts',()=>{
  const s=state([route('draft-001','origin-psav','origin-psav',{destinationRail:'pix',destinationRole:'psav'}),route('draft-002','origin-psav','origin-psav',{destinationRail:'pix',destinationRole:'psav'})]);s.partners[0].review.access.state='blocked';
  const rows=routeRows(s),actions=actionQueue(s,rows);assert.equal(rows.filter(r=>r.blocked).length,2);assert.equal(actions.length,5);assert.equal(actions[0].code,'access');assert.equal(actions[0].priority,'blocked');assert.equal(actions[0].routes.length,2);assert.equal(actions[0].owner,'Review team');
});
test('planning filters intersect partner and rail conditions and exclude archived records',()=>{
  const s=state([route('draft-001'),route('draft-002','third-party','destination-bank',{sourceRail:'ach'}),{...route('draft-003'),archived:true}]);assert.equal(routeRows(s).length,2);assert.equal(routeRows(s,{participant:'origin-psav',sourceRail:'ach'}).length,0);assert.equal(routeRows(s,{sourceRail:'ach'}).length,1);assert.equal(routeRows(s,{review:'documented'}).length,0);
});
test('network includes all 1000 references and direction focus keeps only adjacent drafts',()=>{
  const s=state(Array.from({length:500},(_,i)=>route('draft-'+i,'source-'+i,'dest-'+i)));const all=networkView(s,routeRows(s));assert.equal(all.nodes.length,1000);assert.equal(all.edges.length,500);
  const small=state([route('draft-one','alpha','beta'),route('draft-two','beta','alpha'),route('draft-three','beta','gamma')]);const rows=routeRows(small);assert.equal(networkView(small,rows,'alpha','incoming').edges[0].source,'beta');assert.equal(networkView(small,rows,'alpha','outgoing').edges[0].destination,'beta');assert.equal(networkView(small,rows,'alpha').active,2);assert.equal(networkView(small,rows,'missing').active,0);
});
test('corridor sums retain exact amounts and separate custom rails and destination currencies',()=>{
  const s=state([route('draft-001','origin-psav','bank-001',{sourceRail:'blch',amount:'27000000000.00000001'}),route('draft-002','origin-psav','bank-001',{sourceRail:'blch',amount:'0.00000001'}),route('draft-003','origin-psav','bank-001',{sourceRail:'other',sourceCurrency:'USD',sourceCustom:'wire-one'}),route('draft-004','origin-psav','bank-001',{sourceRail:'other',sourceCurrency:'USD',sourceCustom:'wire-two'})]);const groups=corridorRows(routeRows(s));assert.equal(groups.length,3);assert.equal(groups[0].amount,'2700000000000000002');assert.equal(groups[0].count,2);
});
test('planning CSV preserves exact decimals and labels sample state separately from execution',()=>{const s=state([route('draft-001','origin-psav','bank-001',{sourceRail:'blch',amount:'27000000000.00000001'})]);const csv=operationsCsv(routeRows(s));assert(csv.includes('27000000000.00000001'));assert(csv.includes('sample_state'));assert(csv.includes('execution_enabled'));assert(csv.includes('false'));});
