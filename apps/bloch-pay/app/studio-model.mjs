import {RAILS,ROLES,buildRoute,applySampleEvent} from './integrations.mjs';
export const STUDIO_KEY='bloch-pay-integration-workspace-v1';
export const STAGES=Object.freeze({exploring:'Exploring',discovery:'Discovery',technical_review:'Technical review',sandbox:'Sandbox planning',paused:'Paused'});
export const CHECKS=Object.freeze({entity:'Entity and corridor scope',access:'Rail access and settlement partner',security:'Adapter authentication and events',funding:'Funding, liquidity and conversion',operations:'Reconciliation, returns and recovery'});
export const REVIEW_STATES=Object.freeze({not_started:'Not started',in_review:'In review',documented:'Documented',blocked:'Blocked'});
const fail=message=>{throw new Error(message);};
const text=(value,label,max,optional=false)=>{if(typeof value!=='string'||value.trim().length>max||(!optional&&!value.trim())||/[\u0000-\u001f]/.test(value))fail(`Invalid ${label}.`);return value.trim();};
const reference=(value,label)=>{if(typeof value!=='string'||!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,79}$/.test(value))fail(`Invalid ${label}. Use 3–80 letters, digits, dots, underscores or hyphens.`);return value;};
const time=value=>{if(typeof value!=='string'||!/^20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)||!Number.isFinite(Date.parse(value))||new Date(value).toISOString()!==value)fail('Invalid saved timestamp.');return value;};
const choice=(value,options,label)=>{if(typeof value!=='string'||!Object.hasOwn(options,value))fail(`Invalid ${label}.`);return value;};
export function emptyStudio(){return {schema:'bloch-pay-integration-workspace',version:1,environment:'design',execution_enabled:false,revision:0,partners:[],routes:[]};}
export function emptyReview(){return Object.fromEntries(Object.keys(CHECKS).map(key=>[key,{state:'not_started',reference:''}]));}
export function validatePartner(input){
  if(!input||!Array.isArray(input.rails)||!input.rails.length||input.rails.length>Object.keys(RAILS).length||new Set(input.rails).size!==input.rails.length)fail('Select at least one distinct rail for this partner.');
  const review={};
  for(const key of Object.keys(CHECKS)){const item=input.review?.[key];if(!item)fail('Partner review is incomplete.');const state=choice(item.state,REVIEW_STATES,'review state'),ref=text(item.reference,'evidence reference',180,true);if(state==='documented'&&!ref)fail(`Add an evidence reference for “${CHECKS[key]}”.`);review[key]={state,reference:ref};}
  const result={id:reference(input.id,'partner reference').toLowerCase(),name:text(input.name,'partner name',120),role:choice(input.role,ROLES,'participant role'),jurisdiction:text(input.jurisdiction,'jurisdiction',80),owner:text(input.owner,'owner/team',120,true),stage:choice(input.stage,STAGES,'stage'),rails:input.rails.map(rail=>choice(rail,RAILS,'rail')).sort(),review,note:text(input.note,'partner note',500,true),created_at:time(input.created_at),updated_at:time(input.updated_at)};
  if(result.updated_at<result.created_at)fail('Partner update predates its creation.');return result;
}
export function decimalFromMinor(value,decimals){
  if(typeof value!=='string'||!/^[1-9]\d{0,19}$/.test(value)||![0,2,8].includes(decimals))fail('Invalid saved amount or currency scale.');
  const str=value.padStart(decimals+1,'0');return decimals?str.slice(0,-decimals)+'.'+str.slice(-decimals):str;
}
export function routeForm(draft){return {reference:draft.payment_reference,sourceRail:draft.source.rail,sourceRole:draft.source.partner_role,sourcePartner:draft.source.partner_reference,sourceCurrency:draft.source.currency,sourceCustom:draft.source.custom_rail_reference||'',destinationRail:draft.destination.rail,destinationRole:draft.destination.partner_role,destinationPartner:draft.destination.partner_reference,destinationCurrency:draft.destination.currency,destinationCustom:draft.destination.custom_rail_reference||'',amount:decimalFromMinor(draft.source.amount_minor,draft.source.decimals),destinationAmount:draft.destination.expected_amount_minor===null?'':decimalFromMinor(draft.destination.expected_amount_minor,draft.destination.decimals),quote:draft.conversion.partner_quote_reference||''};}
function sameKnown(input,expected){if(expected===null||typeof expected!=='object')return input===expected;if(!input||typeof input!=='object'||Array.isArray(input)!==Array.isArray(expected))return false;if(Array.isArray(expected)&&input.length!==expected.length)return false;return Object.entries(expected).every(([key,value])=>Object.hasOwn(input,key)&&sameKnown(input[key],value));}
export function validateDraft(input){
  if(!input||input.schema!=='bloch-pay-integration-draft'||input.version!==1||input.environment!=='design'||input.execution_enabled!==false||!input.source||!input.destination||!input.conversion)fail('Only non-executable Bloch Pay integration drafts are supported.');
  const rebuilt=buildRoute(routeForm(input),reference(input.id,'draft identifier'),time(input.created_at));
  if(!sameKnown(input,rebuilt))fail('Draft contains inconsistent currency, connection or settlement fields.');return rebuilt;
}
export function replayRoute(route){let sample=route.draft;for(const event of route.events)sample=applySampleEvent(sample,event);return sample;}
export function validateStudio(input){
  if(!input||input.schema!=='bloch-pay-integration-workspace'||input.version!==1||input.environment!=='design'||input.execution_enabled!==false)fail('This is not a supported integration workspace backup.');
  if(!Number.isSafeInteger(input.revision)||input.revision<0||input.revision>Number.MAX_SAFE_INTEGER-10)fail('Invalid studio revision.');
  if(!Array.isArray(input.partners)||input.partners.length>200||!Array.isArray(input.routes)||input.routes.length>500)fail('The studio limit is 200 partners and 500 saved routes.');
  const partners=input.partners.map(validatePartner),ids=new Set();for(const p of partners){if(ids.has(p.id))fail('Duplicate partner reference.');ids.add(p.id);}
  const routeIds=new Set();
  const routes=input.routes.map(r=>{
    if(!r||typeof r.archived!=='boolean'||!Array.isArray(r.events)||r.events.length>20)fail('Invalid saved route.');
    const draft=validateDraft(r.draft);if(routeIds.has(draft.id))fail('Duplicate saved route.');routeIds.add(draft.id);
    const updated_at=time(r.updated_at);if(updated_at<draft.created_at)fail('Route update predates its creation.');
    let sample=draft;for(const event of r.events){if(!event||event.authentication!=='sample_only')fail('Saved scenarios must contain sample events only.');sample=applySampleEvent(sample,{id:reference(event.id,'sample event identifier'),type:event.type});}
    return {draft,events:sample.events||[],archived:r.archived,updated_at};
  });
  return {...emptyStudio(),revision:input.revision,partners,routes};
}
export function readStudio(raw){if(typeof raw!=='string'||new TextEncoder().encode(raw).length>2_000_000)fail('Integration backup must be smaller than 2 MB.');let parsed;try{parsed=JSON.parse(raw);}catch{fail('Integration backup is not valid JSON.');}return validateStudio(parsed);}
export function saveStudio(storage,previous,next){
  if(storage.getItem(STUDIO_KEY)!==previous)fail('The studio changed in another tab. Reload before saving.');
  const data=validateStudio(next);let revision=0;if(previous){try{revision=readStudio(previous).revision;}catch{/* Confirmed import can recover unreadable local data. */}}
  data.revision=revision+1;const serialized=JSON.stringify(data);if(new TextEncoder().encode(serialized).length>2_000_000)fail('The integration workspace exceeds 2 MB.');storage.setItem(STUDIO_KEY,serialized);return {data,serialized};
}
export function planningGaps(draft,partners){
  const gaps=[];for(const side of ['source','destination']){const leg=draft[side],partner=partners.find(p=>p.id===leg.partner_reference.toLowerCase()),label=side==='source'?'Origin':'Destination';if(!partner){gaps.push({side,code:'missing_partner',message:`${label}: partner is not in the local directory.`});continue;}if(partner.role!==leg.partner_role)gaps.push({side,code:'role',message:`${label}: selected role differs from the directory.`});if(!partner.rails.includes(leg.rail))gaps.push({side,code:'rail',message:`${label}: rail is outside the partner's declared coverage.`});if(partner.stage==='paused')gaps.push({side,code:'paused',message:`${label}: partner planning is paused.`});for(const [key,item]of Object.entries(partner.review))if(item.state!=='documented')gaps.push({side,code:key,message:`${label}: ${CHECKS[key].toLowerCase()} is ${REVIEW_STATES[item.state].toLowerCase()}.`});}
  if(draft.conversion.required&&!draft.conversion.partner_quote_reference)gaps.push({side:'conversion',code:'quote',message:'Conversion: a partner quote reference is missing.'});return gaps;
}
export function studioSummary(state){
  const active=state.routes.filter(r=>!r.archived),edges=new Map(),nodes=new Map(),currencies=new Map();
  for(const r of active){const d=r.draft,source=d.source.partner_reference.toLowerCase(),destination=d.destination.partner_reference.toLowerCase();for(const id of [source,destination])nodes.set(id,state.partners.find(p=>p.id===id)?.name||id);const key=source+'\0'+destination;const edge=edges.get(key)||{source,destination,count:0};edge.count++;edges.set(key,edge);const currency=d.source.currency;currencies.set(currency,(currencies.get(currency)||0n)+BigInt(d.source.amount_minor));}
  return {partners:state.partners.length,active:active.length,archived:state.routes.length-active.length,withGaps:active.filter(r=>planningGaps(r.draft,state.partners).length>0).length,nodes:[...nodes].map(([id,name])=>({id,name})),edges:[...edges.values()],currencies:[...currencies].map(([currency,minor])=>({currency,minor:minor.toString()}))};
}
