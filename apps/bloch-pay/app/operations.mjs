import {planningGaps,studioSummary,CHECKS,REVIEW_STATES} from './studio-model.mjs';
import {RAILS} from './integrations.mjs';
import {csvCell} from './model.mjs';
export const PRIORITIES={blocked:'Blocked planning item',attention:'Needs definition',review:'Documentation review'};
export function routeRows(state,filters={}){
  return state.routes.filter(route=>!route.archived).map(route=>{
    const gaps=planningGaps(route.draft,state.partners);
    const blocked=gaps.some(g=>g.code==='paused'||state.partners.find(p=>p.id===route.draft[g.side]?.partner_reference?.toLowerCase())?.review[g.code]?.state==='blocked');
    return {route,gaps,blocked};
  }).filter(({route:{draft:d},gaps,blocked})=>(!filters.participant||[d.source,d.destination].some(leg=>leg.partner_reference.toLowerCase()===filters.participant))&&(!filters.sourceRail||d.source.rail===filters.sourceRail)&&(!filters.destinationRail||d.destination.rail===filters.destinationRail)&&(!filters.review||filters.review==='blocked'&&blocked||filters.review==='gaps'&&gaps.length>0||filters.review==='documented'&&!gaps.length));
}
export function actionQueue(state,rows){
  const actions=new Map();
  for(const {route,gaps}of rows)for(const gap of gaps){
    const leg=route.draft[gap.side],id=leg?.partner_reference?.toLowerCase()||'',partner=state.partners.find(p=>p.id===id);
    const priority=gap.code==='paused'||partner?.review[gap.code]?.state==='blocked'?'blocked':['missing_partner','role','rail','quote'].includes(gap.code)?'attention':'review';
    const context=gap.code==='role'?leg.partner_role:gap.code==='rail'?leg.rail:gap.code==='quote'?route.draft.id:'';
    const key=[id,gap.code,context].join('|');
    const item=actions.get(key)||{key,participant:id,owner:partner?.owner||'Unassigned',priority,code:gap.code,message:CHECKS[gap.code]?`${CHECKS[gap.code]}: ${REVIEW_STATES[partner.review[gap.code].state]}`:gap.message.replace(/^(Origin|Destination|Conversion): /,''),routes:new Set(),known:!!partner};
    item.routes.add(route.draft.id);actions.set(key,item);
  }
  const order={blocked:0,attention:1,review:2};
  return [...actions.values()].map(a=>({...a,routes:[...a.routes]})).sort((a,b)=>order[a.priority]-order[b.priority]||b.routes.length-a.routes.length||a.key.localeCompare(b.key));
}
export function networkView(state,rows,focus='',direction='both'){
  const routes=rows.map(row=>row.route).filter(r=>!focus||(direction!=='incoming'&&r.draft.source.partner_reference.toLowerCase()===focus)||(direction!=='outgoing'&&r.draft.destination.partner_reference.toLowerCase()===focus));
  const summary=studioSummary({...state,routes});
  return {...summary,nodes:summary.nodes.map(node=>({...node,registered:state.partners.some(p=>p.id===node.id),incoming:summary.edges.filter(edge=>edge.destination===node.id).length,outgoing:summary.edges.filter(edge=>edge.source===node.id).length}))};
}
export function corridorRows(rows){
  const groups=new Map();
  for(const {route:{draft:d},gaps}of rows){const keys=[d.source.rail,d.source.custom_rail_reference,d.source.currency,d.destination.rail,d.destination.custom_rail_reference,d.destination.currency],key=JSON.stringify(keys);const group=groups.get(key)||{key,source:RAILS[d.source.rail].name+(d.source.custom_rail_reference?' / '+d.source.custom_rail_reference:''),destination:RAILS[d.destination.rail].name+(d.destination.custom_rail_reference?' / '+d.destination.custom_rail_reference:''),currency:d.source.currency,destinationCurrency:d.destination.currency,decimals:d.source.decimals,count:0,withGaps:0,amount:0n};group.count++;group.withGaps+=gaps.length?1:0;group.amount+=BigInt(d.source.amount_minor);groups.set(key,group);}
  return [...groups.values()].map(g=>({...g,amount:g.amount.toString()}));
}
export function formatMinor(value,decimals){if(value===null)return 'Not specified';const padded=value.padStart(decimals+1,'0');return decimals?padded.slice(0,-decimals)+'.'+padded.slice(-decimals):padded;}
export function operationsCsv(rows){
  const values=[['environment','payment_reference','draft_id','source_partner','source_rail','source_currency','source_amount','destination_partner','destination_rail','destination_currency','expected_destination_amount','planning_gaps','blocked_planning','sample_state','execution_enabled']];
  for(const {route:{draft:d,events},gaps,blocked}of rows)values.push(['design',d.payment_reference,d.id,d.source.partner_reference,d.source.rail,d.source.currency,formatMinor(d.source.amount_minor,d.source.decimals),d.destination.partner_reference,d.destination.rail,d.destination.currency,d.destination.expected_amount_minor===null?'':formatMinor(d.destination.expected_amount_minor,d.destination.decimals),gaps.length,blocked,events.at(-1)?.type||'draft',false]);
  return values.map(row=>row.map(csvCell).join(',')).join('\r\n');
}
