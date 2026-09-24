export const RAILS = Object.freeze({
  pix:{name:'Pix',currency:'BRL',decimals:2,settlement:'Partner-reported Pix settlement; SPI or the participant’s books, as applicable.'},
  sepa:{name:'SEPA Credit Transfer',currency:'EUR',decimals:2,settlement:'Settlement evidence from the participating PSP and its clearing and settlement arrangement.'},
  sepa_instant:{name:'SEPA Instant Credit Transfer',currency:'EUR',decimals:2,settlement:'Instant-credit-transfer status and settlement evidence from the participating PSP.'},
  ach:{name:'ACH credit',currency:'USD',decimals:2,settlement:'ACH operator / financial-institution settlement evidence, with returns tracked separately.'},
  blch:{name:'Bloch native',currency:'BLCH',decimals:8,settlement:'Qualified Bloch transaction evidence; does not establish settlement of a fiat leg.'},
  other:{name:'Other partner rail',currency:null,decimals:null,settlement:'Settlement rules, currencies and access to be specified by the responsible partner.'}
});
export const ROLES = Object.freeze({bank:'Bank / settlement institution',psp:'Payment service provider',vasp:'VASP',psav:'PSAV',custodian:'Custodian',fx:'FX provider',liquidity:'Liquidity provider',infrastructure:'Payment infrastructure provider'});
const CURRENCIES={BRL:2,EUR:2,USD:2,GBP:2,CHF:2,CAD:2,AUD:2,MXN:2,JPY:0,BLCH:8};
const reference=(input,label)=>{if(typeof input!=='string'||!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,79}$/.test(input))throw new Error(`${label} must contain 3–80 letters, digits, dots, underscores or hyphens.`);return input;};
function leg(railKey,roleKey,partner,currency,custom){
  if(!Object.hasOwn(RAILS,railKey)||!Object.hasOwn(ROLES,roleKey))throw new Error('Select a supported rail and participant role.');
  const rail=RAILS[railKey];const asset=rail.currency||currency;
  if(!Object.hasOwn(CURRENCIES,asset)||(railKey==='other'&&asset==='BLCH'))throw new Error('Select a supported fiat currency for the custom rail.');
  return {partner_reference:reference(partner,'Partner reference'),partner_role:roleKey,rail:railKey,custom_rail_reference:railKey==='other'?reference(custom,'Custom rail reference'):null,currency:asset,decimals:CURRENCIES[asset],connection_status:'not_connected',rail_access:railKey==='blch'?'native_asset_leg':'via_qualified_financial_institution',settlement_partner_reference:null,settlement_authority:'responsible_partner'};
}
export function minorAmount(input,decimals){
  if(typeof input!=='string'||!/^\d{1,12}(\.\d{1,8})?$/.test(input)||/^0\d/.test(input))throw new Error('Use a positive amount without grouping separators.');
  const [whole,fraction='']=input.split('.');if(fraction.length>decimals)throw new Error(`This currency allows ${decimals} decimal places.`);
  const amount=BigInt(whole)*10n**BigInt(decimals)+BigInt(fraction.padEnd(decimals,'0')||'0');if(amount<=0n||amount>100_000_000_000n*10n**BigInt(decimals))throw new Error('Amount is outside the planner range.');return amount.toString();
}
export function buildRoute(form,id=crypto.randomUUID(),now=new Date().toISOString()){
  const source=leg(form.sourceRail,form.sourceRole,form.sourcePartner,form.sourceCurrency,form.sourceCustom);
  const destination=leg(form.destinationRail,form.destinationRole,form.destinationPartner,form.destinationCurrency,form.destinationCustom);
  const amount=minorAmount(form.amount,source.decimals);
  const conversion=source.currency!==destination.currency;
  const expected=form.destinationAmount?minorAmount(form.destinationAmount,destination.decimals):null;
  const quote=form.quote?reference(form.quote,'Quote reference'):null;
  if(conversion&&expected&&!quote)throw new Error('Add a partner quote reference for the destination amount, or leave the destination amount blank until quoted.');
  if(!conversion&&quote)throw new Error('A conversion quote is only applicable when the currencies differ.');
  return {schema:'bloch-pay-integration-draft',version:1,id,created_at:now,environment:'design',execution_enabled:false,status:'draft',payment_reference:reference(form.reference,'Payment reference'),source:{...source,amount_minor:amount},destination:{...destination,expected_amount_minor:expected},conversion:{required:conversion,status:conversion?(quote?'reference_supplied_unverified':'quote_required'):'not_required',partner_quote_reference:quote},settlement:{status:'not_observed',beneficiary_credit:'not_observed',source_evidence:null,destination_evidence:null,return_status:'not_observed'},requirements:['Confirm participant eligibility, permissions and corridor coverage.','Agree settlement accounts, safeguarding or custody responsibilities and funding.','Obtain partner FX, asset-conversion, fee and liquidity terms where needed.','Map identity, screening and applicable Travel Rule responsibilities.','Implement authenticated server-side adapters, signed events and replay protection.','Reconcile source settlement, destination settlement, beneficiary credit and returns.']};
}
// A design contract: this state reducer validates sample events; it does not authenticate them.
export function applySampleEvent(state,event){
  if(!state||state.environment!=='design'||state.execution_enabled!==false)throw new Error('Only design scenarios are supported.');
  if(!event||!['accepted','submitted','settled','credited','failed','returned'].includes(event.type)||typeof event.id!=='string'||!/^[a-zA-Z0-9_.-]{3,80}$/.test(event.id))throw new Error('Invalid sample event.');
  const prior=state.events||[];
  const replay=prior.find(e=>e.id===event.id);
  if(replay){if(replay.type!==event.type)throw new Error('Event identifier conflict.');return state;}
  const allowed={draft:['accepted','failed'],accepted:['submitted','failed'],submitted:['settled','failed','returned'],settled:['credited','returned'],credited:['returned'],returned:[],failed:[]};
  const current=state.sample_state||'draft';
  if(!allowed[current]?.includes(event.type))throw new Error(`Cannot move from ${current} to ${event.type}.`);
  return {...state,sample_state:event.type,events:[...prior,{id:event.id,type:event.type,authentication:'sample_only'}]};
}
