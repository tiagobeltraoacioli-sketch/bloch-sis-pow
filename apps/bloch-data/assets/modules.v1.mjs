export const MODULES = {
  trades: {name:'Trades & executions',version:'trade-comparison.v1',fields:['record_id','trade_date','settlement_date','venue','member','account','instrument','side','quantity','price','currency','net_amount'],keys:['trade_date','venue','member','record_id'],dates:['trade_date','settlement_date'],numbers:{quantity:'positive',price:'nonnegative',net_amount:'signed'},enums:{side:['BUY','SELL']},dateOrder:['trade_date','settlement_date'],labels:['Venue / internal book','Clearing / comparison book'],note:'Trade-level comparison; no netting, partial-fill inference, currency conversion or corporate-action processing.'},
  cash: {name:'Cash & ledger entries',version:'cash-comparison.v1',fields:['entry_id','booking_date','value_date','entity','account','currency','direction','amount','rail','reference','status'],keys:['booking_date','entity','account','entry_id'],dates:['booking_date','value_date'],numbers:{amount:'nonnegative'},enums:{direction:['DEBIT','CREDIT'],status:['BOOKED','PENDING','REVERSED']},labels:['Internal cash ledger','Statement / external ledger'],note:'Entry-level comparison of reference, debit/credit direction, amount, dates, rail and status. No balance certification, netting or payment initiation. Value dates may precede booking dates.'},
  positions: {name:'Positions & custody',version:'position-comparison.v1',fields:['as_of_date','entity','account','instrument','currency','quantity','unit_price','market_value'],keys:['as_of_date','entity','account','instrument','currency'],dates:['as_of_date'],numbers:{quantity:'signed',unit_price:'nonnegative',market_value:'signed'},enums:{},labels:['Portfolio / position book','Custodian / comparison book'],note:'Snapshot-level comparison by date, entity, account, instrument and currency. Signed quantities support short positions. No independent valuation, NAV calculation, settlement certification or corporate-action processing.'},
  onchain: {name:'Bloch on-chain receipt observations',version:'bloch-receipt-comparison.v1',fields:['network','txid','vout','script_hash','value_sat','block_id','height','status'],keys:['network','txid','vout'],dates:[],numbers:{},integers:{vout:'4294967295',value_sat:'18446744073709551615',height:'18446744073709551615'},hex:['txid','script_hash','block_id'],enums:{status:['INCLUDED','FINALIZED']},labels:['Internal expected / retained outputs','Imported Bloch receipt observations'],note:'Read-only comparison of included-output observations in bloch-genesis4. Exact satoshis and block identities are compared; FINALIZED is an imported assertion, not a verified proof. No network fetch, source authentication, commitment binding, settlement authorization or transaction submission.'},
};
export const INSTITUTIONS = {
  exchange:{name:'Stock exchange / trading venue',module:'trades'}, bank:{name:'Bank / payment institution',module:'cash'}, broker:{name:'Broker / securities dealer',module:'trades'}, dtvm:{name:'DTVM / securities distributor',module:'trades'}, manager:{name:'Asset manager / fund',module:'positions'}, custodian:{name:'Custodian / administrator',module:'positions'}, other:{name:'Other financial-market participant',module:'cash'},
};
export const REGIONS = {
  global:{name:'Global / customizable',format:'iso',decimal:'dot',separator:',',note:'Choose the applicable jurisdictions, currency conventions, calendar and sector rules for your institution. GDPR applies where its territorial scope is met.'},
  br:{name:'LatAm / Brazil',format:'dmy',decimal:'comma',separator:';',note:'Brazilian date and decimal presets; local review of LGPD, ANPD, BCB/CMN and CVM scope. Pix, STR, B3 and Open Finance labels describe imported extracts only; no connection is activated.'},
  mx:{name:'LatAm / Mexico',format:'dmy',decimal:'dot',separator:',',note:'Review the current LFPDPPP and the institution-specific CNBV/Banxico requirements. SPEI labels are imported record metadata, not a live connector.'},
  co:{name:'LatAm / Colombia',format:'dmy',decimal:'comma',separator:';',note:'Review the applicable scope of Laws 1581/2012 and 1266/2008, SIC rules and Superintendencia Financiera requirements.'},
  cl:{name:'LatAm / Chile',format:'dmy',decimal:'comma',separator:';',note:'Review Law 19.628 and CMF obligations; prepare for Law 21.719, effective 1 December 2026. Effective dates require local review.'},
  ar:{name:'LatAm / Argentina',format:'dmy',decimal:'comma',separator:';',note:'Review Law 25.326 and institution-specific AAIP, BCRA and CNV requirements.'},
  latam:{name:'LatAm / other jurisdiction',format:'dmy',decimal:'comma',separator:';',note:'Custom country profile. Add local privacy, bank-secrecy, securities and supervisory requirements before institutional use. No common LatAm compliance determination is made.'},
};
export function getModule(id='trades') { if(!Object.hasOwn(MODULES,id))throw new Error('Unknown reconciliation module.');return MODULES[id]; }
export function validateConfig(input) {
  if(!input||typeof input!=='object'||Array.isArray(input))throw new Error('Configuration must be an object.');
  const allowed=['schema','module','institution','region','date_format','decimal_format','separator','column_mapping','purpose','jurisdiction','retention_policy','processing_region','gdpr_in_scope'];
  if(Object.keys(input).some(k=>!allowed.includes(k)))throw new Error('Unknown configuration field.');
  if(input.schema!=='bloch.data.module-config.v1')throw new Error('Unsupported configuration version.');
  if(typeof input.module!=='string')throw new Error('A module identifier is required.');
  const module=getModule(input.module);
  if(!Object.hasOwn(INSTITUTIONS,input.institution)||!Object.hasOwn(REGIONS,input.region))throw new Error('Unknown institution or region.');
  if(!['iso','dmy'].includes(input.date_format)||!['dot','comma'].includes(input.decimal_format)||![',',';'].includes(input.separator))throw new Error('Invalid date, decimal or delimiter configuration.');
  const mapping=input.column_mapping;
  if(!mapping||typeof mapping!=='object'||Array.isArray(mapping)||Object.keys(mapping).some(k=>!module.fields.includes(k)))throw new Error('Column mapping must use canonical module fields.');
  const columns=module.fields.map(f=>mapping[f]??f);
  if(columns.some(v=>typeof v!=='string'||!v.trim()||v!==v.trim()||v.length>80||/[\u0000-\u001f\u007f]/.test(v))||new Set(columns).size!==columns.length)throw new Error('Mapped column names must be unique, nonempty, single-line strings.');
  for(const f of ['purpose','jurisdiction','retention_policy','processing_region'])if(typeof input[f]!=='string'||input[f].length>240||/[\u0000-\u001f\u007f]/.test(input[f]))throw new Error(`Invalid configuration text: ${f}.`);
  if(typeof input.gdpr_in_scope!=='boolean')throw new Error('GDPR scope must be an explicit boolean.');
  return structuredClone(input);
}
export function defaultConfig(module='trades',region='global',institution='exchange') {
  const preset=REGIONS[region];
  return validateConfig({schema:'bloch.data.module-config.v1',module,institution,region,date_format:preset.format,decimal_format:preset.decimal,separator:preset.separator,column_mapping:{},purpose:'Reconciliation and audit evidence',jurisdiction:'',retention_policy:'',processing_region:'',gdpr_in_scope:false});
}
