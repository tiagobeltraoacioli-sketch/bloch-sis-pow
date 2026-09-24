import { FIELDS, parseCSV } from './reconcile.v1.mjs';
import { getModule } from './modules.v1.mjs';
const row = (id, instrument, side, quantity, price, currency, amount) => [id,'2026-09-24','2026-09-25','DEMO-X','MEMBER-DEMO','ACCOUNT-DEMO',instrument,side,quantity,price,currency,amount].join(',');
const common = [row('DEMO-001','SAMPLE-A','BUY','100','12.50','USD','1250.00'),row('DEMO-002','SAMPLE-B','SELL','50','28','USD','1400'),row('DEMO-003','SAMPLE-C','BUY','300','5.25','BRL','1575')];
export const SAMPLE_A = FIELDS.join(',')+'\n'+[...common,row('DEMO-004','SAMPLE-A','BUY','100','12.5','USD','1250'),row('DEMO-005','SAMPLE-B','SELL','25','28','USD','700'),row('DEMO-006','SAMPLE-C','BUY','20','5.25','BRL','105'),row('DEMO-008','SAMPLE-A','BUY','10','12.5','USD','125'),row('DEMO-008','SAMPLE-A','BUY','10','12.5','USD','125')].join('\n')+'\n';
export const SAMPLE_B = FIELDS.join(',')+'\n'+[...common,row('DEMO-004','SAMPLE-A','BUY','110','12.5','USD','1375'),row('DEMO-005','SAMPLE-B','SELL','25','28','BRL','700'),row('DEMO-007','SAMPLE-C','SELL','40','5.25','BRL','210'),row('DEMO-008','SAMPLE-A','BUY','10','12.5','USD','125')].join('\n')+'\n';
export function samplesFor(config) {
  const module=getModule(config.module);
  let pair;
  if(config.module==='trades')pair=[SAMPLE_A,SAMPLE_B].map(text=>parseCSV(text).map(row=>row.values));
  else {
    const record=id=>config.module==='onchain'?{network:'bloch-genesis4',txid:id.toString(16).padStart(64,'0'),vout:'0',script_hash:'a'.repeat(64),value_sat:String(BigInt(id)*100000000n),block_id:'b'.repeat(64),height:'100',status:'INCLUDED'}:config.module==='cash'?{entry_id:`DEMO-${id}`,booking_date:'2026-09-24',value_date:'2026-09-24',entity:'ENTITY-DEMO',account:'ACCOUNT-DEMO',currency:config.region==='br'?'BRL':'USD',direction:id%2?'DEBIT':'CREDIT',amount:String(id*125)+'.50',rail:config.region==='br'?'PIX-EXAMPLE':'BANK-EXAMPLE',reference:`REF-${id}`,status:'BOOKED'}:{as_of_date:'2026-09-24',entity:'FUND-DEMO',account:'CUSTODY-DEMO',instrument:`ASSET-${id}`,currency:config.region==='br'?'BRL':'USD',quantity:String(id*100),unit_price:'12.50',market_value:String(id*1250)};
    const left=[1,2,3,4,5,6,8,8].map(record),right=[1,2,3,4,5,7,8].map(record);
    if(config.module==='onchain'){right[3].value_sat='400000001';right[4].block_id='c'.repeat(64);right[4].height='101';}
    else if(config.module==='cash'){right[3].amount='999.50';right[4].status='PENDING';}
    else {right[3].quantity='450';right[3].market_value='5625';right[4].unit_price='13';}
    pair=[left,right];
  }
  const quote=value=>'"'+String(value).replaceAll('"','""')+'"';
  return pair.map(records=>[module.fields.map(f=>config.column_mapping[f]??f),...records.map(r=>module.fields.map(f=>{
    const v=r[f];if(module.dates.includes(f)&&config.date_format==='dmy')return v.slice(8)+'/'+v.slice(5,7)+'/'+v.slice(0,4);
    if(Object.hasOwn(module.numbers,f)&&config.decimal_format==='comma')return v.replace('.',',');return v;
  }))].map(row=>row.map(quote).join(config.separator)).join('\n')+'\n');
}
