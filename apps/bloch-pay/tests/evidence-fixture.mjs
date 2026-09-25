import {evidencePacket} from '../app/evidence-vendor/graphus-evidence.mjs';
import {emptyStudio,emptyReview} from '../app/studio-model.mjs';
import {buildRoute} from '../app/integrations.mjs';
export const NOW='2026-09-24T12:00:00.000Z';
export function sourcePage(asset='BLCH',count=2){
  const utxo=['BTC','BLCH'].includes(asset),reference=asset==='BTC'?'1ExamplePublicReferenceOnly1234':asset==='BLCH'?'a'.repeat(64):'0x'+'a'.repeat(40),other=asset==='BTC'?'1AnotherPublicReferenceOnly1234':asset==='BLCH'?'b'.repeat(64):'0x'+'b'.repeat(40),kind=asset==='BLCH'?'script_hash':'address',prefix=['ETH','USDT','USDC'].includes(asset)?'0x':'',tx=prefix+'c'.repeat(64),block=prefix+'d'.repeat(64);
  const a={id:`${asset}:${kind}:${reference}`,kind,address:reference},b={id:`${asset}:${kind}:${other}`,kind,address:other},t={id:`${asset}:transaction:${tx}`,kind:'transaction',txid:tx};
  return {status:'source-reported',asset,network:asset==='BLCH'?'bloch-mainnet':asset==='BTC'?'bitcoin-mainnet':'ethereum-mainnet',source:'Explicit synthetic test fixture',retrieved_at:NOW,anchor:{height:100,hash:block,finality:'test fixture only'},coverage:'Synthetic fixture for validation; no live chain claim',scope:{transactions_returned:1},nodes:utxo?[a,b,t]:[a,b],edges:Array.from({length:count},(_,i)=>({event_id:'event-'+i,from:utxo?(i%2?t.id:a.id):a.id,to:utxo?(i%2?b.id:t.id):b.id,kind:utxo?(asset==='BTC'?(i%2?'created_output':'observed_input_prevout'):(i%2?'observed_created_output':'observed_spent_outpoint_reference')):asset==='ETH'?'native_value':'erc20_transfer',amount_base_units:i===0?'2700000000000000001':String(i+1),txid:tx,block_number:100,block_hash:block,position:i})),next_cursor:null};
}
export const packet=async(asset='BLCH',count=2)=>evidencePacket(sourcePage(asset,count),asset);
export function configuredStudio(){
  const participant={id:'origin-psav',name:'Fixture participant',role:'psav',jurisdiction:'Brazil',owner:'Review team',stage:'discovery',rails:['pix'],review:emptyReview(),modules:{enabled:['graphus','aml','system_map'],assets:['BLCH','ETH','BTC'],purpose:'Explicit synthetic browser verification',organization_reference:'',private_profile:'none'},note:'',created_at:NOW,updated_at:NOW};
  const draft=buildRoute({reference:'payment-fixture',sourceRail:'pix',sourceRole:'psav',sourcePartner:participant.id,sourceCurrency:'BRL',sourceCustom:'',destinationRail:'sepa',destinationRole:'bank',destinationPartner:'destination-bank',destinationCurrency:'EUR',destinationCustom:'',amount:'1000.01',destinationAmount:'',quote:''},'route-fixture',NOW);
  return {...emptyStudio(),partners:[participant],routes:[{draft,archived:false,events:[],updated_at:NOW}]};
}
