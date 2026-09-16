#!/usr/bin/env python3
"""Fund a public disposable wallet on an existing loopback BPOSLAB1 chain."""
import argparse,json,os,subprocess,time,urllib.request
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--wallet',type=Path,required=True);p.add_argument('--previous',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--rpc-port',type=int,default=19431);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
def rpc(method,params=[]):
 request=urllib.request.Request(f'http://127.0.0.1:{a.rpc_port}',data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json'})
 result=json.load(urllib.request.urlopen(request,timeout=15))
 if 'error' in result:raise RuntimeError(result['error'])
 return result['result']
def save(name,value):(a.output/name).write_text(json.dumps(value,indent=2)+'\n')
wallet=json.loads(a.wallet.read_text());previous=json.loads(a.previous.read_text());view=rpc('getnativewalletview');info=rpc('getchaininfo')
assert view['format']=='BPOSLAB1' and view['domain']==previous['native_domain']
coin=next(u for u in view['context']['utxos'] if u['txid']==previous['output_txid'] and u['vout']=='0')
assert coin['value']==previous['output_value']
command=[str(a.binary.resolve()),'native-lab-fixture','--kind','fund-wallet','--genesis',str(a.directory/'genesis.blg'),'--sponsor',str(a.directory/'validator'),'--committee',str(a.directory/'committee'),'--input-txid',coin['txid'],'--input-value',coin['value'],'--base-fee',str(info['next_base_fee_millisat_per_gas']),'--native-recipient-public-key',wallet['pubkeyHex'],'--fund-amount','10000000']
packet=json.loads(subprocess.check_output(command,env=dict(os.environ,BLOCH_KEYSTORE_ALLOW_PLAINTEXT='1')))
save('funding.wire.local.json',packet);save('before.view.local.json',view)
submitted=rpc('sendrawtransaction',[packet['hex']]);save('funding.submission.local.json',submitted)
for _ in range(150):
 status=rpc('gettxstatus',[packet['txid']]);current=rpc('getnativewalletview')
 outputs=[u for u in current['context']['utxos'] if u['txid']==packet['txid'] and u['scriptHash']==wallet['scriptHash'] and u['value']=='10000000']
 if status['status'] in ('included','justified','finalized') and outputs:
  save('funding.status.local.json',status);save('after.view.local.json',current);print(json.dumps({'funded':True,'txid':packet['txid'],'height':current['height'],'walletValue':'10000000'}));break
 time.sleep(1)
else:raise RuntimeError('funding remains unresolved; inspect saved packet and live node, do not retry')
