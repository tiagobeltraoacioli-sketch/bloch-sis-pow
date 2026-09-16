#!/usr/bin/env python3
"""Read-only quote and restarted context smoke against the local lab RPC."""
import argparse,importlib.util,json,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('source_lab',Path(__file__).with_name('native-source-process-lab.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=argparse.ArgumentParser();p.add_argument('--wallet',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--rpc-port',type=int,default=19431);a=p.parse_args();wallet=json.loads(a.wallet.read_text());url=f'http://127.0.0.1:{a.rpc_port}'
for _ in range(90):
 try:
  view=m.rpc(url,'getnativewalletview')['result']
  query={'operation':'create-pair','ownerPublicKeyHex':wallet['pubkeyHex'],'expectedHead':view['head'],'validUntil':str(int(view['height'])+100),'asset':'a23fd48ece6d8617c9cdf6f74b634aff5085e55188cfaebbdbe396440c78a275','seed':'2c'*32,'blchAmount':'1000000','nativeAmount':'60'}
  quote=m.rpc(url,'getnativepoolquote',[query])
  if 'error' in quote and 'head changed' in quote['error']['message']:continue
  assert 'result' in quote,quote
  q=quote['result'];assert q['head']==view['head'] and len(q['reserveId'])==64 and q['poolId'] is None
  assert q['transactionHex'].startswith('12') and q['feeSat'].isdigit()
  bad=dict(query,expectedHead='00'*32);assert 'error' in m.rpc(url,'getnativepoolquote',[bad])
  a.output.write_text(json.dumps({'query':query,'quote':q},indent=2)+'\n');print(json.dumps({'quoteReady':True,'height':q['height'],'reserveId':q['reserveId'],'feeSat':q['feeSat']}));break
 except (ConnectionError,OSError,KeyError):time.sleep(1)
else:raise RuntimeError('node quote did not become available')
