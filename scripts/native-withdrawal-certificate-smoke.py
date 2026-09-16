#!/usr/bin/env python3
"""Prepare and certify a local typed withdrawal; never sign as owner or broadcast."""
import argparse,copy,importlib.util,json,os,subprocess,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('source_lab',Path(__file__).with_name('native-source-process-lab.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=argparse.ArgumentParser()
for name in ('wallet','directory','binary','output'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--rpc-port',type=int,default=19431);a=p.parse_args();wallet=json.loads(a.wallet.read_text());url=f'http://127.0.0.1:{a.rpc_port}'
for _ in range(120):
 try:
  view=m.rpc(url,'getnativewalletview')['result'];request={'ownerPublicKeyHex':wallet['pubkeyHex'],'expectedHead':view['head'],'route':'44bc80e7c05bbe7dd2b0a84e4c27af848d8df9f5bdb17ed496ad74409646fa74','amount':'40','recipientHex20':'0f'*20,'nonce':'1','validUntil':str(int(view['height'])+128)}
  reply=m.rpc(url,'getnativewithdrawalquote',[request])
  if 'error' in reply and 'head changed' in reply['error']['message']:continue
  assert 'result' in reply,reply
  quote=reply['result'];assert quote['certificateRequired'] is True and quote['signingAvailable'] is False
  break
 except (OSError,KeyError):time.sleep(1)
else:raise RuntimeError('withdrawal RPC did not become available')
a.output.mkdir(exist_ok=False,parents=True)
request_file=a.output/'request.json';trusted_file=a.output/'trusted-view.json';cert_file=a.output/'certificate.json'
wrapper={'schema':'postern.native-lab-withdrawal-request.v1','quote':quote}
request_file.write_text(json.dumps(wrapper));trusted_file.write_text(json.dumps(m.rpc(url,'getnativewalletview')['result']))
command=[str(a.binary.resolve()),'native-lab-fixture','--kind','certify-withdrawal','--genesis',str(a.directory/'genesis.blg'),'--sponsor',str(a.directory/'validator'),'--committee',str(a.directory/'committee'),'--request',str(request_file),'--trusted-view',str(trusted_file)]
env=dict(os.environ,BLOCH_KEYSTORE_ALLOW_PLAINTEXT='1')
# A changed fee display must not be certified, even if all byte packets remain intact.
corrupt=copy.deepcopy(wrapper);corrupt['quote']['feeSat']=str(int(quote['feeSat'])+1);request_file.write_text(json.dumps(corrupt))
refused=subprocess.run(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);assert refused.returncode!=0 and not refused.stdout
request_file.write_text(json.dumps(wrapper))
certificate=json.loads(subprocess.check_output(command,env=env,timeout=30));assert certificate['authorizationHex']==quote['authorizationHex'] and certificate['domain']==view['domain'] and certificate['schema']=='postern.native-lab-withdrawal-certificate.v1'
cert_file.write_text(json.dumps(certificate,indent=2)+'\n')
summary={'prepared':True,'certified':True,'broadcast':False,'ownerSigned':False,'amount':request['amount'],'nonce':request['nonce'],'authorizationHex':certificate['authorizationHex'],'tamperedFeeRefused':True}
(a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
