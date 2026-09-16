#!/usr/bin/env python3
"""Independently inspect a finalized local withdrawal; never submit or sign."""
import argparse,importlib.util,json,subprocess
from pathlib import Path
spec=importlib.util.spec_from_file_location('source_lab',Path(__file__).with_name('native-source-process-lab.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=argparse.ArgumentParser()
for name in ('report','genesis','binary','output'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--txid',required=True);p.add_argument('--rpc-port',type=int,default=19431);a=p.parse_args()
report=json.loads(a.report.read_text());assert report['sends']==1 and report['finalized'] is True
records=[r for r in report['records'] if r['txid']==a.txid];assert len(records)==1
url=f'http://127.0.0.1:{a.rpc_port}';a.output.mkdir(parents=True,exist_ok=True)
def save(name,value):
 path=a.output/name;path.write_text(json.dumps(value,indent=2)+'\n');return path
packet=save('withdrawal-signed-packet.json',{'transactionHex':records[0]['transactionHex']})
view=m.rpc(url,'getnativewalletview')['result'];viewpath=save('withdrawal-post-view.json',view)
inspection=json.loads(subprocess.check_output([str(a.binary.resolve()),'native-lab-fixture','--kind','inspect-withdrawal','--genesis',str(a.genesis),'--request',str(packet),'--trusted-view',str(viewpath)],timeout=30))
assert inspection['transaction_id']==a.txid and inspection['nonce']=='1' and inspection['amount']=='40' and inspection['recipient']=='0x'+'0f'*20
assert inspection['route_id']=='0x44bc80e7c05bbe7dd2b0a84e4c27af848d8df9f5bdb17ed496ad74409646fa74'
assert inspection['native_domain']=='0x5891725d15178d25c6ac1b933cc6d21507a95e67b132f5ac0ace325fe9587673'
status=m.rpc(url,'gettxstatus',[a.txid]);save('withdrawal-fresh-status.json',status);assert status['result']['status']=='finalized',status
ledger=m.rpc(url,'getnativelabstate',['a23fd48ece6d8617c9cdf6f74b634aff5085e55188cfaebbdbe396440c78a275',inspection['route_id'][2:]])
save('withdrawal-fresh-ledger.json',ledger)
state=ledger['result']['ledger'];assert state['supply']=='60' and state['imported']=='200' and state['burned']=='140' and state['next_release_nonce']==2
save('withdrawal-inspection.json',inspection)
print(json.dumps({'inspection':inspection,'ledger':ledger,'status':status}))
