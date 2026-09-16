#!/usr/bin/env python3
"""Observe one laboratory pool after restart; never submits a transaction."""
import argparse,importlib.util,json,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('source_lab',Path(__file__).with_name('native-source-process-lab.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=argparse.ArgumentParser();p.add_argument('--pool',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--expected-reserves',nargs=2,required=True);p.add_argument('--rpc-port',type=int,default=19431);a=p.parse_args();url=f'http://127.0.0.1:{a.rpc_port}'
for _ in range(120):
 try:
  reply=m.rpc(url,'getnativepool',[a.pool])
  assert 'result' in reply,reply
  result=reply['result'];assert result['format']=='BPOSLAB1' and result['poolId']==a.pool and result['reserves']==a.expected_reserves and result['custody']=='locked-pool-reserves'
  assert all(isinstance(result[k],str) and result[k].isdigit() for k in ('height','revision','lpTotal','feeBps'))
  a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));break
 except (ConnectionError,OSError):time.sleep(1)
else:raise RuntimeError('pool RPC did not become available')
