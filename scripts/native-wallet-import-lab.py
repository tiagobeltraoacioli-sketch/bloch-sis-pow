#!/usr/bin/env python3
"""Import the second verified local deposit to a disposable wallet, no new chain."""
import argparse,hashlib,importlib.util,json,os,subprocess,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('source_lab',Path(__file__).with_name('native-source-process-lab.py'));source_lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(source_lab)
p=argparse.ArgumentParser()
for name in ('directory','wallet','funding','source-manifest','source-compact','output','binary'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--rpc-port',type=int,default=19431);a=p.parse_args();manifest=json.loads(a.source_manifest.read_text());source=json.loads(a.source_compact.read_text());wallet=json.loads(a.wallet.read_text());funding=json.loads(a.funding.read_text())
assert manifest['environment']=='disposable-local-anvil' and manifest['publicDeployment'] is False and manifest['chainId']==31337
assert int(source['deposit_nonce'])==1 and source['pq_recipient_hash'].removeprefix('0x')==hashlib.sha256(bytes.fromhex(wallet['pubkeyHex'])).hexdigest()
def call(method,params=[],endpoint=None):
 reply=source_lab.rpc(endpoint or f'http://127.0.0.1:{a.rpc_port}',method,params)
 if 'error' in reply:raise RuntimeError(reply['error'])
 return reply['result']
assert call('eth_chainId',endpoint=manifest['rpc'])=='0x7a69'
assert call('eth_getBlockByNumber',['0x0',False],manifest['rpc'])['hash']==manifest['genesisHash']
receipt=call('eth_getTransactionReceipt',[source['source_txid']],manifest['rpc']);assert receipt['status']=='0x1'
assert call('eth_getBlockByNumber',[hex(int(source['source_height'])),False],manifest['rpc'])['hash']==source['source_block_hash']
code=call('eth_getCode',[source['vault'],'latest'],manifest['rpc']);assert '0x'+hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()==source['vault_runtime_sha256']
source_lab.validate_deposit(source,receipt)
view=call('getnativewalletview');assert view['format']=='BPOSLAB1' and view['domain']==source['native_domain'].removeprefix('0x')
report=call('getnativelabstate',[source['native_asset'],source['route_id']]);assert report['ledger']['supply']=='0' and report['ledger']['imported']=='100' and report['ledger']['burned']=='100'
coin=next(u for u in view['context']['utxos'] if u['txid']==funding['output_txid'] and u['vout']=='0');assert coin['value']==funding['output_value']
info=call('getchaininfo');command=[str(a.binary.resolve()),'native-lab-fixture','--kind','import','--genesis',str(a.directory/'genesis.blg'),'--sponsor',str(a.directory/'validator'),'--committee',str(a.directory/'committee'),'--base-fee',str(info['next_base_fee_millisat_per_gas']),'--input-txid',coin['txid'],'--input-value',coin['value'],'--native-recipient-public-key',wallet['pubkeyHex'],'--mint-nonce','1','--valid-until',str(int(view['height'])+512)]
for flag,field in [('source-domain','source_domain'),('token','token'),('vault','vault'),('vault-code-hash','vault_runtime_sha256'),('source-tx','source_txid'),('source-block','source_block_hash'),('event-index','event_index'),('deposit-nonce','deposit_nonce'),('deposit-sender','deposit_sender')]:command+=['--'+flag,str(source[field])]
packet=json.loads(subprocess.check_output(command,env=dict(os.environ,BLOCH_KEYSTORE_ALLOW_PLAINTEXT='1')))
assert packet['native_domain']==view['domain'] and packet['native_asset']==source['native_asset'].removeprefix('0x') and packet['route']==source['route_id'].removeprefix('0x') and packet['recipient_hash']==source['pq_recipient_hash'].removeprefix('0x')
a.output.mkdir(parents=True,exist_ok=False)
def save(name,value):(a.output/name).write_text(json.dumps(value,indent=2)+'\n')
save('import.wire.local.json',packet);save('source-deposit.local.json',receipt);save('source-compact.local.json',source)
submitted=call('sendrawtransaction',[packet['hex']]);save('import.submission.local.json',submitted)
for _ in range(150):
 status=call('gettxstatus',[packet['txid']]);report=call('getnativelabstate',[packet['native_asset'],packet['route']])
 if status['status'] in ('included','justified','finalized') and report['ledger']['supply']=='100' and report['ledger']['imported']=='200':
  save('import.status.local.json',status);save('import.state.local.json',report);save('after.view.local.json',call('getnativewalletview'));print(json.dumps({'imported':True,'txid':packet['txid'],'slot':report['slot'],'recipient':packet['recipient_hash']}));break
 time.sleep(1)
else:raise RuntimeError('import unresolved; inspect saved attempt, do not retry')
