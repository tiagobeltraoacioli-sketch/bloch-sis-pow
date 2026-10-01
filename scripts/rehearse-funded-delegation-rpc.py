#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Finite funded-delegation activation and full CLI/RPC lifecycle on loopback.

Requires explicitly lab-only binaries: finite current-regime gates at 1/2,
funded delegation at epoch 8 in the candidate and unarmed in the baseline.
All keys and balances are newly generated here. Never reads production keys.
Real cooldown and withdrawal delays remain unchanged; only slot cadence shrinks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import statistics
import subprocess
import time
import urllib.request
import urllib.error


def main():
    # SSH-launched Python may inherit ignored SIGINT. Ensure a controlled stop
    # always reaches the owned-child cleanup and leaves a non-passing report.
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"rehearsal interrupted by signal {signum}")
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate', 'baseline', 'work'):
        ap.add_argument('--'+name, type=Path, required=True)
    ap.add_argument('--port-base', type=int, default=29600)
    ap.add_argument('--slot-ms', type=int, default=25)
    ap.add_argument('--validators', type=int, choices=[1,3], default=3)
    ap.add_argument('--activation-only', action='store_true')
    args = ap.parse_args()
    if args.validators == 1 and not args.activation_only:
        ap.error("the full lifecycle needs three proposers to include one another's exhausted RANDAO renewals")
    assert 20 <= args.slot_ms <= 1000
    work = args.work.resolve(); work.mkdir(mode=0o700, exist_ok=False)
    candidate, baseline = args.candidate.resolve(), args.baseline.resolve()
    assert 'LAB-ONLY' in candidate.name and 'LAB-ONLY' in baseline.name
    env = {k:v for k,v in os.environ.items() if not k.startswith('BLOCH_')}
    # Disposable keys only, within a new owner-only laboratory directory.
    env['BLOCH_KEYSTORE_ALLOW_PLAINTEXT'] = '1'
    processes, handles, events = [], [], []
    report = {'status':'RUNNING', 'production_changed':False, 'activation_epoch':8,
              'slot_ms':args.slot_ms, 'validator_count':args.validators,
              'mode':'activation-only' if args.activation_only else 'full-lifecycle', 'cooldown_epochs':32, 'withdrawal_delay_epochs':2048,
              'transport':'devnet', 'normal_doppelganger_window':True,
              'binary_sha256':{b.name:hashlib.sha256(b.read_bytes()).hexdigest() for b in (candidate,baseline)},
              'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'max_finality_lag_epochs':0, 'max_behind_by_slots':0}
    def save():
        for name, value in [('report',report),('events',events)]:
            temporary=work/(name+'.json.tmp')
            temporary.write_text(json.dumps(value,indent=2)+'\n')
            temporary.replace(work/(name+'.json'))
    def event(name, value):
        events.append({'name':name,'elapsed_s':round(time.monotonic()-started,3),'value':value});save()
        print(name, flush=True)
    def cli(*command):
        r = subprocess.run([str(candidate),*map(str,command)],env=env,capture_output=True,text=True,timeout=30)
        assert r.returncode==0,(command[0],r.stderr[-2000:])
        return r.stdout
    def raw_rpc(i, method, params=None):
        req=urllib.request.Request(f'http://127.0.0.1:{args.port_base+i}',
            data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params or []}).encode(),
            headers={'Content-Type':'application/json'})
        # Read-only probes tolerate a bounded transient scheduling/HTTP delay.
        # Never retry a submission with an ambiguous response: its transaction
        # may already be admitted, and that uncertainty must remain visible.
        attempts=3 if method.startswith('get') else 1
        for attempt in range(attempts):
            try:
                with urllib.request.urlopen(req,timeout=5) as r:return json.load(r)
            except (TimeoutError, urllib.error.URLError, ConnectionError) as error:
                event('rpc-transport-failure',{'node':i,'method':method,
                      'attempt':attempt+1,'error':repr(error)})
                if attempt+1==attempts:raise
                time.sleep(.25)
    def rpc(i,method,params=None):
        r=raw_rpc(i,method,params);assert 'error' not in r,(i,method,r)
        return r['result']
    def until(predicate, timeout=45):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            assert all(p.poll() is None for p in processes),'a laboratory node exited'
            try:
                value=predicate()
                if value:return value
            except (OSError,ValueError):pass
            time.sleep(.04)
        raise TimeoutError('laboratory predicate timed out')
    def info(i=0):return rpc(i,'getchaininfo')
    def pos(i=0):return rpc(i,'getfundeddelegation',[0])
    def ready_epoch():
        return until(lambda: (s if s['slot_in_epoch']<=7 and s['behind_by_slots']<=4 else None)
                     if (s:=info()) else None)['epoch']
    seq=0
    def intent(kind, key, fields):
        nonlocal seq
        seq+=1;draft=work/f'{seq:03}-{kind}-draft.hex';signed=work/f'{seq:03}-{kind}-signed.hex'
        review=json.loads(cli('funded-delegation','prepare-'+kind,'--genesis',work/'genesis.bin',
                              *fields,'--out',draft))
        checked=json.loads(cli('funded-delegation','inspect','--tx',draft))
        assert review==checked
        signed_info=json.loads(cli('funded-delegation','sign','--genesis',work/'genesis.bin',
                '--tx',draft,'--dir',work/key,'--expected-root',review['signing_root'],'--out',signed))
        verify=['funded-delegation','inspect','--tx',signed]
        if kind=='commission':verify+=['--pubkey',work/(key+'.pub')]
        assert json.loads(cli(*verify))==signed_info
        return signed.read_text().strip(),signed_info
    def submit(wire, i=0):return raw_rpc(i,'sendrawtransaction',[wire])
    def final(txid):
        return until(lambda: all(rpc(i,'gettxstatus',[txid])['status']=='finalized' for i in range(3)),90)
    def operation(kind,key,fields):
        # Epoch-bound intents can expire while an overloaded test host signs.
        # Retain each rejected attempt and prepare a new reviewed intent.
        for attempt in range(8):
            epoch=ready_epoch();wire,review=intent(kind,key,[*fields,'--epoch',epoch])
            receipt=submit(wire);event(kind+'-submission',{'review':review,'receipt':receipt})
            if 'error' not in receipt:
                try:
                    until(lambda: rpc(0,'gettxstatus',[review['txid']])['status'] in ('included','justified','finalized'),3)
                    final(review['txid']);return wire,review,epoch
                except TimeoutError:pass
        raise AssertionError('epoch-bound intent did not land: '+kind)
    def finalized_equal():
        states=[info(i) for i in range(3)]
        report['last_chain_observation']=[{k:s[k] for k in ('slot','epoch','height','finalized','behind_by_slots')} for s in states]
        checkpoint=min(states,key=lambda s:s['finalized']['epoch'])['finalized']['root']
        blocks=[rpc(i,'getblockbyid',[checkpoint]) for i in range(3)]
        assert all(b['finalized'] for b in blocks)
        assert len({(b['block_id'],b['state_root'],b['height']) for b in blocks})==1
        return blocks[0]
    started=time.monotonic()
    try:
        report['buildinfo']={b.name:json.loads(subprocess.check_output([b,'buildinfo'],env=env,timeout=30)) for b in (candidate,baseline)}
        for off in [0,1,2,3,100,101,102,103]:
            with socket.socket() as s:s.bind(('127.0.0.1',args.port_base+off))
        for i in range(3):cli('keygen','--dir',work/f'key{i}','--index',i)
        cli('keygen','--dir',work/'owner','--index','auto')
        for key in ('key0','key1','key2','owner'):
            row=cli('keygen-public','--dir',work/key).strip().split('\t')
            (work/(key+'.pub')).write_text(row[1]+'\n')
        owner_hash=hashlib.sha3_256(bytes.fromhex((work/'owner.pub').read_text())).hexdigest()
        validator_hash=hashlib.sha3_256(bytes.fromhex((work/'key0.pub').read_text())).hexdigest()
        cli('genesis','--keys',','.join(str(work/f'key{i}') for i in range(args.validators)),
            '--alloc',owner_hash+':2000000000','--slot-ms',args.slot_ms,'--start-in','15',
            '--bind-genesis','--out',work/'genesis.bin')
        early_wire,early_review=intent('commission','key0',['--validator',0,'--commission',500,'--epoch',8])
        for i in range(4):
            data=work/f'node{i}';data.mkdir(mode=0o700)
            if i<args.validators:shutil.copy2(work/f'key{i}'/'validator.key',data/'validator.key')
            handle=(work/f'node{i}.log').open('w');handles.append(handle)
            binary=candidate if i<3 else baseline
            command=[str(binary),'run','--data-dir',str(data),'--genesis',str(work/'genesis.bin'),
                     '--transport','devnet','--listen-addr','127.0.0.1','--listen',str(args.port_base+100+i),
                     '--peers',','.join(f'127.0.0.1:{args.port_base+100+j}' for j in range(4) if j!=i),
                     '--rpc-bind','127.0.0.1','--rpc-port',str(args.port_base+i)]
            processes.append(subprocess.Popen(command,env=env,stdout=handle,stderr=subprocess.STDOUT))
        until(lambda: all(info(i)['finalized']['epoch']>=2 for i in range(4)),max(45,180*args.slot_ms/1000))
        snapshots=[info(i) for i in range(4)]
        anchor=min(snapshots,key=lambda s:s['finalized']['epoch'])['finalized']['root']
        blocks=[rpc(i,'getblockbyid',[anchor]) for i in range(4)]
        assert len({b['state_root'] for b in blocks})==1
        assert max(info(i)['epoch'] for i in range(4))<8,'missed preactivation window'
        refusals=[submit(early_wire,i) for i in (0,3)]
        assert all('error' in r for r in refusals)
        event('preactivation-agreement-and-refusal',{'block':blocks[0],'responses':refusals})
        until(lambda: info()['epoch']>=8,max(45,256*args.slot_ms/1000))
        # Real hybrid but unauthorized operator; RPC must refuse, not merely drop later.
        epoch=ready_epoch();forged,_=intent('commission','owner',['--validator',0,'--commission',500,'--epoch',epoch])
        refusal=submit(forged);assert 'error' in refusal;event('wrong-operator-refused',refusal)
        commission_wire,commission,_=operation('commission','key0',['--validator',0,'--commission',500])
        assert all(int(rpc(i,'getvalidator',[0])['commission_bps'])==500 for i in range(3))
        old_refusal=submit(commission_wire,3);assert 'error' in old_refusal
        old=info(3);new=info()
        assert old['height']<new['finalized_height'] and new['epoch']>=8
        assert rpc(3,'gettxstatus',[commission['txid']])['status']=='unknown'
        assert int(rpc(3,'getvalidator',[0])['commission_bps'])==0
        event('finite-activation-old-node-fail-closed',{'old_head':old,'new_finalized':finalized_equal(),'old_refusal':old_refusal})
        utxos=rpc(0,'getutxos',[owner_hash])['utxos'];assert len(utxos)==1
        u=utxos[0];funding=f"{u['txid']}:{u['vout']}:{u['value_sat']}"
        delegate_wire,delegate=intent('delegate','owner',['--pubkey',work/'owner.pub','--validator-hash',validator_hash,
              '--amount',1000000000,'--input',funding,'--change',owner_hash,'--max-base-fee',100,'--tip',0,'--expiry',info()['epoch']+100])
        forged=bytearray.fromhex(delegate_wire);forged[-10]^=1
        refusal=submit(forged.hex());assert 'error' in refusal;event('forged-delegation-refused',refusal)
        receipt=submit(delegate_wire);assert 'error' not in receipt,receipt;final(delegate['txid'])
        assert not rpc(0,'gettxout',[u['txid'],u['vout']])['unspent']
        assert rpc(0,'gettxout',[delegate['txid'],0])['unspent']
        until(lambda: (p if int(p['activated_sat'])==1000000000 and int(p['issuance_rewards_sat'])>0 else None) if (p:=pos()) else None)
        event('funded-delegation-finalized',{'review':delegate,'position':pos(),'checkpoint':finalized_equal()})
        # An increase after a live position exists must be refused.
        epoch=ready_epoch();raised,_=intent('commission','key0',['--validator',0,'--commission',600,'--epoch',epoch])
        refusal=submit(raised);assert 'error' in refusal;event('commission-increase-refused',refusal)
        _,exit_review,_=operation('undelegate','owner',['--pubkey',work/'owner.pub','--delegator',0,'--position',0])
        destination='95'*32
        epoch=ready_epoch();early,early_review=intent('withdraw','owner',['--pubkey',work/'owner.pub','--delegator',0,'--position',0,
              '--epoch',epoch,'--destination',destination,'--max-base-fee',100])
        refusal=submit(early);assert 'error' in refusal
        assert not rpc(0,'gettxout',[early_review['txid'],0])['unspent']
        event('early-withdrawal-refused',{'response':refusal,'position':pos()})
        if args.activation_only:
            report.update(status='PASS',final_checkpoint=finalized_equal(),old_node_head=info(3))
            return
        until(lambda: pos()['withdrawable_epoch'] is not None,max(180,40*32*args.slot_ms/1000))
        maturity=pos()['withdrawable_epoch'];report['maturity_epoch']=maturity;save()
        deadline=time.monotonic()+2048*32*args.slot_ms/1000+300
        previous_final=-1
        while not pos()['mature']:
            assert time.monotonic()<deadline,'maturity timeout'
            checkpoint=finalized_equal();state=info()
            lag=state['epoch']-state['finalized']['epoch']
            report['max_finality_lag_epochs']=max(report['max_finality_lag_epochs'],lag)
            report['max_behind_by_slots']=max(report['max_behind_by_slots'],state['behind_by_slots'])
            report['last_liveness_check']={'head_epoch':state['epoch'],'finalized_epoch':state['finalized']['epoch'],
                  'finality_lag_epochs':lag,'behind_by_slots':state['behind_by_slots'],'elapsed_s':round(time.monotonic()-started,3)}
            assert state['finalized']['epoch']>=previous_final
            previous_final=state['finalized']['epoch']
            assert state['epoch']-state['finalized']['epoch']<12,'finality lag exceeds rehearsal budget'
            assert state['behind_by_slots']<12*32,'head stopped following the slot clock'
            event('cooldown-observation',{'head_epoch':state['epoch'],'finalized_epoch':previous_final,
                  'maturity_epoch':maturity,'checkpoint':checkpoint,'randao_generation':rpc(0,'getvalidator',[0])['randao_generation']})
            time.sleep(20)
        before=pos();assert before['mature'] and not before['withdrawn'];assert int(before['issuance_rewards_sat'])>0
        payout_wire,payout,_=operation('withdraw','owner',['--pubkey',work/'owner.pub','--delegator',0,'--position',0,
                         '--destination',destination,'--max-base-fee',100])
        outputs=[rpc(i,'gettxout',[payout['txid'],0]) for i in range(3)]
        assert all(o['unspent'] and o['utxo']==outputs[0]['utxo'] for o in outputs)
        # Frozen fee schedule: one hybrid verification, flat gas and canonical bytes.
        gas=5000+72748+16*(len(payout_wire)//2)
        fee=(gas*int(before['next_base_fee_millisat_per_gas'])+999)//1000
        expected=int(before['principal_sat'])+int(before['fee_rewards_sat'])+int(before['issuance_rewards_sat'])-int(before['slash_losses_sat'])-fee
        assert int(outputs[0]['utxo']['value_sat'])==expected,(expected,outputs[0])
        assert outputs[0]['utxo']['script_hash']==destination
        assert all(pos(i)['withdrawn'] and int(pos(i)['issuance_rewards_sat'])==0 for i in range(3))
        epoch=ready_epoch();repeat,repeat_review=intent('withdraw','owner',['--pubkey',work/'owner.pub','--delegator',0,'--position',0,
             '--epoch',epoch,'--destination','96'*32,'--max-base-fee',100])
        refusal=submit(repeat);assert 'error' in refusal
        assert not rpc(0,'gettxout',[repeat_review['txid'],0])['unspent']
        event('mature-payout-and-double-withdrawal-refusal',{'before':before,'payout':payout,'utxo':outputs[0],
              'expected_payout_sat':str(expected),'repeat_response':refusal,'checkpoint':finalized_equal()})
        report.update(status='PASS',final_checkpoint=finalized_equal(),old_node_head=info(3))
    except BaseException as error:
        report.update(status='FAIL',error=repr(error));raise
    finally:
        for p in processes:
            if p.poll() is None:p.terminate()
        for p in processes:
            try:p.wait(timeout=15)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        for h in handles:h.close()
        report['node_log_metrics']={}
        for i in range(4):
            path=work/f'node{i}.log'
            if not path.exists():continue
            text=path.read_text(errors='replace')
            timings=[int(x) for x in re.findall(r'state-cache: persisted [^\n]*elapsed_ms=(\d+)',text)]
            report['node_log_metrics'][str(i)]={'reorgs':text.count('REORG:'),'cache_writes':len(timings),
                  'cache_write_max_ms':max(timings,default=0),
                  'cache_write_median_ms':statistics.median(timings) if timings else None}
        report['elapsed_seconds']=round(time.monotonic()-started,3);save()
        print(json.dumps(report,indent=2),flush=True)

if __name__=='__main__':main()
