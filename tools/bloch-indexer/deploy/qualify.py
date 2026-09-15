import json, os, urllib.request
base=os.environ.get('BLOCH_INDEXER_URL', 'http://127.0.0.1:8091/')
def get(path):
    with urllib.request.urlopen(base+path,timeout=20) as r:return json.load(r)
def rpc(method,params):
    req=urllib.request.Request('http://127.0.0.1:17400',data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=20) as r:return json.load(r)['result']
tx=get('tx/d7b1f414163dec0422fcfdcc109eeda8388f7d2980eaa00bedd3c4603d164301')
assert sum(int(i['value_sat']) for i in tx['inputs'])-sum(int(o['value_sat']) for o in tx['outputs'])==int(tx['fee_sat'])==2166
assert tx['outputs'][0]['value_sat']=='500000000'
source=tx['inputs'][0]; old=get('outpoint/'+source['txid']+'/'+str(source['vout']))
assert old['spent_height']==tx['height'] and old['value_sat']==source['value_sat']
report={'txid':tx['txid'],'fee_sat':tx['fee_sat'],'recipient_sat':tx['outputs'][0]['value_sat'],'spent_input_retained':True,'balances':[]}
for sh in dict.fromkeys([i['script_hash'] for i in tx['inputs']+tx['outputs']]):
    seen=set(); total=0; cursor=None; pages=0; snapshot=None
    while True:
        p=get('utxos/'+sh+'?limit=1000'+('&cursor='+cursor if cursor else ''))
        if snapshot is None:snapshot=p['chain_tip']
        assert snapshot==p['chain_tip']
        for out in p['utxos']:
            key=(out['txid'],out['vout']); assert key not in seen;seen.add(key);total+=int(out['value_sat'])
        pages+=1;cursor=p['next_cursor']
        if not cursor:break
    assert len(seen)==p['total']
    balance=rpc('getbalance',[sh]);assert total==int(balance['balance_sat']);assert len(seen)==balance['utxo_count']
    history=get('history/'+sh+'?limit=1000')
    assert history['events']
    if history['next_cursor']:
        second=get('history/'+sh+'?limit=1000&cursor='+history['next_cursor'])
        keys=lambda rows:{(e['txid'],e['vout'],e['kind'],e['height'],e['transaction_id']) for e in rows}
        assert not(keys(history['events']) & keys(second['events']))
    report['balances'].append({'script_hash':sh,'utxos':len(seen),'pages':pages,'balance_sat':str(total),'matches_live_rpc':True,'history_events':history['total']})
print(json.dumps(report,indent=2))
