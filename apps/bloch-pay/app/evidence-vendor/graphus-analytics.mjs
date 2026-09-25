/* Bounded graph statistics. All amounts remain integer strings until chart scaling. */
(function (root) {
  'use strict';
  const DECIMALS = {BTC:8, ETH:18, USDT:6, USDC:6, BLCH:8};
  const KINDS = {
    BTC:['observed_input_prevout','created_output'],
    BLCH:['observed_spent_outpoint_reference','observed_created_output'],
    ETH:['native_value'], USDT:['erc20_transfer'], USDC:['erc20_transfer'],
  };
  const fail = message => { throw new Error(message); };
  const text = (value, max=200) => typeof value==='string' && value.length>0 && value.length<=max;
  function units(value) {
    if(typeof value!=='string'||! /^(0|[1-9][0-9]{0,85})$/.test(value)) fail('Invalid integer amount.');
    return BigInt(value);
  }
  function format(value, asset) {
    const n=units(value), d=DECIMALS[asset];
    if(d===undefined) fail('Unsupported asset.');
    const scale=10n**BigInt(d), fraction=(n%scale).toString().padStart(d,'0').replace(/0+$/,'');
    return (n/scale).toLocaleString('en-US')+(fraction?'.'+fraction:'');
  }
  const ratio = (n,d) => d===0n?0:Number(n*1000000n/d)/1000000;
  function normalize(data) {
    if(!data||!Object.hasOwn(DECIMALS,data.asset)||!['synthetic','source-reported'].includes(data.status)
      ||!Array.isArray(data.nodes)||data.nodes.length>1200||!Array.isArray(data.edges)||data.edges.length>4000)
      fail('Expected a bounded Graphus graph (up to 1,200 nodes and 4,000 connections).');
    const seen=new Set();
    const nodes=data.nodes.map(n=>{
      if(!text(n?.id)||seen.has(n.id)||!['address','script_hash','transaction'].includes(n.kind)) fail('Invalid or duplicate graph node.');
      seen.add(n.id);
      return {id:n.id,kind:n.kind,label:text(n.address)?n.address:text(n.txid)?n.txid:n.id};
    });
    const ids=new Set();
    const edges=data.edges.map((e,i)=>{
      if(!seen.has(e?.from)||!seen.has(e?.to)||!KINDS[data.asset].includes(e.kind)) fail('Invalid graph connection.');
      const id=e.event_id||`record:${i}`;
      if(!text(id,300)||ids.has(id)) fail('Invalid or duplicate event identifier.');
      ids.add(id);
      const value=units(e.amount_base_units).toString();
      if(value.length>78) fail('Source amount exceeds 256-bit decimal size.');
      const block=e.block_number??e.block?.height??null;
      if(block!==null&&(!Number.isSafeInteger(block)||block<0)) fail('Invalid event block.');
      if(['BTC','BLCH'].includes(data.asset)) {
        const from=nodes.find(n=>n.id===e.from),to=nodes.find(n=>n.id===e.to);
        const input=KINDS[data.asset][0]===e.kind;
        if(input?(from.kind==='transaction'||to.kind!=='transaction'):(from.kind!=='transaction'||to.kind==='transaction'))
          fail('UTXO evidence must connect a reference and a transaction.');
      }
      const hash=e.block_hash??e.block?.hash,txid=e.txid??e.transaction_hash;
      return {id,from:e.from,to:e.to,kind:e.kind,amount:value,block,
        ...(typeof hash==='string'&&/^(0x)?[a-f0-9]{64}$/i.test(hash)?{block_hash:hash}:{}),
        ...(typeof txid==='string'&&/^(0x)?[a-f0-9]{64}$/i.test(txid)?{txid}:{}),
        ...(Number.isSafeInteger(e.position)&&e.position>=0?{position:e.position}:{}),
        ...(text(e.block_time,100)?{block_time:e.block_time}:{}),
        ...(e.outpoint&&/^[a-f0-9]{64}$/i.test(e.outpoint.txid)&&Number.isSafeInteger(e.outpoint.vout)&&e.outpoint.vout>=0?{outpoint:{txid:e.outpoint.txid,vout:e.outpoint.vout}}:{}),
      };
    });
    return {asset:data.asset,status:data.status,nodes,edges,
      source:text(data.source,300)?data.source:'Unspecified source',
      retrieved_at:text(data.retrieved_at,100)?data.retrieved_at:null,
      coverage:text(data.coverage,1000)?data.coverage:'Bounded records only',
      ...(data.anchor?{anchor:Object.fromEntries(['height','hash','time','finality','finalized_height'].filter(k=>typeof data.anchor[k]==='string'||Number.isSafeInteger(data.anchor[k])).map(k=>[k,data.anchor[k]]))}:{}),
      ...(data.scope?{scope:Object.fromEntries(Object.entries(data.scope).filter(([key,v])=>/^[a-z_]{1,60}$/.test(key)&&(typeof v==='string'&&v.length<=500||typeof v==='boolean'||Number.isSafeInteger(v))))}:{}),
      ...(Array.isArray(data.snapshots)&&data.snapshots.length<=32?{snapshots:data.snapshots.map(s=>({source:text(s.source,300)?s.source:'Unspecified source',retrieved_at:text(s.retrieved_at,100)?s.retrieved_at:null,coverage:text(s.coverage,1000)?s.coverage:'Bounded source page',anchor:s.anchor&&Number.isSafeInteger(s.anchor.height)&&text(s.anchor.hash,100)?{height:s.anchor.height,hash:s.anchor.hash,finality:text(s.anchor.finality,300)?s.anchor.finality:'Unknown'}:null,records:Number.isSafeInteger(s.records)?s.records:null}))}:{}),
    };
  }
  function fromCollection(bundle){
    if(bundle?.kind!=='graphus_network_collection'||bundle.schema_version!==1||bundle.dataset?.status!=='source-reported'||!Array.isArray(bundle.dataset.snapshots)||bundle.dataset.snapshots.length>32)fail('Invalid bounded network collection.');
    return normalize(bundle.dataset);
  }
  function fromBundle(bundle) {
    if(bundle?.kind!=='graphus_public_chain_observation'||bundle.schema_version!==1
      ||bundle.status!=='source-reported'||!bundle.records) fail('Import a Graphus observation JSON exported from Constellation.');
    const asset=bundle.query?.asset;
    let nodes=bundle.records.nodes, edges=bundle.records.edges;
    // Token log records are authoritative for this local view; do not add a second copy of graph edges.
    if(['USDT','USDC'].includes(asset)&&Array.isArray(bundle.token_logs?.events)) {
      if(bundle.token_logs.events.length>256) fail('Too many token log records.');
      const refs=new Map();
      const address=v=>{
        if(typeof v!=='string'||!/^0x[0-9a-f]{40}$/i.test(v)) fail('Invalid token address.');
        const id=v.toLowerCase();refs.set(id,{id,kind:'address',address:id});return id;
      };
      if(bundle.query.address) address(bundle.query.address);
      edges=bundle.token_logs.events.map(e=>({from:address(e.from),to:address(e.to),kind:'erc20_transfer',
        amount_base_units:e.amount_base_units,event_id:e.event_id||`${e.transaction_hash}:${e.log_index}`,
        block_number:e.block_number,block_hash:e.block_hash,transaction_hash:e.transaction_hash,position:e.log_index}));
      nodes=[...refs.values()];
    }
    const source=bundle.token_logs?.source||bundle.source;
    return normalize({asset,status:'source-reported',nodes,edges,source:source?.source_id,
      retrieved_at:source?.retrieved_at,coverage:source?.coverage});
  }
  function fixture(asset='ETH') {
    if(!Object.hasOwn(DECIMALS,asset)) fail('Unsupported asset.');
    let seed=17+Object.keys(DECIMALS).indexOf(asset);
    const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;};
    const utxo=['BTC','BLCH'].includes(asset);
    const nodes=Array.from({length:144},(_,i)=>({id:`SIM-${asset}-${String(i+1).padStart(3,'0')}`,kind:asset==='BLCH'?'script_hash':'address'}));
    const edges=[];
    const add=(from,to,kind,value,block)=>edges.push({from,to,kind,amount_base_units:value.toString(),block_number:block,event_id:`SIM-${asset}-E${edges.length+1}`});
    const scale=10n**BigInt(Math.max(0,DECIMALS[asset]-4));
    for(let i=0;i<(utxo?288:864);i++) {
      const group=Math.floor(random()*6), first=group*24;
      const a=first+Math.floor(random()*24);
      const b=random()<.07?(a+25)%144:first+(random()<.32?0:Math.floor(random()*24));
      const value=BigInt(1+Math.floor(random()**3*10000000))*scale, block=100000+Math.floor(random()**1.3*72);
      if(utxo) {
        const tx=`SIM-${asset}-TX${i+1}`;nodes.push({id:tx,kind:'transaction'});
        add(nodes[a].id,tx,KINDS[asset][0],value,block);
        add(tx,nodes[b].id,KINDS[asset][1],value*7n/10n,block);
        add(tx,nodes[(b+1)%144].id,KINDS[asset][1],value*3n/10n,block);
      } else add(nodes[a].id,nodes[b].id,KINDS[asset][0],value,block);
    }
    return normalize({asset,status:'synthetic',nodes,edges,source:'Graphus deterministic demonstration v1',
      coverage:'144 generated references across 72 illustrative blocks; no observed chain activity'});
  }
  function filterGraph(data,{minBlock=null,maxBlock=null,kind='all',minimum='0',focus='',direction='all'}={}) {
    const floor=units(minimum);
    const edges=data.edges.filter(e=>(minBlock===null||e.block!==null&&e.block>=minBlock)
      &&(maxBlock===null||e.block!==null&&e.block<=maxBlock)&&(kind==='all'||e.kind===kind)
      &&BigInt(e.amount)>=floor&&(!focus||(direction==='incoming'?e.to===focus:direction==='outgoing'?e.from===focus:e.from===focus||e.to===focus)));
    const ids=new Set(edges.flatMap(e=>[e.from,e.to]));
    if(focus) ids.add(focus);
    const active=minBlock!==null||maxBlock!==null||kind!=='all'||floor>0n||Boolean(focus);
    return {...data,edges,nodes:active?data.nodes.filter(n=>ids.has(n.id)):data.nodes};
  }
  function analyze(data) {
    const rows=new Map(data.nodes.map(n=>[n.id,{...n,incoming:0,outgoing:0,peers:new Set(),rank:0}]));
    const adjacency=new Map(data.nodes.map(n=>[n.id,new Set()]));
    const groups=new Map(),blocks=new Map(),histogram=new Map(),amountBands=new Map();
    let unknownBlocks=0;
    for(const e of data.edges) {
      const a=rows.get(e.from),b=rows.get(e.to); a.outgoing++;b.incoming++;
      if(e.from!==e.to) {a.peers.add(e.to);b.peers.add(e.from);adjacency.get(e.from).add(e.to);adjacency.get(e.to).add(e.from);}
      if(!groups.has(e.kind)) groups.set(e.kind,{kind:e.kind,count:0,amount:0n});
      const group=groups.get(e.kind);group.count++;group.amount+=BigInt(e.amount);
      if(e.block===null)unknownBlocks++;else blocks.set(e.block,(blocks.get(e.block)||0)+1);
      const band=e.amount==='0'?-1:e.amount.length-1;
      amountBands.set(band,(amountBands.get(band)||0)+1);
    }
    let components=0;const visited=new Set(),componentSizes=[];
    for(const node of rows.values()) {
      histogram.set(node.peers.size,(histogram.get(node.peers.size)||0)+1);
      if(visited.has(node.id))continue;
      const stack=[node.id];visited.add(node.id);let size=0;
      while(stack.length) {const id=stack.pop();rows.get(id).component=components;size++;
        for(const peer of adjacency.get(id))if(!visited.has(peer)){visited.add(peer);stack.push(peer);}}
      componentSizes.push(size);components++;
    }
    // PageRank uses unique directed links; repeated events do not inflate link weight.
    const outgoing=new Map(data.nodes.map(n=>[n.id,new Set()]));
    for(const edge of data.edges)outgoing.get(edge.from).add(edge.to);
    const n=rows.size;let ranks=new Map(data.nodes.map(node=>[node.id,n?1/n:0]));
    for(let step=0;step<60&&n;step++) {
      let dangling=0;for(const [id,links] of outgoing)if(!links.size)dangling+=ranks.get(id);
      const next=new Map(data.nodes.map(node=>[node.id,.15/n+.85*dangling/n]));
      for(const [id,links] of outgoing)for(const to of links)next.set(to,next.get(to)+.85*ranks.get(id)/links.size);
      const delta=[...next].reduce((sum,[id,value])=>sum+Math.abs(value-ranks.get(id)),0);ranks=next;if(delta<1e-9)break;
    }
    const ranking=[...rows.values()].map(row=>({...row,degree:row.peers.size,peers:[...row.peers],rank:ranks.get(row.id)}))
      .sort((a,b)=>b.degree-a.degree||a.id.localeCompare(b.id));
    const unique=new Set(data.edges.filter(e=>e.from!==e.to).map(e=>JSON.stringify([e.from,e.to]))).size;
    return {nodes:n,connections:data.edges.length,components,componentSizes,
      density:n>1?unique/(n*(n-1)):0,unknownBlocks,ranking,
      groups:[...groups.values()].map(g=>({...g,amount:g.amount.toString()})),
      blocks:[...blocks].sort((a,b)=>a[0]-b[0]),histogram:[...histogram].sort((a,b)=>a[0]-b[0]),
      amountBands:[...amountBands].sort((a,b)=>a[0]-b[0])};
  }
  function findPath(data,from,to,maxSteps=6) {
    if(!Number.isInteger(maxSteps)||maxSteps<1||maxSteps>6)fail('Path limit must be between one and six.');
    const ids=new Set(data.nodes.map(n=>n.id));if(!ids.has(from)||!ids.has(to))return null;
    if(from===to)return [];
    const outgoing=new Map();for(const e of data.edges){if(!outgoing.has(e.from))outgoing.set(e.from,[]);outgoing.get(e.from).push(e);}
    const queue=[{id:from,path:[]}],seen=new Set([from]);
    for(let i=0;i<queue.length;i++) {
      const current=queue[i];if(current.path.length>=maxSteps)continue;
      for(const edge of outgoing.get(current.id)||[]) {
        const path=[...current.path,edge];if(edge.to===to)return path;
        if(!seen.has(edge.to)){seen.add(edge.to);queue.push({id:edge.to,path});}
      }
    }
    return null;
  }
  function holderStats(data) {
    if(data?.status!=='source-reported'||data.asset!=='BLCH'||!Array.isArray(data.holders)||data.holders.length>64
      ||!Number.isSafeInteger(data.coverage?.positive_script_hashes_in_index)
      ||data.coverage.positive_script_hashes_in_index<data.holders.length
      ||data.coverage.returned!==data.holders.length
      ||!Number.isSafeInteger(data.anchor?.height)||data.anchor.height<0
      ||!/^[a-f0-9]{64}$/i.test(data.anchor.block_id||'')
      ||!text(data.source,300)||!text(data.retrieved_at,100))fail('Invalid indexed balance snapshot.');
    const total=units(data.coverage.indexed_total_sat),seen=new Set();
    const rows=data.holders.map(row=>{
      if(!/^[a-f0-9]{64}$/i.test(row?.script_hash)||seen.has(row.script_hash.toLowerCase())
        ||!Number.isSafeInteger(row.utxo_count)||row.utxo_count<1)fail('Invalid indexed script record.');
      seen.add(row.script_hash.toLowerCase());
      const value=units(row.balance_sat);if(!value)fail('Expected positive indexed balances.');
      return {id:row.script_hash.toLowerCase(),amount:value.toString(),utxos:row.utxo_count};
    }).sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:BigInt(a.amount)<BigInt(b.amount)?1:a.id.localeCompare(b.id));
    const sum=rows.reduce((s,r)=>s+BigInt(r.amount),0n),n=rows.length;
    const complete=data.coverage.positive_script_hashes_in_index===n;
    if(sum>total||complete&&sum!==total)fail('Indexed balances do not reconcile.');
    let cumulative=0n;const lorenz=[{x:0,y:0}];
    const ascending=[...rows].reverse();let weighted=0n,squares=0n;
    ascending.forEach((r,i)=>{const value=BigInt(r.amount);cumulative+=value;weighted+=BigInt(i+1)*value;squares+=value*value;
      lorenz.push({x:(i+1)/n,y:ratio(cumulative,sum)});});
    return {rows,total:total.toString(),sum:sum.toString(),complete,
      returnedShare:ratio(sum,total),top1:ratio(BigInt(rows[0]?.amount||'0'),sum),
      top10:ratio(rows.slice(0,10).reduce((s,r)=>s+BigInt(r.amount),0n),sum),
      gini:n&&sum?ratio(2n*weighted-BigInt(n+1)*sum,BigInt(n)*sum):null,
      hhi:sum?ratio(squares,sum*sum):null,lorenz};
  }
  function csv(rows) {
    const cell=value=>{let s=String(value??'');if(/^[=+@\-\t\r]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"';};
    return rows.map(row=>row.map(cell).join(',')).join('\r\n');
  }
  const api={DECIMALS,KINDS,units,format,ratio,normalize,fromBundle,fromCollection,fixture,filterGraph,analyze,findPath,holderStats,csv};
  root.GraphusAnalytics=api;
  if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof globalThis!=='undefined'?globalThis:window);
