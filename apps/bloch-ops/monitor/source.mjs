import {readRpcResponse} from '../rpc/response-guard.mjs';
import {readBoundedJson} from '../wallets/bounded-json.mjs';
import {SOURCES,normalize} from './model.mjs';
export async function readSource(source,{fetcher=fetch,now=()=>new Date().toISOString(),clock=()=>performance.now(),signal}={}){
  const config=SOURCES[source];if(!config)throw new Error('Unsupported monitor source.');
  const id=crypto.randomUUID(),start=clock(),controller=new AbortController(),timer=setTimeout(()=>controller.abort(),source==='chain'?22000:14000);
  const cancel=()=>controller.abort();signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)cancel();
  try{
    const response=await fetcher(config.relay??config.url,{method:config.method?'POST':'GET',mode:'cors',credentials:'omit',cache:'no-store',redirect:'error',signal:controller.signal,
      headers:config.method?{'content-type':'application/json',accept:'application/json'}:{accept:'application/json'},...(config.method?{body:JSON.stringify({jsonrpc:'2.0',id,method:config.method,params:[]})}:{})});
    if(!response.ok){await response.body?.cancel();throw new Error(`Public source returned HTTP ${response.status}.`);}
    const parsed=config.method?await readRpcResponse(response,id):await readBoundedJson(response,1024*1024);
    if(config.method&&parsed.error)throw new Error(`Read method returned RPC error ${parsed.error.code}.`);
    const raw=config.method?{...parsed.result,corroboration:parsed.corroboration??parsed.result?.corroboration}:parsed;
    return {id,source,at:now(),round_trip_ms:Math.max(0,Math.round(clock()-start)),status:'valid',error:null,data:normalize(source,raw)};
  }catch(error){return {id,source,at:now(),round_trip_ms:Math.max(0,Math.round(clock()-start)),status:'failed',data:null,error:controller.signal.aborted?'Read cancelled or timed out.':error instanceof TypeError?'Public source unreachable from this browser.':String(error.message).slice(0,200)};}
  finally{clearTimeout(timer);signal?.removeEventListener('abort',cancel);}
}
export async function readRound(options={}){
  const now=options.now||(()=>new Date().toISOString()),started_at=now(),observations={},keys=Object.keys(SOURCES);
  for(let offset=0;offset<keys.length;offset+=3){if(options.signal?.aborted)throw new Error('Round cancelled.');const results=await Promise.all(keys.slice(offset,offset+3).map(source=>readSource(source,options)));for(const o of results){observations[o.source]=o;options.onProgress?.(o);}}
  if(options.signal?.aborted)throw new Error('Round cancelled.');return {id:crypto.randomUUID(),started_at,finished_at:now(),observations};
}
