import {normalize,SOURCES} from './model.mjs';
import {readBoundedJson} from '../wallets/bounded-json.mjs';
const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; frame-ancestors 'none'",'referrer-policy':'no-referrer'};
const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers});
// One public, fixed upstream. Never forward cookies, credentials, paths or query values.
export async function indexerHealth(request,{fetcher=fetch,timeout=12000}={}){
  if(request.method!=='GET')return new Response(JSON.stringify({error:'GET required.'}),{status:405,headers:{...headers,allow:'GET'}});
  if(new URL(request.url).search)return reply({error:'Query parameters are not supported.'},400);
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);
  try{
    const upstream=await fetcher(SOURCES.indexer.url,{method:'GET',headers:{accept:'application/json'},redirect:'manual',credentials:'omit',cache:'no-store',signal:controller.signal});
    if(!upstream.ok){await upstream.body?.cancel();return reply({error:'Public indexer unavailable.'},502);}
    const raw=await readBoundedJson(upstream,1024*1024),data=normalize('indexer',raw);
    return reply({...data,relay:{source:SOURCES.indexer.url,received_at:new Date().toISOString(),verification:'validated public source fields; not an attestation'}});
  }catch{return reply({error:controller.signal.aborted?'Public indexer timed out.':'Public indexer response unavailable or invalid.'},controller.signal.aborted?504:502);}
  finally{clearTimeout(timer);}
}
