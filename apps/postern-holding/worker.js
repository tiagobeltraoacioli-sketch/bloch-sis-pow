// posternlabs.com: the holding-company home page is served here; every other path (wallet,
// protocol, docs, supply, releases, ...) passes through unchanged to the existing Pages site.
const HOME=new Set(['/','/index.html']);
const HTML_HEADERS={
  'content-security-policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; object-src 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
  'x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'strict-origin-when-cross-origin',
  'permissions-policy':'camera=(), microphone=(), geolocation=(), payment=()','cache-control':'public, max-age=300'};

function withHeaders(response,headers){
  const output=new Response(response.body,response);
  for(const [name,value] of Object.entries(headers))output.headers.set(name,value);
  output.headers.delete('set-cookie');return output;
}

export async function handlePosternLabs({request,env,fetcher=fetch}){
  const url=new URL(request.url);
  const page=HOME.has(url.pathname),asset=url.pathname.startsWith('/holding/');
  if(!page&&!asset)return fetcher(request);
  if(!['GET','HEAD'].includes(request.method))return new Response('Method not allowed',{status:405,headers:{allow:'GET, HEAD'}});
  const target=new URL(page?'/holding/index.html':url.pathname,url.origin);
  const response=await env.ASSETS.fetch(new Request(target,{method:request.method}));
  if(page)return withHeaders(response,HTML_HEADERS);
  return withHeaders(response,{'x-content-type-options':'nosniff','cache-control':'public, max-age=3600'});
}
export default {fetch(request,env){return handlePosternLabs({request,env});}};
