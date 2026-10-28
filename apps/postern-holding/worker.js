// Shared holding site and original institutional dossier for Postern Labs and
// Bloch Protocol. All other routes retain their existing Pages origin.
const HOME=new Set(['/','/index.html']);
const DOSSIER='/Bloch-SIS-PoW-Institutional-Dossier-EN.pdf';
// Holding-site pages beyond the home page, served from public/holding with the same headers.
const PAGES=new Map([['/upgrades','/holding/upgrades.html']]);
const HTML_HEADERS={
  'content-security-policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; frame-src https://www.youtube-nocookie.com; base-uri 'none'; object-src 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
  'x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'strict-origin-when-cross-origin',
  'permissions-policy':'camera=(), microphone=(), geolocation=(), payment=()','cache-control':'public, max-age=300'};

function withHeaders(response,headers){
  const output=new Response(response.body,response);
  for(const [name,value] of Object.entries(headers))output.headers.set(name,value);
  output.headers.delete('set-cookie');return output;
}

export async function handlePosternLabs({request,env,fetcher=fetch}){
  const url=new URL(request.url);
  const page=HOME.has(url.pathname)?'/holding/index.html':PAGES.get(url.pathname),asset=url.pathname.startsWith('/holding/'),dossier=url.pathname===DOSSIER;
  if(!page&&!asset&&!dossier)return fetcher(request);
  if(!['GET','HEAD'].includes(request.method))return new Response('Method not allowed',{status:405,headers:{allow:'GET, HEAD'}});
  const target=new URL(page||(dossier?'/holding'+DOSSIER:url.pathname),url.origin);
  const response=await env.ASSETS.fetch(new Request(target,{method:request.method}));
  if(page)return withHeaders(response,HTML_HEADERS);
  if(dossier&&response.status===200)return withHeaders(response,{'content-type':'application/pdf','content-disposition':'inline; filename="Bloch-SIS-PoW-Institutional-Dossier-EN.pdf"','x-content-type-options':'nosniff','cache-control':'public, max-age=300'});
  return withHeaders(response,{'x-content-type-options':'nosniff','cache-control':'public, max-age=3600'});
}
export default {fetch(request,env){return handlePosternLabs({request,env});}};
