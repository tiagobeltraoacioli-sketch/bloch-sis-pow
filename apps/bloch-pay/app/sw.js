const CACHE='bloch-pay-shell-v4';
const SHELL=[
  ['/app/','text/html'],['/app/integrations','text/html'],['/app/evidence','text/html'],
  ['/app/evidence.css','text/css'],['/app/evidence-ui.mjs','javascript'],['/app/evidence-model.mjs','javascript'],['/app/evidence-store.mjs','javascript'],
  ['/app/evidence-vendor/graphus-analytics.mjs','javascript'],['/app/evidence-vendor/graphus-evidence.mjs','javascript'],
  ['/app/workspace.css','text/css'],['/app/integrations.css','text/css'],
  ['/app/workspace.mjs','javascript'],['/app/model.mjs','javascript'],
  ['/app/integration-ui.mjs','javascript'],['/app/integrations.mjs','javascript'],
  ['/app/studio-model.mjs','javascript'],['/app/studio-ui.mjs','javascript'],['/app/pwa.mjs','javascript'],
  ['/app/participant-modules.mjs','javascript'],['/app/modules-ui.mjs','javascript'],['/app/operations.mjs','javascript'],['/app/operations-ui.mjs','javascript'],
  ['/app/manifest.webmanifest','json'],['/app/payment-api.openapi.json','json'],
  ['/app/icon.svg','image/svg+xml'],['/assets/favicon.png','image/png'],['/assets/bloch-inc-logo-dark.png','image/png']
];
self.addEventListener('install',event=>event.waitUntil((async()=>{
  const entries=await Promise.all(SHELL.map(async([path,mime])=>{const response=await fetch(new Request(path,{cache:'reload'}));if(!response.ok||response.redirected||!(response.headers.get('content-type')||'').includes(mime))throw new Error('Incomplete app shell: '+path);return[path,response];}));
  const cache=await caches.open(CACHE);await Promise.all(entries.map(([path,response])=>cache.put(path,response)));
})()));
self.addEventListener('activate',event=>event.waitUntil((async()=>{for(const key of await caches.keys())if(key.startsWith('bloch-pay-shell-')&&key!==CACHE)await caches.delete(key);})()));
self.addEventListener('message',event=>{if(event.data?.type==='ACTIVATE')self.skipWaiting();});
self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url);
  if(event.request.method!=='GET'||url.origin!==self.location.origin||!SHELL.some(([path])=>path===url.pathname))return;
  event.respondWith((async()=>{const cached=await caches.match(url.pathname,{cacheName:CACHE});return cached||fetch(event.request);})());
});
