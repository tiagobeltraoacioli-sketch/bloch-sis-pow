import test from 'node:test';
import assert from 'node:assert/strict';
import {handlePosternLabs} from '../worker.js';

const hosts=['posternlabs.com','blochprotocol.io','www.blochprotocol.io'];

const assets={async fetch(request){const path=new URL(request.url).pathname;return new Response('asset:'+path,{headers:{'content-type':path.endsWith('.html')?'text/html':'text/css'}});}};

test('the home page comes from the holding assets with the site security headers',async()=>{
  for(const path of ['/','/index.html','/?utm=1']){
    const response=await handlePosternLabs({request:new Request('https://posternlabs.com'+path),env:{ASSETS:assets},fetcher:()=>{throw new Error('home must not reach Pages');}});
    assert.equal(await response.text(),'asset:/holding/index.html');
    assert.match(response.headers.get('content-security-policy'),/default-src 'none'; script-src 'self'/);
    assert.equal(response.headers.get('x-frame-options'),'DENY');
  }
  const asset=await handlePosternLabs({request:new Request('https://posternlabs.com/holding/holding.css'),env:{ASSETS:assets}});
  assert.equal(await asset.text(),'asset:/holding/holding.css');
  assert.equal((await handlePosternLabs({request:new Request('https://posternlabs.com/',{method:'POST'}),env:{ASSETS:assets}})).status,405);
});

test('the technical specification page is served from the holding assets with the site headers',async()=>{
  for(const path of ['/upgrades','/upgrades?ref=roadmap']){
    const response=await handlePosternLabs({request:new Request('https://posternlabs.com'+path),env:{ASSETS:assets},fetcher:()=>{throw new Error('/upgrades must not reach Pages');}});
    assert.equal(await response.text(),'asset:/holding/upgrades.html');
    assert.match(response.headers.get('content-security-policy'),/default-src 'none'; script-src 'self'/);
    assert.equal(response.headers.get('x-frame-options'),'DENY');
  }
  assert.equal((await handlePosternLabs({request:new Request('https://posternlabs.com/upgrades',{method:'POST'}),env:{ASSETS:assets}})).status,405);
});

test('every other path passes through to the existing site untouched',async()=>{
  for(const path of ['/apps/wallet/','/protocol','/docs','/supply','/releases','/assets/site.css','/migration?x=1']){
    const request=new Request('https://posternlabs.com'+path);let forwarded=null;
    const response=await handlePosternLabs({request,env:{ASSETS:{fetch(){throw new Error('no asset read');}}},fetcher:async r=>{forwarded=r;return new Response('pages');}});
    assert.equal(forwarded,request);assert.equal(await response.text(),'pages');
  }
});

test('both domains serve identical site routes and preserve technical routes',async()=>{
  for(const host of hosts){
    for(const [path,asset] of [['/','/holding/index.html'],['/upgrades','/holding/upgrades.html'],['/holding/holding.css','/holding/holding.css']]){
      const response=await handlePosternLabs({request:new Request('https://'+host+path),env:{ASSETS:assets},fetcher:()=>{throw new Error('site route must not reach Pages');}});
      assert.equal(await response.text(),'asset:'+asset);
    }
    for(const path of ['/protocol','/docs','/apps/wallet/','/releases','/api/status']){
      const request=new Request('https://'+host+path);let forwarded=null;
      const response=await handlePosternLabs({request,env:{ASSETS:assets},fetcher:async r=>{forwarded=r;return new Response('origin');}});
      assert.equal(forwarded,request);
      assert.equal(await response.text(),'origin');
    }
  }
});

test('the canonical dossier URL serves the same PDF asset on all hosts',async()=>{
  for(const host of hosts){
    const path='/Bloch-SIS-PoW-Institutional-Dossier-EN.pdf';
    const response=await handlePosternLabs({request:new Request('https://'+host+path),env:{ASSETS:assets},fetcher:()=>{throw new Error('dossier must not reach Pages');}});
    assert.equal(await response.text(),'asset:/holding'+path);
    assert.equal(response.headers.get('content-type'),'application/pdf');
    assert.match(response.headers.get('content-disposition'),/^inline;/);
  }
});

test('the soundtrack is allowed by the page policy and streams with byte ranges',async()=>{
  const page=await handlePosternLabs({request:new Request('https://posternlabs.com/'),env:{ASSETS:assets}});
  assert.match(page.headers.get('content-security-policy'),/media-src 'self'/);
  let seen=null;
  const ranged={async fetch(request){seen=request.headers.get('range');return new Response('part',{status:206,headers:{'content-range':'bytes 0-1/4'}});}};
  const response=await handlePosternLabs({request:new Request('https://blochprotocol.io/holding/audio/uberbloch-sovereign-of-our-lives.m4a',{headers:{range:'bytes=0-1'}}),env:{ASSETS:ranged}});
  assert.equal(seen,'bytes=0-1');assert.equal(response.status,206);assert.equal(response.headers.get('content-range'),'bytes 0-1/4');
});
