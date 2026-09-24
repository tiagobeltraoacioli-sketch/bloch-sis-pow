import http from 'node:http';
import {readFile,stat} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {defaultConfig} from '../apps/bloch-data/assets/modules.v1.mjs';
import {samplesFor} from '../apps/bloch-data/assets/samples.v1.mjs';
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=process.env.VERIFY_DIR?resolve(process.env.VERIFY_DIR):resolve(fileURLToPath(new URL('../apps/bloch-data',import.meta.url)));
const server=http.createServer(async(req,res)=>{
  try {let file=resolve(root,'.'+new URL(req.url,'http://localhost').pathname);if(!file.startsWith(root+'/')&&file!==root)throw Error('path');if((await stat(file)).isDirectory())file=resolve(file,'index.html');res.setHeader('content-type',({'.html':'text/html','.css':'text/css','.mjs':'application/javascript','.png':'image/png','.csv':'text/csv','.md':'text/plain','.zip':'application/zip'})[extname(file)]||'application/octet-stream');res.end(await readFile(file));}catch{res.writeHead(404);res.end();}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const browser=await chromium.launch({executablePath:process.env.CHROME_PATH||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
try {
  const context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:'reduce',acceptDownloads:true});
  const page=await context.newPage(),errors=[],requests=[];
  page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>requests.push(r.url()));
  const target=process.env.VERIFY_URL||`http://127.0.0.1:${server.address().port}/`;
  await page.goto(target,{waitUntil:'networkidle'});
  await page.waitForFunction(()=>document.getElementById('metric-keys').textContent==='8');
  assert.equal(await page.locator('#metric-matched').innerText(),'3');
  assert.equal(await page.locator('#metric-review').innerText(),'5');
  assert.equal(await page.locator('#module-select option').count(),4);
  assert.equal(await page.locator('#region-select option').count(),7);
  assert.ok(requests.every(url=>url.startsWith(new URL(target).origin+'/')),'Unexpected external asset request');
  assert.equal(await page.evaluate(()=>localStorage.length),0);
  const ids=await page.locator('[id]').evaluateAll(els=>els.map(el=>el.id));assert.equal(new Set(ids).size,ids.length);
  assert.deepEqual(await page.locator('a[href^="#"]').evaluateAll(els=>els.map(el=>el.getAttribute('href').slice(1)).filter(id=>id&&!document.getElementById(id))),[]);
  const layout=[];
  for(const width of [1440,1280,1024,768,390,360]){
    await page.setViewportSize({width,height:width<500?844:1100});await page.evaluate(()=>scrollTo(0,0));
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`Overflow at ${width}`);
    layout.push(width);
    if(width===1440||width===390){await page.screenshot({path:`/private/tmp/blochdata-hero-${width}.png`});await page.locator('#workbench').scrollIntoViewIfNeeded();await page.screenshot({path:`/private/tmp/blochdata-workbench-${width}.png`});await page.locator('.analysis-grid').scrollIntoViewIfNeeded();await page.screenshot({path:`/private/tmp/blochdata-results-${width}.png`});}
  }
  await page.setViewportSize({width:1440,height:1100});
  for(const [institution,module] of [['bank','cash'],['manager','positions'],['broker','trades'],['dtvm','trades']]){
    await page.selectOption('#institution-select',institution);assert.equal(await page.inputValue('#module-select'),module);await page.click('#apply-config');await page.waitForFunction(()=>document.getElementById('metric-keys').textContent==='8'&&!document.getElementById('results').hidden);assert.equal(await page.locator('#manifest-rule').innerText(),module==='trades'?'trade-comparison.v1':module==='cash'?'cash-comparison.v1':'position-comparison.v1');
  }
  await page.selectOption('#module-select','onchain');await page.click('#apply-config');await page.waitForFunction(()=>document.getElementById('manifest-rule').textContent==='bloch-receipt-comparison.v1'&&!document.getElementById('results').hidden);
  assert.ok((await page.locator('#module-note').textContent()).includes('not a verified proof'));
  await page.selectOption('#status-filter','duplicate');assert.equal(await page.locator('#result-rows tr').count(),1);
  await page.selectOption('#institution-select','bank');await page.selectOption('#region-select','br');await page.click('#apply-config');await page.waitForFunction(()=>!document.getElementById('results').hidden);
  const c=defaultConfig('cash','br','bank'),pair=samplesFor(c);
  const privateA=pair[0].replaceAll('ACCOUNT-DEMO','<img src=x onerror=alert(1)>');
  const privateB=pair[1].replaceAll('ACCOUNT-DEMO','<img src=x onerror=alert(1)>');
  const baseline=requests.length;
  await page.setInputFiles('#source-a',{name:'internal.csv',mimeType:'text/csv',buffer:Buffer.from(privateA)});
  await page.setInputFiles('#source-b',{name:'statement.csv',mimeType:'text/csv',buffer:Buffer.from(privateB)});
  await page.click('#run');await page.waitForFunction(()=>!document.getElementById('results').hidden&&document.getElementById('mode-label').textContent==='YOUR FILES / LOCAL ONLY');
  assert.equal(await page.locator('#result-rows img').count(),0);assert.equal(requests.length,baseline,'File contents triggered network requests');
  const exportPromise=page.waitForEvent('download');await page.click('#export-json');const download=await exportPromise;
  const data=await readFile(await download.path(),'utf8'),report=JSON.parse(data);
  assert.equal(createHash('sha256').update(data).digest('hex'),await page.locator('#report-digest').innerText());
  assert.equal(report.sources[0].sha256,createHash('sha256').update(privateA).digest('hex'));
  assert.equal(report.configuration.module,'cash');assert.equal(report.configuration.region,'br');assert.equal(report.assurance.onchain,'not_submitted');assert.equal(report.assurance.regulatory_compliance,'not_certified');
  await page.setInputFiles('#source-b',{name:'invalid.csv',mimeType:'text/csv',buffer:Buffer.from('bad,header\n1,2')});await page.click('#run');await page.waitForSelector('#workbench-status.error');assert.equal(await page.locator('#results').isVisible(),false);
  await page.click('#clear');assert.equal(await page.locator('#results').isVisible(),false);assert.equal(await page.inputValue('#source-a'),'');assert.equal(await page.inputValue('#source-b'),'');
  await context.setOffline(true);await page.click('#sample');await page.waitForFunction(()=>!document.getElementById('results').hidden);assert.equal(await page.locator('#metric-keys').innerText(),'8');
  await context.setOffline(false);
  for(const path of [process.env.VERIFY_DIR?'README.md':'downloads/bloch-data-local-workbench-v1.zip','GOVERNANCE.md','regulatory-register.v1.json','samples/venue.csv'])assert.equal((await context.request.get(new URL(path,target).href)).status(),200,path);
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({url:target,modules:4,regionalProfiles:7,layout,localUploads:'no network requests',exports:'digest verified',malformedFiles:'fail closed',offline:'passed',xss:'text only',errors}));
}finally{await browser.close();server.close();}
