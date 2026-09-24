// End-to-end checks run in an isolated browser profile, including on production.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,dirname,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const artifacts=process.env.PAY_ARTIFACTS||'/private/tmp/bloch-pay-browser';
await mkdir(artifacts,{recursive:true});
let server,base=process.argv[2];
if(!base){
  const mime={'.html':'text/html','.css':'text/css','.mjs':'application/javascript','.js':'application/javascript','.json':'application/json','.webmanifest':'application/manifest+json','.png':'image/png','.svg':'image/svg+xml'};
  server=createServer(async(req,res)=>{
    try{let path=new URL(req.url,'http://localhost').pathname;if(path.endsWith('/index.html')){res.writeHead(308,{Location:path.slice(0,-10)});res.end();return;}if(path.endsWith('.html')){res.writeHead(308,{Location:path.slice(0,-5)});res.end();return;}if(path.endsWith('/'))path+='index.html';else if(!extname(path))path+='.html';const file=resolve(root,'.'+path);assert(file.startsWith(root+'/'));const data=await readFile(file);res.setHeader('Content-Type',mime[extname(file)]||'application/octet-stream');if(path.startsWith('/app/'))res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'");res.end(data);}catch{res.writeHead(404);res.end('Not found');}
  });
  await new Promise(done=>server.listen(0,'127.0.0.1',done));base=`http://127.0.0.1:${server.address().port}`;
}
const browser=await chromium.launch({headless:true,...(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{})});
const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce',acceptDownloads:true});
const page=await context.newPage();
const errors=[],failures=[];
page.on('pageerror',error=>errors.push(error.message));page.on('response',r=>{if(r.url().startsWith(base)&&r.status()>=400)failures.push([r.url(),r.status()]);});
const invoice=async({reference,amount='100.00000001',direction='receivable',counterparty='Example customer'})=>{
  await page.locator('#new-invoice').click();const f=page.locator('#invoice-form');
  for(const [key,value] of Object.entries({reference,amount,counterparty,issued:'2026-09-01',due:'2026-09-20',note:'<img src=x onerror=alert(1)>'}))await f.locator(`[name=${key}]`).fill(value);
  await f.locator('[name=direction]').selectOption(direction);await f.getByRole('button',{name:'Save invoice',exact:true}).click();await page.locator('#invoice-dialog').waitFor({state:'hidden'});
};
const record=async({reference,amount,linked=false,duplicate=false})=>{
  await page.locator('[data-record]').first().click();const f=page.locator('#receipt-form');await f.locator('[name=reference]').fill(reference);await f.locator('[name=amount]').fill(amount);await f.locator('[name=date]').fill('2026-09-22');
  if(linked){await f.locator('[name=txid]').fill('a'.repeat(64));await f.locator('[name=blockId]').fill('b'.repeat(64));await f.locator('[name=output]').fill('0');}
  await f.getByRole('button',{name:'Save payment record',exact:true}).click();
  if(duplicate){assert.match(await f.locator('.form-error').innerText(),/already recorded/);await f.locator('[data-close]').first().click();}else await page.locator('#receipt-dialog').waitFor({state:'hidden'});
};
try{
  assert.equal((await page.goto(base+'/app/',{waitUntil:'networkidle'})).status(),200);
  await invoice({reference:'INV-001',counterparty:'<img src=x onerror=alert(1)>'});
  await record({reference:'REC-001',amount:'25',linked:true});
  assert.equal(await page.locator('.metric strong').first().innerText(),'75.00000001');
  await record({reference:'REC-002',amount:'25',linked:true,duplicate:true});
  await invoice({reference:'INV-002',amount:'40',direction:'payable'});
  assert.equal(await page.locator('.metric strong').nth(1).innerText(),'40');
  const downloadWait=page.waitForEvent('download');await page.locator('#export-backup').click();const download=await downloadWait;await download.saveAs(artifacts+'/workspace-backup.json');const backup=JSON.parse(await readFile(artifacts+'/workspace-backup.json','utf8'));assert.equal(backup.invoices.length,2);assert.equal(backup.receipts.length,1);
  await record({reference:'REC-003',amount:'75.00000001'});assert.equal(await page.locator('.metric strong').first().innerText(),'0');assert((await page.locator('#ledger').innerText()).includes('Matched records'));
  await record({reference:'REC-004',amount:'1'});assert((await page.locator('#ledger').innerText()).includes('Over-recorded'));
  await page.locator('#backup-file').setInputFiles(artifacts+'/workspace-backup.json');await page.locator('#confirm-dialog').waitFor({state:'visible'});assert((await page.locator('#confirm-copy').innerText()).includes('2 invoices and 1 payment records'));await page.locator('#confirm-action').click();await page.locator('#confirm-dialog').waitFor({state:'hidden'});assert.equal(await page.locator('.metric strong').first().innerText(),'75.00000001');
  await page.locator('#backup-file').setInputFiles({name:'invalid.json',mimeType:'application/json',buffer:Buffer.from('{}')});await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Import refused'));assert.equal(await page.locator('.metric strong').first().innerText(),'75.00000001');
  await page.reload({waitUntil:'networkidle'});assert.equal(await page.locator('.metric strong').first().innerText(),'75.00000001');
  assert.equal(await page.locator('#ledger img').count(),0);await page.locator('[data-detail]').first().click();assert.equal(await page.locator('#invoice-detail img').count(),0);assert((await page.locator('#invoice-detail').innerText()).includes('<img src=x'));await page.locator('#detail-dialog [data-close]').first().click();
  for(const width of [1440,390,320]){await page.setViewportSize({width,height:1000});await page.evaluate(()=>scrollTo(0,0));const size=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));assert(size.scroll<=size.width,JSON.stringify(size));await page.screenshot({path:`${artifacts}/workspace-${width}.png`});}
  await page.setViewportSize({width:1440,height:1000});await page.goto(base+'/app/integrations',{waitUntil:'networkidle'});const f=page.locator('#route-form');for(const [key,value]of Object.entries({reference:'cross-border-001',sourcePartner:'origin-psav',destinationPartner:'destination-bank',amount:'1000.00',destinationAmount:'200.00',quote:'quote-001'}))await f.locator(`[name=${key}]`).fill(value);await f.locator('[name=sourceRole]').selectOption('psav');await f.getByRole('button',{name:'Build integration draft'}).click();await page.locator('#route-result').waitFor({state:'visible'});const draft=JSON.parse(await page.locator('#draft-json').textContent());assert.equal(draft.source.partner_role,'psav');assert.equal(draft.source.currency,'BRL');assert.equal(draft.destination.currency,'EUR');assert.equal(draft.execution_enabled,false);
  await page.locator('[data-event=settled]').click();assert((await page.locator('#sample-error').innerText()).includes('Cannot move'));
  for(const type of ['accepted','submitted','settled','credited','returned'])await page.locator(`[data-event=${type}]`).click();assert.equal(await page.locator('#sample-status').innerText(),'returned');const sample=JSON.parse(await page.locator('#sample-json').textContent());assert.equal(sample.settlement.status,'not_observed');assert.equal(sample.execution_enabled,false);
  const routeDownloadWait=page.waitForEvent('download');await page.locator('#download-route').click();await(await routeDownloadWait).saveAs(artifacts+'/integration-draft.json');assert.equal(JSON.parse(await readFile(artifacts+'/integration-draft.json','utf8')).status,'draft');
  for(const width of [1440,390,320]){await page.setViewportSize({width,height:1000});await page.locator('#route-result').scrollIntoViewIfNeeded();const size=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));assert(size.scroll<=size.width,JSON.stringify(size));await page.screenshot({path:`${artifacts}/integrations-${width}.png`});}
  await page.evaluate(()=>navigator.serviceWorker.ready);await page.reload({waitUntil:'networkidle'});assert(await page.evaluate(()=>Boolean(navigator.serviceWorker.controller)));
  const cacheKeys=await page.evaluate(async()=>{const cache=await caches.open('bloch-pay-shell-v1');return(await cache.keys()).map(r=>new URL(r.url).pathname);});assert(cacheKeys.includes('/app/integrations'));assert(cacheKeys.includes('/app/'));
  await context.setOffline(true);await page.reload({waitUntil:'networkidle'});assert.equal(await page.locator('#route-form').count(),1);await page.goto(base+'/app/',{waitUntil:'networkidle'});assert.equal(await page.locator('.metric strong').first().innerText(),'75.00000001');assert((await page.locator('#connection').innerText()).includes('Offline'));await context.setOffline(false);
  const other=await context.newPage();await other.goto(base+'/app/',{waitUntil:'networkidle'});await invoice({reference:'INV-003',amount:'10'});await other.locator('#new-invoice').click();const stale=other.locator('#invoice-form');for(const [key,value]of Object.entries({reference:'INV-stale',counterparty:'Stale tab',amount:'10'}))await stale.locator(`[name=${key}]`).fill(value);await stale.getByRole('button',{name:'Save invoice',exact:true}).click();assert((await stale.locator('.form-error').innerText()).includes('another tab'));await other.close();
  await page.goto(base+'/',{waitUntil:'networkidle'});assert.equal(await page.locator('a[href="app/"]').count()>0,true);assert((await page.locator('#connectivity').innerText()).includes('VASPs'));assert((await page.locator('#connectivity').innerText()).includes('SEPA'));await page.screenshot({path:artifacts+'/homepage-mobile.png'});
  assert.deepEqual(errors,[]);assert.deepEqual(failures,[]);
  const report={url:base,time:new Date().toISOString(),result:'PASS',checks:['Invoice creation and persistence','One-satoshi precision','Partial / matched / excess records','Duplicate transaction output refused','Backup export, replacement and malformed import','HTML escaped','Three responsive widths','Cross-border PSAV to bank draft','Sample state ordering and returns','Export remains non-executable','PWA offline reload and saved records','Stale-tab writes rejected','Homepage entry points'],cachedFiles:cacheKeys,errors,failures};await writeFile(artifacts+'/verification.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));
}finally{await browser.close();if(server)await new Promise(done=>server.close(done));}
