// Explicit real public-source verification in an isolated browser profile.
// The local participant is a test context, not a real onboarded institution.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {emptyStudio,emptyReview} from '../app/studio-model.mjs';
import {validatePacket} from '../app/evidence-model.mjs';
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const origin=process.argv[2];if(!origin)throw new Error('Pass an explicit preview or production origin.');
const assets=(process.env.PAY_LIVE_ASSETS||'BLCH,BTC,ETH,USDT,USDC').split(',');
const out=process.env.PAY_ARTIFACTS||'/private/tmp/bloch-pay-evidence-live';await mkdir(out,{recursive:true});
const studio=emptyStudio(),now=new Date().toISOString();studio.partners.push({id:'verification-context',name:'Isolated source verification context',role:'infrastructure',jurisdiction:'Test context only',owner:'',stage:'discovery',rails:['blch'],review:emptyReview(),modules:{enabled:['graphus','constellation','system_map'],assets,purpose:'Read-only source verification; no real participant onboarding',organization_reference:'',private_profile:'none'},note:'Temporary isolated browser profile',created_at:now,updated_at:now});
const browser=await chromium.launch({headless:true,...(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{})});
const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce',acceptDownloads:true});
const page=await context.newPage(),errors=[],reads=[],transport=[];page.on('pageerror',error=>errors.push(error.message));page.on('dialog',dialog=>dialog.accept());
page.on('requestfailed',request=>{transport.push({url:request.url(),error:request.failure()?.errorText});console.error(JSON.stringify(transport.at(-1)));});page.on('console',message=>{if(message.type()==='error')console.error(message.text());});
page.on('request',request=>{if(request.url().startsWith('https://bloch-graphus.xyz/api/chain/network')){const url=new URL(request.url());assert.deepEqual([...url.searchParams.keys()],['asset']);assert.equal(request.headers().authorization,undefined);assert.equal(request.headers().cookie,undefined);reads.push(url.searchParams.get('asset'));}});
const report={origin,verified_at:now,participant:'Isolated synthetic local context',sources:[],transport};
try{
  await page.goto(origin+'/app/evidence',{waitUntil:'networkidle'});assert.equal(reads.length,0);await page.evaluate(studio=>localStorage.setItem('bloch-pay-integration-workspace-v1',JSON.stringify(studio)),studio);await page.reload({waitUntil:'networkidle'});await page.waitForFunction(()=>!document.querySelector('#export-evidence-vault').disabled);
  for(const asset of assets){
    await page.locator('#new-evidence').click();await page.locator('#capture-asset').selectOption(asset);await page.locator('#capture-public').click();await page.waitForFunction(()=>!document.querySelector('#capture-public').disabled,{},{timeout:55000});const status=await page.locator('#capture-status').innerText();assert(status.startsWith('Captured '),status);
    const downloaded=page.waitForEvent('download');await page.locator('#export-evidence-packet').click();const file=out+'/'+asset+'.json';await(await downloaded).saveAs(file);const packet=await validatePacket(JSON.parse(await readFile(file,'utf8')));assert.equal(packet.dataset.asset,asset);
    await page.locator('#save-evidence').click();await page.waitForFunction(()=>document.querySelector('#evidence-saved-state').textContent==='REVISION 1');await page.locator('#evidence-source').scrollIntoViewIfNeeded();await page.screenshot({path:out+'/'+asset+'.png'});
    const observed={asset,records:packet.diagnostics.records,references:packet.diagnostics.references,transactions:packet.diagnostics.transactions,source:packet.dataset.source,retrieved_at:packet.dataset.retrieved_at,anchor_height:packet.dataset.anchor.height,sha256:packet.dataset_sha256};report.sources.push(observed);console.log(JSON.stringify(observed));
  }
  await page.evaluate(()=>navigator.serviceWorker.ready);await page.reload({waitUntil:'networkidle'});await context.setOffline(true);await page.reload({waitUntil:'networkidle'});await page.waitForFunction(n=>document.querySelectorAll('[data-open-evidence]').length===n,assets.length);await page.locator('[data-open-evidence]').first().click();assert.equal(await page.locator('#evidence-saved-state').innerText(),'REVISION 1');assert.equal(reads.length,assets.length);assert.deepEqual(errors,[]);
  Object.assign(report,{result:'PASS',credential_free:true,offline_saved_reviews:assets.length,source_requests:reads.length,errors});await writeFile(out+'/verification.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));
}catch(error){Object.assign(report,{result:'FAIL',error:error.message,source_requests:reads.length,errors});await writeFile(out+'/verification.json',JSON.stringify(report,null,2));throw error;}finally{await browser.close();}
