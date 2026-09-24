import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {pbkdf2Sync,createDecipheriv,createHash} from 'node:crypto';

export async function verifyEncryption({page,context,text,digest,evidenceDigest}){
  const password='Browser QA fixture only: audit bundle 42 🐎';
  const file=(name,value)=>({name,mimeType:'application/json',buffer:Buffer.from(value)});
  const waitStatus=(id,needle)=>page.waitForFunction(({id,needle})=>document.getElementById(id).textContent.includes(needle),{id,needle});
  const encryptPassword=async()=>{await page.fill('#eb-password',password);await page.fill('#eb-confirm',password);};
  const unlock=async(secret=password)=>{await page.fill('#eb-unlock-password',secret);await page.click('#eb-decrypt');};
  const download=async selector=>{const pending=page.waitForEvent('download');await page.click(selector);return readFile(await (await pending).path(),'utf8');};
  function independentlyDecrypt(bytes,secret){
    const {ciphertext,...header}=JSON.parse(bytes),body=Buffer.from(ciphertext,'base64'),key=pbkdf2Sync(Buffer.from(secret),Buffer.from(header.kdf.salt,'base64'),600000,32,'sha256');
    const cipher=createDecipheriv('aes-256-gcm',key,Buffer.from(header.cipher.iv,'base64'),{authTagLength:16});cipher.setAAD(Buffer.from(JSON.stringify(header,null,2)+'\n'));cipher.setAuthTag(body.subarray(-16));
    const result=Buffer.concat([cipher.update(body.subarray(0,-16)),cipher.final()]).toString('utf8');key.fill(0);return result;
  }
  await page.click('#eb-use-current');await waitStatus('eb-encrypt-status','Prepare an audit bundle');
  await page.click('#ab-example');await page.waitForSelector('#ab-ready:visible');const copiedDigest=await page.locator('#ab-build-digest').innerText();
  await page.click('#eb-use-current');await page.click('#ab-build-clear');
  await page.click('#eb-generate');const generated=await page.inputValue('#eb-password');assert.match(generated,/^[A-Za-z0-9_-]{32}$/);assert.equal(await page.inputValue('#eb-confirm'),generated);
  assert.equal(await page.locator('#eb-password').getAttribute('type'),'password');await page.check('#eb-show-password');assert.equal(await page.locator('#eb-password').getAttribute('type'),'text');
  await page.click('#eb-encrypt');await page.waitForSelector('#eb-ready:visible');
  assert.equal(await page.inputValue('#eb-password'),'');assert.equal(await page.inputValue('#eb-confirm'),'');assert.equal(await page.isChecked('#eb-show-password'),false);assert.equal(await page.locator('#eb-password').getAttribute('type'),'password');
  const copied=independentlyDecrypt(await download('#eb-download'),generated);assert.equal(createHash('sha256').update(copied).digest('hex'),copiedDigest,'Prepared bundle copy survives clearing its original builder');
  await page.click('#eb-clear-encrypt');assert.equal(await page.locator('#eb-ready').isVisible(),false);
  await page.setInputFiles('#eb-source',file('private.bundle.json',text));await page.fill('#eb-source-pin',digest);
  await page.fill('#eb-password',password);await page.fill('#eb-confirm',password+' mismatch');await page.click('#eb-encrypt');await waitStatus('eb-encrypt-status','Passwords do not match');assert.equal(await page.locator('#eb-ready').isVisible(),false);assert.equal(await page.inputValue('#eb-password'),'');assert.equal(await page.inputValue('#eb-confirm'),'');
  await encryptPassword();await page.click('#eb-encrypt');await page.waitForSelector('#eb-ready:visible');
  const encrypted=await download('#eb-download'),encryptedDigest=createHash('sha256').update(encrypted).digest('hex');assert.equal(independentlyDecrypt(encrypted,password),text);assert.equal(await page.locator('#eb-encrypted-digest').innerText(),encryptedDigest);
  assert.equal(await download('#eb-download-hash'),`${encryptedDigest}  bloch-data-audit.encrypted.json\n`);assert.equal(encrypted.includes(digest),false);assert.equal(encrypted.includes(password),false);
  await page.locator('#encrypted-bundle').evaluate(element=>element.scrollIntoView({block:'start'}));await page.screenshot({path:'/private/tmp/blochdata-encrypted-bundle-1440.png'});
  await page.setInputFiles('#eb-encrypted-file',file('retained.encrypted.json',encrypted));await page.fill('#eb-pin',encryptedDigest);await page.fill('#eb-inner-pin',digest);
  await page.check('#eb-show-unlock');await unlock('Browser QA incorrect password');await waitStatus('eb-unlock-status','incorrect password or altered');assert.equal(await page.locator('#eb-unlocked').isVisible(),false);assert.equal(await page.inputValue('#eb-unlock-password'),'');assert.equal(await page.locator('#eb-unlock-password').getAttribute('type'),'password');assert.equal(await page.isChecked('#eb-show-unlock'),false);
  await unlock();await page.waitForSelector('#eb-unlocked:visible');assert.equal(await page.locator('#eb-bundle-digest').innerText(),digest);assert.equal(await page.locator('#eb-envelope-digest').innerText(),encryptedDigest);assert.equal(await page.locator('#eb-pin-result').innerText(),'Encrypted file reference: matched. Decrypted bundle reference: matched.');assert.ok((await page.locator('#eb-open-summary').innerText()).startsWith('LOCAL FILES'));
  assert.equal(await download('#eb-plaintext'),text);await page.click('#eb-open-case');assert.equal(await page.locator('#report-digest').innerText(),evidenceDigest);assert.equal(await page.locator('#review-entry-count').innerText(),'1');assert.equal(await page.locator('#review-history img, #review-history script').count(),0);
  for(const width of [1440,1280,1024,768,390,360]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`Encrypted outputs overflow at ${width}`);}
  await page.setViewportSize({width:390,height:844});await page.locator('#encrypted-bundle').evaluate(element=>element.scrollIntoView({block:'start'}));await page.screenshot({path:'/private/tmp/blochdata-encrypted-bundle-390.png'});await page.setViewportSize({width:1440,height:1100});
  await page.click('#eb-lock');assert.equal(await page.locator('#eb-unlocked').isVisible(),false);assert.equal(await page.inputValue('#eb-encrypted-file'),'');assert.equal(await page.locator('#eb-bundle-digest').innerText(),'');assert.equal(await page.locator('#report-digest').innerText(),evidenceDigest,'Lock only clears its own workspace');assert.equal(await page.locator('#review-entry-count').innerText(),'1');
  await page.setInputFiles('#eb-encrypted-file',file('retained.encrypted.json',encrypted));await page.fill('#eb-pin','0'.repeat(64));await unlock();await waitStatus('eb-unlock-status','Encrypted file does not match');assert.equal(await page.locator('#eb-unlocked').isVisible(),false);
  await page.fill('#eb-pin',encryptedDigest);await page.fill('#eb-inner-pin','0'.repeat(64));await unlock();await waitStatus('eb-unlock-status','does not match');assert.equal(await page.locator('#eb-unlocked').isVisible(),false);
  await page.fill('#eb-pin','');await page.fill('#eb-inner-pin','');await unlock();await page.waitForSelector('#eb-unlocked:visible');assert.equal(await page.locator('#eb-pin-result').innerText(),'Encrypted file reference: not supplied. Decrypted bundle reference: not supplied.');
  const tampered=JSON.parse(encrypted),payload=Buffer.from(tampered.ciphertext,'base64');payload[0]^=1;tampered.ciphertext=payload.toString('base64');await page.setInputFiles('#eb-encrypted-file',file('altered.encrypted.json',JSON.stringify(tampered,null,2)+'\n'));assert.equal(await page.locator('#eb-unlocked').isVisible(),false);await unlock();await waitStatus('eb-unlock-status','incorrect password or altered');assert.equal(await page.locator('#eb-unlocked').isVisible(),false);
  await page.setInputFiles('#eb-encrypted-file',file('invalid.encrypted.json',Buffer.from([0xc3,0x28])));await unlock();await waitStatus('eb-unlock-status','valid UTF-8');
  await page.setInputFiles('#eb-encrypted-file',file('retained.encrypted.json',encrypted));
  // Hold the real key derivation result to exercise clear/lock during async crypto.
  async function holdDerivation(){await page.evaluate(()=>{
    window.ebNativeDerive=crypto.subtle.deriveKey;window.ebDerivations=[];
    crypto.subtle.deriveKey=function(...args){const actual=window.ebNativeDerive.apply(this,args);return new Promise((resolve,reject)=>{window.ebDerivations.push(async()=>{try{resolve(await actual);}catch(error){reject(error);}});});};
    window.ebEncryptDone=false;window.ebDecryptDone=false;window.ebNativeEncrypt=crypto.subtle.encrypt;window.ebNativeDecrypt=crypto.subtle.decrypt;
    crypto.subtle.encrypt=async function(...args){try{return await window.ebNativeEncrypt.apply(this,args);}finally{window.ebEncryptDone=true;}};
    crypto.subtle.decrypt=async function(...args){try{return await window.ebNativeDecrypt.apply(this,args);}finally{window.ebDecryptDone=true;}};
  });}
  async function releaseDerivation(){await page.evaluate(async()=>{crypto.subtle.deriveKey=window.ebNativeDerive;await Promise.all(window.ebDerivations.map(release=>release()));});}
  async function restoreCrypto(){await page.evaluate(()=>{crypto.subtle.encrypt=window.ebNativeEncrypt;crypto.subtle.decrypt=window.ebNativeDecrypt;});}
  await holdDerivation();await unlock();await page.waitForFunction(()=>window.ebDerivations.length===1);await page.click('#eb-lock');await releaseDerivation();await page.waitForFunction(()=>window.ebDecryptDone);await restoreCrypto();assert.equal(await page.locator('#eb-unlocked').isVisible(),false);assert.equal(await page.inputValue('#eb-encrypted-file'),'');
  await holdDerivation();await encryptPassword();await page.click('#eb-encrypt');await page.waitForFunction(()=>window.ebDerivations.length===1);await page.click('#eb-clear-encrypt');await releaseDerivation();await page.waitForFunction(()=>window.ebEncryptDone);await restoreCrypto();assert.equal(await page.locator('#eb-ready').isVisible(),false);assert.equal(await page.inputValue('#eb-source'),'');
  // A fresh successful operation settles after the cancelled crypto tasks as well.
  await page.setInputFiles('#eb-encrypted-file',file('retained.encrypted.json',encrypted));await unlock();await page.waitForSelector('#eb-unlocked:visible');assert.equal(await page.locator('#eb-bundle-digest').innerText(),digest);await page.click('#eb-lock');
  assert.equal(await page.evaluate(()=>localStorage.length),0);assert.equal(await page.evaluate(()=>sessionStorage.length),0);assert.deepEqual(await page.evaluate(()=>indexedDB.databases()),[]);assert.deepEqual(await context.cookies(),[]);
}
