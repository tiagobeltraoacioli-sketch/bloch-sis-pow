import test from 'node:test';
import assert from 'node:assert/strict';
import {pbkdf2Sync,createCipheriv,createDecipheriv,randomBytes,createHash} from 'node:crypto';
import {defaultConfig} from '../apps/bloch-data/assets/modules.v1.mjs';
import {auditBundleExample} from '../apps/bloch-data/assets/audit-bundle-samples.v1.mjs';
import {encryptAuditBundle,decryptAuditBundle,validateBundlePassword,generateBundlePassword,PBKDF2_ITERATIONS} from '../apps/bloch-data/assets/encrypted-bundle.v1.mjs';

const encode=value=>JSON.stringify(value,null,2)+'\n';
const password='Test fixture only: correct horse 42 🐎';
const sha=text=>createHash('sha256').update(text).digest('hex');
const example=await auditBundleExample(defaultConfig('cash','br','bank'));
const sealed=await encryptAuditBundle({text:example.bytes,password});
// Independent Node cipher API: fixed wire parameters are not imported from the app.
function referenceEncrypt(plaintext,secret=password,wrongHeader=false){
  const salt=randomBytes(32),iv=randomBytes(12),header={schema:'bloch.data.encrypted-audit-bundle.v1',content_type:'bloch.data.audit-bundle.v1',encoding:'base64',kdf:{name:'PBKDF2',hash:'SHA-256',iterations:600000,salt:salt.toString('base64')},cipher:{name:'AES-GCM',key_bits:256,iv:iv.toString('base64'),tag_bits:128}};
  const key=pbkdf2Sync(Buffer.from(secret,'utf8'),salt,600000,32,'sha256'),cipher=createCipheriv('aes-256-gcm',key,iv,{authTagLength:16});
  cipher.setAAD(Buffer.from(wrongHeader ? "wrong authenticated metadata" : encode(header)));const content=Buffer.concat([cipher.update(plaintext),cipher.final(),cipher.getAuthTag()]);key.fill(0);
  return encode({...header,ciphertext:content.toString('base64')});
}
function referenceDecrypt(text,secret=password){
  const {ciphertext,...header}=JSON.parse(text),payload=Buffer.from(ciphertext,'base64'),key=pbkdf2Sync(Buffer.from(secret,'utf8'),Buffer.from(header.kdf.salt,'base64'),600000,32,'sha256');
  const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(header.cipher.iv,'base64'),{authTagLength:16});
  decipher.setAAD(Buffer.from(encode(header)));decipher.setAuthTag(payload.subarray(-16));const plaintext=Buffer.concat([decipher.update(payload.subarray(0,-16)),decipher.final()]);key.fill(0);return plaintext.toString('utf8');
}
test('Web Crypto encryption interoperates with the independent Node cipher API',()=>{
  assert.equal(PBKDF2_ITERATIONS,600000);assert.equal(referenceDecrypt(sealed.bytes),example.bytes);assert.equal(sealed.digest,sha(sealed.bytes));
});
test('Node cipher export opens in Web Crypto and retains exact bundle bytes',async()=>{
  const text=referenceEncrypt(Buffer.from(example.bytes)),result=await decryptAuditBundle({text,password,expectedDigest:sha(text),expectedBundleDigest:example.digest});
  assert.equal(result.pinned,true);assert.equal(result.verified.pinned,true);assert.equal(result.verified.bytes,example.bytes);
});
for(const module of ['trades','cash','positions','onchain'])test(`${module}: encrypted round trip retains originals, prepared case and review`,async()=>{
  const original=await auditBundleExample(defaultConfig(module,'br','bank')),encrypted=await encryptAuditBundle({text:original.bytes,password,expectedBundleDigest:original.digest});
  const result=await decryptAuditBundle({text:encrypted.bytes,password});
  assert.equal(result.pinned,false);assert.equal(result.verified.pinned,false);assert.equal(result.verified.digest,original.digest);assert.equal(result.verified.bytes,original.bytes);
  assert.equal(result.verified.case.review.events.length,1);assert.equal(result.verified.case.review.events[0].state,'investigating');assert.equal(result.verified.bundle.assurance.encryption,'none');
  assert.deepEqual(result.verified.bundle.components,original.bundle.components);
});
test('same input receives fresh salt, IV and ciphertext on every export',async()=>{
  const again=await encryptAuditBundle({text:example.bytes,password}),first=JSON.parse(sealed.bytes),second=JSON.parse(again.bytes);
  for(const [a,b] of [[first.kdf.salt,second.kdf.salt],[first.cipher.iv,second.cipher.iv],[first.ciphertext,second.ciphertext],[sealed.digest,again.digest]])assert.notEqual(a,b);
  assert.equal(Buffer.from(second.kdf.salt,'base64').length,32);assert.equal(Buffer.from(second.cipher.iv,'base64').length,12);
});
test('envelope omits plaintext identities, names, notes, password and timestamps',()=>{
  const value=JSON.parse(sealed.bytes);assert.deepEqual(Object.keys(value),['schema','content_type','encoding','kdf','cipher','ciphertext']);
  for(const text of [example.digest,password,'Synthetic reviewer','original-a.csv','created_at','review_sha256','"module"','"mode"'])assert.equal(sealed.bytes.includes(text),false,text);
});
test('incorrect password fails without returning plaintext',async()=>{
  await assert.rejects(decryptAuditBundle({text:sealed.bytes,password:'A completely different password'}),/incorrect password or altered/);
});
for(const part of ['ciphertext','tag','salt','iv'])test(`altered ${part} fails authenticated decryption`,async()=>{
  const value=JSON.parse(sealed.bytes),field=part==='salt'?value.kdf:part==='iv'?value.cipher:value,key=part==='tag'?'ciphertext':part;
  const bytes=Buffer.from(field[key],'base64');bytes[part==='tag'?bytes.length-1:0]^=1;field[key]=bytes.toString('base64');
  await assert.rejects(decryptAuditBundle({text:encode(value),password}),/incorrect password or altered/);
});
test('encrypted and plaintext independent references gate different exact identities',async()=>{
  await assert.rejects(decryptAuditBundle({text:sealed.bytes,password,expectedDigest:'0'.repeat(64)}),/Encrypted file does not match/);
  await assert.rejects(decryptAuditBundle({text:sealed.bytes,password,expectedDigest:'invalid'}),/Encrypted file does not match/);
  await assert.rejects(decryptAuditBundle({text:sealed.bytes,password,expectedBundleDigest:'0'.repeat(64)}),/does not match/);
  await assert.rejects(encryptAuditBundle({text:example.bytes,password,expectedBundleDigest:'0'.repeat(64)}),/does not match/);
});
test('downgraded, excessive or unsupported algorithms and header fields fail closed',async()=>{
  const mutations=[v=>v.kdf.iterations=1,v=>v.kdf.iterations=600000000,v=>v.kdf.hash='SHA-1',v=>v.kdf.name='HKDF',v=>v.cipher.tag_bits=96,v=>v.cipher.key_bits=128,v=>v.cipher.name='AES-CBC',v=>v.content_type='arbitrary',v=>v.schema+='x',v=>v.encoding='utf8',v=>v.kdf.extra=true,v=>v.extra=true];
  for(const mutate of mutations){const value=JSON.parse(sealed.bytes);mutate(value);await assert.rejects(decryptAuditBundle({text:encode(value),password}),/Unsupported/);}
});
test('rejects noncanonical JSON, field order, base64, and incorrect sizes',async()=>{
  await assert.rejects(decryptAuditBundle({text:JSON.stringify(JSON.parse(sealed.bytes)),password}),/canonical|exact|original|format/i);
  const reordered=JSON.parse(sealed.bytes),{schema,...rest}=reordered;await assert.rejects(decryptAuditBundle({text:encode({...rest,schema}),password}),/field order/);
  for(const mutate of [v=>v.kdf.salt='AAAA',v=>v.cipher.iv='AAAA',v=>v.ciphertext='A'.repeat(24),v=>v.ciphertext='AA==',v=>v.kdf.salt+='\n',v=>v.kdf.salt=v.kdf.salt.slice(0,-2)+'B=',v=>v.ciphertext='!' + v.ciphertext.slice(1)]){
    const value=JSON.parse(sealed.bytes);mutate(value);await assert.rejects(decryptAuditBundle({text:encode(value),password}));
  }
});
test('export refuses damaged source bundles even if a password is valid',async()=>{
  const value=JSON.parse(example.bytes);value.components[2].content+=' ';
  await assert.rejects(encryptAuditBundle({text:encode(value),password}),/mismatch/);
});
test('authentic ciphertext with damaged inner components still fails complete verification',async()=>{
  const value=JSON.parse(example.bytes);value.components[2].content+=' ';
  await assert.rejects(decryptAuditBundle({text:referenceEncrypt(Buffer.from(encode(value))),password}),/mismatch/);
});
test('a tag computed over different authenticated metadata cannot be opened',async()=>{
  await assert.rejects(decryptAuditBundle({text:referenceEncrypt(Buffer.from(example.bytes),password,true),password}),/incorrect password or altered/);
});
test('authenticated non-bundle or malformed UTF-8 payload is never opened',async()=>{
  await assert.rejects(decryptAuditBundle({text:referenceEncrypt(Buffer.from('{}\n')),password}));
  await assert.rejects(decryptAuditBundle({text:referenceEncrypt(Buffer.from([0xc3,0x28])),password}),/not a valid UTF-8/);
});
test('passwords use exact Unicode bytes, including leading/trailing spaces',async()=>{
  const secret='  Résumé for local audit 42  ',text=referenceEncrypt(Buffer.from(example.bytes),secret);
  assert.equal((await decryptAuditBundle({text,password:secret})).verified.bytes,example.bytes);
  await assert.rejects(decryptAuditBundle({text,password:secret.normalize('NFD')}),/incorrect password/);
  await assert.rejects(decryptAuditBundle({text,password:secret.trim()}),/incorrect password/);
});
test('password limits count Unicode code points and reject invalid or control input',()=>{
  for(const value of [undefined,42,'short',' '.repeat(20),'a'.repeat(257),'a'.repeat(20)+'\n','a'.repeat(20)+'\u007f','a'.repeat(20)+'\u0085','a'.repeat(20)+'\ud800'])assert.throws(()=>validateBundlePassword(value));
  for(const value of ['a'.repeat(16),'a'.repeat(256),'🐎'.repeat(256),'  spaces are significant  '])assert.deepEqual(validateBundlePassword(value),new TextEncoder().encode(value));
});
test('generated passwords use 24 random bytes in a portable 32-character representation',()=>{
  const passwords=new Set();for(let i=0;i<16;i++){const value=generateBundlePassword();assert.match(value,/^[A-Za-z0-9_-]{32}$/);validateBundlePassword(value).fill(0);passwords.add(value);}assert.equal(passwords.size,16);
});
