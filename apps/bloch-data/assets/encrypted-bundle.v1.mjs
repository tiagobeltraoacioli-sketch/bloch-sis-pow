import {sha256} from './reconcile.v1.mjs';
import {readExport} from './audit.v1.mjs';
import {verifyAuditBundle,MAX_AUDIT_BUNDLE_BYTES} from './audit-bundle.v1.mjs';

export const MAX_ENCRYPTED_BUNDLE_BYTES=129*1024*1024;
export const PBKDF2_ITERATIONS=600000;
const schema='bloch.data.encrypted-audit-bundle.v1';
const encode=value=>JSON.stringify(value,null,2)+'\n';
const utf8=new TextEncoder();
const exactKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const hex=/^[0-9a-f]{64}$/;
function requireCrypto(){if(!globalThis.crypto?.subtle||!globalThis.crypto?.getRandomValues)throw new Error('Secure Web Crypto is required. Use HTTPS or a trusted localhost server.');}
export function validateBundlePassword(password){
  if(typeof password!=='string'||!password.isWellFormed()||password.length>512||/\p{Cc}/u.test(password))throw new Error('Use a password of 16–256 Unicode characters without control characters.');
  const length=[...password].length;
  if(length<16||length>256||!password.trim())throw new Error('Use a password of 16–256 Unicode characters; whitespace alone is not accepted.');
  // No trimming, case folding or Unicode normalization: exact UTF-8 is the key input.
  return utf8.encode(password);
}
function base64(bytes){const chunks=[];for(let index=0;index<bytes.length;index+=32768)chunks.push(String.fromCharCode(...bytes.subarray(index,index+32768)));return btoa(chunks.join(''));}
function decodeBase64(value,limit,label,exactLength){
  if(typeof value!=='string'||!value.length||value.length%4!==0||value.length>Math.ceil(limit/3)*4||/[^A-Za-z0-9+/=]/.test(value))throw new Error(`Invalid ${label} encoding or size.`);
  let binary;try{binary=atob(value);}catch{throw new Error(`Invalid ${label} encoding.`);}
  if(binary.length>limit||(exactLength!==undefined&&binary.length!==exactLength))throw new Error(`Invalid ${label} size.`);
  const bytes=new Uint8Array(binary.length);for(let index=0;index<binary.length;index++)bytes[index]=binary.charCodeAt(index);
  if(base64(bytes)!==value)throw new Error(`Use canonical base64 for ${label}.`);return bytes;
}
function header(salt,iv){return {schema,content_type:'bloch.data.audit-bundle.v1',encoding:'base64',kdf:{name:'PBKDF2',hash:'SHA-256',iterations:PBKDF2_ITERATIONS,salt:base64(salt)},cipher:{name:'AES-GCM',key_bits:256,iv:base64(iv),tag_bits:128}};}
async function derive(passwordBytes,salt,usage){
  let material;
  try{material=await crypto.subtle.importKey('raw',passwordBytes,{name:'PBKDF2'},false,['deriveKey']);}
  finally{passwordBytes.fill(0);}
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:PBKDF2_ITERATIONS,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,[usage]);
}
function parseEnvelope(text){
  if(typeof text!=='string'||!text.isWellFormed()||utf8.encode(text).length>MAX_ENCRYPTED_BUNDLE_BYTES)throw new Error('Encrypted file must be valid UTF-8 and at most 129 MiB.');
  const value=readExport(text,MAX_ENCRYPTED_BUNDLE_BYTES);
  if(!exactKeys(value,['schema','content_type','encoding','kdf','cipher','ciphertext'])||value.schema!==schema||value.content_type!=='bloch.data.audit-bundle.v1'||value.encoding!=='base64'||!exactKeys(value.kdf,['name','hash','iterations','salt'])||value.kdf.name!=='PBKDF2'||value.kdf.hash!=='SHA-256'||value.kdf.iterations!==PBKDF2_ITERATIONS||!exactKeys(value.cipher,['name','key_bits','iv','tag_bits'])||value.cipher.name!=='AES-GCM'||value.cipher.key_bits!==256||value.cipher.tag_bits!==128)throw new Error('Unsupported encrypted bundle format or cryptographic parameters.');
  const salt=decodeBase64(value.kdf.salt,32,'salt',32),iv=decodeBase64(value.cipher.iv,12,'IV',12);
  const ciphertext=decodeBase64(value.ciphertext,MAX_AUDIT_BUNDLE_BYTES+16,'ciphertext');
  if(ciphertext.length<=16)throw new Error('Encrypted bundle payload is empty.');
  const metadata=header(salt,iv);
  if(encode({...metadata,ciphertext:value.ciphertext})!==text)throw new Error('Use the exact encrypted export, including field order and formatting.');
  return {metadata,salt,iv,ciphertext};
}

export function generateBundlePassword(){requireCrypto();return base64(crypto.getRandomValues(new Uint8Array(24))).replaceAll('+','-').replaceAll('/','_');}

export async function encryptAuditBundle({text,password,expectedBundleDigest=''}){
  requireCrypto();const passwordBytes=validateBundlePassword(password);let plaintext;
  try{
    // Only a fully verified audit bundle can be protected by this exporter.
    await verifyAuditBundle(text,expectedBundleDigest);
    const salt=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12)),metadata=header(salt,iv);
    const key=await derive(passwordBytes,salt,'encrypt');plaintext=utf8.encode(text);
    const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,tagLength:128,additionalData:utf8.encode(encode(metadata))},key,plaintext));
    const envelope={...metadata,ciphertext:base64(encrypted)},bytes=encode(envelope);
    if(utf8.encode(bytes).length>MAX_ENCRYPTED_BUNDLE_BYTES)throw new Error('Encrypted export exceeds the supported size limit.');
    return {bytes,digest:await sha256(bytes)};
  }finally{passwordBytes.fill(0);plaintext?.fill(0);}
}

export async function decryptAuditBundle({text,password,expectedDigest='',expectedBundleDigest=''}){
  requireCrypto();const passwordBytes=validateBundlePassword(password);let plaintext;
  try{
    const parsed=parseEnvelope(text),digest=await sha256(text);
    if(expectedDigest!==''&&(!hex.test(expectedDigest)||digest!==expectedDigest))throw new Error('Encrypted file does not match the independently retained SHA-256.');
    const key=await derive(passwordBytes,parsed.salt,'decrypt');
    try{plaintext=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:parsed.iv,tagLength:128,additionalData:utf8.encode(encode(parsed.metadata))},key,parsed.ciphertext));}
    catch{throw new Error('Unable to decrypt: incorrect password or altered encrypted file.');}
    let bundleText;
    try{bundleText=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(plaintext);}
    catch{throw new Error('Decrypted payload is not a valid UTF-8 audit bundle.');}
    // A valid authentication tag is not a substitute for source/case verification.
    const verified=await verifyAuditBundle(bundleText,expectedBundleDigest);
    return {digest,pinned:expectedDigest!=='',verified};
  }finally{passwordBytes.fill(0);plaintext?.fill(0);}
}
