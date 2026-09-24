import {MAX_AUDIT_BUNDLE_BYTES} from './audit-bundle.v1.mjs';
import {MAX_ENCRYPTED_BUNDLE_BYTES,encryptAuditBundle,decryptAuditBundle,generateBundlePassword,validateBundlePassword} from './encrypted-bundle.v1.mjs';

const $=id=>document.getElementById(id);
export function setupEncryptedBundles(getPreparedBundle,openForReview,download){
  let encryptGeneration=0,decryptGeneration=0,copiedSource=null,sealed=null,opened=null;
  const status=(id,message,error=false)=>{$(id).textContent=message;$(id).classList.toggle('error',error);};
  function invalidateEncrypt(){encryptGeneration++;sealed=null;$('eb-ready').hidden=true;$('eb-encrypted-digest').textContent='';$('eb-encrypted-size').textContent='';$('eb-encrypt').disabled=false;}
  function invalidateDecrypt(){decryptGeneration++;opened=null;$('eb-unlocked').hidden=true;for(const id of ['eb-open-summary','eb-envelope-digest','eb-bundle-digest','eb-pin-result'])$(id).textContent='';$('eb-decrypt').disabled=false;}
  function hidePasswords(side){const ids=side==='encrypt'?['eb-password','eb-confirm']:['eb-unlock-password'];for(const id of ids){$(id).value='';$(id).type='password';}$(side==='encrypt'?'eb-show-password':'eb-show-unlock').checked=false;}
  function lock(){invalidateDecrypt();hidePasswords('decrypt');for(const id of ['eb-encrypted-file','eb-pin','eb-inner-pin'])$(id).value='';status('eb-unlock-status','This encrypted-file workspace is locked and cleared. Other workspaces, original files and downloads remain separate.');}
  async function read(file,limit){if(file.size>limit)throw new Error('File exceeds the displayed size limit.');try{return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer());}catch(error){if(error instanceof TypeError)throw new Error('Use valid UTF-8 JSON.');throw error;}}
  $('eb-source').addEventListener('change',()=>{copiedSource=null;invalidateEncrypt();hidePasswords('encrypt');$('eb-source-name').textContent=$('eb-source').files[0]?.name??'No bundle selected';status('eb-encrypt-status','Source changed. Enter and confirm the password to verify and encrypt it.');});
  $('eb-use-current').addEventListener('click',()=>{invalidateEncrypt();hidePasswords('encrypt');copiedSource=getPreparedBundle();$('eb-source').value='';$('eb-source-pin').value='';$('eb-source-name').textContent=copiedSource?'Prepared audit bundle copied into this workspace':'No bundle selected';status('eb-encrypt-status',copiedSource?'Copied the prepared bundle snapshot. Save a unique password before encrypting. Later changes above do not change this input.':'Prepare an audit bundle above first, or select a retained plaintext bundle.',!copiedSource);});
  $('eb-clear-encrypt').addEventListener('click',()=>{invalidateEncrypt();copiedSource=null;hidePasswords('encrypt');$('eb-source').value='';$('eb-source-pin').value='';$('eb-source-name').textContent='No bundle selected';status('eb-encrypt-status','Encryption inputs and output cleared here. Existing plaintext files, other workspaces and downloads remain unchanged.');});
  for(const id of ['eb-password','eb-confirm','eb-source-pin'])$(id).addEventListener('input',invalidateEncrypt);
  $('eb-generate').addEventListener('click',()=>{invalidateEncrypt();try{const password=generateBundlePassword();$('eb-password').value=password;$('eb-confirm').value=password;status('eb-encrypt-status','A random password was generated. Save it in your password manager before encrypting. It cannot be recovered here.');}catch(error){status('eb-encrypt-status',error.message,true);}});
  $('eb-show-password').addEventListener('change',()=>{for(const id of ['eb-password','eb-confirm'])$(id).type=$('eb-show-password').checked?'text':'password';});
  $('eb-show-unlock').addEventListener('change',()=>{$('eb-unlock-password').type=$('eb-show-unlock').checked?'text':'password';});
  $('eb-encrypt').addEventListener('click',async()=>{
    invalidateEncrypt();const token=encryptGeneration,file=$('eb-source').files[0],snapshot=copiedSource,expectedBundleDigest=$('eb-source-pin').value.trim().toLowerCase();let password=$('eb-password').value,confirmation=$('eb-confirm').value;hidePasswords('encrypt');
    try{
      if(!file&&!snapshot)throw new Error('Select a plaintext audit bundle or copy the prepared bundle above.');
      if(password!==confirmation)throw new Error('Passwords do not match. Enter both again.');
      validateBundlePassword(password).fill(0);confirmation='';$('eb-encrypt').disabled=true;status('eb-encrypt-status','Verifying the complete audit bundle, deriving the key and encrypting locally…');
      const text=snapshot??await read(file,MAX_AUDIT_BUNDLE_BYTES);if(token!==encryptGeneration)return;
      const task=encryptAuditBundle({text,password,expectedBundleDigest});password='';const result=await task;if(token!==encryptGeneration)return;
      sealed=result;$('eb-encrypted-digest').textContent=result.digest;$('eb-encrypted-size').textContent=`${new TextEncoder().encode(result.bytes).length.toLocaleString('en-US')} UTF-8 bytes · AES-256-GCM · encrypted file only`;$('eb-ready').hidden=false;status('eb-encrypt-status','Encrypted file ready. Password fields were cleared. Keep the password separately; plaintext originals and other workspaces are not deleted.');
    }catch(error){if(token===encryptGeneration)status('eb-encrypt-status','Encryption failed: '+error.message,true);}
    finally{password='';confirmation='';if(token===encryptGeneration)$('eb-encrypt').disabled=false;}
  });
  $('eb-download').addEventListener('click',()=>{if(sealed)download('bloch-data-audit.encrypted.json',sealed.bytes,'application/json');});
  $('eb-download-hash').addEventListener('click',()=>{if(sealed)download('bloch-data-audit.encrypted.json.sha256',`${sealed.digest}  bloch-data-audit.encrypted.json\n`,'text/plain');});
  $('eb-encrypted-file').addEventListener('change',()=>{invalidateDecrypt();hidePasswords('decrypt');status('eb-unlock-status','Encrypted file changed. Enter its exact password and verify again.');});
  for(const id of ['eb-unlock-password','eb-pin','eb-inner-pin'])$(id).addEventListener('input',invalidateDecrypt);
  $('eb-lock').addEventListener('click',lock);
  $('eb-decrypt').addEventListener('click',async()=>{
    invalidateDecrypt();const token=decryptGeneration,file=$('eb-encrypted-file').files[0],expectedDigest=$('eb-pin').value.trim().toLowerCase(),expectedBundleDigest=$('eb-inner-pin').value.trim().toLowerCase();let password=$('eb-unlock-password').value;hidePasswords('decrypt');
    try{
      if(!file)throw new Error('Select an encrypted audit bundle.');validateBundlePassword(password).fill(0);$('eb-decrypt').disabled=true;status('eb-unlock-status','Decrypting and verifying the original extracts, preparation, evidence and review history…');
      const text=await read(file,MAX_ENCRYPTED_BUNDLE_BYTES);if(token!==decryptGeneration)return;const task=decryptAuditBundle({text,password,expectedDigest,expectedBundleDigest});password='';const result=await task;if(token!==decryptGeneration)return;
      opened=result;const bundle=result.verified;$('eb-open-summary').textContent=`${bundle.bundle.mode==='synthetic_example'?'SYNTHETIC EXAMPLE':'LOCAL FILES'} · ${bundle.bundle.module} · ${bundle.case.evidence.report.result.key_count} keys · review entries: ${bundle.case.review.events.length}`;
      $('eb-envelope-digest').textContent=result.digest;$('eb-bundle-digest').textContent=bundle.digest;$('eb-pin-result').textContent=`Encrypted file reference: ${result.pinned?'matched':'not supplied'}. Decrypted bundle reference: ${bundle.pinned?'matched':'not supplied'}.`;
      $('eb-unlocked').hidden=false;status('eb-unlock-status','Decryption authenticated and complete bundle verification passed. Plaintext is now available in this workspace; the password field was cleared.');
    }catch(error){if(token===decryptGeneration)status('eb-unlock-status','Unlock failed: '+error.message,true);}
    finally{password='';if(token===decryptGeneration)$('eb-decrypt').disabled=false;}
  });
  $('eb-plaintext').addEventListener('click',()=>{if(opened)download('bloch-data-audit.bundle.json',opened.verified.bytes,'application/json');});
  $('eb-open-case').addEventListener('click',()=>{if(opened)openForReview(structuredClone(opened.verified.case));});
}
