import {MAX_BYTES} from './reconcile.v1.mjs';
import {MAX_EVIDENCE_BYTES,MAX_REVIEW_BYTES,readExport,verifyEvidence,validateReview,verificationExport} from './audit.v1.mjs';

export function setupVerification(openForReview,download) {
  const $=id=>document.getElementById(id);
  const ids=['verify-report','verify-a','verify-b','verify-review'];
  let generation=0,verified=null,receipt=null;
  const status=(message,error=false)=>{$('verify-status').textContent=message;$('verify-status').classList.toggle('error',error);};
  function invalidate() {generation++;verified=null;receipt=null;$('verify-results').hidden=true;for(const id of ['verify-report-digest','verify-pin-result','verify-source-result','verify-comparison-result','verify-review-result'])$(id).textContent='';$('verify-run').disabled=false;}
  for(const id of ids)$(id).addEventListener('change',()=>{invalidate();status('Selection changed. Run verification again.');});
  $('verify-digest').addEventListener('input',()=>{invalidate();status('Retained digest changed. Run verification again.');});
  $('verify-clear').addEventListener('click',()=>{invalidate();for(const id of ids)$(id).value='';$('verify-digest').value='';status('Verification inputs and results cleared from this page. Downloads remain on your device.');});
  async function read(file,limit) {
    if(file.size>limit)throw new Error(`${file.name}: file exceeds the displayed size limit.`);
    try {return {name:file.name,text:new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer())};}
    catch(error) {if(error instanceof TypeError)throw new Error('Use valid UTF-8 files.');throw error;}
  }
  $('verify-run').addEventListener('click',async()=>{
    invalidate();const token=generation,files=ids.map(id=>$(id).files[0]),pin=$('verify-digest').value.trim().toLowerCase();
    if(!files.slice(0,3).every(Boolean)){status('Select the evidence JSON and both original CSV sources.',true);return;}
    $('verify-run').disabled=true;status('Recomputing file digests, rules and every comparison outcome locally…');
    try {
      const [json,left,right,journal]=await Promise.all(files.map((f,i)=>f?read(f,[MAX_EVIDENCE_BYTES,MAX_BYTES,MAX_BYTES,MAX_REVIEW_BYTES][i]):null));
      const evidence=await verifyEvidence(json.text,left,right,pin);
      const review=journal?validateReview(readExport(journal.text,MAX_REVIEW_BYTES),evidence.report,evidence.digest):null;
      const output=await verificationExport(evidence,review);
      if(token!==generation)return;
      verified={evidence,sources:[left,right],review};receipt=output;
      $('verify-report-digest').textContent=evidence.digest;
      $('verify-pin-result').textContent=evidence.pinned?'Retained report digest matched':'No independent digest supplied';
      $('verify-source-result').textContent='Both source files match their recorded byte digests';
      $('verify-comparison-result').textContent=`${evidence.report.result.key_count} keys recomputed · ${evidence.report.result.counts.matched} matched · ${evidence.report.mode==='synthetic_example'?'synthetic example':'local-file report'}`;
      $('verify-review-result').textContent=review?`${review.events.length} review entries validated against this report`:'No review journal supplied';
      $('verify-results').hidden=false;
      status('Consistency checks passed. Source authenticity, reviewer identity, earlier versions and on-chain inclusion remain unverified.');
    } catch(error) {if(token===generation)status('Verification failed: '+error.message,true);}
    finally {if(token===generation)$('verify-run').disabled=false;}
  });
  $('verify-export').addEventListener('click',()=>{if(receipt)download('bloch-data-verification.json',receipt.bytes,'application/json');});
  $('verify-open').addEventListener('click',()=>{if(verified)openForReview(verified);});
}
