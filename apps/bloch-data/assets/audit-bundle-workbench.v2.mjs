import {MAX_BYTES} from './reconcile.v1.mjs';
import {MAX_CASE_BYTES} from './case-file.v1.mjs';
import {MAX_PREPARATION_BYTES} from './preparation-verification.v1.mjs';
import {createAuditBundle,verifyAuditBundle,auditBundleVerificationExport,MAX_AUDIT_BUNDLE_BYTES} from './audit-bundle.v1.mjs';
import {auditBundleExample} from './audit-bundle-samples.v1.mjs';

const $=id=>document.getElementById(id);
function node(tag,text,classes){const element=document.createElement(tag);if(text!==undefined)element.textContent=text;if(classes)element.className=classes;return element;}

export function setupAuditBundles(getConfiguration,openForReview,download){
  const inputs=['ab-case','ab-preparation','ab-original-a','ab-original-b'];
  let buildGeneration=0,verifyGeneration=0,prepared=null,verified=null,receipt=null;
  const status=(id,text,error=false)=>{$(id).textContent=text;$(id).classList.toggle('error',error);};
  function invalidateBuild(){buildGeneration++;prepared=null;$('ab-ready').hidden=true;$('ab-build-digest').textContent='';$('ab-build-summary').textContent='';$('ab-build-parts').replaceChildren();$('ab-build').disabled=false;$('ab-example').disabled=false;}
  function invalidateVerify(){verifyGeneration++;verified=null;receipt=null;$('ab-results').hidden=true;for(const id of ['ab-digest','ab-pin-result','ab-summary','ab-component-rows','ab-graph','ab-detail','ab-receipt-digest'])$(id).replaceChildren();$('ab-verify').disabled=false;}
  function clearVerify(){invalidateVerify();$('ab-input').value='';$('ab-pin').value='';}
  for(const id of inputs)$(id).addEventListener('change',()=>{invalidateBuild();status('ab-build-status','Inputs changed. Verify the complete file set to prepare a bundle.');});
  for(const id of ['ab-case-pin','ab-preparation-pin'])$(id).addEventListener('input',()=>{invalidateBuild();status('ab-build-status','Retained input digest changed. Prepare the bundle again.');});
  $('ab-build-clear').addEventListener('click',()=>{invalidateBuild();for(const id of [...inputs,'ab-case-pin','ab-preparation-pin'])$(id).value='';status('ab-build-status','Bundle preparation files and output cleared. Bundle verification and other workspaces remain separate.');});
  $('ab-input').addEventListener('change',()=>{invalidateVerify();status('ab-status','Bundle changed. Verify it before opening or extracting components.');});
  $('ab-pin').addEventListener('input',()=>{invalidateVerify();status('ab-status','Retained bundle digest changed. Verify again.');});
  $('ab-clear').addEventListener('click',()=>{clearVerify();status('ab-status','Bundle verification inputs and results cleared. Downloads and other workspaces remain separate.');});
  async function read(file,limit){if(file.size>limit)throw new Error(`${file.name}: exceeds its displayed size limit.`);try{return {name:file.name,text:new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer())};}catch(error){if(error instanceof TypeError)throw new Error('Use valid UTF-8 files.');throw error;}}
  function ready(result){prepared=result;$('ab-build-digest').textContent=result.digest;$('ab-build-summary').textContent=`${result.bundle.mode==='synthetic_example'?'SYNTHETIC EXAMPLE':'LOCAL FILES'} · ${result.bundle.module} · five top-level components · ${new TextEncoder().encode(result.bytes).length.toLocaleString('en-US')} bytes`;for(const part of result.bundle.components)$('ab-build-parts').append(node('li',`${part.name} · ${part.bytes.toLocaleString('en-US')} UTF-8 bytes`));$('ab-ready').hidden=false;}
  $('ab-build').addEventListener('click',async()=>{
    invalidateBuild();const token=buildGeneration,files=inputs.map(id=>$(id).files[0]),caseDigest=$('ab-case-pin').value.trim().toLowerCase(),preparationDigest=$('ab-preparation-pin').value.trim().toLowerCase();
    if(!files.every(Boolean)){status('ab-build-status','Select a retained case, its preparation receipt and both original extracts.',true);return;}
    $('ab-build').disabled=true;status('ab-build-status','Verifying the case, review history, original extracts and preparation before packaging…');
    try{const [caseFile,preparation,left,right]=await Promise.all(files.map((file,index)=>read(file,[MAX_CASE_BYTES,MAX_PREPARATION_BYTES,MAX_BYTES,MAX_BYTES][index])));if(token!==buildGeneration)return;const result=await createAuditBundle({caseText:caseFile.text,preparationText:preparation.text,originals:[left,right],caseDigest,preparationDigest});if(token!==buildGeneration)return;ready(result);status('ab-build-status','Bundle ready. The retained case and preparation bytes are preserved. Download the bundle and retain its SHA-256 separately.');}
    catch(error){if(token===buildGeneration)status('ab-build-status','Bundle not prepared: '+error.message,true);}
    finally{if(token===buildGeneration)$('ab-build').disabled=false;}
  });
  function detail(stage){
    const container=$('ab-detail');container.replaceChildren();
    if(stage==='originals'){
      container.append(node('h4','Original extracts · exact retained bytes'));
      for(const source of verified.preparation.receipt.sources){container.append(node('p',`Source ${source.side} · ${source.input.name} · ${source.input.rows} rows · ${source.input.bytes} bytes`),node('code',source.input.sha256),node('p',`Included original columns: ${source.input.columns.join(' · ')}`));}
      container.append(node('p','Originals include cells excluded from prepared output. They are packaged as private plaintext and checked against the preparation receipt.'));
    }else if(stage==='preparation'){
      container.append(node('h4','Preparation · reproduced from packaged originals'),node('code',verified.preparation.digest));
      for(const source of verified.preparation.receipt.sources){container.append(node('p',`Source ${source.side}: ${source.lineage.length} row references checked; ${Object.keys(source.profile.column_mapping).length} mapped columns; excluded: ${source.profile.excluded_columns.join(' · ')||'none'}.`),node('p',`Prepared CSV SHA-256: ${source.output.sha256}`));}
      container.append(node('p','The reproduced CSVs match the case sources byte-for-byte, with the same configuration and data mode.'));
    }else if(stage==='case'){
      container.append(node('h4','Retained case · six original components'),node('code',verified.case.digest));
      const list=node('ul');for(const part of verified.case.caseFile.components)list.append(node('li',`${part.name} · ${part.bytes} bytes · SHA-256 ${part.sha256}`));container.append(list,node('p',`Evidence SHA-256: ${verified.case.evidence.digest}. Reconciliation was recomputed from the packaged prepared CSVs.`));
    }else{
      container.append(node('h4','Review journal · bound to the exact evidence'),node('code',verified.case.caseFile.review_sha256),node('p',`${verified.case.review.events.length} entries checked. Reviewer identities and timestamps are self-declared; annotations are not authorized approvals.`));
      const list=node('ol');for(const entry of verified.case.review.events.slice(-10))list.append(node('li',`#${entry.sequence} · ${entry.record_key.join(' / ')} · ${entry.state} · ${entry.reviewer} · ${entry.recorded_at}\n${entry.note}`));container.append(list,node('p','Showing the last 10 entries. Open the case for the complete review workflow; the packaged snapshot remains unchanged.'));
    }
    for(const button of $('ab-graph').querySelectorAll('button'))button.setAttribute('aria-pressed',String(button.dataset.stage===stage));
  }
  function render(){
    $('ab-digest').textContent=verified.digest;$('ab-receipt-digest').textContent=receipt.digest;
    $('ab-pin-result').textContent=verified.pinned?'Independently retained bundle digest matched':'No independent bundle digest supplied; internal consistency only';
    $('ab-summary').textContent=`${verified.bundle.mode==='synthetic_example'?'SYNTHETIC EXAMPLE':'LOCAL FILES'} · ${verified.bundle.module} · ${verified.case.evidence.report.result.key_count} keys recomputed · ${verified.case.review.events.length} review entries · five components and their links verified`;
    const graph=$('ab-graph');graph.replaceChildren();
    const stages=[['originals','01 / ORIGINALS',`${verified.preparation.receipt.sources[0].input.rows} A + ${verified.preparation.receipt.sources[1].input.rows} B rows`],['preparation','02 / PREPARATION','Mappings + lineage reproduced'],['case','03 / RETAINED CASE',`${verified.case.evidence.report.result.key_count} comparison keys`],['review','04 / REVIEW JOURNAL',`${verified.case.review.events.length} retained entries`]];
    for(const [stage,label,title] of stages){const button=node('button',undefined,'ab-node');button.type='button';button.dataset.stage=stage;button.append(node('span',label),node('strong',title),node('small',stage==='review'?'Bound to case evidence':'Select to inspect verified relationships'));button.addEventListener('click',()=>detail(stage));graph.append(button);}
    detail('originals');$('ab-component-rows').replaceChildren();
    for(const part of verified.bundle.components){const tr=node('tr'),action=node('td'),button=node('button','Download');button.type='button';button.setAttribute('aria-label',`Download bundle component ${part.name}`);button.addEventListener('click',()=>download(part.name,part.content,part.media_type));action.append(button);tr.append(node('td',part.name),node('td',part.bytes.toLocaleString('en-US')),node('td',part.sha256),action);$('ab-component-rows').append(tr);}
    $('ab-results').hidden=false;
  }
  async function verifyText(text,pin,token){const result=await verifyAuditBundle(text,pin),output=await auditBundleVerificationExport(result);if(token!==verifyGeneration)return;verified=result;receipt=output;render();status('ab-status','Bundle consistency verified. Originals, preparation, case and review history are linked. Source identity, completeness and on-chain status remain unverified.');}
  $('ab-verify').addEventListener('click',async()=>{
    invalidateVerify();const token=verifyGeneration,file=$('ab-input').files[0],pin=$('ab-pin').value.trim().toLowerCase();if(!file){status('ab-status','Choose an audit bundle first.',true);return;}
    $('ab-verify').disabled=true;status('ab-status','Checking every component, reproducing preparation and recomputing the case locally…');
    try{const input=await read(file,MAX_AUDIT_BUNDLE_BYTES);if(token!==verifyGeneration)return;await verifyText(input.text,pin,token);}catch(error){if(token===verifyGeneration)status('ab-status','Bundle verification failed: '+error.message,true);}finally{if(token===verifyGeneration)$('ab-verify').disabled=false;}
  });
  $('ab-check-ready').addEventListener('click',async()=>{
    if(!prepared)return;const text=prepared.bytes;clearVerify();const token=verifyGeneration;$('ab-verify').disabled=true;status('ab-status','Verifying the prepared bundle as a separate snapshot…');
    try{await verifyText(text,'',token);if(token===verifyGeneration)$('ab-results').scrollIntoView({block:'start'});}catch(error){if(token===verifyGeneration)status('ab-status','Bundle verification failed: '+error.message,true);}finally{if(token===verifyGeneration)$('ab-verify').disabled=false;}
  });
  $('ab-example').addEventListener('click',async()=>{
    invalidateBuild();const token=buildGeneration;for(const id of [...inputs,'ab-case-pin','ab-preparation-pin'])$(id).value='';$('ab-example').disabled=true;$('ab-build').disabled=true;status('ab-build-status','Creating a labelled synthetic bundle using the active module…');
    try{const output=await auditBundleExample(structuredClone(getConfiguration()));if(token!==buildGeneration)return;ready(output);status('ab-build-status','Synthetic bundle ready. Verify it below to explore the retained path and review entry.');}catch(error){if(token===buildGeneration)status('ab-build-status','Example failed: '+error.message,true);}finally{if(token===buildGeneration){$('ab-example').disabled=false;$('ab-build').disabled=false;}}
  });
  $('ab-download').addEventListener('click',()=>{if(prepared)download('bloch-data-audit.bundle.json',prepared.bytes,'application/json');});
  $('ab-download-hash').addEventListener('click',()=>{if(prepared)download('bloch-data-audit.bundle.json.sha256',`${prepared.digest}  bloch-data-audit.bundle.json\n`,'text/plain');});
  $('ab-retained').addEventListener('click',()=>{if(verified)download('bloch-data-audit.bundle.json',verified.bytes,'application/json');});
  $('ab-export-receipt').addEventListener('click',()=>{if(receipt)download('bloch-data-audit-bundle-verification.json',receipt.bytes,'application/json');});
  $('ab-export-hash').addEventListener('click',()=>{if(receipt)download('bloch-data-audit-bundle-verification.json.sha256',`${receipt.digest}  bloch-data-audit-bundle-verification.json\n`,'text/plain');});
  $('ab-open').addEventListener('click',()=>{if(verified)openForReview(structuredClone(verified.case));});
  return {getPreparedBundle:()=>prepared?.bytes??null};
}
