import {createCaseFile,verifyCaseFile,caseVerificationExport,MAX_CASE_BYTES} from './case-file.v1.mjs';

export function setupCaseFiles(getSession,openForReview,download) {
  const $=id=>document.getElementById(id);
  let exportGeneration=0,importGeneration=0,prepared=null,verified=null,receipt=null;
  const message=(id,text,error=false)=>{$(id).textContent=text;$(id).classList.toggle('error',error);};
  const node=(tag,text)=>{const element=document.createElement(tag);if(text!==undefined)element.textContent=text;return element;};
  function invalidateExport() {
    exportGeneration++;prepared=null;$('case-export-ready').hidden=true;$('case-export-digest').textContent='';$('case-export-list').replaceChildren();
    $('prepare-case').disabled=!getSession();
    message('case-export-status','Prepare a snapshot of the current report, both original CSVs, review journal, configuration and verification receipt. Queue filters do not limit its contents.');
  }
  function invalidateImport() {
    importGeneration++;verified=null;receipt=null;$('case-results').hidden=true;$('case-component-rows').replaceChildren();
    for(const id of ['case-digest','case-pin-result','case-summary'])$(id).textContent='';
    $('case-verify').disabled=false;
  }
  $('prepare-case').addEventListener('click',async()=>{
    invalidateExport();const session=getSession(),token=exportGeneration;
    if(!session){message('case-export-status','Run reconciliation or open verified evidence before preparing a case.',true);return;}
    $('prepare-case').disabled=true;message('case-export-status','Recomputing the report and checking each component before preparing the case…');
    try {
      const output=await createCaseFile(session.evidence.bytes,session.sources[0],session.sources[1],session.review);
      if(token!==exportGeneration)return;
      prepared=output;$('case-export-digest').textContent=output.digest;
      for(const part of output.caseFile.components)$('case-export-list').append(node('li',`${part.name} · ${part.bytes.toLocaleString('en-US')} UTF-8 bytes`));
      $('case-export-ready').hidden=false;
      message('case-export-status',`Case ready · ${session.evidence.report.mode==='synthetic_example'?'synthetic example':'local files'} · six components · ${new TextEncoder().encode(output.bytes).length.toLocaleString('en-US')} bytes. Download the case and retain its SHA-256 separately.`);
    }catch(error){if(token===exportGeneration)message('case-export-status','Case not prepared: '+error.message,true);}
    finally{if(token===exportGeneration)$('prepare-case').disabled=!getSession();}
  });
  $('download-case').addEventListener('click',()=>{if(prepared)download('bloch-data-case.bloch.json',prepared.bytes,'application/json');});
  $('download-case-hash').addEventListener('click',()=>{if(prepared)download('bloch-data-case.bloch.json.sha256',`${prepared.digest}  bloch-data-case.bloch.json\n`,'text/plain');});
  $('case-input').addEventListener('change',()=>{invalidateImport();message('case-status','Selection changed. Verify the case before opening or extracting components.');});
  $('case-pin').addEventListener('input',()=>{invalidateImport();message('case-status','Retained digest changed. Verify again.');});
  $('case-clear').addEventListener('click',()=>{invalidateImport();$('case-input').value='';$('case-pin').value='';message('case-status','Case verification inputs and results cleared. The comparison session and downloaded files remain separate.');});
  $('case-verify').addEventListener('click',async()=>{
    invalidateImport();const token=importGeneration,file=$('case-input').files[0],pin=$('case-pin').value.trim().toLowerCase();
    if(!file){message('case-status','Choose a Bloch Data case file first.',true);return;}
    $('case-verify').disabled=true;message('case-status','Checking the manifest, all component digests and a fresh reconciliation locally…');
    try {
      if(file.size>MAX_CASE_BYTES)throw new Error('Case file must be at most 64 MiB.');
      const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer());
      if(token!==importGeneration)return;
      const result=await verifyCaseFile(text,pin),output=await caseVerificationExport(result);
      if(token!==importGeneration)return;
      verified=result;receipt=output;$('case-digest').textContent=result.digest;
      $('case-pin-result').textContent=result.pinned?'Independently retained case digest matched':'No independent case digest supplied; internal consistency only';
      $('case-summary').textContent=`${result.evidence.report.configuration.module} · ${result.evidence.report.mode==='synthetic_example'?'synthetic example':'local-file report'} · ${result.evidence.report.result.key_count} keys recomputed · ${result.review.events.length} review entries · six components verified`;
      for(const part of result.caseFile.components){
        const row=node('tr'),name=node('td',part.name),size=node('td',part.bytes.toLocaleString('en-US')),digest=node('td',part.sha256),action=node('td'),button=node('button','Download');
        button.type='button';button.setAttribute('aria-label',`Download verified ${part.name}`);button.addEventListener('click',()=>download(part.name,part.content,part.media_type));
        action.append(button);row.append(name,size,digest,action);$('case-component-rows').append(row);
      }
      $('case-results').hidden=false;message('case-status','Case consistency verified. Original report bytes and review history can now be reopened. Identity, source truth, protected time and on-chain status remain unverified.');
    }catch(error){if(token===importGeneration)message('case-status','Case verification failed: '+(error instanceof TypeError?'Use valid UTF-8 text and the supported case format.':error.message),true);}
    finally{if(token===importGeneration)$('case-verify').disabled=false;}
  });
  $('case-open').addEventListener('click',()=>{if(verified)openForReview(verified);});
  $('case-receipt').addEventListener('click',()=>{if(receipt)download('bloch-data-case-verification.json',receipt.bytes,'application/json');});
  return {invalidateExport};
}
