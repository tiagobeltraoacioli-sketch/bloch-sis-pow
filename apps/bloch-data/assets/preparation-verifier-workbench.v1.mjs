import {MAX_BYTES} from './reconcile.v1.mjs';
import {MAX_EVIDENCE_BYTES} from './audit.v1.mjs';
import {MAX_PREPARATION_BYTES,verifyPreparation,preparationVerificationExport} from './preparation-verification.v1.mjs';
import {preparationExample} from './preparation-samples.v1.mjs';

const $=id=>document.getElementById(id);
function node(tag,text,classes){const element=document.createElement(tag);if(text!==undefined)element.textContent=text;if(classes)element.className=classes;return element;}

export function setupPreparationVerification(getConfiguration,openPrepared,download) {
  const fileIds=['pv-receipt','pv-original-a','pv-original-b','pv-prepared-a','pv-prepared-b','pv-evidence'];
  let generation=0,verified=null,exported=null;
  function status(message,error=false){$('pv-status').textContent=message;$('pv-status').classList.toggle('error',error);}
  function invalidate(){generation++;verified=null;exported=null;$('pv-results').hidden=true;for(const id of ['pv-graph','pv-detail','pv-summary','pv-pins','pv-evidence-summary','pv-receipt-digest','pv-export-digest'])$(id).replaceChildren();$('pv-run').disabled=false;$('pv-example').disabled=false;}
  function clear(){invalidate();for(const id of [...fileIds,'pv-pin','pv-evidence-pin'])$(id).value='';}
  for(const id of fileIds)$(id).addEventListener('change',()=>{invalidate();status('Selection changed. Verify the complete file set again.');});
  for(const id of ['pv-pin','pv-evidence-pin'])$(id).addEventListener('input',()=>{invalidate();status('Retained digest changed. Verify again.');});
  $('pv-clear').addEventListener('click',()=>{clear();status('Preparation verification files and results cleared. Other workspaces and downloaded files remain separate.');});
  async function read(file,limit){
    if(file.size>limit)throw new Error(`${file.name}: file exceeds its displayed size limit.`);
    try{return {name:file.name,text:new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer())};}
    catch(error){if(error instanceof TypeError)throw new Error('Use valid UTF-8 files.');throw error;}
  }
  function detail(side,stage) {
    const source=verified.receipt.sources[side],container=$('pv-detail');container.replaceChildren();
    const title=stage==='input'?'Original extract':stage==='output'?'Prepared CSV':'Recomputed transformation';container.append(node('h4',`Source ${source.side} · ${title}`));
    if(stage==='input'||stage==='output'){
      const file=source[stage];container.append(node('p',`${file.name} · ${file.bytes} UTF-8 bytes · ${file.rows} data rows`),node('code',file.sha256));
      container.append(node('p',stage==='input'?'Exact original bytes match the receipt, including excluded cells, BOM and line endings. Filenames shown here are the retained declarations.':'Every output byte matches the locally reproduced CSV, including canonical headers, quoting, row order and CRLF line endings.'));
    }else{
      container.append(node('p',`${source.profile.date_format==='dmy'?'DD/MM/YYYY':'YYYY-MM-DD'} · decimal ${source.profile.decimal_format} · ${source.profile.separator===';'?'semicolon':'comma'} delimiter → ISO dates · decimal dot · comma delimiter`));
      const list=node('ul');for(const [field,header] of Object.entries(source.profile.column_mapping))list.append(node('li',`${header} → ${field} · ${source.changed_cells_by_field[field]} cells normalized`));container.append(list,node('p',`Excluded columns: ${source.profile.excluded_columns.join(' · ')||'none'}. These are retained declarations; their authorization is not authenticated.`));
      const scroll=node('div',undefined,'table-scroll');scroll.tabIndex=0;scroll.setAttribute('role','region');scroll.setAttribute('aria-label','Recomputed preparation row lineage');const table=node('table'),head=node('thead'),tr=node('tr'),body=node('tbody');for(const label of ['Original row','Prepared row','Normalized fields'])tr.append(node('th',label));head.append(tr);
      for(const entry of source.lineage.slice(0,20)){const row=node('tr');for(const value of [entry.source_row,entry.prepared_row,entry.changed_fields.join(' · ')||'None'])row.append(node('td',value));body.append(row);}table.append(head,body);scroll.append(table);container.append(scroll,node('p',`Showing the first ${Math.min(20,source.lineage.length)} of ${source.lineage.length} verified row references. The retained preparation receipt contains every row.`));
    }
    for(const button of $('pv-graph').querySelectorAll('button'))button.setAttribute('aria-pressed',String(button.dataset.side===String(side)&&button.dataset.stage===stage));
  }
  function render(){
    const data=verified.receipt;
    $('pv-summary').textContent=`${verified.mode==='synthetic_example'?'SYNTHETIC EXAMPLE':'LOCAL FILES'} · ${data.module} · ${data.sources[0].input.rows} A rows + ${data.sources[1].input.rows} B rows reproduced exactly.`;
    $('pv-pins').textContent=`Preparation digest: ${verified.pinned?'independently retained digest matched':'no independent digest supplied'}.`;
    $('pv-receipt-digest').textContent=verified.digest;$('pv-export-digest').textContent=exported.digest;
    $('pv-evidence-summary').textContent=verified.evidence?`Evidence linked and recomputed · ${verified.evidence.report.result.key_count} keys · ${verified.evidence.report.result.counts.matched} matched · ${verified.evidence.pinned?'retained evidence digest matched':'no independent evidence digest supplied'}. Review history was not supplied or verified.`:'No evidence supplied. Verification ends at the prepared CSVs; no reconciliation linkage is claimed.';
    const graph=$('pv-graph');graph.replaceChildren();
    for(let index=0;index<2;index++){
      const source=data.sources[index],row=node('div',undefined,'pv-flow');row.setAttribute('role','group');row.setAttribute('aria-label',`Source ${source.side} verified preparation path`);
      for(const stage of ['input','transform','output']){
        if(stage!=='input')row.append(node('span','→','pv-arrow'));
        const button=node('button',undefined,'pv-node');button.type='button';button.dataset.side=index;button.dataset.stage=stage;
        button.append(node('span',`SOURCE ${source.side} / ${stage==='input'?'ORIGINAL':stage==='output'?'PREPARED':'TRANSFORMATION'}`));
        if(stage==='transform')button.append(node('strong',`${Object.keys(source.profile.column_mapping).length} mapped columns`),node('small',`${source.profile.excluded_columns.length} excluded · ${source.lineage.length} row references verified`));
        else {const file=source[stage];button.append(node('strong',file.name),node('small',`${file.rows} rows · ${file.bytes} bytes`),node('code',file.sha256));}
        button.addEventListener('click',()=>detail(index,stage));row.append(button);
      }
      graph.append(row);
    }
    const evidence=node('div',undefined,'pv-evidence-node');evidence.append(node('span','PREPARED A + B → RECONCILIATION EVIDENCE'));
    if(verified.evidence)evidence.append(node('strong',`${verified.evidence.report.result.key_count} keys recomputed · configuration and source bytes matched`),node('code',verified.evidence.digest));
    else evidence.append(node('strong','Not supplied · linkage not checked'));
    graph.append(evidence);detail(0,'transform');$('pv-results').hidden=false;
  }
  async function finish(inputs,token){
    const checked=await verifyPreparation(inputs),receipt=await preparationVerificationExport(checked);
    if(token!==generation)return;
    verified=checked;exported=receipt;render();status(`${verified.mode==='synthetic_example'?'Synthetic example':'Local files'} · Preparation consistency checks passed${verified.evidence?' and reconciliation evidence linked':''}. Source identity and completeness remain unverified.`);
  }
  $('pv-run').addEventListener('click',async()=>{
    invalidate();const token=generation,files=fileIds.map(id=>$(id).files[0]),pin=$('pv-pin').value.trim().toLowerCase(),evidencePin=$('pv-evidence-pin').value.trim().toLowerCase();
    if(!files.slice(0,5).every(Boolean)){status('Select the preparation receipt, both original extracts and both prepared CSVs.',true);return;}
    if(!files[5]&&evidencePin){status('An evidence digest requires the corresponding evidence JSON.',true);return;}
    $('pv-run').disabled=true;status('Reading local files, reproducing transformations and checking exact output bytes…');
    try{
      const [receipt,left,right,preparedA,preparedB,evidence]=await Promise.all(files.map((file,index)=>file?read(file,[MAX_PREPARATION_BYTES,MAX_BYTES,MAX_BYTES,MAX_BYTES,MAX_BYTES,MAX_EVIDENCE_BYTES][index]):null));
      if(token!==generation)return;
      await finish({receiptText:receipt.text,originals:[left,right],prepared:[preparedA,preparedB],expectedDigest:pin,evidenceText:evidence?.text??null,expectedEvidenceDigest:evidencePin},token);
    }catch(error){if(token===generation)status('Verification failed: '+error.message,true);}
    finally{if(token===generation)$('pv-run').disabled=false;}
  });
  $('pv-example').addEventListener('click',async()=>{
    clear();const token=generation;const config=structuredClone(getConfiguration());$('pv-example').disabled=true;$('pv-run').disabled=true;status('Building and verifying labelled synthetic extracts locally…');
    try{const inputs=await preparationExample(config);if(token!==generation)return;await finish(inputs,token);}
    catch(error){if(token===generation)status('Example failed: '+error.message,true);}
    finally{if(token===generation){$('pv-run').disabled=false;$('pv-example').disabled=false;}}
  });
  $('pv-download').addEventListener('click',()=>{if(exported)download('bloch-data-preparation-verification.json',exported.bytes,'application/json');});
  $('pv-hash').addEventListener('click',()=>{if(exported)download('bloch-data-preparation-verification.json.sha256',`${exported.digest}  bloch-data-preparation-verification.json\n`,'text/plain');});
  $('pv-retained').addEventListener('click',()=>{if(verified)download('bloch-data-preparation.json',verified.bytes,'application/json');});
  $('pv-open').addEventListener('click',()=>{if(verified)openPrepared(structuredClone({sources:verified.sources,configuration:verified.configuration,mode:verified.mode}));});
}
