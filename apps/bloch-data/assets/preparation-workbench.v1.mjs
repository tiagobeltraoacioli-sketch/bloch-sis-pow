import {getModule, validateConfig} from './modules.v1.mjs';
import {MAX_BYTES, parseCSV} from './reconcile.v1.mjs';
import {samplesFor} from './samples.v1.mjs';
import {inspectSource, prepareSources, machineCSV} from './preparation.v1.mjs';

const $=id=>document.getElementById(id);
function node(tag,text,classes) {const element=document.createElement(tag);if(text!==undefined)element.textContent=text;if(classes)element.className=classes;return element;}
function select(id,label,options,value) {const wrapper=node('label',label),input=node('select');input.id=id;for(const [key,text] of options){const option=node('option',text);option.value=key;input.append(option);}input.value=value;wrapper.append(input);return wrapper;}

export function setupPreparation(getConfiguration, openPrepared, download) {
  let config=validateConfig(getConfiguration()),sources=[null,null],tables=[null,null],tokens=[0,0],pending=[false,false],generation=0,result=null,mode='local_files';
  const prefix=index=>'prep-'+(index?'b':'a');
  function status(message,error=false){$('prep-status').textContent=message;$('prep-status').classList.toggle('error',error);}
  function invalidate(){generation++;result=null;$('prep-results').hidden=true;$('prep-output').replaceChildren();$('prep-digest').textContent='';$('prep-run').disabled=pending.some(Boolean);}
  function describe(){ $('prep-config').textContent=`${getModule(config.module).name} · ${config.institution} · ${config.region} · prepared output: ISO dates, decimal dot, comma CSV. Policy references are copied from the captured configuration.`; }
  function reset(){tokens=tokens.map(token=>token+1);pending=[false,false];sources=[null,null];tables=[null,null];mode='local_files';invalidate();renderInputs();describe();}
  function formats(index){const p=prefix(index);return {separator:$(p+'-separator').value,date_format:$(p+'-date').value,decimal_format:$(p+'-decimal').value};}
  function mapping(index){return Object.fromEntries(getModule(config.module).fields.map(field=>[field,$(prefix(index)+'-map-'+field)?.value??'']));}
  function extras(index){const used=Object.values(mapping(index));return (tables[index]?.headers??[]).filter(header=>!used.includes(header));}
  function acknowledge(index){const p=prefix(index),excluded=extras(index);$(p+'-consent').checked=false;$(p+'-consent').disabled=!excluded.length;$(p+'-excluded').textContent=excluded.length?`Excluded from prepared CSV: ${excluded.join(' · ')}`:'No input columns excluded.';}
  function renderMapping(index,preset={}) {
    const p=prefix(index),container=$(p+'-mapping');container.replaceChildren();
    if(!tables[index]){acknowledge(index);return;}
    for(const field of getModule(config.module).fields) {
      const proposed=preset[field]??config.column_mapping[field]??field;
      const wrapper=select(p+'-map-'+field,field,[['','Select input column'],...tables[index].headers.map(header=>[header,header])],tables[index].headers.includes(proposed)?proposed:'');
      wrapper.querySelector('select').addEventListener('change',()=>{invalidate();acknowledge(index);status('Mapping changed. Review exclusions and prepare both sources again.');});container.append(wrapper);
    }
    acknowledge(index);
  }
  function inspect(index,preset) {
    tables[index]=null;
    try {if(sources[index])tables[index]=inspectSource(sources[index].text,formats(index).separator);renderMapping(index,preset);$(prefix(index)+'-name').textContent=sources[index]?`${sources[index].name} · ${tables[index].records.length} rows · ${tables[index].headers.length} columns`:'No source loaded';}
    catch(error){renderMapping(index);$(prefix(index)+'-name').textContent='Source unavailable for preparation';status(`Source ${index?'B':'A'}: ${error.message}`,true);}
  }
  async function read(index) {
    const file=$(prefix(index)+'-file').files[0];
    if(mode==='synthetic_example'){
      tokens=tokens.map(token=>token+1);pending=[false,false];sources=[null,null];tables=[null,null];mode='local_files';
      for(let side=0;side<2;side++){if(side!==index)$(prefix(side)+'-file').value='';renderMapping(side);$(prefix(side)+'-name').textContent='No source loaded';}
    }
    const token=++tokens[index];sources[index]=null;tables[index]=null;pending[index]=!!file;invalidate();renderMapping(index);
    $(prefix(index)+'-name').textContent=file?'Reading local file…':'No source loaded';
    if(!file)return;
    try {
      if(file.size>MAX_BYTES)throw new Error('Each source must be at most 2 MiB.');
      const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer());
      if(token!==tokens[index])return;
      sources[index]={name:file.name,text};status('Map all required fields and review the excluded columns.');inspect(index);
    }catch(error){if(token===tokens[index])status(`Source ${index?'B':'A'}: ${error.message}`,true);}
    finally {if(token===tokens[index]){pending[index]=false;$('prep-run').disabled=pending.some(Boolean);}}
  }
  function renderInputs() {
    $('prep-inputs').replaceChildren();
    for(let index=0;index<2;index++) {
      const p=prefix(index),panel=node('article',undefined,'prep-source');panel.append(node('h3',`Source ${index?'B':'A'} · ${getModule(config.module).labels[index]}`));
      const label=node('label','Local extract · UTF-8 CSV · up to 2 MiB'),file=node('input');file.id=p+'-file';file.type='file';file.accept='.csv,text/csv';file.addEventListener('change',()=>read(index));label.append(file);panel.append(label);
      const name=node('p','No source loaded','prep-note');name.id=p+'-name';panel.append(name);
      const controls=node('div',undefined,'prep-formats');controls.append(select(p+'-separator','Delimiter',[[',','Comma'],[';','Semicolon']],config.separator),select(p+'-date','Date format',[['iso','YYYY-MM-DD'],['dmy','DD/MM/YYYY']],config.date_format),select(p+'-decimal','Decimal mark',[['dot','Dot'],['comma','Comma']],config.decimal_format));panel.append(controls);
      for(const input of controls.querySelectorAll('select'))input.addEventListener('change',()=>{invalidate();status('Source format changed. Review mappings and exclusions again.');if(input.id===p+'-separator')inspect(index);else acknowledge(index);});
      const mappings=node('div',undefined,'prep-mapping');mappings.id=p+'-mapping';panel.append(mappings);
      const excluded=node('p','No input columns excluded.','prep-note');excluded.id=p+'-excluded';panel.append(excluded);
      const consentLabel=node('label',undefined,'prep-check'),consent=node('input');consent.type='checkbox';consent.id=p+'-consent';consent.disabled=true;consent.addEventListener('change',invalidate);consentLabel.append(consent,node('span','I acknowledge excluding every column listed above.'));panel.append(consentLabel);$('prep-inputs').append(panel);
    }
  }
  function example(){config=validateConfig(getConfiguration());reset();mode='synthetic_example';
    for(let index=0;index<2;index++) {
      const p=prefix(index),sourceConfig={...config,separator:index?',':';',date_format:index?'iso':'dmy',decimal_format:index?'dot':'comma',column_mapping:{}};
      for(const [suffix,key] of [['separator','separator'],['date','date_format'],['decimal','decimal_format']])$(p+'-'+suffix).value=sourceConfig[key];
      const sample=inspectSource(samplesFor(sourceConfig)[index],sourceConfig.separator),aliases=Object.fromEntries(getModule(config.module).fields.map(field=>[field,`${index?'statement':'book'}_${field}`]));
      const text=machineCSV([[...sample.headers.map(field=>aliases[field]),'extract_note'],...sample.records.map(row=>[...row.values,'Synthetic extraction note'])],sourceConfig.separator);
      sources[index]={name:`synthetic-${index?'statement':'book'}.csv`,text:index?text:'\uFEFF\r\n'+text};inspect(index,aliases);
    }
    describe();status('SYNTHETIC EXTRACTS · Different headers and formats are mapped explicitly. Acknowledge the excluded extract_note column on each side, then prepare.');
  }
  function renderResult() {
    const output=$('prep-output');output.replaceChildren();
    for(let index=0;index<2;index++) {
      const descriptor=result.receipt.sources[index],card=node('article',undefined,'prep-source');card.append(node('h3',`Source ${descriptor.side} · ${descriptor.output.rows} rows preserved`));
      for(const [label,file] of [['Original',descriptor.input],['Prepared',descriptor.output]]){const paragraph=node('p',`${label}: ${file.name} · ${file.bytes} bytes`,'prep-note');paragraph.append(node('code',file.sha256));card.append(paragraph);}
      card.append(node('p',`Excluded columns: ${descriptor.profile.excluded_columns.join(' · ')||'none'}`,'prep-note'),node('h4','Cells normalized by field'),node('p','Counts compare exact mapped input text with canonical output. Select a bar to inspect row lineage.','prep-note'));
      const chart=node('div',undefined,'prep-chart'),detail=node('p',undefined,'prep-note'),scroll=node('div',undefined,'table-scroll'),table=node('table'),head=node('thead'),header=node('tr'),body=node('tbody');scroll.tabIndex=0;scroll.setAttribute('role','region');scroll.setAttribute('aria-label',`Source ${descriptor.side} row lineage`);
      for(const label of ['Source row','Prepared row','Normalized fields'])header.append(node('th',label));head.append(header);table.append(head,body);scroll.append(table);
      const showRows=field=>{const selected=descriptor.lineage.filter(row=>!field||row.changed_fields.includes(field));detail.textContent=`${selected.length} rows${field?' with '+field+' normalized':''}. Showing the first 10; the receipt retains every row reference.`;body.replaceChildren();for(const row of selected.slice(0,10)){const tr=node('tr');for(const value of [row.source_row,row.prepared_row,row.changed_fields.join(' · ')||'None'])tr.append(node('td',value));body.append(tr);}for(const button of chart.querySelectorAll('button'))button.setAttribute('aria-pressed',String(button.dataset.field===field));};
      const all=node('button','Show all rows');all.type='button';all.dataset.field='';all.addEventListener('click',()=>showRows(''));chart.append(all);
      for(const [field,count] of Object.entries(descriptor.changed_cells_by_field)){
        const button=node('button',undefined,'prep-bar');button.type='button';button.dataset.field=field;button.disabled=!count;
        const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 100 8');svg.setAttribute('aria-hidden','true');svg.setAttribute('preserveAspectRatio','none');
        for(const [width,fill] of [[100,'#e1e8d8'],[100*count/descriptor.output.rows,'#658849']]){const rect=document.createElementNS(svg.namespaceURI,'rect');for(const [key,value] of Object.entries({width,height:8,rx:2,fill}))rect.setAttribute(key,value);svg.append(rect);}
        button.append(node('span',field),svg,node('b',count));button.addEventListener('click',()=>showRows(field));chart.append(button);
      }
      card.append(chart,detail,scroll);showRows('');
      const preview=node('details'),summary=node('summary','Preview prepared records · first 5');preview.append(summary);
      for(const row of parseCSV(result.sources[index].text,result.configuration).slice(0,5))preview.append(node('p',JSON.stringify(row.values),'prep-preview'));
      card.append(preview);output.append(card);
    }
    $('prep-digest').textContent=result.digest;$('prep-results').hidden=false;
  }
  $('prep-capture').addEventListener('click',()=>{config=validateConfig(getConfiguration());reset();status('Captured the active module and policy settings. Select both extracts.');});
  $('prep-example').addEventListener('click',example);
  $('prep-clear').addEventListener('click',()=>{reset();status('Preparation sources, mappings and receipt cleared. The reconciliation session is separate. Downloads remain on your device.');});
  $('prep-run').addEventListener('click',async()=>{
    invalidate();const token=generation;
    try {
      if(pending.some(Boolean)||!sources.every(Boolean)||!tables.every(Boolean))throw new Error('Load and inspect both source files first.');
      const inputs=sources.map((source,index)=>({...source,profile:{...formats(index),column_mapping:mapping(index),excluded_columns:$(prefix(index)+'-consent').checked?extras(index):[]}}));
      $('prep-run').disabled=true;status('Validating mapped records and hashing exact source bytes…');
      const prepared=await prepareSources(inputs,config,mode);if(token!==generation)return;result=prepared;renderResult();status(`${mode==='synthetic_example'?'SYNTHETIC EXTRACTS':'LOCAL EXTRACTS'} · Both sources validated. Retain originals, receipt and prepared files together.`);
    }catch(error){if(token===generation)status(error.message,true);}
    finally {if(token===generation)$('prep-run').disabled=false;}
  });
  for(const [id,action] of [
    ['prep-download-a',()=>download(result.sources[0].name,result.sources[0].text,'text/csv')],['prep-download-b',()=>download(result.sources[1].name,result.sources[1].text,'text/csv')],
    ['prep-receipt',()=>download('bloch-data-preparation.json',result.bytes,'application/json')],['prep-hash',()=>download('bloch-data-preparation.json.sha256',`${result.digest}  bloch-data-preparation.json\n`,'text/plain')],
    ['prep-configuration',()=>download('bloch-data-prepared-configuration.json',JSON.stringify(result.configuration,null,2)+'\n','application/json')],
    ['prep-open',()=>openPrepared(structuredClone(result))],
  ])$(id).addEventListener('click',()=>{if(result)action();});
  renderInputs();describe();
}
