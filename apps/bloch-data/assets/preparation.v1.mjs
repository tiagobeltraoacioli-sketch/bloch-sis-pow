import {getModule, validateConfig} from './modules.v1.mjs';
import {MAX_BYTES, MAX_ROWS, parseCSV, sha256} from './reconcile.v1.mjs';

export const MAX_COLUMNS = 64;
const bytes = text => new TextEncoder().encode(text).length;
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));

// Machine CSV preserves values, including formula-like identifiers. It is not a spreadsheet report.
export function machineCSV(rows, separator=',') {
  return rows.map(row=>row.map(value=>'"'+String(value).replaceAll('"','""')+'"').join(separator)).join('\r\n')+'\r\n';
}

export function inspectSource(text, separator=',') {
  if(typeof text!=='string' || !text.isWellFormed() || bytes(text)>MAX_BYTES)throw new Error('Provide valid UTF-8 CSV, at most 2 MiB.');
  if(![',',';'].includes(separator))throw new Error('Choose a comma or semicolon delimiter.');
  const records=[];let values=[],cell='',state='start',line=1,start=1;
  const field=()=>{values.push(cell);cell='';state='start';if(values.length>MAX_COLUMNS)throw new Error(`Maximum ${MAX_COLUMNS} input columns.`);};
  const record=()=>{field();if(values.some(value=>value!==''))records.push({row:start,values});values=[];if(records.length>MAX_ROWS+1)throw new Error(`Maximum ${MAX_ROWS} data rows per source.`);};
  text=text.replace(/^\uFEFF/,'');
  for(let i=0;i<text.length;i++) {
    const c=text[i];
    if(state==='quoted') {
      if(c==='"'){if(text[i+1]==='"'){cell+='"';i++;}else state='closed';}
      else {cell+=c;if(c==='\r'||(c==='\n'&&text[i-1]!=='\r'))line++;}
    } else if(c===separator)field();
    else if(c==='\r'||c==='\n'){if(c==='\r'&&text[i+1]==='\n')i++;record();line++;start=line;}
    else if(c==='"'&&state==='start')state='quoted';
    else {if(state==='closed'||c==='"')throw new Error(`Source row ${line}: malformed CSV quoting.`);cell+=c;state='plain';}
  }
  if(state==='quoted')throw new Error('Unclosed CSV quote.');
  if(cell||values.length||state==='closed')record();
  if(records.length<2)throw new Error('Provide a header and at least one data row.');
  const headers=records.shift().values.map(value=>value.trim());
  if(headers.some(value=>!value||value.length>80||/[\u0000-\u001f\u007f]/.test(value))||new Set(headers).size!==headers.length)throw new Error('Input headers must be unique, nonempty, single-line names of at most 80 characters after trimming.');
  for(const row of records)if(row.values.length!==headers.length)throw new Error(`Source row ${row.row}: column count differs from the header.`);
  return {headers,records};
}

export function validatePreparationProfile(profile, moduleId, headers) {
  if(!exactKeys(profile,['separator','date_format','decimal_format','column_mapping','excluded_columns']))throw new Error('Invalid preparation profile fields.');
  if(![',',';'].includes(profile.separator)||!['iso','dmy'].includes(profile.date_format)||!['dot','comma'].includes(profile.decimal_format))throw new Error('Invalid source formats.');
  const fields=getModule(moduleId).fields;
  if(!exactKeys(profile.column_mapping,fields))throw new Error('Map every required field explicitly.');
  const mapped=fields.map(field=>profile.column_mapping[field]);
  if(mapped.some(name=>typeof name!=='string'||!headers.includes(name))||new Set(mapped).size!==mapped.length)throw new Error('Every field must map to a different existing input column.');
  const excluded=headers.filter(header=>!mapped.includes(header));
  if(!Array.isArray(profile.excluded_columns)||profile.excluded_columns.length!==excluded.length||new Set(profile.excluded_columns).size!==excluded.length||!excluded.every(header=>profile.excluded_columns.includes(header)))throw new Error('Explicitly acknowledge every excluded column before preparation.');
  return structuredClone(profile);
}

export async function prepareSources(sources, configuration, mode='local_files') {
  const base=validateConfig(configuration), module=getModule(base.module);
  if(!['local_files','synthetic_example'].includes(mode)||!Array.isArray(sources)||sources.length!==2)throw new Error('Prepare exactly two sources with a declared data mode.');
  // Snapshot all caller-owned inputs before hashing yields control.
  sources=structuredClone(sources);
  const outputConfig=validateConfig({...base,date_format:'iso',decimal_format:'dot',separator:',',column_mapping:{}});
  const prepared=[],descriptors=[];
  for(let index=0;index<2;index++) {
    const source=sources[index],side=index?'B':'A';
    if(typeof source?.name!=='string'||!source.name||source.name.length>1024||!source.name.isWellFormed()||/[\u0000-\u001f\u007f]/.test(source.name))throw new Error(`Source ${side}: invalid filename.`);
    try {
      const inspected=inspectSource(source.text,source.profile?.separator);
      const profile=validatePreparationProfile(source.profile,base.module,inspected.headers);
      const positions=module.fields.map(field=>inspected.headers.indexOf(profile.column_mapping[field]));
      const projected=inspected.records.map(row=>positions.map(position=>row.values[position]));
      for(let i=0;i<projected.length;i++)if(projected[i].every(value=>value===''))throw new Error(`Source row ${inspected.records[i].row}: all mapped fields are empty.`);
      // Validate each mapped value through the existing financial module rules. Never infer a missing value.
      const inputConfig={...base,separator:profile.separator,date_format:profile.date_format,decimal_format:profile.decimal_format,column_mapping:{}};
      let normalized;
      const projectedText=machineCSV([module.fields,...projected],profile.separator);
      const projectedRows=inspectSource(projectedText,profile.separator).records;
      try {normalized=parseCSV(projectedText,inputConfig);}
      catch(error) {
        const match=/^Row (\d+): (.*)$/.exec(error.message);
        if(match){const position=projectedRows.findIndex(row=>row.row===Number(match[1]));if(position>=0)throw new Error(`Source row ${inspected.records[position].row}: ${match[2]}`);}
        throw error;
      }
      if(normalized.length!==inspected.records.length)throw new Error('Preparation must preserve every source data row.');
      const output=machineCSV([module.fields,...normalized.map(row=>module.fields.map(field=>row.values[field]))]);
      parseCSV(output,outputConfig);
      const changed=Object.fromEntries(module.fields.map(field=>[field,0]));
      const lineage=inspected.records.map((row,i)=>{
        const changedFields=module.fields.filter((field,j)=>projected[i][j]!==normalized[i].values[field]);
        for(const field of changedFields)changed[field]++;
        return {source_row:row.row,prepared_row:i+2,changed_fields:changedFields};
      });
      const name=`prepared-${index?'b':'a'}.csv`;
      prepared.push({name,text:output});
      descriptors.push({side,input:{name:source.name,bytes:bytes(source.text),sha256:await sha256(source.text),columns:inspected.headers,rows:inspected.records.length},profile,
        output:{name,bytes:bytes(output),sha256:await sha256(output),columns:module.fields,rows:normalized.length},changed_cells_by_field:changed,lineage});
    }catch(error){throw new Error(`Source ${side}: ${error.message}`);}
  }
  const receipt={schema:'bloch.data.source-preparation.v1',rule_version:'bloch.data.source-preparation.v1',generated_at:new Date().toISOString(),clock_source:'local_browser_untrusted',processing:'local_browser',mode,
    module:base.module,validation_rule:'bloch.data.'+module.version,configuration:outputConfig,
    rules:{header_whitespace:'trimmed',column_mapping:'explicit_one_to_one',excluded_columns:'explicitly_acknowledged',outer_whitespace:'trimmed',dates:'iso',decimal_mark:'dot',numeric_scale:8,tolerance:'0',uppercase_fields:[...Object.keys(module.enums),...(module.fields.includes('currency')?['currency']:[])],lowercase_fields:module.hex??[],row_order:'preserved',duplicates:'preserved',values_inferred:false,csv_formula_escaping:false},sources:descriptors,
    assurance:{source_authentication:'not_verified',source_completeness:'not_verified',signature:'absent',onchain:'not_submitted',regulatory_compliance:'not_certified',receipt_retention:'separate_from_evidence_and_case',evidence_source_binding:'prepared_csv_only'}};
  const text=JSON.stringify(receipt,null,2)+'\n';
  return {receipt,bytes:text,digest:await sha256(text),sources:prepared,configuration:outputConfig,mode};
}
