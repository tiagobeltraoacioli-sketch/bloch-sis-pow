import { getModule, defaultConfig, validateConfig } from './modules.v1.mjs';
export const FIELDS = getModule('trades').fields;
export const KEY_FIELDS = getModule('trades').keys;
export const MAX_BYTES = 2 * 1024 * 1024;
export const MAX_ROWS = 5000;
export const RULE_VERSION = 'bloch.data.trade-comparison.v1';

export function decimal(value) {
  if (!/^-?(?:0|[1-9]\d{0,23})(?:\.\d{1,8})?$/.test(value)) throw new Error('Use decimal notation with up to 24 integer and 8 fractional digits.');
  const [whole, fraction = ''] = value.split('.');
  const scaled = BigInt(whole.replace('-', '')) * 100000000n + BigInt(fraction.padEnd(8, '0'));
  const signed = value.startsWith('-') ? -scaled : scaled;
  const normalizedFraction = fraction.replace(/0+$/, '');
  return { value: signed, text: signed === 0n ? '0' : `${signed < 0n ? '-' : ''}${whole.replace('-', '')}${normalizedFraction ? '.' + normalizedFraction : ''}` };
}

function date(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(value + 'T00:00:00Z');
  return Number.isFinite(parsed.valueOf()) && parsed.toISOString().slice(0,10) === value;
}

export function parseCSV(text, configuration=defaultConfig()) {
  const config=validateConfig(configuration), module=getModule(config.module), fields=module.fields;
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_BYTES) throw new Error('Each CSV must be at most 2 MiB.');
  text = text.replace(/^\uFEFF/, '');
  const rows = []; let row = [], cell = '', state = 'start', lineNumber=1, rowStart=1;
  const field = () => { row.push(cell); cell = ''; state = 'start'; if (row.length > fields.length) throw new Error('Too many columns. Use the selected module template.'); };
  const line = () => { field(); if (row.some(v => v !== '')) rows.push({values:row,line:rowStart}); row = []; if (rows.length > MAX_ROWS + 1) throw new Error(`Maximum ${MAX_ROWS} data rows per source.`); };
  for (let i=0; i<text.length; i++) {
    const c = text[i];
    if (state === 'quoted') {
      if (c === '"') { if (text[i+1] === '"') { cell += '"'; i++; } else state = 'closed'; }
      else {cell += c;if(c==='\n')lineNumber++;}
    } else if (c === config.separator) field();
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i+1] === '\n') i++; line();lineNumber++;rowStart=lineNumber; }
    else if (c === '"' && state === 'start') state = 'quoted';
    else { if (state === 'closed' || c === '"') throw new Error('Malformed CSV quoting.'); cell += c; state = 'plain'; }
  }
  if (state === 'quoted') throw new Error('Unclosed CSV quote.');
  if (cell || row.length || state === 'closed') line();
  if (rows.length < 2) throw new Error('Provide a header and at least one data row.');
  const externalHeader=rows.shift().values.map(v=>v.trim());
  const aliases=Object.fromEntries(fields.map(f=>[config.column_mapping[f]??f,f]));
  const header=externalHeader.map(v=>Object.hasOwn(aliases,v)?aliases[v]:null);
  if (header.length !== fields.length || new Set(header).size !== header.length || !fields.every(f => header.includes(f))) throw new Error('CSV columns must match the selected module and mapping exactly; column order may vary.');
  return rows.map(({values,line:sourceLine}) => {
    const index=sourceLine-2;
    if (values.length !== header.length) throw new Error(`Row ${index+2}: column count differs from the header.`);
    const record = Object.fromEntries(header.map((f,i) => [f, values[i].trim()]));
    for (const f of fields) {
      const v = record[f];
      if (!v || v.length > 160 || /[\u0000-\u001f\u007f]/.test(v)) throw new Error(`Row ${index+2}: ${f} must be a nonempty, single-line value (maximum 160 characters).`);
      if (Object.hasOwn(module.numbers,f)) {
        let parsed; try { if(config.decimal_format==='comma'&&v.includes('.'))throw new Error('Ambiguous separator'); parsed = decimal(config.decimal_format==='comma'?v.replace(',','.'):v); } catch { throw new Error(`Row ${index+2}: invalid ${f}. Use the configured decimal mark, up to 8 fractional digits, without thousands separators.`); }
        if ((module.numbers[f]==='positive'&&parsed.value<=0n)||(module.numbers[f]==='nonnegative'&&parsed.value<0n)) throw new Error(`Row ${index+2}: invalid sign for ${f}.`);
        record[f] = parsed.text;
      }
      if(module.dates.includes(f)) {
        const normalized=config.date_format==='dmy'&&/^\d{2}\/\d{2}\/\d{4}$/.test(v)?v.slice(6)+'-'+v.slice(3,5)+'-'+v.slice(0,2):v;
        if((config.date_format==='dmy'&&!/^\d{2}\/\d{2}\/\d{4}$/.test(v))||!date(normalized))throw new Error(`Row ${index+2}: invalid ${f}; use ${config.date_format==='dmy'?'DD/MM/YYYY':'YYYY-MM-DD'}.`);
        record[f]=normalized;
      }
      if(Object.hasOwn(module.integers??{},f)) {
        if(!/^(?:0|[1-9]\d{0,19})$/.test(v)||BigInt(v)>BigInt(module.integers[f]))throw new Error(`Row ${index+2}: ${f} must be an unsigned integer within the module bound.`);
      }
      if(module.hex?.includes(f)) {if(!/^[0-9a-fA-F]{64}$/.test(v))throw new Error(`Row ${index+2}: ${f} must be 64 hexadecimal characters.`);record[f]=v.toLowerCase();}
    }
    if(module.dateOrder&&record[module.dateOrder[1]]<record[module.dateOrder[0]])throw new Error(`Row ${index+2}: settlement date cannot precede trade date.`);
    for(const [field,options] of Object.entries(module.enums)){record[field]=record[field].toUpperCase();if(!options.includes(record[field]))throw new Error(`Row ${index+2}: ${field} must be ${options.join(', ')}.`);}
    if(fields.includes('currency')) {record.currency=record.currency.toUpperCase();if(!/^[A-Z]{3}$/.test(record.currency))throw new Error(`Row ${index+2}: currency must have three letters.`);}
    if(config.module==='onchain'&&record.network!=='bloch-genesis4')throw new Error(`Row ${index+2}: network must be bloch-genesis4.`);
    return { row: index+2, values: Object.fromEntries(fields.map(f => [f, record[f]])) };
  });
}

export function compare(left, right, moduleId='trades') {
  const module=getModule(moduleId);
  const group = records => {
    const map = new Map();
    for (const record of records) { const key = JSON.stringify(module.keys.map(f => record.values[f])); if (!map.has(key)) map.set(key, []); map.get(key).push(record); }
    return map;
  };
  const a=group(left), b=group(right), counts={matched:0,different:0,left_only:0,right_only:0,duplicate:0};
  const items = [...new Set([...a.keys(),...b.keys()])].sort().map(key => {
    const l=a.get(key)||[], r=b.get(key)||[];
    let status, differences=[];
    if (l.length>1 || r.length>1) status='duplicate';
    else if (!l.length) status='right_only';
    else if (!r.length) status='left_only';
    else { differences=module.fields.filter(f => l[0].values[f]!==r[0].values[f]); status=differences.length?'different':'matched'; }
    counts[status]++;
    return {key:JSON.parse(key),status,differences,left:l,right:r};
  });
  return {counts, key_fields:module.keys, key_count:items.length, left_rows:left.length, right_rows:right.length, items};
}

export async function sha256(bytes) {
  if (typeof bytes === 'string') bytes = new TextEncoder().encode(bytes);
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(v=>v.toString(16).padStart(2,'0')).join('');
}

export async function createReport(leftSource, rightSource, context, configuration=defaultConfig()) {
  const config=validateConfig(configuration), module=getModule(config.module);
  const result = compare(parseCSV(leftSource.text,config), parseCSV(rightSource.text,config),config.module);
  const report = {
    schema:'bloch.data.financial-evidence.v1', rule_version:'bloch.data.'+module.version,
    generated_at:new Date().toISOString(), clock_source:'local_browser_untrusted',
    mode:context, processing:'local_browser',
    configuration:config, matching_key:module.keys, compared_fields:module.fields,
    rules:{numeric_scale:8,tolerance:'0',uppercase_fields:[...Object.keys(module.enums),...(module.fields.includes('currency')?['currency']:[])],lowercase_fields:module.hex??[],outer_whitespace:'trimmed',duplicates:'always_review',row_order:'ignored',partial_matching:false},
    sources:await Promise.all([leftSource,rightSource].map(async(source,i)=>({side:i?'B':'A',name:source.name,bytes:new TextEncoder().encode(source.text).length,sha256:await sha256(source.text)}))),
    result,
    assurance:{source_authentication:'not_verified',source_completeness:'not_verified',auditor_signature:'absent',onchain:'not_submitted',settlement:'not_determined',regulatory_compliance:'not_certified',policy_fields:'declarations_not_runtime_enforcement'},
  };
  const bytes = JSON.stringify(report,null,2)+'\n';
  return {report,bytes,digest:await sha256(bytes)};
}

export function resultsCSV(result) {
  const safe = value => { let text=String(value); if (/^[\s]*[=+\-@]/.test(text)) text="'"+text; return '"'+text.replaceAll('"','""')+'"'; };
  const header = ['status',...result.key_fields,'fields_different','source_a_rows','source_b_rows'];
  return [header,...result.items.map(item=>[item.status,...item.key,item.differences.join(' | '),item.left.map(r=>r.row).join(' | '),item.right.map(r=>r.row).join(' | ')])].map(row=>row.map(safe).join(',')).join('\r\n')+'\r\n';
}
