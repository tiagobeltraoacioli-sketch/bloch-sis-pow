// BLCH uses eight decimal places; monetary arithmetic never uses floating point.
export const UNIT = 100_000_000n;
export const MAX_AMOUNT = 100_000_000_000n * UNIT;
export const STORAGE_KEY = 'bloch-pay-workspace-v1';
const MAX_ROWS = 1000;
const HASH = /^[a-f0-9]{64}$/;
const ID = /^[a-zA-Z0-9-]{1,80}$/;
const fail = (message) => { throw new Error(message); };
export function parseAmount(input) {
  if (typeof input !== 'string' || !/^(0|[1-9]\d{0,11})(\.\d{1,8})?$/.test(input.trim())) fail('Use a positive BLCH amount with up to 8 decimal places, without separators.');
  const [whole, fraction = ''] = input.trim().split('.');
  const value = BigInt(whole) * UNIT + BigInt(fraction.padEnd(8, '0'));
  if (value <= 0n || value > MAX_AMOUNT) fail('The amount must be between 0.00000001 and 100,000,000,000 BLCH.');
  return value.toString();
}
export function formatAmount(value, grouped = true) {
  let amount = BigInt(value), sign = '';
  if (amount < 0n) { sign = '−'; amount = -amount; }
  const whole = (amount / UNIT).toString();
  const fraction = (amount % UNIT).toString().padStart(8, '0').replace(/0+$/, '');
  return sign + (grouped ? whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',') : whole) + (fraction ? '.' + fraction : '');
}
export function localDate(date = new Date()) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')}`;
}
export function validDate(value) {
  if (typeof value !== 'string' || !/^20\d{2}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(value + 'T12:00:00Z');
  return Number.isFinite(date.valueOf()) && date.toISOString().slice(0,10) === value;
}
const day = (value) => Date.parse(value + 'T12:00:00Z') / 86400000;
const text = (value, name, max, optional = false) => {
  if (typeof value !== 'string' || value.trim().length > max || (!optional && !value.trim()) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) fail(`Invalid ${name}.`);
  return value.trim();
};
const integerAmount = (value) => {
  if (typeof value !== 'string' || !/^[1-9]\d{0,19}$/.test(value) || BigInt(value) > MAX_AMOUNT) fail('Invalid amount in backup.');
  return value;
};
const timestamp = (value) => {
  if (typeof value !== 'string' || !/^20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) fail('Invalid record timestamp.');
  return value;
};
const identifier = (value) => { if (typeof value !== 'string' || !ID.test(value)) fail('Invalid record identifier.'); return value; };
export function emptyWorkspace() { return {schema:'bloch-pay-workspace', version:1, network:'bloch-genesis4', asset:'BLCH', decimals:8, revision:0, invoices:[], receipts:[]}; }
export function validateWorkspace(input) {
  if (!input || input.schema !== 'bloch-pay-workspace' || input.version !== 1 || input.network !== 'bloch-genesis4' || input.asset !== 'BLCH' || input.decimals !== 8) fail('This is not a supported Bloch Pay backup.');
  if (!Number.isSafeInteger(input.revision) || input.revision < 0 || input.revision > Number.MAX_SAFE_INTEGER - 10) fail('Invalid workspace revision.');
  if (!Array.isArray(input.invoices) || input.invoices.length > MAX_ROWS || !Array.isArray(input.receipts) || input.receipts.length > MAX_ROWS * 3) fail('Backup exceeds the workspace limit (1,000 invoices / 3,000 records).');
  const ids = new Set(), refs = new Set();
  const invoices = input.invoices.map(i => {
    if (!i || !['receivable','payable'].includes(i.direction) || !['active','void'].includes(i.state)) fail('Invalid invoice state.');
    const result = {id:identifier(i.id), reference:text(i.reference,'invoice reference',60), counterparty:text(i.counterparty,'counterparty',120), direction:i.direction, amount:integerAmount(i.amount), due:i.due, issued:i.issued, recipient:text(i.recipient,'recipient',160,true), note:text(i.note,'note',500,true), state:i.state, createdAt:timestamp(i.createdAt)};
    if (!validDate(result.due) || !validDate(result.issued) || result.due < result.issued) fail('Invoice due date must be on or after its issue date.');
    if (ids.has(result.id) || refs.has(result.reference.toLowerCase())) fail('Duplicate invoice identifier or reference.');
    ids.add(result.id); refs.add(result.reference.toLowerCase()); return result;
  });
  const invoiceMap = new Map(invoices.map(i => [i.id,i]));
  const receiptIds = new Set(), receiptRefs = new Set(), outputs = new Set();
  const receipts = input.receipts.map(r => {
    if (!r || !invoiceMap.has(r.invoiceId) || invoiceMap.get(r.invoiceId).state === 'void') fail('Receipt refers to a missing or void invoice.');
    const result = {id:identifier(r.id), invoiceId:identifier(r.invoiceId), reference:text(r.reference,'record reference',80), amount:integerAmount(r.amount), date:r.date, txid:text(r.txid,'transaction ID',64,true).toLowerCase(), blockId:text(r.blockId,'block ID',64,true).toLowerCase(), output:r.output, note:text(r.note,'receipt note',500,true), createdAt:timestamp(r.createdAt)};
    if (!validDate(result.date) || result.date < invoiceMap.get(r.invoiceId).issued || result.date > localDate()) fail('Receipt date must be between the invoice issue date and today.');
    if (result.txid || result.blockId || result.output !== null) {
      if (!HASH.test(result.txid) || !HASH.test(result.blockId) || !Number.isSafeInteger(result.output) || result.output < 0 || result.output > 4294967295) fail('Provide the transaction ID, block ID and output index together.');
      const outpoint = `${result.blockId}:${result.txid}:${result.output}`;
      if (outputs.has(outpoint)) fail('This transaction output is already recorded.');
      outputs.add(outpoint);
    }
    if (receiptIds.has(result.id) || receiptRefs.has(result.reference.toLowerCase())) fail('Duplicate receipt identifier or record reference.');
    receiptIds.add(result.id); receiptRefs.add(result.reference.toLowerCase()); return result;
  });
  return {...emptyWorkspace(),revision:input.revision,invoices,receipts};
}
export function readBackup(raw) {
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > 2_000_000) fail('Backup must be smaller than 2 MB.');
  let input;
  try { input = JSON.parse(raw); } catch { fail('The backup is not valid JSON.'); }
  return validateWorkspace(input);
}
export function invoiceSummary(invoice, receipts, today = localDate()) {
  const recorded = receipts.filter(r => r.invoiceId === invoice.id).reduce((sum,r) => sum + BigInt(r.amount),0n);
  const expected = BigInt(invoice.amount);
  const remaining = recorded < expected && invoice.state === 'active' ? expected - recorded : 0n;
  let status = invoice.state === 'void' ? 'void' : recorded > expected ? 'over-recorded' : recorded === expected ? 'matched' : recorded > 0n ? 'partial' : 'open';
  return {recorded,remaining,excess:recorded > expected ? recorded - expected : 0n,status,overdue:remaining > 0n && invoice.due < today};
}
export function analytics(invoices, receipts, today = localDate()) {
  const result = {receivable:0n,payable:0n,inflow:0n,outflow:0n,overdue:0n,excess:0n,active:0,matched:0,aging:[0n,0n,0n,0n],schedule:Array.from({length:5},(_,i)=>({label:i===0?'Overdue':`Days ${1+(i-1)*7}–${i*7}`,receivable:0n,payable:0n})),counterparties:[]};
  const counterparties = new Map();
  for (const invoice of invoices) {
    if (invoice.state === 'void') continue;
    const s = invoiceSummary(invoice,receipts,today);
    result.active++; result[invoice.direction] += s.remaining; result.excess += s.excess;
    if (s.status === 'matched') result.matched++;
    result[invoice.direction === 'receivable'?'inflow':'outflow'] += s.recorded;
    if (s.overdue) result.overdue += s.remaining;
    const age = day(today) - day(invoice.due);
    result.aging[age <= 0 ? 0 : age <= 7 ? 1 : age <= 30 ? 2 : 3] += s.remaining;
    const ahead = day(invoice.due) - day(today);
    if (ahead < 0) result.schedule[0][invoice.direction] += s.remaining;
    else if (ahead <= 27) result.schedule[1+Math.floor(ahead/7)][invoice.direction] += s.remaining;
    const name = invoice.counterparty;
    const row = counterparties.get(name) || {name,receivable:0n,payable:0n};
    row[invoice.direction] += s.remaining; counterparties.set(name,row);
  }
  result.schedule[1].label = 'Today–6 days';
  result.schedule[2].label = '7–13 days'; result.schedule[3].label = '14–20 days'; result.schedule[4].label = '21–27 days';
  result.counterparties = [...counterparties.values()].filter(r=>r.receivable+r.payable>0n).sort((a,b)=>(a.receivable+a.payable)>(b.receivable+b.payable)?-1:(a.receivable+a.payable)<(b.receivable+b.payable)?1:a.name.localeCompare(b.name)).slice(0,8);
  return result;
}
export function chartPercent(value, maximum) { return maximum > 0n ? Number(value * 10000n / maximum) / 100 : 0; }
export function csvCell(value) {
  let str = String(value);
  if (/^[\s]*[=+\-@\t\r]/.test(str)) str = "'" + str;
  return '"' + str.replaceAll('"','""') + '"';
}
export function invoicesCSV(workspace, today = localDate()) {
  const rows = [['reference','direction','counterparty','amount_BLCH','recorded_BLCH','outstanding_BLCH','excess_BLCH','issue_date','due_date','record_status','overdue','recipient_reference','note']];
  for(const i of workspace.invoices) {
    const s=invoiceSummary(i,workspace.receipts,today);
    rows.push([i.reference,i.direction,i.counterparty,formatAmount(i.amount,false),formatAmount(s.recorded,false),formatAmount(s.remaining,false),formatAmount(s.excess,false),i.issued,i.due,s.status,s.overdue?'yes':'no',i.recipient,i.note]);
  }
  return rows.map(row=>row.map(csvCell).join(',')).join('\r\n');
}
export function receiptsCSV(workspace) {
  const rows=[['reference','invoice_reference','direction','amount_BLCH','record_date','txid','block_id','output_index','evidence','note']];
  for(const r of workspace.receipts) { const i=workspace.invoices.find(i=>i.id===r.invoiceId); rows.push([r.reference,i.reference,i.direction,formatAmount(r.amount,false),r.date,r.txid,r.blockId,r.output??'','manually entered; not chain-verified',r.note]); }
  return rows.map(row=>row.map(csvCell).join(',')).join('\r\n');
}
export function storeWorkspace(storage, previous, next) {
  const current = storage.getItem(STORAGE_KEY);
  if (current !== previous) fail('The workspace changed in another tab. Reload before saving.');
  const data=validateWorkspace(next);
  let priorRevision=0;
  if(previous){try{priorRevision=readBackup(previous).revision;}catch{/* A confirmed import may recover corrupt local data. */}}
  data.revision=priorRevision+1;
  const serialized=JSON.stringify(data);
  if(new TextEncoder().encode(serialized).length>2_000_000) fail('Workspace exceeds 2 MB. Export your backup before reducing its size.');
  storage.setItem(STORAGE_KEY,serialized);
  return {data,serialized};
}
