import {validateWorkspace,parseAmount,formatAmount,invoiceSummary,csvCell} from './model.mjs';

export const CSV_COLUMNS=['reference','invoice_reference','amount_BLCH','record_date','txid','block_id','output_index','note'];
const REQUIRED=CSV_COLUMNS.slice(0,4),OPTIONAL=[...CSV_COLUMNS.slice(4),'direction','evidence'];
export const BATCH_LIMITS=Object.freeze({bytes:2_000_000,rows:3000});
const check=(ok,message)=>{if(!ok)throw new Error(message);};
const size=value=>new TextEncoder().encode(value).length;
export const csvTemplate=()=>CSV_COLUMNS.join(',')+'\r\n';

// RFC-style quoted CSV, including escaped quotes and embedded CR/LF. No dialect guessing.
export function parseRecordCsv(raw){
  check(typeof raw==='string'&&size(raw)<=BATCH_LIMITS.bytes,'Choose a UTF-8 CSV file no larger than 2 MB.');
  raw=raw.replace(/^\uFEFF/,'');
  check(!raw.includes('\uFFFD')&&!raw.includes('\0'),'CSV contains invalid UTF-8 or null characters.');
  const rows=[];let row=[],cell='',mode='start';
  const field=()=>{row.push(cell);check(row.length<=10,'CSV has too many columns. Use the provided template.');cell='';mode='start';};
  const record=()=>{field();if(row.some(value=>value!==''))rows.push(row);check(rows.length<=BATCH_LIMITS.rows+1,'CSV exceeds 3,000 payment records.');row=[];};
  for(let i=0;i<raw.length;i++){
    const char=raw[i];
    if(mode==='quoted'){
      if(char==='"'){if(raw[i+1]==='"'){cell+='"';i++;}else mode='closed';}else cell+=char;
      continue;
    }
    if(char===','){field();continue;}
    if(char==='\n'||char==='\r'){if(char==='\r'&&raw[i+1]==='\n')i++;record();continue;}
    check(mode!=='closed','Unexpected text after a closing CSV quote.');
    if(char==='"'){check(mode==='start','Quotes must enclose the entire CSV field.');mode='quoted';}
    else{cell+=char;mode='plain';}
  }
  check(mode!=='quoted','CSV contains an unclosed quoted field.');
  if(row.length||cell||mode!=='start')record();
  check(rows.length>1,'Add at least one payment record below the CSV header.');
  const header=rows.shift().map(value=>value.trim());
  check(new Set(header).size===header.length,'CSV contains duplicate column names.');
  check(REQUIRED.every(key=>header.includes(key))&&header.every(key=>[...REQUIRED,...OPTIONAL].includes(key)),'Use the template columns: reference, invoice_reference, amount_BLCH and record_date are required.');
  return rows.map((values,index)=>({row:index+2,values:values.length===header.length?Object.fromEntries(header.map((key,i)=>[key,values[i]])):null,error:values.length===header.length?'':'Column count does not match the header.'}));
}

const signature=r=>JSON.stringify([r.reference.toLowerCase(),r.invoiceId,r.amount,r.date,r.txid,r.blockId,r.output,r.note]);
const outpoint=r=>r.txid?`${r.blockId}:${r.txid}:${r.output}`:null;
export function previewReconciliation(raw,input,{now=new Date().toISOString(),idFactory=()=>crypto.randomUUID()}={}){
  const state=validateWorkspace(input),parsed=parseRecordCsv(raw);
  const invoices=new Map(state.invoices.map(i=>[i.reference.toLowerCase(),i]));
  const references=new Map(state.receipts.map(r=>[r.reference.toLowerCase(),r]));
  const outputs=new Set(state.receipts.map(outpoint).filter(Boolean));
  const additions=[],rows=[];
  for(const entry of parsed){
    const data=entry.values||{},row={row:entry.row,reference:data.reference||'',invoice:data.invoice_reference||'',amount:data.amount_BLCH||'',status:'blocked',message:entry.error};
    try{
      check(entry.values,entry.error);
      const invoice=invoices.get(data.invoice_reference.trim().toLowerCase());
      check(invoice,'Invoice reference was not found in this workspace.');
      check(invoice.state==='active','This invoice is void.');
      check(!data.direction?.trim()||data.direction.trim()===invoice.direction,'Direction conflicts with the invoice.');
      const output=(data.output_index||'').trim();
      check(!output||/^(0|[1-9]\d{0,9})$/.test(output),'Output index must be an unsigned integer.');
      const candidate={id:idFactory(),invoiceId:invoice.id,reference:data.reference,amount:parseAmount(data.amount_BLCH),date:data.record_date.trim(),txid:data.txid||'',blockId:data.block_id||'',output:output===''?null:Number(output),note:data.note||'',createdAt:now};
      const receipt=validateWorkspace({...state,invoices:[invoice],receipts:[candidate]}).receipts[0];
      row.amount=formatAmount(receipt.amount,false);row.invoice=invoice.reference;row.reference=receipt.reference;
      const existing=references.get(receipt.reference.toLowerCase());
      if(existing){check(signature(existing)===signature(receipt),'Record reference already exists with different data.');row.status='duplicate';row.message='Identical record already saved or included earlier in this file; skipped.';}
      else{
        check(!outpoint(receipt)||!outputs.has(outpoint(receipt)),'Transaction output is already allocated to another record.');
        references.set(receipt.reference.toLowerCase(),receipt);if(outpoint(receipt))outputs.add(outpoint(receipt));
        additions.push(receipt);row.status='ready';row.message='New manual record; ready for review.';
      }
    }catch(error){row.message=error.message;}
    rows.push(row);
  }
  let batchError='';
  const next={...state,receipts:[...state.receipts,...additions]};
  try{validateWorkspace(next);check(size(JSON.stringify({...next,revision:next.revision+1}))<=BATCH_LIMITS.bytes,'The resulting workspace exceeds 2 MB.');}catch(error){batchError=error.message;}
  const touched=new Set(additions.map(r=>r.invoiceId));
  const impacts=state.invoices.filter(i=>touched.has(i.id)).map(invoice=>{
    const before=invoiceSummary(invoice,state.receipts),after=invoiceSummary(invoice,next.receipts);
    return {id:invoice.id,reference:invoice.reference,direction:invoice.direction,expected:invoice.amount,added:(after.recorded-before.recorded).toString(),before:before.status,after:after.status,outstanding:after.remaining.toString(),excess:after.excess.toString(),newExcess:after.excess>before.excess};
  });
  return {baseline:JSON.stringify(state),revision:state.revision,rows,additions,impacts,batchError,
    counts:{ready:additions.length,duplicate:rows.filter(r=>r.status==='duplicate').length,blocked:rows.filter(r=>r.status==='blocked').length},
    totals:{receivable:impacts.filter(i=>i.direction==='receivable').reduce((sum,i)=>sum+BigInt(i.added),0n).toString(),payable:impacts.filter(i=>i.direction==='payable').reduce((sum,i)=>sum+BigInt(i.added),0n).toString()}};
}

export function applyReconciliation(preview,input){
  const state=validateWorkspace(input);
  check(preview.baseline===JSON.stringify(state),'The workspace changed after preview. Reload and review the CSV again.');
  check(!preview.batchError&&!preview.counts.blocked,'Resolve every blocked row before importing this batch.');
  check(preview.additions.length>0,'There are no new records to import.');
  const next=validateWorkspace({...state,receipts:[...state.receipts,...preview.additions]});
  check(size(JSON.stringify({...next,revision:next.revision+1}))<=BATCH_LIMITS.bytes,'The resulting workspace exceeds 2 MB.');
  return next;
}

export function reconciliationCsv(preview){
  const rows=[['csv_record','record_reference','invoice_reference','amount_BLCH','review_status','message','workspace_revision','batch_can_import','evidence']];
  for(const row of preview.rows)rows.push([row.row,row.reference,row.invoice,row.amount,row.status,row.message,preview.revision,!preview.batchError&&!preview.counts.blocked&&preview.counts.ready>0,'User-supplied; not chain-verified']);
  if(preview.batchError)rows.push(['','','','','batch_blocked',preview.batchError,preview.revision,false,'']);
  return rows.map(row=>row.map(csvCell).join(',')).join('\r\n');
}
