import {prepareSources} from './preparation.v1.mjs';
import {MAX_BYTES,sha256} from './reconcile.v1.mjs';
import {readExport,verifyEvidence} from './audit.v1.mjs';

export const MAX_PREPARATION_BYTES=8*1024*1024;
const encode=value=>JSON.stringify(value,null,2)+'\n';
const digestPattern=/^[0-9a-f]{64}$/;
const timestamp=value=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
function stable(value,depth=0) {
  if(depth>24)throw new Error('Preparation JSON nesting exceeds its supported schema.');
  if(Array.isArray(value))return '['+value.map(entry=>stable(entry,depth+1)).join(',')+']';
  if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+stable(value[key],depth+1)).join(',')+'}';
  return JSON.stringify(value);
}
const equal=(left,right)=>stable(left)===stable(right);
function sourcePair(pair,label) {
  if(!Array.isArray(pair)||pair.length!==2||pair.some(file=>!file||typeof file.text!=='string'||!file.text.isWellFormed()||new TextEncoder().encode(file.text).length>MAX_BYTES))throw new Error(`${label}: supply two valid UTF-8 CSVs, at most 2 MiB each, in A/B order.`);
  return pair.map(file=>({text:file.text}));
}

export async function verifyPreparation({receiptText,originals,prepared,expectedDigest='',evidenceText=null,expectedEvidenceDigest=''}) {
  // Capture all caller-owned source text before hashing yields control.
  const originalFiles=sourcePair(originals,'Original sources'),preparedFiles=sourcePair(prepared,'Prepared sources');
  const receipt=readExport(receiptText,MAX_PREPARATION_BYTES),digest=await sha256(receiptText);
  if(expectedDigest!==''&&(!digestPattern.test(expectedDigest)||expectedDigest!==digest))throw new Error('The preparation receipt does not match the independently retained SHA-256.');
  if(!receipt||receipt.schema!=='bloch.data.source-preparation.v1')throw new Error('Unsupported preparation receipt schema.');
  if(!timestamp(receipt.generated_at)||!['synthetic_example','local_files'].includes(receipt.mode))throw new Error('Invalid preparation mode or declared local timestamp.');
  if(!Array.isArray(receipt.sources)||receipt.sources.length!==2||receipt.sources.some(source=>!source?.input||!source?.output||!source?.profile))throw new Error('Invalid preparation source declarations.');
  if(evidenceText===null&&expectedEvidenceDigest!=='')throw new Error('An evidence digest requires the corresponding evidence JSON.');
  const inputs=originalFiles.map((file,index)=>({name:receipt.sources[index].input.name,text:file.text,profile:receipt.sources[index].profile}));
  const rebuilt=await prepareSources(inputs,receipt.configuration,receipt.mode);
  rebuilt.receipt.generated_at=receipt.generated_at;
  for(let index=0;index<2;index++) {
    const side=index?'B':'A';
    if(!equal(receipt.sources[index].input,rebuilt.receipt.sources[index].input))throw new Error(`Original source ${side} bytes or declarations do not match the receipt.`);
    if(preparedFiles[index].text!==rebuilt.sources[index].text)throw new Error(`Prepared source ${side} does not exactly match the recomputed CSV bytes.`);
  }
  if(!equal(receipt,rebuilt.receipt))throw new Error('Recomputed preparation mappings, lineage, counts, rules or metadata differ from the receipt.');
  let evidence=null;
  if(evidenceText!==null) {
    evidence=await verifyEvidence(evidenceText,rebuilt.sources[0],rebuilt.sources[1],expectedEvidenceDigest);
    if(!equal(evidence.report.configuration,receipt.configuration)||evidence.report.mode!==receipt.mode)throw new Error('Evidence configuration and data mode must match the preparation receipt.');
  }
  return {receipt,bytes:receiptText,digest,pinned:expectedDigest!=='',sources:rebuilt.sources,configuration:rebuilt.configuration,mode:receipt.mode,evidence};
}

export async function preparationVerificationExport(verified) {
  const report={schema:'bloch.data.source-preparation-verification.v1',verified_at:new Date().toISOString(),clock_source:'local_browser_untrusted',
    preparation_sha256:verified.digest,retained_preparation_digest_check:verified.pinned?'matched':'not_provided',
    preparation:'recomputed_and_matched',original_bytes:'matched',prepared_bytes:'exactly_reproduced',rules_and_metadata:'matched_supported_schema',module:verified.receipt.module,mode:verified.mode,
    sources:verified.receipt.sources.map(source=>({side:source.side,original:{sha256:source.input.sha256,bytes:source.input.bytes,rows:source.input.rows},prepared:{sha256:source.output.sha256,bytes:source.output.bytes,rows:source.output.rows},mapped_columns:Object.keys(source.profile.column_mapping).length,excluded_columns:source.profile.excluded_columns.length,lineage_rows:source.lineage.length,changed_cells_by_field:source.changed_cells_by_field})),
    evidence:verified.evidence?{sha256:verified.evidence.digest,retained_digest_check:verified.evidence.pinned?'matched':'not_provided',source_binding:'prepared_bytes_matched',configuration:'matched',comparison:'recomputed_and_matched',counts:verified.evidence.report.result.counts}:null,
    assurance:{scope:'local_consistency_only',source_authentication:'not_verified',source_completeness:'not_verified',mapping_authorization:'not_authenticated',signature:'absent',rollback_protection:'absent',review_journal:'not_supplied_or_verified',onchain:'not_verified',regulatory_compliance:'not_certified'}};
  const bytes=encode(report);return {report,bytes,digest:await sha256(bytes)};
}
