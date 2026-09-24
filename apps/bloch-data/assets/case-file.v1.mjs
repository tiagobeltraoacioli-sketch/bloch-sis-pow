import {sha256,MAX_BYTES} from './reconcile.v1.mjs';
import {readExport,verifyEvidence,validateReview,reviewExport,verificationExport,MAX_EVIDENCE_BYTES,MAX_REVIEW_BYTES} from './audit.v1.mjs';

export const MAX_CASE_BYTES=64*1024*1024;
export const CASE_COMPONENTS=Object.freeze([
  {name:'evidence.json',media_type:'application/json',limit:MAX_EVIDENCE_BYTES},
  {name:'source-a.csv',media_type:'text/csv',limit:MAX_BYTES},
  {name:'source-b.csv',media_type:'text/csv',limit:MAX_BYTES},
  {name:'review.json',media_type:'application/json',limit:MAX_REVIEW_BYTES},
  {name:'configuration.json',media_type:'application/json',limit:16384},
  {name:'verification.json',media_type:'application/json',limit:16384},
].map(Object.freeze));
const encode=value=>JSON.stringify(value,null,2)+'\n';
const digestPattern=/^[0-9a-f]{64}$/;
const assurance=Object.freeze({scope:'local_consistency_only',encryption:'none',signatures:'absent',source_authentication:'not_verified',reviewer_identity:'not_verified',rollback_protection:'absent',onchain:'not_verified',regulatory_compliance:'not_certified'});
const exactKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const isTimestamp=value=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
function equalFields(a,b) {return exactKeys(a,Object.keys(b))&&Object.entries(b).every(([key,value])=>a[key]===value);}
function boundedText(text,limit,name) {
  if(typeof text!=='string'||!text.isWellFormed())throw new Error(`${name}: expected valid Unicode text.`);
  const bytes=new TextEncoder().encode(text).length;
  if(bytes>limit)throw new Error(`${name}: exceeds the supported size limit.`);
  return bytes;
}

export async function createCaseFile(evidenceText,left,right,review) {
  const originals=[{...left},{...right}],journalState=structuredClone(review);
  // Recompute rather than attaching a previously displayed success flag. The
  // report digest in app memory is not an independently retained reference.
  const evidence=await verifyEvidence(evidenceText,...originals);
  const journal=await reviewExport(journalState,evidence.report,evidence.digest);
  const receipt=await verificationExport(evidence,journalState);
  const contents=[evidenceText,originals[0].text,originals[1].text,journal.bytes,encode(evidence.report.configuration),receipt.bytes];
  const components=await Promise.all(CASE_COMPONENTS.map(async(spec,i)=>({name:spec.name,media_type:spec.media_type,bytes:boundedText(contents[i],spec.limit,spec.name),sha256:await sha256(contents[i]),content:contents[i]})));
  const caseFile={schema:'bloch.data.case-file.v1',created_at:new Date().toISOString(),clock_source:'local_browser_untrusted',encoding:'embedded_utf8_text',evidence_sha256:evidence.digest,review_sha256:journal.digest,assurance:{...assurance},components};
  const bytes=encode(caseFile);boundedText(bytes,MAX_CASE_BYTES,'Case file');
  return {caseFile,bytes,digest:await sha256(bytes)};
}

export async function verifyCaseFile(text,expectedDigest='') {
  boundedText(text,MAX_CASE_BYTES,'Case file');
  const digest=await sha256(text);
  if(expectedDigest!==''&&(!digestPattern.test(expectedDigest)||digest!==expectedDigest))throw new Error('Case file does not match the independently retained SHA-256.');
  const caseFile=readExport(text,MAX_CASE_BYTES);
  if(!exactKeys(caseFile,['schema','created_at','clock_source','encoding','evidence_sha256','review_sha256','assurance','components'])||caseFile.schema!=='bloch.data.case-file.v1'||caseFile.clock_source!=='local_browser_untrusted'||caseFile.encoding!=='embedded_utf8_text'||!isTimestamp(caseFile.created_at)||!digestPattern.test(caseFile.evidence_sha256)||!digestPattern.test(caseFile.review_sha256)||!equalFields(caseFile.assurance,assurance))throw new Error('Unsupported case manifest or assurance fields.');
  if(!Array.isArray(caseFile.components)||caseFile.components.length!==CASE_COMPONENTS.length)throw new Error('Case file must contain exactly six supported components.');
  // Fixed names and order avoid ambiguous duplicates or extraction paths. No
  // component is executed, fetched, unzipped or written to a filesystem here.
  for(let i=0;i<CASE_COMPONENTS.length;i++){
    const part=caseFile.components[i],spec=CASE_COMPONENTS[i];
    if(!exactKeys(part,['name','media_type','bytes','sha256','content'])||part.name!==spec.name||part.media_type!==spec.media_type)throw new Error('Unexpected, duplicate or reordered case component.');
    const length=boundedText(part.content,spec.limit,spec.name);
    if(!Number.isSafeInteger(part.bytes)||part.bytes!==length||!digestPattern.test(part.sha256)||part.sha256!==await sha256(part.content))throw new Error(`${spec.name}: component size or SHA-256 mismatch.`);
  }
  const parts=caseFile.components;
  const sources=[{name:parts[1].name,text:parts[1].content},{name:parts[2].name,text:parts[2].content}];
  // The internal manifest digest is checked, but never presented as an
  // independent pin. The optional external reference binds the whole case.
  const evidence=await verifyEvidence(parts[0].content,...sources);
  if(evidence.digest!==caseFile.evidence_sha256||parts[3].sha256!==caseFile.review_sha256)throw new Error('Case manifest does not bind the evidence and review components.');
  const review=validateReview(readExport(parts[3].content,MAX_REVIEW_BYTES),evidence.report,evidence.digest);
  if(parts[4].content!==encode(evidence.report.configuration))throw new Error('Packaged configuration differs from the evidence configuration.');
  const retainedReceipt=readExport(parts[5].content,16384);
  if(!retainedReceipt||!isTimestamp(retainedReceipt.verified_at))throw new Error('Invalid packaged verification receipt.');
  const expectedReceipt=JSON.parse((await verificationExport(evidence,review)).bytes);
  expectedReceipt.verified_at=retainedReceipt.verified_at;
  if(encode(expectedReceipt)!==parts[5].content)throw new Error('Packaged verification receipt differs from the recomputed evidence and review.');
  return {caseFile,digest,pinned:expectedDigest!=='',evidence,review,sources};
}

export async function caseVerificationExport(verified) {
  const receipt={schema:'bloch.data.case-verification.v1',verified_at:new Date().toISOString(),clock_source:'local_browser_untrusted',case_sha256:verified.digest,retained_case_digest_check:verified.pinned?'matched':'not_provided',evidence_sha256:verified.evidence.digest,review_sha256:verified.caseFile.review_sha256,components:verified.caseFile.components.map(({name,bytes,sha256})=>({name,bytes,sha256,check:'matched'})),comparison:'recomputed_and_matched',configuration:'matched_evidence',packaged_receipt:'matched_recomputed_evidence_and_review',module:verified.evidence.report.configuration.module,mode:verified.evidence.report.mode,key_count:verified.evidence.report.result.key_count,review_entries:verified.review.events.length,assurance:{...assurance}};
  const bytes=encode(receipt);return {bytes,digest:await sha256(bytes)};
}
