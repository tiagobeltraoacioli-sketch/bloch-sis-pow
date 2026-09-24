import {sha256,MAX_BYTES} from './reconcile.v1.mjs';
import {readExport} from './audit.v1.mjs';
import {verifyCaseFile,MAX_CASE_BYTES} from './case-file.v1.mjs';
import {verifyPreparation,preparationVerificationExport,MAX_PREPARATION_BYTES} from './preparation-verification.v1.mjs';

export const MAX_AUDIT_BUNDLE_BYTES=96*1024*1024;
export const AUDIT_BUNDLE_COMPONENTS=Object.freeze([
  {name:'case.bloch.json',media_type:'application/json',limit:MAX_CASE_BYTES},
  {name:'preparation.json',media_type:'application/json',limit:MAX_PREPARATION_BYTES},
  {name:'original-a.csv',media_type:'text/csv',limit:MAX_BYTES},
  {name:'original-b.csv',media_type:'text/csv',limit:MAX_BYTES},
  {name:'preparation-verification.json',media_type:'application/json',limit:16384},
].map(Object.freeze));
const encode=value=>JSON.stringify(value,null,2)+'\n';
const digestPattern=/^[0-9a-f]{64}$/;
const assurance=Object.freeze({scope:'local_consistency_only',encryption:'none',signatures:'absent',source_authentication:'not_verified',source_completeness:'not_verified',mapping_authorization:'not_authenticated',reviewer_identity:'not_verified',rollback_protection:'absent',onchain:'not_verified',regulatory_compliance:'not_certified'});
const exactKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const timestamp=value=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
const sameFields=(value,expected)=>exactKeys(value,Object.keys(expected))&&Object.entries(expected).every(([key,entry])=>value[key]===entry);
function boundedText(text,limit,name){
  if(typeof text!=='string'||!text.isWellFormed())throw new Error(`${name}: expected valid Unicode text.`);
  const size=new TextEncoder().encode(text).length;if(size>limit)throw new Error(`${name}: exceeds the supported size limit.`);return size;
}
function binding(caseResult,preparation){return {case_sha256:caseResult.digest,preparation_sha256:preparation.digest,evidence_sha256:caseResult.evidence.digest,review_sha256:caseResult.caseFile.review_sha256,module:caseResult.evidence.report.configuration.module,mode:caseResult.evidence.report.mode};}
async function checkSources(caseText,preparationText,originals,caseDigest='',preparationDigest=''){
  const caseResult=await verifyCaseFile(caseText,caseDigest);
  const preparation=await verifyPreparation({receiptText:preparationText,originals,prepared:caseResult.sources,evidenceText:caseResult.evidence.bytes,expectedDigest:preparationDigest});
  return {caseResult,preparation};
}

export async function createAuditBundle({caseText,preparationText,originals,caseDigest='',preparationDigest=''}){
  if(!Array.isArray(originals)||originals.length!==2)throw new Error('Supply both original extracts in A/B order.');
  const sources=originals.map((file,index)=>{const text=file?.text;boundedText(text,MAX_BYTES,`Original ${index?'B':'A'}`);return {text};});
  const {caseResult,preparation}=await checkSources(caseText,preparationText,sources,caseDigest,preparationDigest);
  // Embedded identities are not independent references. Package a fresh, unpinned
  // consistency receipt; externally retained input pins only gate creation.
  const verification=await preparationVerificationExport({...preparation,pinned:false});
  const contents=[caseText,preparationText,sources[0].text,sources[1].text,verification.bytes];
  const components=await Promise.all(AUDIT_BUNDLE_COMPONENTS.map(async(spec,index)=>({name:spec.name,media_type:spec.media_type,bytes:boundedText(contents[index],spec.limit,spec.name),sha256:await sha256(contents[index]),content:contents[index]})));
  const bundle={schema:'bloch.data.audit-bundle.v1',created_at:new Date().toISOString(),clock_source:'local_browser_untrusted',encoding:'embedded_utf8_text',...binding(caseResult,preparation),assurance:{...assurance},components};
  const bytes=encode(bundle);boundedText(bytes,MAX_AUDIT_BUNDLE_BYTES,'Audit bundle');return {bundle,bytes,digest:await sha256(bytes)};
}

export async function verifyAuditBundle(text,expectedDigest=''){
  boundedText(text,MAX_AUDIT_BUNDLE_BYTES,'Audit bundle');const digest=await sha256(text);
  if(expectedDigest!==''&&(!digestPattern.test(expectedDigest)||digest!==expectedDigest))throw new Error('Audit bundle does not match the independently retained SHA-256.');
  const bundle=readExport(text,MAX_AUDIT_BUNDLE_BYTES);
  if(!exactKeys(bundle,['schema','created_at','clock_source','encoding','case_sha256','preparation_sha256','evidence_sha256','review_sha256','module','mode','assurance','components'])||bundle.schema!=='bloch.data.audit-bundle.v1'||bundle.clock_source!=='local_browser_untrusted'||bundle.encoding!=='embedded_utf8_text'||!timestamp(bundle.created_at)||!sameFields(bundle.assurance,assurance))throw new Error('Unsupported audit bundle manifest or assurance fields.');
  if(!Array.isArray(bundle.components)||bundle.components.length!==AUDIT_BUNDLE_COMPONENTS.length)throw new Error('Audit bundle must contain exactly five supported components.');
  for(let index=0;index<AUDIT_BUNDLE_COMPONENTS.length;index++){
    const spec=AUDIT_BUNDLE_COMPONENTS[index],part=bundle.components[index];
    if(!exactKeys(part,['name','media_type','bytes','sha256','content'])||part.name!==spec.name||part.media_type!==spec.media_type)throw new Error('Unexpected, duplicate or reordered audit bundle component.');
    const length=boundedText(part.content,spec.limit,spec.name);
    if(!Number.isSafeInteger(part.bytes)||part.bytes!==length||!digestPattern.test(part.sha256)||part.sha256!==await sha256(part.content))throw new Error(`${spec.name}: component size or SHA-256 mismatch.`);
  }
  const parts=bundle.components,originals=[{name:parts[2].name,text:parts[2].content},{name:parts[3].name,text:parts[3].content}];
  const {caseResult,preparation}=await checkSources(parts[0].content,parts[1].content,originals);
  if(!Object.entries(binding(caseResult,preparation)).every(([key,value])=>bundle[key]===value))throw new Error('Audit bundle identities, module or data mode do not match its verified contents.');
  const retained=readExport(parts[4].content,16384);
  if(!retained||!timestamp(retained.verified_at))throw new Error('Invalid packaged preparation verification timestamp.');
  const expected=(await preparationVerificationExport(preparation)).report;expected.verified_at=retained.verified_at;
  if(encode(expected)!==parts[4].content)throw new Error('Packaged preparation verification differs from the recomputed file relationships.');
  return {bundle,bytes:text,digest,pinned:expectedDigest!=='',case:caseResult,preparation,originals};
}

export async function auditBundleVerificationExport(verified){
  const report={schema:'bloch.data.audit-bundle-verification.v1',verified_at:new Date().toISOString(),clock_source:'local_browser_untrusted',audit_bundle_sha256:verified.digest,retained_bundle_digest_check:verified.pinned?'matched':'not_provided',...binding(verified.case,verified.preparation),components:verified.bundle.components.map(({name,bytes,sha256})=>({name,bytes,sha256,check:'matched'})),checks:{case:'six_components_verified',preparation:'recomputed_and_matched',prepared_source_binding:'exact_bytes_matched',configuration_and_mode:'matched',comparison:'recomputed_and_matched',review:'validated_against_exact_evidence',packaged_preparation_receipt:'matched_recomputation'},key_count:verified.case.evidence.report.result.key_count,counts:verified.case.evidence.report.result.counts,review_entries:verified.case.review.events.length,original_rows:verified.preparation.receipt.sources.map(source=>({side:source.side,rows:source.input.rows,lineage_rows:source.lineage.length})),assurance:{...assurance}};
  const bytes=encode(report);return {report,bytes,digest:await sha256(bytes)};
}
