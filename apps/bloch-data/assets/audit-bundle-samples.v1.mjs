import {preparationExample} from './preparation-samples.v1.mjs';
import {sha256} from './reconcile.v1.mjs';
import {newReview,appendReview} from './audit.v1.mjs';
import {createCaseFile} from './case-file.v1.mjs';
import {createAuditBundle} from './audit-bundle.v1.mjs';

export async function auditBundleExample(configuration){
  const input=await preparationExample(configuration),report=JSON.parse(input.evidenceText),digest=await sha256(input.evidenceText);
  const exception=report.result.items.find(item=>item.status!=='matched');
  const review=appendReview(newReview(digest),report,digest,{record_key:exception.key,original_outcome:exception.status,state:'investigating',reviewer:'Synthetic reviewer',note:'Illustrative follow-up only; no institutional approval.'});
  const caseFile=await createCaseFile(input.evidenceText,input.prepared[0],input.prepared[1],review);
  return createAuditBundle({caseText:caseFile.bytes,preparationText:input.receiptText,originals:input.originals});
}
