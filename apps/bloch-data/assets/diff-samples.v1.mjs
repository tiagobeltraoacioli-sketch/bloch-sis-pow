import {defaultConfig,getModule} from './modules.v1.mjs';
import {samplesFor} from './samples.v1.mjs';
import {parseCSV,createReport} from './reconcile.v1.mjs';
import {newReview,appendReview} from './audit.v1.mjs';
import {createCaseFile} from './case-file.v1.mjs';

export async function exampleCasePair() {
  const config=defaultConfig('cash','global','bank'),module=getModule('cash'),texts=samplesFor(config);
  const books=texts.map(text=>parseCSV(text,config).map(row=>row.values));
  const csv=rows=>[module.fields,...rows.map(row=>module.fields.map(field=>row[field]))].map(row=>row.map(value=>'"'+value.replaceAll('"','""')+'"').join(',')).join('\r\n')+'\r\n';
  const source=(text,side)=>({name:`synthetic-${side}.csv`,text});
  const before=await createReport(source(csv(books[0]),'a'),source(csv(books[1]),'b'),'synthetic_example',config);
  const matches=before.report.result.items.filter(item=>item.status==='matched'),differences=before.report.result.items.filter(item=>item.status==='different'),missing=before.report.result.items.find(item=>item.status==='left_only');
  const key=record=>JSON.stringify(module.keys.map(field=>record[field]));
  const changed=structuredClone(books).map(rows=>rows.filter(row=>key(row)!==JSON.stringify(matches[0].key)));
  const modified=changed[1].find(row=>key(row)===JSON.stringify(matches[1].key));modified.amount='9999999.5';
  const corrected=changed[1].findIndex(row=>key(row)===JSON.stringify(differences[0].key));changed[1][corrected]=structuredClone(differences[0].left[0].values);
  changed[1].push(structuredClone(missing.left[0].values));
  const added={...matches[0].left[0].values,entry_id:'DEMO-NEW'};changed[0].push({...added});changed[1].push({...added});
  const beforeSources=books.map((rows,i)=>source(csv(rows),i?'b':'a')),afterSources=changed.map((rows,i)=>source(csv(rows),i?'b':'a'));
  const after=await createReport(...afterSources,'synthetic_example',config);
  const noteItem=after.report.result.items.find(item=>JSON.stringify(item.key)===JSON.stringify(differences[1].key));
  const review=appendReview(newReview(after.digest),after.report,after.digest,{record_key:noteItem.key,original_outcome:noteItem.status,state:'investigating',reviewer:'SYNTHETIC REVIEWER',note:'Synthetic follow-up: compare posting status with the retained statement.'});
  const baseline=await createCaseFile(before.bytes,...beforeSources,newReview(before.digest));
  const candidate=await createCaseFile(after.bytes,...afterSources,review);
  return [baseline.bytes,candidate.bytes];
}
