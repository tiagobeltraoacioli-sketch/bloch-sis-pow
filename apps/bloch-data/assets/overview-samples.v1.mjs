import {defaultConfig} from './modules.v1.mjs';
import {samplesFor} from './samples.v1.mjs';
import {createReport} from './reconcile.v1.mjs';
import {newReview,appendReview} from './audit.v1.mjs';
import {createCaseFile} from './case-file.v1.mjs';
import {exampleCasePair} from './diff-samples.v1.mjs';

export async function overviewExample(){
  const pair=await exampleCasePair(),inputs=pair.map((text,index)=>({name:`synthetic-cash-${index+1}.bloch.json`,text}));
  for(const [index,[module,region,institution]] of [['trades','br','exchange'],['positions','mx','manager'],['onchain','global','custodian']].entries()){
    const config=defaultConfig(module,region,institution),sources=samplesFor(config).map((text,side)=>({name:`synthetic-${module}-${side?'b':'a'}.csv`,text}));
    const evidence=await createReport(...sources,'synthetic_example',config),items=evidence.report.result.items.filter(item=>item.status!=='matched');let review=newReview(evidence.digest);
    for(let i=0;i<=index+1;i++)review=appendReview(review,evidence.report,evidence.digest,{record_key:items[i].key,original_outcome:items[i].status,state:['investigating','explained','follow_up','reopened'][i],reviewer:'Synthetic reviewer',note:'Illustrative review only; no institutional approval.'});
    inputs.push({name:`synthetic-${module}.bloch.json`,text:(await createCaseFile(evidence.bytes,...sources,review)).bytes});
  }
  return inputs;
}
