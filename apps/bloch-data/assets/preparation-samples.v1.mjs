import {defaultConfig,validateConfig,getModule} from './modules.v1.mjs';
import {samplesFor} from './samples.v1.mjs';
import {inspectSource,machineCSV,prepareSources} from './preparation.v1.mjs';
import {createReport} from './reconcile.v1.mjs';

export async function preparationExample(configuration=defaultConfig('cash','br','bank')) {
  const config=validateConfig(configuration);
  const originals=[0,1].map(index=>{
    const formats={separator:index?',':';',date_format:index?'iso':'dmy',decimal_format:index?'dot':'comma'};
    const table=inspectSource(samplesFor({...config,...formats,column_mapping:{}})[index],formats.separator);
    const mapping=Object.fromEntries(getModule(config.module).fields.map(field=>[field,`${index?'statement':'book'}_${field}`]));
    return {name:`synthetic-original-${index?'b':'a'}.csv`,text:(index?'':'\uFEFF\r\n')+machineCSV([[...Object.values(mapping),'extract_note'],...table.records.map(row=>[...row.values,'Synthetic extraction note'])],formats.separator),profile:{...formats,column_mapping:mapping,excluded_columns:['extract_note']}};
  });
  const prepared=await prepareSources(originals,config,'synthetic_example');
  const evidence=await createReport(prepared.sources[0],prepared.sources[1],'synthetic_example',prepared.configuration);
  return {receiptText:prepared.bytes,originals:originals.map(({name,text})=>({name,text})),prepared:prepared.sources,evidenceText:evidence.bytes};
}
