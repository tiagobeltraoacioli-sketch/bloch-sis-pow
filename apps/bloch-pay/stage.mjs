import {mkdir,copyFile,readFile,writeFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=dirname(fileURLToPath(import.meta.url));
const output=process.argv[2];
if(!output||!output.startsWith('/'))throw new Error('Pass a new absolute output directory.');
const files=['index.html','_headers','assets/style.css','assets/pay-launch.css','assets/favicon.png','assets/bloch-inc-logo-dark.png','app/index.html','app/workspace.css','app/workspace.mjs','app/model.mjs','app/integrations.html','app/integrations.css','app/integrations.mjs','app/integration-ui.mjs','app/studio-model.mjs','app/studio-ui.mjs','app/pwa.mjs','app/participant-modules.mjs','app/modules-ui.mjs','app/operations.mjs','app/operations-ui.mjs','app/payment-api.openapi.json','app/manifest.webmanifest','app/icon.svg','app/sw.js'];
const api=JSON.parse(await readFile(resolve(root,'app/payment-api.openapi.json'),'utf8'));
function validateRefs(value){if(!value||typeof value!=='object')return;if(value.$ref){let target=api;for(const segment of value.$ref.replace(/^#\//,'').split('/'))target=target?.[segment];if(!target)throw new Error('Unresolved API schema: '+value.$ref);}for(const entry of Object.values(value))validateRefs(entry);}
validateRefs(api);
await mkdir(output,{recursive:false});
const entries=[];
for(const file of files){const source=resolve(root,file),destination=resolve(output,file);const content=await readFile(source);await mkdir(dirname(destination),{recursive:true});await copyFile(source,destination);entries.push({file,bytes:content.length,sha256:createHash('sha256').update(content).digest('hex')});}
await writeFile(output+'.manifest.json',JSON.stringify({created_at:new Date().toISOString(),files:entries},null,2));
console.log(JSON.stringify({directory:output,files:entries.length,bytes:entries.reduce((sum,e)=>sum+e.bytes,0)}));
