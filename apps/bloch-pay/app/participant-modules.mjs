export const GRAPHUS_ORIGIN='https://bloch-graphus.xyz';
export const REGISTRY_URL=GRAPHUS_ORIGIN+'/api/system/map';
export const ASSETS=Object.freeze(['BTC','ETH','USDT','USDC','BLCH']);
export const MODULES=Object.freeze({
  graphus:{name:'Graphus',description:'Public data, source provenance and bounded chain observations.',ids:['manifest','events','quality','daas']},
  constellation:{name:'Constellation',description:'Explore transaction and reference relationships in a selected asset sample.',ids:['tx-node','utxo-node','account-node','paths']},
  aml:{name:'AML / BI-PoRB',description:'Prepare public evidence; open private observations and descriptive Red/Blue results through organization access.',ids:['aml-evidence','scores','ml','blue','review','aml-monitoring']},
  system_map:{name:'System Map',description:'Inspect module contracts, source coverage and upstream/downstream dependencies.',ids:[]}
});
export const PRIVATE_PROFILES=Object.freeze({none:'Public tools only',read:'Request private analysis read access',collect:'Request private collection and analysis access'});
export function emptyModules(){return {enabled:[],assets:['BLCH'],purpose:'',organization_reference:'',private_profile:'none'};}
export function validateModules(value=emptyModules()){
  if(!value||!Array.isArray(value.enabled)||value.enabled.length>4||new Set(value.enabled).size!==value.enabled.length||value.enabled.some(k=>typeof k!=='string'||!Object.hasOwn(MODULES,k)))throw new Error('Invalid participant module selection.');
  if(!Array.isArray(value.assets)||!value.assets.length||value.assets.length>5||new Set(value.assets).size!==value.assets.length||value.assets.some(a=>!ASSETS.includes(a)))throw new Error('Choose at least one supported module asset.');
  for(const [key,max]of [['purpose',240],['organization_reference',80]])if(typeof value[key]!=='string'||value[key].length>max||/[\u0000-\u001f]/.test(value[key]))throw new Error('Invalid module '+key.replaceAll('_',' ')+'.');
  if(value.enabled.length&&!value.purpose.trim())throw new Error('Describe the purpose of the selected modules.');
  if(typeof value.private_profile!=='string'||!Object.hasOwn(PRIVATE_PROFILES,value.private_profile))throw new Error('Invalid private access profile.');
  const org=value.organization_reference.trim();if(org&&!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,79}$/.test(org))throw new Error('Use an internal organization reference, not a credential.');
  if(value.private_profile!=='none'&&(!value.enabled.includes('aml')||!org))throw new Error('Private access planning requires AML / BI-PoRB and an organization reference.');
  return {enabled:[...value.enabled].sort(),assets:[...value.assets].sort(),purpose:value.purpose.trim(),organization_reference:org,private_profile:value.private_profile};
}
export function moduleLinks(key,asset,profile='none'){
  if(!Object.hasOwn(MODULES,key)||!ASSETS.includes(asset))return [];
  const query=asset.toLowerCase();
  const links={
    graphus:[['Open Graphus data',GRAPHUS_ORIGIN+'/daas'],['Open field catalog',GRAPHUS_ORIGIN+'/catalog']],
    constellation:[['Open Constellation',GRAPHUS_ORIGIN+'/constellation?asset='+query]],
    aml:[['Prepare public evidence',GRAPHUS_ORIGIN+'/map?category=aml&module=aml-evidence&asset='+asset],...(profile!=='none'?[['Open private BI-PoRB','https://rednblue.space/portal/?view=analyses'],['Manage organization access','https://rednblue.space/portal/?view=access']]:[])],
    system_map:[['Open System Map',GRAPHUS_ORIGIN+'/map?asset='+asset]]
  };
  return links[key].map(([label,href])=>({label,href}));
}
export function integrationManifest(partner){
  const plan=validateModules(partner.modules),scopes=plan.private_profile==='none'?[]:plan.private_profile==='read'?['analyses:read','scores:read']:['data:read','analyses:write','analyses:read','scores:read'];
  return {schema:'bloch-pay-participant-integration',version:1,environment:'design',execution_enabled:false,participant_reference:partner.id,participant_role:partner.role,configuration:plan,
    public_registry:{url:REGISTRY_URL,method:'GET',credentials:'omit',semantics:'Implementation descriptions, not live health or an executed analysis'},
    launchers:plan.enabled.map(key=>({module:key,assets:plan.assets.map(asset=>({asset,links:moduleLinks(key,asset,plan.private_profile)}))})),
    private_access:{authorization_status:'not_verified',organization_reference:plan.organization_reference||null,tenant_binding:'Authenticated BI-PoRB principal; this reference grants no access',requested_scopes:scopes,credential_location:'Organization server secret store; never the browser or this export',api_origin:'https://rednblue.space',operations:scopes.length?[{method:'GET',path:'/api/porb/v1/analyses',scopes:['analyses:read','scores:read']},{method:'GET',path:'/api/porb/v1/analyses/{id}/export',scopes:['analyses:read','scores:read']},...(plan.private_profile==='collect'?[{method:'POST',path:'/api/porb/v1/analyses',scopes:['data:read','analyses:write','scores:read'],body_schema:{asset:plan.assets,pages:{minimum:1,maximum:4}}}]:[])]:[]},
    boundaries:{payment_execution:false,automatic_screening:false,participant_identity_verified:false,red_blue:'Descriptive observation indices, not an AML verdict',data_handoff:'Product links include asset only; participant records, scores and credentials are not transmitted'}};
}
const bounded=(value,max,label)=>{if(typeof value!=='string'||!value.length||value.length>max)throw new Error('Invalid registry '+label+'.');return value;};
export function validateRegistry(raw){
  if(!raw||raw.schema_version!==1||raw.source!==GRAPHUS_ORIGIN+'/map'||!Array.isArray(raw.modules)||!raw.modules.length||raw.modules.length>128)throw new Error('Unsupported Graphus capability registry.');
  const ids=new Set();const modules=raw.modules.map(node=>{
    const id=bounded(node.id,80,'identifier');if(!/^[a-z0-9-]+$/.test(id)||ids.has(id))throw new Error('Invalid or duplicate registry module.');ids.add(id);
    if(!['available','prototype','design'].includes(node.status)||!['public','private','research'].includes(node.access)||!Array.isArray(node.assets)||!node.assets.length||node.assets.some(a=>!ASSETS.includes(a)))throw new Error('Invalid registry availability or asset coverage.');
    return {id,title:bounded(node.title,140,'title'),description:bounded(node.description,2000,'description'),limits:bounded(node.limits,2000,'limits'),status:node.status,access:node.access,assets:[...node.assets]};
  });
  return {version:bounded(raw.registry_version,80,'version'),modules};
}
export async function fetchRegistry({fetcher=fetch,signal}={}){
  const response=await fetcher(REGISTRY_URL,{method:'GET',credentials:'omit',cache:'no-store',redirect:'error',headers:{Accept:'application/json'},signal});
  if(!response.ok||!response.headers.get('content-type')?.includes('application/json'))throw new Error('Graphus registry is unavailable (HTTP '+response.status+').');
  const reader=response.body?.getReader();if(!reader)throw new Error('Registry response cannot be read.');
  let bytes=0;const chunks=[];try{while(true){const {value,done}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>1_000_000)throw new Error('Registry exceeds the 1 MB limit.');chunks.push(value);}}catch(error){await reader.cancel();throw error;}finally{reader.releaseLock();}
  const data=new Uint8Array(bytes);let offset=0;for(const chunk of chunks){data.set(chunk,offset);offset+=chunk.length;}return validateRegistry(JSON.parse(new TextDecoder().decode(data)));
}
