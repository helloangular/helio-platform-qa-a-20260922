'use strict';
// Provider-owned records survive artifact deletion/full reruns. Refs are created
// atomically, never force-updated. Existing signed-plan/attempt validation remains
// mandatory after a read; a body digest alone is not deployment authorization.
const c=require('./contract.cjs');
const fail=code=>{throw Error('platform_'+code);};
const nameOK=n=>typeof n==='string'&&/^helio-platform-(?:plan|build|(?:intent|evidence)-[A-Za-z0-9][A-Za-z0-9_.-]{0,99}-[1-9][0-9]{0,9})$/.test(n)&&!n.includes('..');
function base(scope,api){
 if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(scope?.repository)||!/^[1-9][0-9]{0,19}$/.test(scope?.run_id)||!/^[1-9][0-9]{0,19}$/.test(scope?.repository_id)||!/^[a-f0-9]{40}$/.test(scope?.head_sha))fail('record_scope');
 return `${api}/repos/${scope.repository}`;
}
async function read({scope,api,token,name,request}){
 const root=base(scope,api);if(!nameOK(name))fail('record_scope');let ref;
 try{ref=await request(`${root}/git/ref/tags/helio/run-records/${scope.run_id}/${name}`,token);}catch(e){if(e.message==='platform_provider_http_404')return null;throw e;}
 if(ref?.object?.type!=='tag'||!/^[a-f0-9]{40}$/.test(ref.object.sha||''))fail('record_scope');
 const tag=await request(`${root}/git/tags/${ref.object.sha}`,token);
 if(tag?.sha!==ref.object.sha||tag.object?.type!=='commit'||tag.object.sha!==scope.head_sha||typeof tag.message!=='string'||Buffer.byteLength(tag.message)>1048576)fail('record_scope');
 let body;try{body=JSON.parse(tag.message);}catch{fail('record_json');}
 if(body.schema!=='helio_platform_record_v1'||body.repository!==scope.repository||body.repository_id!==scope.repository_id||body.run_id!==scope.run_id||body.name!==name||body.source_sha!==scope.head_sha||!body.record||body.record_digest!==c.digest(body.record))fail('record_scope');
 return body.record;
}
async function put(opts){
 const {scope,api,token,name,record,request}=opts,root=base(scope,api);if(!nameOK(name)||!record)fail('record_scope');
 const body={schema:'helio_platform_record_v1',repository:scope.repository,repository_id:scope.repository_id,run_id:scope.run_id,name,source_sha:scope.head_sha,record_digest:c.digest(record),record};
 const message=c.canonical(body);if(Buffer.byteLength(message)>1048576)fail('record_size');
 const old=await read(opts);if(old){if(c.canonical(old)!==c.canonical(record))fail('record_conflict');return old;}
 const tag=await request(`${root}/git/tags`,token,{method:'POST',body:{tag:`helio-record-${scope.run_id}-${name}`,message,object:scope.head_sha,type:'commit'}});
 if(!/^[a-f0-9]{40}$/.test(tag?.sha||''))fail('record_scope');
 try{await request(`${root}/git/refs`,token,{method:'POST',body:{ref:`refs/tags/helio/run-records/${scope.run_id}/${name}`,sha:tag.sha}});}
 catch(e){if(!['platform_provider_http_422','platform_provider_http_409'].includes(e.message))throw e;
  const concurrent=await read(opts);if(!concurrent||c.canonical(concurrent)!==c.canonical(record))fail('record_conflict');}
 return record;
}
async function intents({scope,api,token,target,request}){
 const root=base(scope,api),prefix=`refs/tags/helio/run-records/${scope.run_id}/helio-platform-intent-${target}-`;
 if(!nameOK(`helio-platform-intent-${target}-1`))fail('record_scope');
 const rows=await request(`${root}/git/matching-refs/tags/helio/run-records/${scope.run_id}/helio-platform-intent-${target}-`,token);
 if(!Array.isArray(rows)||rows.length>1000)fail('record_bound');
 return rows.map(row=>{if(typeof row.ref!=='string'||!row.ref.startsWith(prefix)||!/^[1-9][0-9]{0,9}$/.test(row.ref.slice(prefix.length)))fail('record_scope');return {name:row.ref.slice(`refs/tags/helio/run-records/${scope.run_id}/`.length),attempt:Number(row.ref.slice(prefix.length))};});
}
module.exports={read,put,intents};
