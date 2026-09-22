'use strict';
// Runs only inside the shared target concurrency group. Never infers success
// from a terminal workflow or an expired lease.
const fail=code=>{throw Error(`platform_${code}`);};
function instant(v){const n=typeof v==='string'?Date.parse(v):NaN;if(!Number.isFinite(n))fail('current_state_unknown');return n;}
function assertCurrent(source,deployments){
 if(!source||source.latest_status?.state!=='success'||!Array.isArray(deployments)||!deployments.length||deployments.length>1000)fail('current_state_unknown');
 const created=instant(source.created_at),completed=instant(source.latest_status.created_at);
 if(deployments.filter(d=>String(d.id)===String(source.id)).length!==1)fail('current_state_unknown');
 for(const d of deployments){
  if(d.environment!==source.environment)fail('current_state_unknown');
  if(String(d.id)===String(source.id))continue;
  if(instant(d.created_at)>=created)fail('current_state_changed');
  const envelope=d.task==='deploy'&&d.sha===source.sha&&d.latest_status?.state==='success'&&
    /\/actions\/runs\/\d+\/job\/\d+$/.test(source.latest_status.log_url||'')&&d.latest_status.log_url===source.latest_status.log_url;
  if(!envelope&&d.latest_status?.state!=='inactive'&&(!d.latest_status||instant(d.latest_status.created_at)>=completed))fail('current_state_changed');
 }
 return true;
}
function verifyLock(ref,tag,proof,sourceSHA){
 if(ref?.object?.type!=='tag'||ref.object.sha!==tag?.sha||tag.object?.type!=='commit'||tag.object.sha!==sourceSHA||typeof tag.message!=='string'||tag.message.length>8192)fail('target_lock_owner');
 let owner;try{owner=JSON.parse(tag.message);}catch{fail('target_lock_owner');}
 for(const k of ['repository_id','run_id','run_attempt','plan_digest','instance_id','artifact_digest'])if(owner[k]!==proof[k])fail('target_lock_owner');
 return true;
}
async function current(request,base,token,source){
 const rows=[],started=Date.now();
 const within=()=>{if(Date.now()-started>=30000)fail('current_state_bound');};
 for(let page=1;page<=10;page++){
  within();
  const pageRows=await request(`${base}/deployments?environment=${encodeURIComponent(source.environment)}&per_page=100&page=${page}`,token);
  if(!Array.isArray(pageRows)||pageRows.length>100)fail('current_state_unknown');
  rows.push(...pageRows);if(pageRows.length<100)break;if(page===10)fail('current_state_bound');
 }
 // Bounded targeted status reads; no need to poll every historical deployment.
 for(const d of rows){
  within();
  if(String(d.id)===String(source.id))d.latest_status=source.latest_status;
  else {
   if(instant(d.created_at)>=instant(source.created_at))fail('current_state_changed');
   // A later status on an older deployment may mean a rollback or outside deploy.
   d.latest_status=(await request(`${base}/deployments/${d.id}/statuses?per_page=1`,token))[0];
  }
 }
 return assertCurrent(source,rows);
}
module.exports={assertCurrent,verifyLock,current};
