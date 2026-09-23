'use strict';
// Runs inside the approved reusable workflow. It has no Helio endpoint.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const c=require('./contract.cjs');
const protection=require('./protection.cjs');
const gates=require('./gates.cjs');
const recovery=require('./recovery.cjs');
const records=require('./records.cjs');
const fail=code=>{throw Error(`platform_${code}`);};
const targetJob=(name,id)=>typeof name==='string'&&(name===`helio-target:${id}`||name.endsWith(` / helio-target:${id}`));
async function bootstrap({store,source,roots,identity,request}) {
 const saved=await store.loadPlan();
 if(saved)return c.resumePlan(saved,roots,identity,request);
 if(identity.run_attempt!==1)fail('retained_plan_missing');
 const activation=c.verify(await source.active(),roots,'activation');
 if(activation.schema!=='helio_platform_activation_v1'||activation.repository!==source.repository||!/^[a-f0-9]{40}$/.test(activation.configuration_commit))fail('activation_scope');
 const envelope=await source.configuration(activation.configuration_commit);
 if(envelope.digest!==activation.configuration_digest)fail('activation_digest');
 const plan=c.createPlan(envelope,roots,identity,request,activation.configuration_commit);
 return store.savePlan(plan);
}
async function buildOnce(plan,existing,adapter,context) {
 if(existing){c.verifyBuild(plan,existing);return existing;}
 let artifact;
 if(plan.purpose!=='forward'){
   const {sourcePlan,sourceBuild,sourceRun,sourceEvidence,sourceDeployment,sourceJob,roots}=context;
   if(!sourcePlan||sourcePlan.run_id!==plan.source_run_id||sourcePlan.repository_id!==plan.repository_id||sourcePlan.application_id!==plan.application_id)fail('redeploy_source');
   const evidence=validateSource(sourcePlan,plan,sourceRun,sourceEvidence,roots);
   artifact=c.verifyBuild(sourcePlan,sourceBuild);
   if(!sourceJob||String(sourceJob.id)!==evidence.job_id||String(sourceJob.run_id)!==sourcePlan.run_id||sourceJob.run_attempt!==sourceRun.run_attempt||sourceJob.head_sha!==sourcePlan.head_sha||sourceJob.status!=='completed'||sourceJob.conclusion!=='success'||!targetJob(sourceJob.name,evidence.instance_id))fail('redeploy_source_job');
   const d=sourceDeployment,p=d?.payload,t=sourcePlan.targets.find(t=>t.id===evidence.instance_id);
   if(!d||String(d.id)!==evidence.deployment_id||d.sha!==sourcePlan.head_sha||d.environment!==t.name||d.task!=='helio-platform-release'||d.latest_status?.state!=='success'||d.latest_status?.log_url!==sourceJob.html_url||
     p?.plan_digest!==sourcePlan.plan_digest||String(p?.run_id)!==sourcePlan.run_id||p?.run_attempt!==sourceRun.run_attempt||p?.instance_id!==t.id||p?.binding_id!==t.binding_id||p?.binding_version!==t.binding_version||p?.workflow_revision!==sourcePlan.template.workflow_sha||
     p?.artifact_digest!==artifact.digest||p?.artifact_uri!==artifact.uri||evidence.artifact_digest!==artifact.digest)fail('redeploy_source_artifact');
 }else{
   artifact=await adapter.build({...context,plan});
   if(artifact?.source_sha!==plan.head_sha)fail('build_source');
 }
 const record=c.buildRecord(plan,artifact);
 if(plan.purpose!=='forward'){
   const {sourcePlan,sourceBuild,sourceEvidence}=context;
   const {record_digest,...body}=record;
   body.source={plan:sourcePlan,build:c.buildRecord(sourcePlan,c.verifyBuild(sourcePlan,sourceBuild)),evidence:sourceEvidence[0]};
   return {...body,record_digest:c.digest(body)};
 }
 return record;
}
async function jsonRequest(url,token,{method='GET',body,fetchImpl=fetch}={}) {
 const res=await fetchImpl(url,{method,redirect:'manual',signal:AbortSignal.timeout(10000),headers:{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',...(body?{'Content-Type':'application/json'}:{}),...(token?{Authorization:`Bearer ${token}`}:{})},...(body?{body:JSON.stringify(body)}:{})});
 if(res.status<200||res.status>=300)fail(`provider_http_${res.status}`);
 if(res.status===204)return null;
 const chunks=[];let size=0,count=0;
 for await(const chunk of res.body){size+=chunk.length;if(size>4*1024*1024||++count>4096)fail('provider_response_bound');chunks.push(chunk);}
 return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
function verifyToken(token,jwks,{issuer,audience,now=Date.now()/1000}) {
 const parts=String(token).split('.');if(parts.length!==3)fail('oidc_format');
 const header=JSON.parse(Buffer.from(parts[0],'base64url')),claims=JSON.parse(Buffer.from(parts[1],'base64url'));
 const keys=jwks.keys?.filter(k=>k.kid===header.kid&&k.kty==='RSA');
 if(header.alg!=='RS256'||keys?.length!==1||!crypto.verify('RSA-SHA256',Buffer.from(`${parts[0]}.${parts[1]}`),crypto.createPublicKey({key:keys[0],format:'jwk'}),Buffer.from(parts[2],'base64url')))fail('oidc_signature');
 if(claims.iss!==issuer||claims.aud!==audience||!Number.isFinite(claims.exp)||claims.exp<=now||!Number.isFinite(claims.nbf)||claims.nbf>now+30)fail('oidc_claims');
 return {repository:claims.repository,repository_id:claims.repository_id,run_id:claims.run_id,run_attempt:Number(claims.run_attempt),head_sha:claims.sha,
         job_workflow_ref:claims.job_workflow_ref,job_workflow_sha:claims.job_workflow_sha};
}
async function runtimeIdentity(policy) {
 const audience='helio-platform-plan';const issuer=policy.oidc_issuer||'https://token.actions.githubusercontent.com';
 const tokenURL=new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);tokenURL.searchParams.set('audience',audience);
 const response=await jsonRequest(tokenURL.toString(),process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN);
 const discovery=await jsonRequest(`${issuer}/.well-known/openid-configuration`);
 const jwksURL=new URL(discovery.jwks_uri);
 if(jwksURL.origin!==new URL(issuer).origin)fail('oidc_key_origin');
 const jwks=await jsonRequest(jwksURL.toString());
 return verifyToken(response.value,jwks,{issuer,audience});
}
function readJSON(file,optional=false){if(optional&&!fs.existsSync(file))return null;const text=fs.readFileSync(file,'utf8');if(Buffer.byteLength(text)>4*1024*1024)fail('file_bound');return JSON.parse(text);}
function writeJSON(file,value){fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,c.canonical(value),{flag:'wx',mode:0o600});}
function output(key,value){if(!/^[a-z_]+$/.test(key)||/[\r\n]/.test(value))fail('output');fs.appendFileSync(process.env.GITHUB_OUTPUT,`${key}=${value}\n`);}
async function artifacts(api,token,repository,run){
 const found=[];for(let page=1;page<=10;page++){
  const result=await jsonRequest(`${api}/repos/${repository}/actions/runs/${run}/artifacts?per_page=100&page=${page}`,token);
  found.push(...result.artifacts);if(result.artifacts.length<100)return found;
 }return fail('artifact_listing_bound');
}
function artifactID(rows,name){const matches=rows.filter(a=>a.name===name&&!a.expired);if(matches.length>1)fail('artifact_ambiguous');return matches.length?String(matches[0].id):'';}
function assertUnsent(rows,target){
 // Expired intent is still evidence of a possibly sent operation. No automatic
 // replay is allowed just because the artifact can no longer be downloaded.
 if(rows.some(a=>a.name.startsWith(`helio-platform-intent-${target}-`)))fail('deployment_uncertain');
}
async function verifyProtection(api,token,identity,target,request=jsonRequest){
 const root=`${api}/repos/${identity.repository}/environments/${encodeURIComponent(target.name)}`;
 const environment=await request(root,token);
 const policies=[],variables={};
 for(const [kind,key] of [['deployment-branch-policies','branch_policies'],['variables','variables']]){
  const perPage=key==='variables'?30:100,maxPages=key==='variables'?20:10;
  for(let page=1;page<=maxPages;page++){
   const data=await request(`${root}/${kind}?per_page=${perPage}&page=${page}`,token),rows=data[key];
   if(!Array.isArray(rows))fail('protection_response');
   if(key==='variables')for(const row of rows)variables[row.name]=row.value;
   else policies.push(...rows);
   if(rows.length<perPage)break;if(page===maxPages)fail('protection_page_bound');
  }
 }
 return protection.verify(target,environment,policies,variables);
}
async function verifyApproval(api,token,plan,identity,target,roots,request=jsonRequest){
 if(target.gate_mode!=='helio_governed')return null;
 const reviews=await request(`${api}/repos/${plan.repository}/actions/runs/${plan.run_id}/approvals`,token);
 return gates.verify(plan,identity,target,reviews,roots);
}
async function withTargetLock(lock,operation){
 await lock.acquire();
 const result=await operation();
 if(result?.verified!==true)fail('deployment_unverified');
 // The workflow supplies a no-op release here: its separate unlock step runs
 // only after the success evidence artifact has been retained successfully.
 await lock.release();return result;
}
function validateSource(source,plan,run,evidence,roots){
 if(!run||String(run.id)!==plan.source_run_id||String(run.repository?.id)!==plan.repository_id||run.head_sha!==source.head_sha||run.status!=='completed')fail('redeploy_source');
 const workflow=(run.referenced_workflows||[]).filter(w=>w.path===`${source.template.repository}/${source.template.workflow}@${source.template.workflow_sha}`&&w.sha===source.template.workflow_sha);
 if(workflow.length!==1)fail('redeploy_source_workflow');
 c.resumePlan(source,roots,{repository:run.repository.full_name,repository_id:String(run.repository.id),run_id:String(run.id),run_attempt:run.run_attempt,head_sha:run.head_sha,
   job_workflow_ref:workflow[0].path,job_workflow_sha:workflow[0].sha},{application_id:plan.application_id});
 if(plan.targets.length!==1)fail('redeploy_source_target');
 const target=plan.targets[0],original=source.targets.find(t=>t.id===target.id);
 if(!original||original.name!==target.name||original.target_key!==target.target_key)fail('physical_target_changed');
 const matches=(evidence||[]).filter(e=>e.instance_id===target.id&&e.status==='succeeded'&&e.run_attempt===run.run_attempt&&e.run_id===source.run_id&&e.repository_id===source.repository_id&&e.plan_digest===source.plan_digest);
 if(matches.length!==1||!matches[0].deployment_id||!matches[0].job_id)fail('redeploy_source_evidence');
 return matches[0];
}
function executionEnvelope(plan,identity,run,job){
 if(plan.targets.length!==1||!run||String(run.id)!==plan.run_id||String(run.id)!==String(identity.run_id)||
    run.run_attempt!==identity.run_attempt||run.head_sha!==plan.head_sha||String(run.repository?.id)!==plan.repository_id||run.repository.full_name!==plan.repository||
    !['in_progress','waiting'].includes(run.status)||!Number.isSafeInteger(run.actor?.id)||run.actor.id<=0||
    !job||!Number.isSafeInteger(job.id)||job.id<=0||String(job.run_id)!==plan.run_id||job.run_attempt!==identity.run_attempt||
    job.head_sha!==plan.head_sha||job.status!=='in_progress'||!targetJob(job.name,plan.targets[0].id)||
    job.html_url!==`https://github.com/${plan.repository}/actions/runs/${plan.run_id}/job/${job.id}`)fail('current_job_identity');
 return {sha:plan.head_sha,actor_id:run.actor.id,job_url:job.html_url};
}
async function readExecutionEnvelope(plan,identity,api,token,request=jsonRequest,job=null){
 const base=`${api}/repos/${plan.repository}`,run=await request(`${base}/actions/runs/${plan.run_id}`,token);
 if(!job){
  const jobs=[];
  for(let page=1;page<=2;page++){
   const result=await request(`${base}/actions/runs/${plan.run_id}/attempts/${identity.run_attempt}/jobs?per_page=100&page=${page}`,token);
   if(!Array.isArray(result.jobs)||result.total_count>105||jobs.length+result.jobs.length>105)fail('job_listing_bound');
   jobs.push(...result.jobs);if(result.jobs.length<100)break;if(page===2)fail('job_listing_bound');
  }
  const matches=jobs.filter(j=>targetJob(j.name,plan.targets[0].id)&&j.status==='in_progress');
  if(matches.length!==1)fail('current_job_identity');job=matches[0];
 }
 return executionEnvelope(plan,identity,run,job);
}
// Ignore only a still-queued sibling from this exact signed workflow and target.
// A prior intent means it may already have changed the target and is never exempt.
async function verifyQueuedEnvelope(plan,identity,roots,api,token,deployment,request=jsonRequest){
 const target=plan.targets[0],base=`${api}/repos/${plan.repository}`;
 let logURL=deployment.latest_status?.log_url,linkedCheck=null;
 // A queued concurrency job can have a deployment row but no status yet.
 // CheckRun.deployment supplies the exact link; SHA only bounds the lookup.
 if(deployment.latest_status==null){
  if(!/^[a-f0-9]{40}$/.test(deployment.sha||''))fail('current_state_changed');
  const matches=[];let complete=false;
  for(let page=1;page<=5;page++){
   const listing=await request(`${base}/commits/${deployment.sha}/check-runs?filter=all&per_page=100&page=${page}`,token);
   if(!Number.isSafeInteger(listing.total_count)||listing.total_count<0||listing.total_count>500||!Array.isArray(listing.check_runs)||listing.check_runs.length>100)fail('current_state_bound');
   matches.push(...listing.check_runs.filter(j=>String(j.deployment?.id)===String(deployment.id)));
   if(listing.check_runs.length<100){complete=true;break;}
  }
  if(!complete)fail('current_state_bound');
  if(matches.length!==1)fail('current_state_changed');
  linkedCheck=matches[0];logURL=linkedCheck.details_url;
 }
 const match=/^https:\/\/github\.com\/([^/]+\/[^/]+)\/actions\/runs\/([1-9][0-9]*)\/job\/([1-9][0-9]*)$/.exec(logURL||'');
 if(!recovery.queuedJobEnvelope(deployment)||!match||match[1]!==plan.repository||match[2]===plan.run_id||deployment.environment!==target.name)fail('current_state_changed');
 const run=await request(`${base}/actions/runs/${match[2]}`,token);
 const workflow=`${plan.template.repository}/${plan.template.workflow}@${plan.template.workflow_sha}`;
 if(String(run.id)!==match[2]||String(run.repository?.id)!==plan.repository_id||run.repository?.full_name!==plan.repository||run.head_sha!==deployment.sha||
    !Number.isSafeInteger(run.actor?.id)||run.actor.id<1||run.actor.id!==deployment.creator?.id||!Number.isSafeInteger(run.run_attempt)||run.run_attempt<1||!['pending','queued','waiting','in_progress'].includes(run.status)||
    (run.referenced_workflows||[]).filter(w=>w.path===workflow&&w.sha===plan.template.workflow_sha).length!==1)fail('current_state_changed');
 const checkJob=job=>{
  if(String(job.id)!==match[3]||String(job.run_id)!==match[2]||job.run_attempt!==run.run_attempt||job.head_sha!==run.head_sha||
     !['pending','queued','waiting'].includes(job.status)||job.conclusion!==null||!targetJob(job.name,target.id)||job.html_url!==logURL)fail('current_state_changed');
 };
 const checkLink=check=>{
  if(String(check.id)!==match[3]||String(check.deployment?.id)!==String(deployment.id)||check.deployment?.environment!==target.name||check.deployment?.task!=='deploy'||
     check.head_sha!==run.head_sha||check.details_url!==logURL||!['pending','queued','waiting'].includes(check.status)||check.conclusion!==null)fail('current_state_changed');
 };
 if(linkedCheck)checkLink(linkedCheck);
 checkJob(await request(`${base}/actions/jobs/${match[3]}`,token));
 const scope={repository:plan.repository,repository_id:plan.repository_id,run_id:match[2],head_sha:run.head_sha};
 const retained=await records.read({scope,api,token,name:'helio-platform-plan',request});
 const other=c.resumePlan(retained,roots,{...scope,run_attempt:run.run_attempt,job_workflow_ref:workflow,job_workflow_sha:plan.template.workflow_sha},{application_id:plan.application_id});
 const otherTarget=other.targets.find(t=>t.id===target.id);
 if(c.canonical(other.template)!==c.canonical(plan.template)||otherTarget?.target_key!==target.target_key||otherTarget?.name!==target.name)fail('current_state_changed');
 if((await records.intents({scope,api,token,target:target.id,request})).length)fail('current_state_changed');
 checkJob(await request(`${base}/actions/jobs/${match[3]}`,token));
 const after=await request(`${base}/actions/runs/${match[2]}`,token);
 if(after.run_attempt!==run.run_attempt||after.status==='completed')fail('current_state_changed');
 if(linkedCheck)checkLink(await request(`${base}/check-runs/${match[3]}`,token));
 return true;
}
async function verifySourceNow(plan,record,identity,roots,api,token,request=jsonRequest,currentExecution=null){
 const source=record.source;if(!source?.plan||!source?.build||!source?.evidence)fail('redeploy_source_missing');
 const base=`${api}/repos/${plan.repository}`;
 const sourceRun=await request(`${base}/actions/runs/${plan.source_run_id}`,token);
 const evidence=validateSource(source.plan,plan,sourceRun,[source.evidence],roots);
 if(!/^\d+$/.test(evidence.deployment_id)||!/^\d+$/.test(evidence.job_id))fail('redeploy_source_evidence');
 const sourceDeployment=await request(`${base}/deployments/${evidence.deployment_id}`,token);
 sourceDeployment.latest_status=(await request(`${base}/deployments/${evidence.deployment_id}/statuses?per_page=1`,token))[0];
 const sourceJob=await request(`${base}/actions/jobs/${evidence.job_id}`,token);
 const rebuilt=await buildOnce(plan,null,null,{sourcePlan:source.plan,sourceBuild:source.build,sourceRun,sourceEvidence:[evidence],sourceDeployment,sourceJob,roots});
 if(c.canonical(rebuilt)!==c.canonical(record))fail('redeploy_source_changed');
 await recovery.current(request,base,token,sourceDeployment,currentExecution,
   currentExecution?d=>verifyQueuedEnvelope(plan,identity,roots,api,token,d,request):null);
 // Read again after the evidence reads, so an intervening rerun fails closed.
 const after=await request(`${base}/actions/runs/${plan.source_run_id}`,token);
 if(after.run_attempt!==sourceRun.run_attempt||after.status!=='completed')fail('redeploy_source_changed');
 if(String(identity.repository_id)!==plan.repository_id)fail('redeploy_source');
 return {source,sourceRun,sourceDeployment};
}
async function recoverLock({plan,record,identity,roots,api,token,intent,previous,prepareOnly=false,request=jsonRequest,currentExecution=null}){
 if(plan.purpose!=='recover'||plan.targets.length!==1)fail('recovery_scope');
 const target=plan.targets[0],proof=await verifySourceNow(plan,record,identity,roots,api,token,request,currentExecution);
 const base=`${api}/repos/${plan.repository}`,refPath=`${base}/git/ref/tags/helio/target-lock/${target.target_key}`;
 let ref;
 try{ref=await request(refPath,token);}catch(e){if(e.message!=='platform_provider_http_404')throw e;}
 const retained=prepareOnly?previous:intent;
 if(retained&&!(retained.purpose==='recover'&&retained.plan_digest===plan.plan_digest&&retained.run_id===plan.run_id&&retained.instance_id===target.id&&
     retained.artifact_digest===record.artifact.digest&&Number.isSafeInteger(retained.run_attempt)&&retained.run_attempt>=1&&retained.run_attempt<=identity.run_attempt))fail('recovery_intent_scope');
 const sha=retained?.recovery_lock_sha||ref?.object?.sha;
 if(!/^[a-f0-9]{40}$/.test(sha||'')||(!prepareOnly&&!intent))fail('recovery_intent_missing');
 const tag=await request(`${base}/git/tags/${sha}`,token);
 const original={repository_id:plan.repository_id,run_id:plan.source_run_id,run_attempt:proof.sourceRun.run_attempt,
   plan_digest:proof.source.plan.plan_digest,instance_id:target.id,artifact_digest:record.artifact.digest};
 recovery.verifyLock(ref||{object:{type:'tag',sha}},tag,original,proof.source.plan.head_sha);
 if(prepareOnly)return {recovery_lock_sha:sha};
 if(ref)await request(`${base}/git/refs/tags/helio/target-lock/${target.target_key}`,token,{method:'DELETE'});
 return {schema:'helio_platform_recovery_v1',...intent,source_run_id:plan.source_run_id,source_attempt:proof.sourceRun.run_attempt,
   recovered_lock_sha:sha,source_deployment_id:String(proof.sourceDeployment.id),status:'recovered'};
}
async function restoreRetained({scope,api,token,request=jsonRequest,planID,buildID,attempt,command}){
 const opts={scope,api,token,request};
 const plan=planID?null:await records.read({...opts,name:'helio-platform-plan'});
 if(!planID&&!plan&&(attempt!==1||command!=='probe'))fail('retained_plan_missing');
 const build=command==='probe'?null:(buildID?null:await records.read({...opts,name:'helio-platform-build'}));
 if(command!=='probe'&&!buildID&&!build&&(attempt!==1||command==='probe-deploy'))fail('retained_build_missing');
 return {plan,build};
}
function requestFromEnv(){return {application_id:process.env.HELIO_APPLICATION,purpose:process.env.HELIO_PURPOSE||'forward',
 ...(process.env.HELIO_TARGETS?{targets:JSON.parse(process.env.HELIO_TARGETS)}:{}),...(process.env.HELIO_SOURCE_RUN?{source_run_id:process.env.HELIO_SOURCE_RUN}:{})};}
function emitPlan(plan){
 output('plan_digest',plan.plan_digest);output('purpose',plan.purpose);output('adapter_id',plan.adapter_id);output('source_run_id',plan.source_run_id||'');
 for(const tier of c.TIERS){const targets=c.matrix(plan,tier);output(`${tier}_count`,String(targets.length));
  // GitHub rejects an empty matrix; a disabled sentinel is never deployed.
  output(`${tier}_matrix`,JSON.stringify({include:targets.length?targets:[{id:'empty',name:'empty',runner:{labels:['ubuntu-latest']},target_key:'empty'}]}));}
}
async function cli(){
 const command=process.argv[2],state=process.env.HELIO_STATE_DIR||'.helio-state';
 if(command==='init'){
   const scope=`${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}-${process.env.GITHUB_JOB}`;
   if(!/^[A-Za-z0-9_-]{1,160}$/.test(scope)||!process.env.RUNNER_TEMP||!process.env.GITHUB_ENV)fail('workspace_identity');
   const directory=fs.mkdtempSync(path.join(process.env.RUNNER_TEMP,`helio-${scope}-`));
   if(/[\r\n]/.test(directory))fail('workspace_identity');
   fs.appendFileSync(process.env.GITHUB_ENV,`HELIO_STATE_DIR=${directory}\n`);return;
 }
 const policy=readJSON(path.join(__dirname,'trust.json')),roots=policy.keys;
 const api=process.env.GITHUB_API_URL||'https://api.github.com',token=process.env.GITHUB_TOKEN;
 const identity=await runtimeIdentity(policy),request=requestFromEnv();
 const recordOptions={scope:identity,api,token,request:jsonRequest};
 if(['probe','probe-build','probe-deploy'].includes(command)){
   const rows=await artifacts(api,token,identity.repository,identity.run_id);
   const p=artifactID(rows,'helio-platform-plan'),b=artifactID(rows,'helio-platform-build');
   const restored=await restoreRetained({...recordOptions,planID:p,buildID:b,attempt:identity.run_attempt,command});
   if(restored.plan)writeJSON(path.join(state,'plan.json'),restored.plan);
   if(restored.build)writeJSON(path.join(state,'build.json'),restored.build);
   output('plan_id',p);output('build_id',b);
   if(command==='probe-deploy'){
     let previous='';
     if(request.purpose==='recover'){
       const prefix=`helio-platform-intent-${process.env.HELIO_TARGET_ID}-`;
       const durable=await records.intents({...recordOptions,target:process.env.HELIO_TARGET_ID});
       const prior=[...rows.filter(a=>a.name.startsWith(prefix)),...durable.filter(d=>!rows.some(a=>a.name===d.name))];
       if(prior.some(a=>a.expired||!/^\d+$/.test(a.name.slice(prefix.length))||Number(a.name.slice(prefix.length))>=identity.run_attempt))fail('recovery_intent_scope');
       prior.sort((a,b)=>Number(b.name.slice(prefix.length))-Number(a.name.slice(prefix.length)));
       if(prior.length){if(prior[0].id)previous=String(prior[0].id);
         else {const retained=await records.read({...recordOptions,name:prior[0].name});if(!retained)fail('recovery_intent_missing');writeJSON(path.join(state,'previous','intent.json'),retained);}}
     }
     output('prior_intent_id',previous);
   }
   return;
 }
 if(command==='plan'){
   const repository=policy.configuration_repository,branch=policy.configuration_branch||'main';
   const configToken=process.env.HELIO_CONFIGURATION_TOKEN;
   const content=async(file,ref)=>{const item=await jsonRequest(`${api}/repos/${repository}/contents/${file}?ref=${encodeURIComponent(ref)}`,configToken);
     if(item.encoding!=='base64')fail('configuration_encoding');return JSON.parse(Buffer.from(item.content,'base64').toString('utf8'));};
   const plan=await bootstrap({roots,identity,request,
     store:{loadPlan:async()=>readJSON(path.join(state,'plan.json'),true),savePlan:async p=>{writeJSON(path.join(state,'plan.json'),p);return p;}},
     source:{repository,active:async()=>{const ref=await jsonRequest(`${api}/repos/${repository}/git/ref/heads/${encodeURIComponent(branch)}`,configToken);return content('active.json',ref.object.sha);},
       configuration:async commit=>content('configuration.json',commit)}});
   await records.put({...recordOptions,name:'helio-platform-plan',record:plan});
   emitPlan(plan);return;
 }
 const plan=c.resumePlan(readJSON(path.join(state,'plan.json')),roots,identity,request);
 if(command==='source-probe'){
   if(plan.purpose==='forward'||plan.targets.length!==1)fail('redeploy_source');
   const sourceRun=await jsonRequest(`${api}/repos/${identity.repository}/actions/runs/${plan.source_run_id}`,token);
   const rows=await artifacts(api,token,identity.repository,plan.source_run_id);
   for(const [key,name] of [['plan_id','helio-platform-plan'],['build_id','helio-platform-build'],['evidence_id',`helio-platform-evidence-${plan.targets[0].id}-${sourceRun.run_attempt}`]]){
     const id=artifactID(rows,name);
     if(!id){const saved=await records.read({...recordOptions,scope:{...identity,run_id:plan.source_run_id,head_sha:sourceRun.head_sha},name});
       if(!saved)fail('redeploy_source_missing');writeJSON(path.join(state,'source',key==='plan_id'?'plan.json':key==='build_id'?'build.json':'evidence.json'),saved);}
     output(key,id);
   }
   output('run_id',plan.source_run_id);return;
 }
 if(command==='build'){
   const adapterPath=path.join(__dirname,'adapters',`${plan.adapter_id}.cjs`);
   const existing=readJSON(path.join(state,'build.json'),true);
   if(!existing&&identity.run_attempt!==1)fail('retained_build_missing');
   const sourceRun=plan.purpose!=='forward'?await jsonRequest(`${api}/repos/${identity.repository}/actions/runs/${plan.source_run_id}`,token):null;
   const sourceEvidence=[readJSON(path.join(state,'source','evidence.json'),true)].filter(Boolean);
   let sourceDeployment,sourceJob;
   if(sourceRun){
     const e=sourceEvidence[0];if(!e||!/^\d+$/.test(e.deployment_id)||!/^\d+$/.test(e.job_id))fail('redeploy_source_evidence');
     sourceDeployment=await jsonRequest(`${api}/repos/${identity.repository}/deployments/${e.deployment_id}`,token);
     sourceDeployment.latest_status=(await jsonRequest(`${api}/repos/${identity.repository}/deployments/${e.deployment_id}/statuses?per_page=1`,token))[0];
     sourceJob=await jsonRequest(`${api}/repos/${identity.repository}/actions/jobs/${e.job_id}`,token);
   }
   const record=await buildOnce(plan,existing,plan.purpose==='forward'?require(adapterPath):null,{roots,sourceRun,sourceEvidence,sourceDeployment,sourceJob,sourceDirectory:path.resolve(process.env.HELIO_SOURCE_DIR||'.'),
     sourcePlan:readJSON(path.join(state,'source','plan.json'),true),sourceBuild:readJSON(path.join(state,'source','build.json'),true)});
   if(!existing)writeJSON(path.join(state,'build.json'),record);
   await records.put({...recordOptions,name:'helio-platform-build',record});
   output('artifact_digest',record.artifact.digest);return;
 }
 if(command==='prepare'){
   const target=plan.targets.find(t=>t.id===process.env.HELIO_TARGET_ID);if(!target)fail('target_identity');
   await verifyApproval(api,token,plan,identity,target,roots);
   await verifyProtection(api,process.env.HELIO_PROTECTION_TOKEN,identity,target);
   // This check runs under the repository environment concurrency group.
   if(plan.purpose!=='recover')assertUnsent([...(await artifacts(api,token,identity.repository,identity.run_id)),...(await records.intents({...recordOptions,target:target.id}))],target.id);
   const record=readJSON(path.join(state,'build.json')),artifact=c.verifyBuild(plan,record);
   const extra=plan.purpose==='recover'?await recoverLock({plan,record,identity,roots,api,token,prepareOnly:true,previous:readJSON(path.join(state,'previous','intent.json'),true),
     currentExecution:await readExecutionEnvelope(plan,identity,api,token)}):{};
   const intent={purpose:plan.purpose,plan_digest:plan.plan_digest,run_id:plan.run_id,run_attempt:identity.run_attempt,instance_id:target.id,artifact_digest:artifact.digest,...extra};
   await records.put({...recordOptions,name:`helio-platform-intent-${target.id}-${identity.run_attempt}`,record:intent});
   writeJSON(path.join(state,'intent.json'),intent);
   return;
 }
 if(command==='unlock'){
   if(plan.purpose==='recover')return;
   const target=plan.targets.find(t=>t.id===process.env.HELIO_TARGET_ID);if(!target)fail('target_identity');
   const evidence=readJSON(path.join(state,'evidence',target.id,'evidence.json')),lock=readJSON(path.join(state,'lock.json'));
   if(evidence.status!=='succeeded'||evidence.plan_digest!==plan.plan_digest||evidence.run_attempt!==identity.run_attempt)fail('unlock_evidence');
   const rows=await artifacts(api,token,identity.repository,identity.run_id);
   if(!artifactID(rows,`helio-platform-evidence-${target.id}-${identity.run_attempt}`))fail('evidence_not_retained');
   const ref=await jsonRequest(`${api}/repos/${identity.repository}/git/ref/tags/helio/target-lock/${target.target_key}`,token);
   if(ref.object.sha!==lock.sha)fail('target_lock_owner');
   await jsonRequest(`${api}/repos/${identity.repository}/git/refs/tags/helio/target-lock/${target.target_key}`,token,{method:'DELETE'});return;
 }
 if(command==='deploy'){
   const target=plan.targets.find(t=>t.id===process.env.HELIO_TARGET_ID);if(!target)fail('target_identity');
   await verifyApproval(api,token,plan,identity,target,roots);
   await verifyProtection(api,process.env.HELIO_PROTECTION_TOKEN,identity,target);
   const record=readJSON(path.join(state,'build.json')),artifact=c.verifyBuild(plan,record);
   const intent=readJSON(path.join(state,'intent.json'));
   if(intent.plan_digest!==plan.plan_digest||intent.run_attempt!==identity.run_attempt||intent.instance_id!==target.id||intent.artifact_digest!==artifact.digest)fail('intent_scope');
   const rows=await artifacts(api,token,identity.repository,identity.run_id);
   if(!artifactID(rows,`helio-platform-intent-${target.id}-${identity.run_attempt}`))fail('intent_not_retained');
   const durableIntent=await records.read({...recordOptions,name:`helio-platform-intent-${target.id}-${identity.run_attempt}`});
   if(c.canonical(durableIntent)!==c.canonical(intent))fail('intent_not_retained');
   if(plan.purpose!=='recover')assertUnsent([...rows,...(await records.intents({...recordOptions,target:target.id}))].filter(a=>a.name!==`helio-platform-intent-${target.id}-${identity.run_attempt}`),target.id);
   if(plan.purpose==='recover'){
     const receipt=await recoverLock({plan,record,identity,roots,api,token,intent,currentExecution:await readExecutionEnvelope(plan,identity,api,token)});
     writeJSON(path.join(state,'evidence',target.id,'evidence.json'),receipt);
     await records.put({...recordOptions,name:`helio-platform-evidence-${target.id}-${identity.run_attempt}`,record:receipt});
     return {verified:true};
   }
   const jobs=[];for(let page=1;page<=10;page++){
     const result=await jsonRequest(`${api}/repos/${identity.repository}/actions/runs/${identity.run_id}/attempts/${identity.run_attempt}/jobs?per_page=100&page=${page}`,token);
     jobs.push(...result.jobs);if(result.jobs.length<100)break;if(page===10)fail('job_listing_bound');
   }
   const matches=jobs.filter(j=>targetJob(j.name,target.id)&&String(j.run_id)===plan.run_id&&j.run_attempt===identity.run_attempt&&j.status==='in_progress');
   if(matches.length!==1)fail('job_identity');const job=matches[0];
   // GitHub already holds this target's concurrency group. Reject stale source
   // evidence before acquiring a durable reservation or making a deploy POST.
   if(plan.purpose==='redeploy')await verifySourceNow(plan,record,identity,roots,api,token,jsonRequest,
     await readExecutionEnvelope(plan,identity,api,token,jsonRequest,job));
   const idempotencyKey=`${identity.repository_id}/${plan.run_id}/${identity.run_attempt}/${target.id}`;
   const adapter=require(path.join(__dirname,'adapters',`${plan.adapter_id}.cjs`));
   const lock={acquire:async()=>{
     const tag=await jsonRequest(`${api}/repos/${identity.repository}/git/tags`,token,{method:'POST',body:{tag:`helio-target-${target.target_key}`,message:c.canonical({...intent,repository_id:identity.repository_id}),object:plan.head_sha,type:'commit'}});
     // GitHub create-ref is atomic. Existing/uncertain ownership never falls
     // through to the adapter. A dead JVM cannot drop this durable reservation.
     await jsonRequest(`${api}/repos/${identity.repository}/git/refs`,token,{method:'POST',body:{ref:`refs/tags/helio/target-lock/${target.target_key}`,sha:tag.sha}});
     writeJSON(path.join(state,'lock.json'),{sha:tag.sha});
   },release:async()=>{}};
   return withTargetLock(lock,async()=>{
   const deployment=await jsonRequest(`${api}/repos/${identity.repository}/deployments`,token,{method:'POST',body:{ref:plan.head_sha,auto_merge:false,required_contexts:[],environment:target.name,task:'helio-platform-release',
     payload:{plan_digest:plan.plan_digest,application_id:plan.application_id,run_id:plan.run_id,run_attempt:identity.run_attempt,instance_id:target.id,binding_id:target.binding_id,binding_version:target.binding_version,
              artifact_uri:artifact.uri,artifact_digest:artifact.digest,workflow_revision:plan.template.workflow_sha,idempotency_key:idempotencyKey}}});
   if(!deployment?.id)fail('deployment_intent_uncertain');
   const base={schema:'helio_platform_evidence_v1',repository_id:identity.repository_id,run_id:plan.run_id,run_attempt:identity.run_attempt,job_id:String(job.id),deployment_id:String(deployment.id),
     instance_id:target.id,binding_id:target.binding_id,binding_version:target.binding_version,plan_digest:plan.plan_digest,artifact_digest:artifact.digest};
   let outcome='unknown';
   try{const result=await adapter.deploy({plan,target,artifact,idempotencyKey,sourceDirectory:path.resolve(process.env.HELIO_SOURCE_DIR||'.')});
     if(result?.artifact_digest!==artifact.digest||result?.verified!==true)fail('deployment_verification');outcome='succeeded';
   }finally{
     const status=await jsonRequest(`${api}/repos/${identity.repository}/deployments/${deployment.id}/statuses`,token,{method:'POST',body:{state:outcome==='succeeded'?'success':'error',log_url:job.html_url,environment:target.name,auto_inactive:false}});
     const evidence={...base,status:outcome,provider_status:status.state,provider_event_at:status.created_at};
     writeJSON(path.join(state,'evidence',target.id,'evidence.json'),evidence);
     await records.put({...recordOptions,name:`helio-platform-evidence-${target.id}-${identity.run_attempt}`,record:evidence});
   }
   return {verified:true};
   });
 }
 fail('command');
}
if(require.main===module)cli().catch(error=>{const code=/^platform_[a-zA-Z0-9_]+$/.test(error.message)?error.message:'platform_runtime_failed';process.stderr.write(`${code}\n`);process.exitCode=1;});
module.exports={bootstrap,buildOnce,verifyToken,jsonRequest,artifactID,assertUnsent,verifyProtection,verifyApproval,withTargetLock,validateSource,verifySourceNow,verifyQueuedEnvelope,recoverLock,executionEnvelope,restoreRetained,cli};
