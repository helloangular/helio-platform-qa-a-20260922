'use strict';
// Qualification fixture: the deployed target is a dedicated branch containing
// the exact artifact bytes. No customer endpoint, shell or arbitrary repo input.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const repos=['helloangular/helio-platform-qa-a-20260922','helloangular/helio-platform-qa-b-20260922'];
const digest=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
function scope(plan){if(!repos.includes(plan?.repository)||!(/^[a-f0-9]{40}$/).test(plan.head_sha))throw Error('sandbox_scope');}
async function api(repo,resource,{method='GET',body}={}){
 const r=await fetch(`https://api.github.com/repos/${repo}${resource}`,{method,redirect:'error',signal:AbortSignal.timeout(10000),headers:{Authorization:'Bearer '+process.env.GITHUB_TOKEN,Accept:'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28'},...(body?{body:JSON.stringify(body)}:{})});
 if(r.status===404&&method==='GET')return null;
 if(r.status<200||r.status>=300)throw Error('sandbox_http_'+r.status);
 return r.json();
}
async function build({plan,sourceDirectory}){
 scope(plan);const bytes=fs.readFileSync(path.join(sourceDirectory,'qa-artifact.txt'));if(bytes.length>4096)throw Error('sandbox_artifact_bound');
 return {uri:`helio-qa://${plan.repository}/${plan.head_sha}@${digest(bytes)}`,digest:digest(bytes),source_sha:plan.head_sha};
}
async function deploy({plan,target,artifact,idempotencyKey}){
 scope(plan);if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(target?.id))throw Error('sandbox_target');
 if(!/^[a-f0-9]{40}$/.test(artifact?.source_sha)||!/^sha256:[a-f0-9]{64}$/.test(artifact.digest)||artifact.uri!==`helio-qa://${plan.repository}/${artifact.source_sha}@${artifact.digest}`)throw Error('sandbox_artifact_scope');
 const r=await fetch(`https://raw.githubusercontent.com/${plan.repository}/${artifact.source_sha}/qa-artifact.txt`,{redirect:'error',signal:AbortSignal.timeout(10000)});
 if(r.status!==200)throw Error('sandbox_source_unavailable');const bytes=Buffer.from(await r.arrayBuffer());
 if(bytes.length>4096||digest(bytes)!==artifact.digest)throw Error('sandbox_artifact_digest');
 const branch='helio-sandbox-target/'+target.id;
 if(!await api(plan.repository,'/git/ref/heads/'+branch))await api(plan.repository,'/git/refs',{method:'POST',body:{ref:'refs/heads/'+branch,sha:plan.head_sha}});
 const endpoint='/contents/deployed-artifact.txt',query='?ref='+encodeURIComponent(branch);
 const before=await api(plan.repository,endpoint+query),content=bytes.toString('base64');
 if(!before||Buffer.from(before.content,'base64').compare(bytes)!==0)await api(plan.repository,endpoint,{method:'PUT',body:{message:'Sandbox deployment '+idempotencyKey,branch,content,...(before?{sha:before.sha}:{})}});
 const after=await api(plan.repository,endpoint+query);
 if(!after||digest(Buffer.from(after.content,'base64'))!==artifact.digest)throw Error('sandbox_readback_failed');
 return {verified:true,artifact_digest:artifact.digest};
}
module.exports={build,deploy};
