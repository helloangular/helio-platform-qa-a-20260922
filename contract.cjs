'use strict';
// Versioned, deliberately constrained platform contract. No expression evaluation.
const crypto = require('node:crypto');
const TIERS = Object.freeze(['qa','preprod','production']);
const fail = code => { throw new Error(`platform_${code}`); };
const clone = value => JSON.parse(JSON.stringify(value));
function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return fail('non_canonical_value');
}
const digest = value => crypto.createHash('sha256').update(canonical(value)).digest('hex');
const id = v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(v);
const sha = v => typeof v === 'string' && /^[a-f0-9]{40}$/.test(v);
const hash = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const repo = v => typeof v === 'string' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(v);
const positive = v => Number.isSafeInteger(v) && v>0 && v<=2147483647;
function bounded(xs, max, code, min=1) {if (!Array.isArray(xs)||xs.length<min||xs.length>max) fail(`${code}_bound`); return xs;}
function unique(xs, key, code) {if(new Set(xs.map(key)).size!==xs.length) fail(`${code}_duplicate`);}
function only(object, keys, code) {if(!object||typeof object!=='object'||Array.isArray(object)||Object.keys(object).some(k=>!keys.includes(k))) fail(`${code}_field`);}
function sign(body,key_id,privateKey,kind) {
  const message={kind,key_id,body};
  return {...message,algorithm:'Ed25519',digest:digest(body),signature:crypto.sign(null,Buffer.from(canonical(message)),privateKey).toString('base64')};
}
function verify(envelope,roots,kind) {
  if(!envelope||envelope.algorithm!=='Ed25519'||envelope.kind!==kind) fail('signature_kind');
  const key=roots?.[envelope.key_id]; if(!key) fail('trust_root_unknown');
  if(envelope.digest!==digest(envelope.body)) fail('digest_mismatch');
  if(!crypto.verify(null,Buffer.from(canonical({kind:envelope.kind,key_id:envelope.key_id,body:envelope.body})),key,Buffer.from(envelope.signature||'','base64'))) fail('signature_invalid');
  return clone(envelope.body);
}
function validateConfiguration(c) {
  only(c,['schema','tenant_id','version','templates','profiles','subscriptions','expires_at'],'configuration');
  if(c.schema!=='helio_platform_v1'||!id(c.tenant_id)||!positive(c.version)) fail('schema_invalid');
  bounded(c.templates,20,'templates'); bounded(c.profiles,100,'profiles'); bounded(c.subscriptions,500,'subscriptions');
  unique(c.templates,t=>t.id,'template'); unique(c.profiles,p=>`${p.id}/${p.version}`,'profile');
  unique(c.subscriptions,s=>s.repository_id,'subscription_repository'); unique(c.subscriptions,s=>s.application_id,'subscription_application');
  for(const t of c.templates) {
    only(t,['id','repository','workflow','workflow_sha','runtime_sha','adapter_ids','gate_proof_format'],'template');
    if(!id(t.id)||!repo(t.repository)||!/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(t.workflow)||!sha(t.workflow_sha)||!sha(t.runtime_sha)) fail('template_invalid');
    if(t.gate_proof_format!==undefined&&!['v1','compact_v2'].includes(t.gate_proof_format))fail('template_invalid');
    bounded(t.adapter_ids,50,'adapters'); if(!t.adapter_ids.every(id)) fail('adapter_invalid');
  }
  for(const p of c.profiles) {
    only(p,['id','version','targets'],'profile'); if(!id(p.id)||!positive(p.version)) fail('profile_invalid');
    bounded(p.targets,100,'targets'); unique(p.targets,t=>t.id,'target'); unique(p.targets,t=>t.name.toLowerCase(),'environment');
    for(const t of p.targets) {
      only(t,['id','name','tier','binding_id','binding_version','target_key','runner','gate_mode','policy_hash'],'target');
      if(!id(t.id)||!id(t.name)||!TIERS.includes(t.tier)||!id(t.target_key)||!id(t.binding_id)||!positive(t.binding_version)||!hash(t.policy_hash)) fail('target_invalid');
      if(!['none','native','helio_governed'].includes(t.gate_mode)) fail('gate_mode_invalid');
      only(t.runner,['labels','group'],'runner'); bounded(t.runner.labels,20,'runner_labels');
      if(!t.runner.labels.every(id)||(t.runner.group!==undefined&&!id(t.runner.group))) fail('runner_invalid');
    }
  }
  const physical = new Map();
  for(const s of c.subscriptions) {
    only(s,['application_id','repository','repository_id','template_id','profile_id','profile_version','adapter_id','enabled','bindings'],'subscription');
    if(!id(s.application_id)||!repo(s.repository)||!/^\d+$/.test(s.repository_id)||typeof s.enabled!=='boolean') fail('subscription_invalid');
    const t=c.templates.find(t=>t.id===s.template_id),p=c.profiles.find(p=>p.id===s.profile_id&&p.version===s.profile_version);
    if(!t||!p||!t.adapter_ids.includes(s.adapter_id)) fail('subscription_compatibility');
    bounded(s.bindings,100,'bindings'); unique(s.bindings,b=>b.instance_id,'binding');
    for(const b of s.bindings) {
      only(b,['instance_id','binding_id','binding_version','policy_hash','target_key','protection','governance'],'binding');
      if(b.protection!==undefined)require('./protection.cjs').validate(b.protection);
      if(!id(b.instance_id)||!id(b.binding_id)||!positive(b.binding_version)||!hash(b.policy_hash)||(b.target_key!==undefined&&!id(b.target_key))) fail('binding_invalid');
    }
    for(const target of p.targets) {
      const b=s.bindings.find(b=>b.instance_id===target.id);
      if(!b||b.policy_hash!==target.policy_hash) fail('subscription_readiness');
      require('./gates.cjs').validate({...target,...(b.protection?{protection:b.protection}:{}),...(b.governance?{governance:b.governance}:{})});
      const key=(b.target_key||target.target_key).toLowerCase();
      if(physical.has(key)&&physical.get(key)!==s.repository.toLowerCase()) fail('cross_repository_target_unsupported');
      physical.set(key,s.repository.toLowerCase());
    }
  }
  if(c.expires_at!==undefined&&(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:[0-5]\d(?:\.\d{1,9})?Z$/.test(c.expires_at)||!Number.isFinite(Date.parse(c.expires_at))||new Date(c.expires_at).toISOString().slice(0,19)!==c.expires_at.slice(0,19))) fail('configuration_expiry_invalid');
  if(Buffer.byteLength(canonical(c))>750000)fail('configuration_size_bound');
  return clone(c);
}
function subscription(c,identity,request) {
  const s=c.subscriptions.find(s=>s.enabled&&s.application_id===request.application_id&&s.repository_id===String(identity.repository_id)&&s.repository.toLowerCase()===identity.repository.toLowerCase());
  if(!s) fail('subscription_identity');
  const t=c.templates.find(t=>t.id===s.template_id);
  if(identity.job_workflow_sha!==t.workflow_sha||identity.job_workflow_ref!==`${t.repository}/${t.workflow}@${t.workflow_sha}`) fail('template_identity');
  if(!/^\d+$/.test(String(identity.run_id))||!positive(identity.run_attempt)||!sha(identity.head_sha)) fail('run_identity');
  return [s,t];
}
function planBody(envelope,roots,identity,request,configuration_commit,retained=false) {
  const c=validateConfiguration(verify(envelope,roots,'configuration'));
  if(!retained&&c.expires_at&&Date.now()>=Date.parse(c.expires_at)) fail('configuration_expired');
  if(!sha(configuration_commit)) fail('configuration_commit');
  const [s,t]=subscription(c,identity,request),profile=c.profiles.find(p=>p.id===s.profile_id&&p.version===s.profile_version);
  const purpose=request.purpose||'forward'; if(!['forward','redeploy','recover'].includes(purpose)) fail('purpose');
  const selected=request.targets===undefined?profile.targets.map(t=>t.id):request.targets;
  bounded(selected,100,'selection'); unique(selected,x=>x,'selection');
  if(selected.some(x=>!profile.targets.some(t=>t.id===x))) fail('selection_unknown');
  if(purpose!=='forward'&&(selected.length!==1||!/^\d+$/.test(String(request.source_run_id)))) fail('redeploy_selection');
  const targets=profile.targets.filter(t=>selected.includes(t.id)).map(target=>{
    const b=s.bindings.find(b=>b.instance_id===target.id);
    return {...target,binding_id:b.binding_id,binding_version:b.binding_version,target_key:b.target_key||target.target_key,
      ...(b.protection?{protection:clone(b.protection)}:{}),...(b.governance?{governance:clone(b.governance)}:{})};
  }).sort((a,b)=>TIERS.indexOf(a.tier)-TIERS.indexOf(b.tier)||(a.id<b.id?-1:a.id>b.id?1:0));
  targets.forEach(t=>require('./gates.cjs').validate(t));
  if(purpose==='forward') {
    const tier=Math.max(...targets.map(t=>TIERS.indexOf(t.tier)));
    if(profile.targets.some(t=>TIERS.indexOf(t.tier)<tier&&!selected.includes(t.id))) fail('selection_predecessor');
  }
  const result={schema:'helio_platform_plan_v1',repository:s.repository,repository_id:s.repository_id,application_id:s.application_id,run_id:String(identity.run_id),head_sha:identity.head_sha,
    template:t,profile:{id:profile.id,version:profile.version},adapter_id:s.adapter_id,purpose,targets,config_digest:envelope.digest,configuration_commit,configuration:clone(envelope)};
  if(purpose!=='forward') result.source_run_id=String(request.source_run_id);
  return {...result,plan_digest:digest(result)};
}
function resumePlan(plan,roots,identity,request) {
  if(!plan) fail('retained_plan_missing');
  const {plan_digest,...body}=plan;
  if(plan.schema!=='helio_platform_plan_v1'||plan_digest!==digest(body)) fail('retained_plan_digest');
  const c=validateConfiguration(verify(plan.configuration,roots,'configuration'));
  // A signed config's execution expiry governs new admissions, not a retained run.
  subscription(c,identity,request);
  if(plan.run_id!==String(identity.run_id)||plan.head_sha!==identity.head_sha||plan.repository_id!==String(identity.repository_id)) fail('retained_plan_identity');
  const expectedTargets=plan.targets.map(t=>t.id);
  const rebuilt=planBody(plan.configuration,roots,identity,{application_id:plan.application_id,targets:expectedTargets,purpose:plan.purpose,source_run_id:plan.source_run_id},plan.configuration_commit,true);
  if(digest(rebuilt)!==digest(plan)) fail('retained_plan_scope');
  return clone(plan);
}
function createPlan(envelope,roots,identity,request,commit) {
  return planBody(envelope,roots,identity,request,commit,false);
}
function buildRecord(plan,artifact) {
  if(!artifact||!/^sha256:[a-f0-9]{64}$/.test(artifact.digest)||typeof artifact.uri!=='string'||artifact.uri.length>2048||/[?#\s]/.test(artifact.uri)||/:\/\/[^/]*@/.test(artifact.uri)||!artifact.uri.endsWith(`@${artifact.digest}`)||!sha(artifact.source_sha)) fail('build_artifact');
  only(artifact,['uri','digest','source_sha'],'artifact');
  const result={schema:'helio_platform_build_v1',repository_id:plan.repository_id,run_id:plan.run_id,plan_digest:plan.plan_digest,artifact:clone(artifact)};
  return {...result,record_digest:digest(result)};
}
function verifyBuild(plan,record) {
  if(!record) fail('build_record_missing');
  const {record_digest,...body}=record;
  if(record.schema!=='helio_platform_build_v1'||record_digest!==digest(body)||record.plan_digest!==plan.plan_digest||record.repository_id!==plan.repository_id||record.run_id!==plan.run_id) fail('build_identity');
  buildRecord(plan,record.artifact); return clone(record.artifact);
}
function matrix(plan,tier) {if(!TIERS.includes(tier)) fail('tier'); return plan.targets.filter(t=>t.tier===tier).map(clone);}
function observe(plan,identity,rows) {
  bounded(rows,100,'observations',0); unique(rows,r=>r.instance_id,'observation');
  if(String(identity.run_id)!==plan.run_id||String(identity.repository_id)!==plan.repository_id) fail('observation_identity');
  for(const r of rows) if(!plan.targets.some(t=>t.id===r.instance_id)||String(r.run_id)!==plan.run_id||r.run_attempt!==identity.run_attempt||!id(String(r.job_id))) fail('observation_identity');
  const targets=plan.targets.map(t=>{
    const r=rows.find(r=>r.instance_id===t.id);
    const status=r?.status||'unobserved'; if(!['succeeded','failed','skipped','cancelled','running','unobserved'].includes(status)) fail('observation_status');
    const deployed=status==='succeeded'&&/^sha256:[a-f0-9]{64}$/.test(identity.artifact_digest||'')&&!!r.deployment_id&&r.binding_id===t.binding_id&&r.binding_version===t.binding_version&&r.artifact_digest===identity.artifact_digest;
    return {instance_id:t.id,status,deployed,...(r?{job_id:r.job_id,deployment_id:r.deployment_id||null}:{})};
  });
  return {result:targets.some(t=>['failed','cancelled'].includes(t.status))?'failed':targets.every(t=>t.deployed)?'succeeded':'unverified',targets};
}
module.exports={TIERS,canonical,digest,sign,verify,validateConfiguration,createPlan,resumePlan,buildRecord,verifyBuild,matrix,observe};
