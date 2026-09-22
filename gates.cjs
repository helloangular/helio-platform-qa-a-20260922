'use strict';
// Purpose-separated approval proof, verified without contacting Helio.
const fail=code=>{throw Error(`platform_${code}`);};
function validate(target){
 const g=target.governance,p=target.protection;
 if(target.gate_mode!=='helio_governed'){if(g!==undefined)fail('unexpected_governance');return target;}
 const keys=['reviewer_instance_id','reviewer_account_id','required_signatures','eligible_principals','separation_of_duties','expires_after_seconds'];
 if(!g||Object.keys(g).length!==keys.length||Object.keys(g).some(k=>!keys.includes(k))||
 !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(g.reviewer_instance_id)||
 !Number.isSafeInteger(g.reviewer_account_id)||g.reviewer_account_id<1||!Number.isInteger(g.required_signatures)||g.required_signatures<1||g.required_signatures>4||
 typeof g.separation_of_duties!=='boolean'||!Number.isInteger(g.expires_after_seconds)||g.expires_after_seconds<60||g.expires_after_seconds>2592000||
 !Array.isArray(g.eligible_principals)||!g.eligible_principals.length||g.eligible_principals.length>100||new Set(g.eligible_principals).size!==g.eligible_principals.length||
 !g.eligible_principals.every(v=>typeof v==='string'&&/^(?:user:[a-fA-F0-9-]{36}|role:[a-z][a-z0-9-]{0,63})$/.test(v))||
 !p||p.name!==target.name||p.can_admins_bypass!==false||p.prevent_self_review!==true||p.reviewers?.length!==1||p.reviewers[0].type!=='User'||p.reviewers[0].id!==g.reviewer_account_id)fail('governed_hold_unavailable');
 return target;
}
function scope(plan,identity,target){
 if(String(identity.run_id)!==plan.run_id||String(identity.repository_id)!==plan.repository_id||!Number.isSafeInteger(identity.run_attempt)||identity.run_attempt<1)fail('gate_scope');
 return {schema:'helio_platform_gate_v1',tenant_id:plan.configuration.body.tenant_id,repository_id:plan.repository_id,run_id:plan.run_id,run_attempt:identity.run_attempt,
 instance_id:target.id,binding_id:target.binding_id,binding_version:target.binding_version,environment_id:target.protection.environment_id,policy_hash:target.policy_hash,plan_digest:plan.plan_digest};
}
const prefix='helio-platform-gate:v1:';
function encode(envelope){return prefix+Buffer.from(require('./contract.cjs').canonical(envelope)).toString('base64url');}
function verify(plan,identity,target,reviews,roots,now=Math.floor(Date.now()/1000)){
 validate(target);if(target.gate_mode!=='helio_governed')return null;
 if(!Array.isArray(reviews)||reviews.length>1000)fail('gate_reviews_bound');
 const c=require('./contract.cjs'),expected=scope(plan,identity,target),matches=new Map();
 for(const r of reviews){
  if(r.state!=='approved'||r.user?.id!==target.governance.reviewer_account_id||!r.environments?.some(e=>String(e.id)===expected.environment_id&&e.name===target.name)||
   typeof r.comment!=='string'||!r.comment.startsWith(prefix))continue;
  if(r.comment.length>4096)fail('gate_comment_bound');
  let envelope;try{envelope=JSON.parse(Buffer.from(r.comment.slice(prefix.length),'base64url').toString('utf8'));}catch{fail('gate_proof_invalid');}
  const body=c.verify(envelope,roots,'gate-approval');
  // Reviews from previous attempts are harmless, but cannot authorize this one.
  if(Object.entries(expected).some(([k,v])=>body[k]!==v))continue;
  if(Object.keys(body).length!==Object.keys(expected).length+3||body.decision!=='approved'||typeof body.gate_id!=='string'||!body.gate_id||!Number.isSafeInteger(body.expires_at)||body.expires_at<=now)fail('gate_proof_invalid');
  matches.set(envelope.digest,body);
 }
 if(matches.size!==1)fail(matches.size?'gate_proof_ambiguous':'gate_proof_missing');
 return [...matches.values()][0];
}
module.exports={validate,scope,encode,verify};
