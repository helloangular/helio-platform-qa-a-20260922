'use strict';
const {canonical}=require('./contract.cjs');
const fail=()=>{throw Error('platform_protection_mismatch');};
const compare=(a,b)=>a<b?-1:a>b?1:0;
const managed=['HELIO_TARGET_KIND','AWS_ROLE_ARN','AWS_REGION','AWS_ACCOUNT_ID'];
function only(value,fields){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!fields.includes(k)))fail();}
function validate(value){
 only(value,['environment_id','name','can_admins_bypass','prevent_self_review','reviewers','branch_policy','variables']);
 if(!/^[1-9][0-9]{0,19}$/.test(value.environment_id)||typeof value.name!=='string'||typeof value.can_admins_bypass!=='boolean'||!(value.prevent_self_review===null||typeof value.prevent_self_review==='boolean')||!Array.isArray(value.reviewers)||value.reviewers.length>6)fail();
 for(const r of value.reviewers){only(r,['type','id']);if(!['User','Team'].includes(r.type)||!Number.isSafeInteger(r.id)||r.id<1)fail();}
 const bp=value.branch_policy;only(bp,['custom','protected','entries']);
 if(typeof bp.custom!=='boolean'||typeof bp.protected!=='boolean'||!Array.isArray(bp.entries)||bp.entries.length>100)fail();
 for(const e of bp.entries){only(e,['name','type']);if(!['branch','tag'].includes(e.type)||typeof e.name!=='string'||e.name.length>255)fail();}
 only(value.variables,managed);
 const patterns={HELIO_TARGET_KIND:/^(aws|on_prem)$/,AWS_ROLE_ARN:/^arn:aws(?:-[a-z]+)?:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@/-]+$/,AWS_REGION:/^[a-z]{2}-[a-z0-9-]+-[0-9]+$/,AWS_ACCOUNT_ID:/^[0-9]{12}$/};
 for(const [k,v] of Object.entries(value.variables))if(typeof v!=='string'||v.length>2048||!patterns[k].test(v))fail();
 return value;
}
function snapshot(environment,entries,variables){
 if(!environment||!Number.isSafeInteger(environment.id)||environment.id<1||!Array.isArray(environment.protection_rules)||!Array.isArray(entries)||entries.length>100||!variables||typeof variables!=='object')fail();
 if(environment.protection_rules.some(r=>!['required_reviewers','branch_policy'].includes(r.type)))fail();
 if(environment.protection_rules.filter(r=>r.type==='branch_policy').length>1)fail();
 const rules=environment.protection_rules.filter(r=>r.type==='required_reviewers');if(rules.length>1)fail();
 const reviewers=(rules[0]?.reviewers||[]).map(r=>({type:r.type,id:r.reviewer?.id}));
 if(reviewers.some(r=>!['User','Team'].includes(r.type)||!Number.isSafeInteger(r.id)||r.id<1))fail();
 const bp=environment.deployment_branch_policy;
 if(typeof environment.can_admins_bypass!=='boolean'||typeof bp?.custom_branch_policies!=='boolean'||typeof bp?.protected_branches!=='boolean')fail();
 if(rules.length&&typeof rules[0].prevent_self_review!=='boolean')fail();
 if(entries.some(e=>!['branch','tag'].includes(e.type)||typeof e.name!=='string'))fail();
 return {environment_id:String(environment.id),name:environment.name,can_admins_bypass:environment.can_admins_bypass,
  prevent_self_review:rules.length?rules[0].prevent_self_review:null,
  reviewers:reviewers.sort((a,b)=>compare(a.type,b.type)||a.id-b.id),
  branch_policy:{custom:bp.custom_branch_policies,protected:bp.protected_branches,
    entries:entries.map(e=>({name:e.name,type:e.type})).sort((a,b)=>compare(a.type,b.type)||compare(a.name,b.name))},
  variables:Object.fromEntries(managed.filter(k=>Object.hasOwn(variables,k)).map(k=>[k,String(variables[k])]))};
}
function verify(target,environment,entries,variables){
 if(!target?.protection||target.name!==target.protection.name)fail();
 validate(target.protection);
 const actual=snapshot(environment,entries,variables);
 if(canonical(actual)!==canonical(target.protection))fail();
 if(target.gate_mode!=='none'&&(actual.can_admins_bypass!==false||actual.prevent_self_review!==true||!actual.reviewers.length))fail();
 return true;
}
module.exports={snapshot,verify,validate};
