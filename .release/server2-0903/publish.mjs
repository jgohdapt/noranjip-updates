import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {distribution,targets,sha256,readJson,verifyManifest,compareVersions} from '../common/tools/manifest.mjs';
import {verifyPackage} from '../common/tools/package.mjs';
import {assertCommonVersion} from '../common/tools/common-version.mjs';
import {githubTransport} from '../common/tools/github-publication.mjs';

// One-time server2-only publication of 0.9.0.3. Writes are limited to the
// server2 version tag and server2 stable; server1 is only read and must stay 0.9.0.2.
const t2=targets.server2;
export const fixed=Object.freeze({
  schema:1,
  id:'20261101T092310Z-8e0751cf',
  scope:'server2-only',
  profile:'server2',
  version:'0.9.0.3',
  sourceCommit:'40ec1d55f5bb09d40f3a81e57be06bb05d3dd67b',
  previousVersion:'0.9.0.1',
  previousManifestSha256:'5D2CA0ADEA7E0C24426BE709F6A3EB7AF2BADDB8808C13CFB538DB25E7312DC2'
});
export const unselected=Object.freeze({server1:Object.freeze({version:'0.9.0.2',manifestSha256:'4234E10CC6989EFBC9E9173CB8C4EEB484266C2A44798C6B320B5B1A20AECEE4'})});
export const binding=Object.freeze({
  signerKeySha256:t2.keyHash,
  tag:t2.tagPrefix+fixed.version,
  packageName:`remote-${fixed.version}.zip`,
  packageUrl:`https://github.com/${distribution}/releases/download/${t2.tagPrefix}${fixed.version}/remote-${fixed.version}.zip`,
  entry:t2.entry
});
// Only these come from the signed build; everything else is fixed above.
const digests=['manifestSha256','packageSha256','packageBytes','exeSha256','exeBytes'];
const bundleFiles=[binding.packageName,'remote-manifest.xml'].sort();
const here=path.dirname(fileURLToPath(import.meta.url));
const plain=(o,keys)=>!!o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===[...keys].sort().join('|');

export function assertRequest(request){
  const fail=why=>{throw new Error('Request does not match the fixed server2-only 0.9.0.3 constraints: '+why);};
  if(!plain(request,[...Object.keys(fixed),'authorization','unselected','signed']))fail('keys');
  for(const k of Object.keys(fixed))if(request[k]!==fixed[k])fail(k);
  const a=request.authorization;
  if(!plain(a,['date','server2','server1'])||a.date!=='2026-11-01'||a.server2!=='authorized'||a.server1!=='unselected')fail('authorization');
  const u=request.unselected;
  if(!plain(u,['server1'])||!plain(u.server1,['version','manifestSha256'])||u.server1.version!==unselected.server1.version||u.server1.manifestSha256!==unselected.server1.manifestSha256)fail('unselected');
  const s=request.signed;
  if(!plain(s,[...Object.keys(binding),...digests]))fail('signed keys');
  for(const k of Object.keys(binding))if(s[k]!==binding[k])fail(k);
  for(const k of ['manifestSha256','packageSha256','exeSha256'])if(typeof s[k]!=='string'||!/^[A-F0-9]{64}$/.test(s[k]))fail(k);
  for(const k of ['packageBytes','exeBytes'])if(!Number.isSafeInteger(s[k])||s[k]<=0||s[k]>100*1024*1024)fail(k);
  if(s.manifestSha256===fixed.previousManifestSha256||s.manifestSha256===unselected.server1.manifestSha256)fail('manifestSha256 is not new');
  assertCommonVersion(fixed.version);
  if(compareVersions(fixed.version,fixed.previousVersion)<=0||compareVersions(fixed.version,unselected.server1.version)<=0)throw new Error('Version must be higher than both existing stables');
  return request;
}

// Production uses the pinned server2 key; tests may pass an ephemeral key hash.
export function verifyBundle(request,{manifestBytes,packageBytes,keyBytes},{expectedKeyHash=binding.signerKeySha256,now=Date.now()}={}){
  const s=assertRequest(request).signed;
  if(sha256(keyBytes)!==expectedKeyHash)throw new Error('Pinned public key mismatch');
  if(sha256(manifestBytes)!==s.manifestSha256)throw new Error('Signed manifest differs from the requested digest');
  const manifest=verifyManifest(manifestBytes,keyBytes,'server2',{now,expectedKeyHash});
  if(manifest.version!==fixed.version||manifest.stable!==t2.stable)throw new Error('Signed manifest version/stable mismatch');
  for(const k of ['tag','packageName','packageUrl','entry',...digests])if(manifest[k]!==s[k])throw new Error('Signed manifest differs from the request: '+k);
  const exe=verifyPackage(packageBytes,manifest);
  return {bundle:{sourceCommit:fixed.sourceCommit,manifest,manifestBytes:Buffer.from(manifestBytes),packageBytes:Buffer.from(packageBytes)},exe};
}

export function loadBundle(directory,keyBytes,request){
  // Only the signed manifest and ZIP are public; receipts and logs stay private.
  const names=fs.readdirSync(directory).sort();
  if(names.join('|')!==bundleFiles.join('|'))throw new Error('Signed bundle directory must contain only the manifest and ZIP');
  for(const n of names)if(!fs.lstatSync(path.join(directory,n)).isFile())throw new Error('Signed bundle entries must be regular files');
  return verifyBundle(request,{manifestBytes:fs.readFileSync(path.join(directory,'remote-manifest.xml')),packageBytes:fs.readFileSync(path.join(directory,binding.packageName)),keyBytes});
}

export async function readPublicPackage(url,maximum){
  if(url!==binding.packageUrl)throw new Error('Unexpected public package URL');
  const response=await fetch(url,{signal:AbortSignal.timeout(60000),headers:{'User-Agent':'NoranJipCommonRelease','Cache-Control':'no-cache'}});
  if(!response.ok)throw new Error(`Public package read failed: HTTP ${response.status}`);
  const chunks=[];let size=0;
  for await(const part of response.body){size+=part.length;if(size>maximum)throw new Error('Public package exceeds expected size');chunks.push(part);}
  return Buffer.concat(chunks);
}

// server1 is readable for identity checks only. Writes are refused unless they
// target exactly the owned server2 version tag and server2 stable.
export function server2Only(transport,{readPackage=readPublicPackage}={}){
  const own=b=>{const m=b?.manifest;if(m?.profile!=='server2'||m.version!==fixed.version||m.tag!==binding.tag||m.stable!==t2.stable)throw new Error('Refused write outside the owned server2 version and stable');};
  return Object.freeze({
    latest:()=>transport.latest(),
    stable:p=>{if(p!=='server2'&&p!=='server1')throw new Error('Refused unknown channel');return transport.stable(p);},
    ensureVersion:b=>{own(b);return transport.ensureVersion(b);},
    promote:(b,previous,id)=>{own(b);if(id!==fixed.id)throw new Error('Refused foreign publication id');return transport.promote(b,previous,id);},
    readPackage:(url,maximum)=>{if(url!==binding.packageUrl)throw new Error('Unexpected public package URL');return readPackage(url,maximum);}
  });
}

const latestIdentity=r=>r?{id:r.id,tag:r.tag_name??null}:null;
const stableIdentity=s=>({version:s.version,manifestSha256:s.manifestSha256,releaseId:s.releaseId,assetId:s.assetId});
const sameStable=(a,b)=>a.version===b.version&&a.manifestSha256===b.manifestSha256&&a.releaseId===b.releaseId&&a.assetId===b.assetId;
const sameBytes=(a,b)=>!!a&&!!b&&Buffer.compare(Buffer.from(a),Buffer.from(b))===0;

async function server1Unchanged(transport,before,state,label){
  const s=await transport.stable('server1');state[label]=stableIdentity(s);
  if(s.version!==unselected.server1.version||s.manifestSha256!==unselected.server1.manifestSha256||(before&&!sameStable(s,before)))throw new Error('Unselected server1 stable is not the expected 0.9.0.2 manifest');
  return s;
}

// Result status: failed-before-mutation | partial-version-only (server2 stable
// untouched, version tag may be partial) | uncertain (promotion started) |
// published-with-error | complete.
export async function publishServer2Only(request,bundle,transport,save){
  const s=assertRequest(request).signed,m=bundle?.manifest;
  if(bundle?.sourceCommit!==fixed.sourceCommit||m?.profile!=='server2'||m.version!==fixed.version||m.tag!==s.tag||m.packageUrl!==s.packageUrl||m.manifestSha256!==s.manifestSha256||m.packageSha256!==s.packageSha256||m.exeSha256!==s.exeSha256||sha256(bundle.manifestBytes)!==s.manifestSha256||sha256(bundle.packageBytes)!==s.packageSha256)throw new Error('Bundle/request mismatch');
  const state={schema:1,id:fixed.id,scope:fixed.scope,profile:'server2',version:fixed.version,sourceCommit:fixed.sourceCommit,tag:s.tag,manifestSha256:s.manifestSha256,packageSha256:s.packageSha256,exeSha256:s.exeSha256,previousManifestSha256:fixed.previousManifestSha256,server1:'read-only-unselected',status:'checking',immutable:'not-started',server2:'pending',startedUtc:new Date().toISOString()};
  const write=async()=>save(structuredClone(state));
  await write();
  try{
    const latest=await transport.latest();state.latestBefore=latestIdentity(latest);
    const server1=await server1Unchanged(transport,null,state,'server1Before');
    const current=await transport.stable('server2');state.stableBefore=stableIdentity(current);
    let already=false;
    if(current.manifestSha256===s.manifestSha256){
      if(current.version!==fixed.version||!sameBytes(current.bytes,bundle.manifestBytes))throw new Error('Stable server2 digest matches but version or bytes differ');
      already=true;state.server2='already-published';
    }else if(current.manifestSha256!==fixed.previousManifestSha256||current.version!==fixed.previousVersion)throw new Error('Stable server2 is not the expected previous manifest');
    state.status='immutable';state.immutable='started';await write();
    // Existing transport: creates with make_latest false or byte-verifies existing
    // assets; a differing existing asset is a conflict and is never overwritten.
    await transport.ensureVersion(bundle);
    state.immutable='verified';await write();
    if(already){
      const live=await transport.stable('server2');
      if(!sameStable(live,current)||!sameBytes(live.bytes,bundle.manifestBytes))throw new Error('Stable changed during already-published verification');
    }else{
      state.status='promoting';await write();
      const recheck=await transport.stable('server2');
      if(!sameStable(recheck,current)||!sameBytes(recheck.bytes,current.bytes))throw new Error('Concurrent server2 stable change before promotion');
      await server1Unchanged(transport,server1,state,'server1BeforePromotion');
      state.server2='promotion-started';await write();
      await transport.promote(bundle,recheck,fixed.id);
      const after=await transport.stable('server2');
      if(after.manifestSha256!==s.manifestSha256||after.version!==fixed.version||after.releaseId!==current.releaseId||!sameBytes(after.bytes,bundle.manifestBytes))throw new Error('Stable server2 readback failed');
      state.stableAfter=stableIdentity(after);state.server2='published';await write();
    }
    const zip=await transport.readPackage(s.packageUrl,s.packageBytes+1);
    if(!sameBytes(zip,bundle.packageBytes))throw new Error('Public package readback differs from the signed ZIP');
    const exe=verifyPackage(zip,m);state.packageReadback={packageSha256:sha256(zip),exeSha256:exe.sha256};
    await server1Unchanged(transport,server1,state,'server1After');
    const latestAfter=await transport.latest();state.latestAfter=latestIdentity(latestAfter);
    if((latestAfter?.id??null)!==(latest?.id??null))throw new Error('Global Latest release changed; investigate before reporting success');
    state.status='complete';state.completedUtc=new Date().toISOString();await write();return state;
  }catch(error){
    state.status=['published','already-published'].includes(state.server2)?'published-with-error':state.server2==='promotion-started'?'uncertain':state.immutable==='not-started'?'failed-before-mutation':'partial-version-only';
    state.error=error.message;state.completedUtc=new Date().toISOString();await write();throw error;
  }
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const output=process.env.PUBLICATION_RESULT||'server2-0903-publication-result.json';
  const persist=s=>fs.writeFileSync(output,JSON.stringify({...s,distributionCommit:process.env.GITHUB_SHA||null},null,2)+'\n');
  try{
    const sha=process.env.GITHUB_SHA||'';
    if(process.env.GITHUB_ACTIONS!=='true'||process.env.GITHUB_REPOSITORY!==distribution||process.env.GITHUB_REF!=='refs/heads/main'||process.env.GITHUB_EVENT_NAME!=='push'||!/^[0-9a-f]{40}$/.test(sha))throw new Error('Publication only runs from a push to the expected GitHub main');
    if(process.env.GITHUB_WORKFLOW_REF!==`${distribution}/.github/workflows/server2-0903-publish.yml@refs/heads/main`)throw new Error('Publication only runs from the server2-0903 workflow');
    if(execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim()!==sha)throw new Error('Checked-out commit differs from GITHUB_SHA');
    const request=assertRequest(readJson(path.join(here,'request.json')));
    const keys={server1:fs.readFileSync(path.join(here,'..','common','keys','server1.xml')),server2:fs.readFileSync(path.join(here,'..','common','keys','server2.xml'))};
    if(sha256(keys.server1)!==targets.server1.keyHash)throw new Error('Pinned server1 public key mismatch');
    const {bundle}=loadBundle(path.join(here,'server2'),keys.server2,request);
    // The server1 key only lets the transport verify server1 reads; the wrapper refuses its writes.
    await publishServer2Only(request,bundle,server2Only(githubTransport(keys,process.env.GH_TOKEN)),persist);
    console.log(fs.readFileSync(output,'utf8'));
  }catch(error){
    if(!fs.existsSync(output))persist({schema:1,id:fixed.id,scope:fixed.scope,status:'failed-before-mutation',server1:'read-only-unselected',error:error.message,completedUtc:new Date().toISOString()});
    console.error(error.message);process.exitCode=1;
  }
}
