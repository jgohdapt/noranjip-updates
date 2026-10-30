import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {distribution,targets,sha256,readJson,verifyManifest,compareVersions} from '../common/tools/manifest.mjs';
import {verifyPackage} from '../common/tools/package.mjs';
import {assertCommonVersion} from '../common/tools/common-version.mjs';
import {githubTransport} from '../common/tools/github-publication.mjs';

// One-time server1-only publication of 0.9.0.2. The user explicitly authorized
// server1 alone on 2026-10-30 and deferred server2; nothing here reaches server2.
export const fixed=Object.freeze({
  schema:1,
  id:'20261030-server1-0902',
  scope:'server1-only',
  profile:'server1',
  version:'0.9.0.2',
  sourceCommit:'70c33fb136c77ad4e9b61ee14fd9b389a0f32297',
  previousVersion:'0.9.0.1',
  previousManifestSha256:'6F9D465D99924B4D0860F08F953942B0FEF6D106707E25E371519202AFE1AE09',
  manifestSha256:'4234E10CC6989EFBC9E9173CB8C4EEB484266C2A44798C6B320B5B1A20AECEE4'
});
const here=path.dirname(fileURLToPath(import.meta.url));

export function assertRequest(request){
  const {authorization,...rest}=request||{};
  const expected=Object.keys(fixed).sort();
  if(Object.keys(rest).sort().join('|')!==expected.join('|')||expected.some(k=>rest[k]!==fixed[k]))throw new Error('Request does not match the fixed server1-only 0.9.0.2 constraints');
  if(authorization?.server1!=='authorized'||authorization?.server2!=='deferred'||!/^2026-10-30$/.test(authorization?.date||''))throw new Error('Explicit server1-only authorization is missing');
  assertCommonVersion(fixed.version);
  if(compareVersions(fixed.version,fixed.previousVersion)<=0)throw new Error('Version must be higher than the previous stable');
  return request;
}

export function loadBundle(directory,keyFile){
  const key=fs.readFileSync(keyFile);
  if(sha256(key)!==targets.server1.keyHash)throw new Error('Pinned public key mismatch');
  const manifestBytes=fs.readFileSync(path.join(directory,'remote-manifest.xml'));
  if(sha256(manifestBytes)!==fixed.manifestSha256)throw new Error('Signed manifest hash differs from the fixed expected hash');
  const manifest=verifyManifest(manifestBytes,key,'server1');
  if(manifest.version!==fixed.version||manifest.tag!==targets.server1.tagPrefix+fixed.version||manifest.stable!==targets.server1.stable)throw new Error('Manifest version/tag mismatch');
  const packageBytes=fs.readFileSync(path.join(directory,manifest.packageName));
  const exe=verifyPackage(packageBytes,manifest);
  return {key,bundle:{sourceCommit:fixed.sourceCommit,manifest,manifestBytes,packageBytes},exe};
}

// Only the four server1 operations are exposed; any other profile is refused
// before the underlying transport is called.
export function server1Only(transport){
  const check=p=>{if(p!=='server1')throw new Error('Refused non-server1 channel operation');};
  return {
    latest:()=>transport.latest(),
    stable:p=>{check(p);return transport.stable(p);},
    ensureVersion:b=>{check(b?.manifest?.profile);return transport.ensureVersion(b);},
    promote:(b,previous,id)=>{check(b?.manifest?.profile);return transport.promote(b,previous,id);}
  };
}

const latestIdentity=r=>r?{id:r.id,tag:r.tag_name??null}:null;
const stableIdentity=s=>({version:s.version,manifestSha256:s.manifestSha256,releaseId:s.releaseId,assetId:s.assetId});

export async function publishServer1Only(request,bundle,transport,save){
  assertRequest(request);
  const m=bundle.manifest;
  if(bundle.sourceCommit!==fixed.sourceCommit||m.profile!=='server1'||m.version!==fixed.version||m.manifestSha256!==fixed.manifestSha256)throw new Error('Bundle/request mismatch');
  const state={schema:1,id:fixed.id,scope:fixed.scope,profile:'server1',version:fixed.version,sourceCommit:fixed.sourceCommit,manifestSha256:m.manifestSha256,packageSha256:m.packageSha256,exeSha256:m.exeSha256,previousManifestSha256:fixed.previousManifestSha256,server2:'not-touched-deferred',status:'checking',server1:'pending',startedUtc:new Date().toISOString()};
  const write=async()=>save(structuredClone(state));
  await write();
  try{
    const latest=await transport.latest();state.latestBefore=latestIdentity(latest);
    const current=await transport.stable('server1');state.stableBefore=stableIdentity(current);
    let already=false;
    if(current.manifestSha256===fixed.manifestSha256){
      if(current.version!==fixed.version)throw new Error('Stable hash matches but version differs');
      already=true;state.server1='already-published';
    }else if(current.manifestSha256!==fixed.previousManifestSha256||current.version!==fixed.previousVersion)throw new Error('Stable server1 is not the expected previous manifest');
    state.status='immutable';await write();
    // Existing transport: creates with make_latest false or byte-verifies existing assets.
    await transport.ensureVersion(bundle);
    state.immutable='verified';
    if(already){
      const live=await transport.stable('server1');
      if(live.manifestSha256!==fixed.manifestSha256)throw new Error('Stable changed during already-published verification');
    }else{
      state.status='promoting';await write();
      const recheck=await transport.stable('server1');
      if(recheck.manifestSha256!==fixed.previousManifestSha256||recheck.releaseId!==current.releaseId||recheck.assetId!==current.assetId)throw new Error('Concurrent server1 stable change before promotion');
      state.server1='promotion-started';await write();
      await transport.promote(bundle,recheck,fixed.id);
      const after=await transport.stable('server1');
      if(after.manifestSha256!==fixed.manifestSha256||after.version!==fixed.version)throw new Error('Stable readback failed');
      state.stableAfter=stableIdentity(after);state.server1='published';await write();
    }
    const latestAfter=await transport.latest();state.latestAfter=latestIdentity(latestAfter);
    if((latestAfter?.id??null)!==(latest?.id??null))throw new Error('Global Latest release changed; investigate before reporting success');
    state.status='complete';state.completedUtc=new Date().toISOString();await write();return state;
  }catch(error){
    state.status=['published','already-published'].includes(state.server1)?'published-with-error':state.server1==='promotion-started'?'uncertain':'failed-before-promotion';
    state.error=error.message;state.completedUtc=new Date().toISOString();await write();throw error;
  }
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const output=process.env.PUBLICATION_RESULT||'server1-0902-publication-result.json';
  const persist=s=>fs.writeFileSync(output,JSON.stringify({...s,distributionCommit:process.env.GITHUB_SHA||null},null,2)+'\n');
  try{
    const sha=process.env.GITHUB_SHA||'';
    if(process.env.GITHUB_ACTIONS!=='true'||process.env.GITHUB_REPOSITORY!==distribution||process.env.GITHUB_REF!=='refs/heads/main'||process.env.GITHUB_EVENT_NAME!=='push'||!/^[0-9a-f]{40}$/.test(sha))throw new Error('Publication only runs from a push to the expected GitHub main');
    if(execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim()!==sha)throw new Error('Checked-out commit differs from GITHUB_SHA');
    const request=assertRequest(readJson(path.join(here,'request.json')));
    const {key,bundle}=loadBundle(path.join(here,'server1'),path.join(here,'..','common','keys','server1.xml'));
    // Only the server1 key is given, so the transport cannot verify any other channel.
    await publishServer1Only(request,bundle,server1Only(githubTransport({server1:key},process.env.GH_TOKEN)),persist);
    console.log(fs.readFileSync(output,'utf8'));
  }catch(error){
    if(!fs.existsSync(output))persist({schema:1,id:fixed.id,scope:fixed.scope,status:'failed-before-promotion',server2:'not-touched-deferred',error:error.message,completedUtc:new Date().toISOString()});
    console.error(error.message);process.exitCode=1;
  }
}
