import {assertSameReleaseVersion} from './common-version.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {distribution,targets,sha256,readJson,verifyManifest} from './manifest.mjs';
import {verifyPackage} from './package.mjs';
import {publishTogether} from './publication.mjs';

async function publicBytes(url,maximum=101*1024*1024){
  if(!url.startsWith(`https://github.com/${distribution}/releases/download/`))throw new Error('Unexpected public asset URL');
  const response=await fetch(url,{signal:AbortSignal.timeout(60000),headers:{'User-Agent':'NoranJipCommonRelease','Cache-Control':'no-cache'}});
  if(!response.ok)throw new Error(`Public asset read failed: HTTP ${response.status}`);
  if(Number(response.headers.get('content-length')||0)>maximum)throw new Error('Asset exceeds size limit');
  const chunks=[];let size=0;
  for await(const part of response.body){size+=part.length;if(size>maximum)throw new Error('Asset exceeds size limit');chunks.push(part);}
  return Buffer.concat(chunks);
}
export function githubTransport(keys,token){
  if(!token)throw new Error('GitHub Actions publication token is missing');
  const base=`https://api.github.com/repos/${distribution}`;
  async function api(endpoint,method='GET',body){
    const url=endpoint.startsWith('https:')?endpoint:base+endpoint;
    if(!url.startsWith(base+'/')&&!url.startsWith(`https://uploads.github.com/repos/${distribution}/`))throw new Error('Refused API destination');
    const raw=Buffer.isBuffer(body);
    const r=await fetch(url,{method,redirect:'manual',signal:AbortSignal.timeout(60000),headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'NoranJipCommonRelease',...(body===undefined?{}:{'Content-Type':raw?'application/octet-stream':'application/json'})},body:body===undefined?undefined:raw?body:JSON.stringify(body)});
    if(r.status===404&&method==='GET')return null;
    if(!r.ok)throw new Error(`GitHub ${method} ${new URL(url).pathname}: HTTP ${r.status}`);
    if(r.status===204)return null;return r.json();
  }
  const release=tag=>api('/releases/tags/'+encodeURIComponent(tag));
  const assetUrl=asset=>{
    if(!Number.isSafeInteger(asset.id)||asset.id<=0)throw new Error('Invalid GitHub asset identity');
    const url=new URL(asset.browser_download_url);
    // Renaming preserves the canonical URL; a cached redirect may still lead
    // to the old asset. Bind each public read to the API-confirmed asset id.
    url.searchParams.set('asset_id',String(asset.id));return url.href;
  };
  async function assets(r){
    let all=[];for(let page=1;page<=20;page++){const part=await api(`/releases/${r.id}/assets?per_page=100&page=${page}`);all.push(...part);if(part.length<100)return all;}throw new Error('Too many release assets');
  }
  async function verifyAsset(asset,bytes){
    if(asset.size!==bytes.length||sha256(await publicBytes(assetUrl(asset),bytes.length+1))!==sha256(bytes))throw new Error('Uploaded asset readback mismatch');return asset;
  }
  async function upload(r,name,bytes){
    const old=(await assets(r)).find(a=>a.name===name);if(old)return verifyAsset(old,bytes);
    return verifyAsset(await api(`https://uploads.github.com/repos/${distribution}/releases/${r.id}/assets?name=${encodeURIComponent(name)}`,'POST',bytes),bytes);
  }
  const rename=(a,name)=>api(`/releases/assets/${a.id}`,'PATCH',{name});
  return {
    latest:()=>api('/releases/latest'),
    async stable(profile){
      const r=await release(targets[profile].stable);if(!r){if(profile==='server2')return {missing:true,version:'0.0.0.0',manifestSha256:null};throw new Error('Existing server1 administrator channel missing');}
      const a=(await assets(r)).find(a=>a.name==='admin-manifest.xml');if(!a){if(profile==='server2'&&r.body==='Signed administrator update channel.'&&(await assets(r)).length===0)return {missing:true,emptyReleaseId:r.id,version:'0.0.0.0',manifestSha256:null};throw new Error('Existing stable manifest missing; inspect recovery assets');}
      const bytes=await publicBytes(assetUrl(a),65536);
      return {...verifyManifest(bytes,keys[profile],profile),releaseId:r.id,assetId:a.id,bytes};
    },
    async ensureVersion(bundle){
      const m=bundle.manifest;let r=await release(m.tag);
      if(!r)r=await api('/releases','POST',{tag_name:m.tag,target_commitish:process.env.GITHUB_SHA,name:`Administrator ${m.version}`,body:`Verified admin-ui update for ${m.profile}. Common source ${bundle.sourceCommit}.`,draft:false,prerelease:false,make_latest:'false'});
      if(r.draft||r.prerelease)throw new Error('Unexpected immutable release state');
      await upload(r,m.packageName,bundle.packageBytes);await upload(r,'admin-manifest.xml',bundle.manifestBytes);
    },
    async promote(bundle,previous,id){
      const profile=bundle.manifest.profile;
      let r=await release(targets[profile].stable);
      if(previous.missing){
        if(profile!=='server2'||(r&&r.id!==previous.emptyReleaseId))throw new Error('New channel appeared during preparation');
        if(r&&(await assets(r)).length)throw new Error('New channel gained assets during preparation');
        if(!r)r=await api('/releases','POST',{tag_name:targets[profile].stable,target_commitish:process.env.GITHUB_SHA,name:'Server2 administrator stable',body:'Signed administrator update channel.',draft:false,prerelease:false,make_latest:'false'});
        await upload(r,'admin-manifest.xml',bundle.manifestBytes);return;
      }
      const before=await assets(r);
      if(r.id!==previous.releaseId)throw new Error('Stable release identity changed');
      const current=before.find(a=>a.name==='admin-manifest.xml');
      if(!current||current.id!==previous.assetId)throw new Error('Stable asset identity changed');
      await verifyAsset(current,previous.bytes);
      const archiveName=`admin-manifest-${previous.version}-${id}.xml`,stagedName=`admin-manifest-${bundle.manifest.version}-${id}.pending.xml`;
      if(before.some(a=>a.name===archiveName))throw new Error('Recovery archive already exists; inspect previous attempt');
      const staged=await upload(r,stagedName,bundle.manifestBytes);
      // Recheck after upload. Preserve every previous asset; no deletion is used.
      const live=(await assets(r)).find(a=>a.name==='admin-manifest.xml');
      if(!live||live.id!==current.id)throw new Error('Concurrent stable change after staging');
      await verifyAsset(live,previous.bytes);
      await rename(current,archiveName);
      try{await rename(staged,'admin-manifest.xml');}
      catch(error){
        const found=(await assets(r)).find(a=>a.name==='admin-manifest.xml');
        if(!found)await rename(current,'admin-manifest.xml');
        throw error;
      }
      const after=await assets(r),fixed=after.find(a=>a.name==='admin-manifest.xml');
      if(!fixed||fixed.id!==staged.id)throw new Error('Stable promotion not confirmed');
      await verifyAsset(fixed,bundle.manifestBytes);
      if(!after.some(a=>a.id===current.id&&a.name===archiveName))throw new Error('Previous manifest archive not preserved');
      for(const a of before)if(a.id!==current.id&&!after.some(b=>b.id===a.id&&b.name===a.name))throw new Error('Unrelated release asset changed');
    }
  };
}

export function loadPublication(directory,keyDirectory){
  const request=readJson(path.join(directory,'request.json')),keys={},bundles={};
  assertSameReleaseVersion(request.servers);
  for(const profile of ['server1','server2']){
    const r=request.servers[profile];
    keys[profile]=fs.readFileSync(path.join(keyDirectory,profile+'.xml'));
    const manifestBytes=fs.readFileSync(path.join(directory,profile,'admin-manifest.xml'));
    const manifest=verifyManifest(manifestBytes,keys[profile],profile);
    const packageBytes=fs.readFileSync(path.join(directory,profile,manifest.packageName));verifyPackage(packageBytes,manifest);
    const provenance=readJson(path.join(directory,profile,'provenance.json'));
    if(provenance.sourceCommit!==request.sourceCommit||provenance.profile!==profile||provenance.manifestSha256!==manifest.manifestSha256||provenance.packageSha256!==manifest.packageSha256||provenance.fullValidation!==true)throw new Error('Publication provenance mismatch');
    bundles[profile]={sourceCommit:provenance.sourceCommit,manifest,manifestBytes,packageBytes};
  }
  return {request,keys,bundles};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const output=process.env.PUBLICATION_RESULT||'publication-result.json';
  try{
    if(process.env.GITHUB_REPOSITORY!==distribution||process.env.GITHUB_REF!=='refs/heads/main'||!/^[0-9a-f]{40}$/.test(process.env.GITHUB_SHA||''))throw new Error('Publication only runs in the expected GitHub main workflow');
    const {request,keys,bundles}=loadPublication(process.argv[2],process.argv[3]);
    await publishTogether(request,bundles,githubTransport(keys,process.env.GH_TOKEN),s=>fs.writeFileSync(output,JSON.stringify(s,null,2)+'\n'));
    console.log(fs.readFileSync(output,'utf8'));
  }catch(error){console.error(error.message);process.exitCode=1;}
}
