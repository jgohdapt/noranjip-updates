// Runs only in the distribution repository's GitHub Actions job.
// No credentials, source code, session data, or machine settings are published.
import fs from 'node:fs';import crypto from 'node:crypto';import path from 'node:path';import {pathToFileURL} from 'node:url';
const repo='jgohdapt/noranjip-updates',base=`https://api.github.com/repos/${repo}`;
const hash=(b,algorithm='sha256',encoding='hex')=>crypto.createHash(algorithm).update(b).digest(encoding);
export function verifyRequest(r){
  if(r.schema!==1||r.repository!==repo||!/^\d+\.\d+\.\d+$/.test(r.version)||r.name!==`YellowHouseAITalk-Setup-${r.version}.exe`||!Number.isSafeInteger(r.size)||r.size<1||r.size>300*1024*1024||!/^[a-f0-9]{64}$/.test(r.sha256)||!/^[A-Za-z0-9+/]{86}==$/.test(r.sha512)||!Array.isArray(r.parts)||!r.parts.length||r.parts.length>8)throw Error('Invalid AI Talk release request');
  for(const [i,p] of r.parts.entries())if(p.name!==`part-${String(i).padStart(3,'0')}.bin`||!/^[a-f0-9]{64}$/.test(p.sha256)||!Number.isSafeInteger(p.size)||p.size<1||p.size>40*1024*1024)throw Error('Invalid binary part');
  if(r.parts.reduce((a,p)=>a+p.size,0)!==r.size)throw Error('Part size mismatch');
  return r;
}
export function updateMetadata(r){return Buffer.from(JSON.stringify({version:r.version,files:[{url:`https://github.com/${repo}/releases/download/ai-talk-v${r.version}/${r.name}`,sha512:r.sha512,size:r.size}],path:`https://github.com/${repo}/releases/download/ai-talk-v${r.version}/${r.name}`,sha512:r.sha512,releaseDate:r.createdAt},null,2)+'\n');}
export async function publish(){
  const commit=process.env.GITHUB_SHA,token=process.env.GH_TOKEN;
  if(process.env.GITHUB_REPOSITORY!==repo||process.env.GITHUB_REF!=='refs/heads/main'||!/^[a-f0-9]{40}$/.test(commit)||!token)throw Error('Publication context refused');
  async function bytes(url,max=300*1024*1024){const r=await fetch(url,{signal:AbortSignal.timeout(180000),headers:{'User-Agent':'YellowHouseAITalk-Publisher','Cache-Control':'no-cache'}});if(!r.ok)throw Error(`Public read HTTP ${r.status}`);const parts=[];let count=0;for await(const p of r.body){count+=p.length;if(count>max)throw Error('Public asset exceeds size limit');parts.push(p);}return Buffer.concat(parts);}
  const raw=`https://raw.githubusercontent.com/${repo}/${commit}/.release/ai-talk/`;
  const request=verifyRequest(JSON.parse(await bytes(raw+'request.json',65536)));
  const chunks=[];for(const part of request.parts){const b=await bytes(raw+'payload/'+part.name,part.size);if(b.length!==part.size||hash(b)!==part.sha256)throw Error('Binary part checksum mismatch');chunks.push(b);}
  const installer=Buffer.concat(chunks);if(installer.length!==request.size||hash(installer)!==request.sha256||hash(installer,'sha512','base64')!==request.sha512)throw Error('Installer checksum mismatch');
  const metadata=updateMetadata(request);
  async function api(endpoint,method='GET',body){
    const url=endpoint.startsWith('https:')?endpoint:base+endpoint;if(!url.startsWith(base+'/')&&!url.startsWith(`https://uploads.github.com/repos/${repo}/`))throw Error('Publication destination refused');
    const r=await fetch(url,{method,redirect:'manual',signal:AbortSignal.timeout(180000),headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'YellowHouseAITalk-Publisher',...(body===undefined?{}:{'Content-Type':Buffer.isBuffer(body)?'application/octet-stream':'application/json'})},body:body===undefined?undefined:Buffer.isBuffer(body)?body:JSON.stringify(body)});
    if(r.status===404&&method==='GET')return null;if(!r.ok)throw Error(`GitHub ${method} ${new URL(url).pathname}: HTTP ${r.status}`);return r.status===204?null:r.json();
  }
  async function release(tag,name,body){let r=await api('/releases/tags/'+tag);if(!r)r=await api('/releases','POST',{tag_name:tag,target_commitish:commit,name,body,draft:false,prerelease:false,make_latest:'false'});if(r.draft||r.prerelease)throw Error('Unexpected release state');return r;}
  async function assets(r){const all=[];for(let page=1;page<=20;page++){const part=await api(`/releases/${r.id}/assets?per_page=100&page=${page}`);all.push(...part);if(part.length<100)return all;}throw Error('Too many release assets');}
  async function verify(a,data){if(a.size!==data.length||hash(await bytes(a.browser_download_url+'?asset_id='+a.id,data.length))!==hash(data))throw Error('Published asset readback mismatch');return a;}
  async function upload(r,name,data){const old=(await assets(r)).find(a=>a.name===name);if(old)return verify(old,data);const a=await api(`https://uploads.github.com/repos/${repo}/releases/${r.id}/assets?name=${encodeURIComponent(name)}`,'POST',data);return verify(a,data);}
  const rename=(asset,name)=>api(`/releases/assets/${asset.id}`,'PATCH',{name});
  const version=await release('ai-talk-v'+request.version,'노란집AI톡 '+request.version,request.notes+'\n\nInstaller SHA-256: `'+request.sha256+'`\n\nAI톡 전용 배포입니다. 관리자/원격 프로그램 채널은 변경하지 않습니다.');
  await upload(version,request.name,installer);await upload(version,'latest.yml',metadata);
  const stable=await release('ai-talk-stable','노란집AI톡 자동 업데이트','AI톡 설치형 앱의 전용 업데이트 경로입니다. 최신 설치 파일은 AI톡 버전 릴리스에서 받을 수 있습니다.');
  const old=(await assets(stable)).find(a=>a.name==='latest.yml');
  if(old){const prior=await bytes(old.browser_download_url+'?asset_id='+old.id,65536);if(hash(prior)===hash(metadata)){console.log('AI_TALK_RELEASE_ALREADY_PUBLISHED '+request.version);return;}
    const prev=JSON.parse(prior).version;if(!/^\d+\.\d+\.\d+$/.test(prev))throw Error('Invalid prior channel version');
    const a=request.version.split('.').map(Number),b=prev.split('.').map(Number);let newer=false;for(let i=0;i<3;i++){if(a[i]===b[i])continue;newer=a[i]>b[i];break;}if(!newer)throw Error('Refused channel downgrade or version overwrite');
  }
  const staged=await upload(stable,`latest-${request.version}.pending.yml`,metadata);
  const live=(await assets(stable)).find(a=>a.name==='latest.yml');if((live?.id||null)!==(old?.id||null))throw Error('Update channel changed concurrently');
  if(old)await rename(old,`latest-previous-${old.id}.yml`);
  try{await rename(staged,'latest.yml');}catch(e){if(old)await rename(old,'latest.yml');throw e;}
  const final=(await assets(stable)).find(a=>a.name==='latest.yml');await verify(final,metadata);
  console.log('AI_TALK_RELEASE_PUBLISHED '+request.version+' '+version.html_url);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href&&process.argv.includes('--publish'))publish().catch(error=>{console.error(error.message);process.exitCode=1;});
