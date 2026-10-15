import {test} from 'node:test';
import assert from 'node:assert/strict';
import {githubTransport} from '../tools/github-publication.mjs';
import {sha256} from '../tools/manifest.mjs';

function mockGitHub(){
 const tag='remote-v2-stable',assets=new Map(),calls=[],releases=new Map([[tag,{id:10,tag_name:tag,draft:false,prerelease:false}]]);
 let next=100,failPromotion=false,cacheCanonical=false;
 function add(releaseId,name,bytes){const a={id:next++,releaseId,name,size:bytes.length,bytes:Buffer.from(bytes)};assets.set(a.id,a);return a;}
 function publicAsset(a){const r=[...releases.values()].find(r=>r.id===a.releaseId);return {id:a.id,name:a.name,size:a.size,browser_download_url:`https://github.com/jgohdapt/noranjip-updates/releases/download/${r.tag_name}/${a.name}`};}
 const previousBytes=Buffer.from('old signed manifest'),newBytes=Buffer.from('new signed manifest');
 const old=add(10,'remote-manifest.xml',previousBytes),unrelated=add(10,'unchanged.zip',Buffer.from('existing'));
 const bundle={sourceCommit:'a'.repeat(40),manifest:{profile:'server1',version:'0.9.0.0',tag:'remote-v2-0.9.0.0',packageName:'remote-0.9.0.0.zip'},manifestBytes:newBytes,packageBytes:Buffer.from('verified package')};
 const previous={version:'0.8.1.58',releaseId:10,assetId:old.id,bytes:previousBytes};
 const fetch=async(url,options={})=>{
  const u=new URL(url),method=options.method||'GET';calls.push({url,method,options});
  if(u.hostname==='github.com'){
   assert.equal(options.headers?.Authorization,undefined,'never forward the Actions token to public downloads');
   const parts=u.pathname.split('/'),assetName=decodeURIComponent(parts.pop()),tag=decodeURIComponent(parts.pop()),r=releases.get(tag);
   const a=[...assets.values()].find(a=>a.releaseId===r?.id&&a.name===assetName);
   if(cacheCanonical&&assetName==='remote-manifest.xml'&&a?.id!==old.id&&u.searchParams.get('asset_id')!==String(a?.id))return new Response(previousBytes,{status:200,headers:{'content-length':String(previousBytes.length)}});
   return new Response(a?.bytes,{status:a?200:404,headers:{'content-length':String(a?.size||0)}});
  }
  assert.equal(options.headers.Authorization,'Bearer synthetic-token');assert.equal(options.redirect,'manual');
  if(method==='GET'&&u.pathname.includes('/releases/tags/')){const r=releases.get(decodeURIComponent(u.pathname.split('/').pop()));return Response.json(r||{},{status:r?200:404});}
  if(method==='POST'&&u.pathname.endsWith('/releases')){
   const body=JSON.parse(options.body);assert.equal(body.make_latest,'false');assert.equal(body.draft,false);
   const r={...body,id:200+releases.size};releases.set(r.tag_name,r);return Response.json(r);
  }
  const releaseAssets=/\/releases\/(\d+)\/assets$/.exec(u.pathname);
  if(releaseAssets&&method==='GET')return Response.json([...assets.values()].filter(a=>a.releaseId===Number(releaseAssets[1])).map(publicAsset));
  if(releaseAssets&&method==='POST'){
   const name=u.searchParams.get('name');assert.ok(![...assets.values()].some(a=>a.releaseId===Number(releaseAssets[1])&&a.name===name));
   return Response.json(publicAsset(add(Number(releaseAssets[1]),name,options.body)));
  }
  const assetId=/\/releases\/assets\/(\d+)$/.exec(u.pathname);
  if(assetId&&method==='PATCH'){
   const a=assets.get(Number(assetId[1])),name=JSON.parse(options.body).name;
   if(failPromotion&&a.id!==old.id&&name==='remote-manifest.xml')return new Response('failure',{status:503});
   assert.ok(![...assets.values()].some(b=>b.id!==a.id&&b.releaseId===a.releaseId&&b.name===name));a.name=name;return Response.json(publicAsset(a));
  }
  throw new Error(`Unexpected mocked API call: ${method} ${u.pathname}`);
 };
 return {fetch,calls,assets,releases,bundle,previous,old,unrelated,newBytes,setFail:()=>{failPromotion=true;},cacheCanonical:()=>{cacheCanonical=true;}};
}
async function withMock(run){const original=globalThis.fetch,f=mockGitHub();globalThis.fetch=f.fetch;try{await run(f,githubTransport({},'synthetic-token'));}finally{globalThis.fetch=original;}}

test('GitHub immutable release preserves Latest and verifies bytes before idempotent reuse',()=>withMock(async(f,t)=>{
 await t.ensureVersion(f.bundle);const writes=f.calls.filter(x=>x.method==='POST').length;
 await t.ensureVersion(f.bundle);assert.equal(f.calls.filter(x=>x.method==='POST').length,writes);
 f.bundle.packageBytes=Buffer.from('different bytes');await assert.rejects(t.ensureVersion(f.bundle),/readback mismatch/);
 assert.ok(f.calls.every(x=>x.method!=='DELETE'));
}));

test('GitHub promotion archives old manifest and retains unrelated assets',()=>withMock(async(f,t)=>{
 await t.promote(f.bundle,f.previous,'20261015T120000Z-aaaaaaaa');
 const canonical=[...f.assets.values()].find(a=>a.releaseId===10&&a.name==='remote-manifest.xml');
 assert.equal(sha256(canonical.bytes),sha256(f.newBytes));assert.notEqual(canonical.id,f.old.id);
 assert.match(f.old.name,/^remote-manifest-0\.8\.1\.58-/);assert.equal(f.assets.get(f.unrelated.id).name,'unchanged.zip');
 assert.ok(f.calls.every(x=>x.method!=='DELETE'));
}));

test('failed GitHub rename restores the previous canonical manifest without deleting evidence',()=>withMock(async(f,t)=>{
 f.setFail();await assert.rejects(t.promote(f.bundle,f.previous,'20261015T120000Z-aaaaaaaa'),/HTTP 503/);
 assert.equal(f.assets.get(f.old.id).name,'remote-manifest.xml');assert.equal(f.assets.get(f.unrelated.id).name,'unchanged.zip');
 assert.ok([...f.assets.values()].some(a=>a.name.endsWith('.pending.xml')));
}));

test('GitHub API redirect is rejected without forwarding authentication',async()=>{
 const original=globalThis.fetch;let calls=0;
 globalThis.fetch=async(_url,options)=>{calls++;assert.equal(options.redirect,'manual');return new Response(null,{status:302,headers:{location:'https://untrusted.invalid'}});};
 try{await assert.rejects(githubTransport({},'synthetic-token').latest(),/HTTP 302/);assert.equal(calls,1);}finally{globalThis.fetch=original;}
});
test('canonical manifest readback is bound to the new asset despite an old cached redirect',()=>withMock(async(f,t)=>{
 f.cacheCanonical();await t.promote(f.bundle,f.previous,'20261015T120000Z-aaaaaaaa');
 const publicReads=f.calls.filter(x=>new URL(x.url).hostname==='github.com');
 assert.ok(publicReads.every(x=>new URL(x.url).searchParams.has('asset_id')));
}));
