import {test} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {fixed,unselected,binding,assertRequest,verifyBundle,loadBundle,server2Only,publishServer2Only} from './publish.mjs';
import {githubTransport} from '../common/tools/github-publication.mjs';
import {targets,sha256,readJson,verifyManifest} from '../common/tools/manifest.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
const keyDir=path.join(here,'..','common','keys');
const realKeys=()=>({server1:fs.readFileSync(path.join(keyDir,'server1.xml')),server2:fs.readFileSync(path.join(keyDir,'server2.xml'))});

// Synthetic signer and ZIP; no product bytes or private key material are used.
const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:3072});
const jwk=publicKey.export({format:'jwk'});
const testKey=Buffer.from(`<RSAKeyValue><Modulus>${Buffer.from(jwk.n,'base64url').toString('base64')}</Modulus><Exponent>${Buffer.from(jwk.e,'base64url').toString('base64')}</Exponent></RSAKeyValue>`);
const testOptions={expectedKeyHash:sha256(testKey)};
function zipFixture(name=binding.entry,body=Buffer.from('synthetic executable, not a product')){
  const n=Buffer.from(name);
  const local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50);local.writeUInt16LE(0x800,6);local.writeUInt32LE(body.length,18);local.writeUInt32LE(body.length,22);local.writeUInt16LE(n.length,26);
  const central=Buffer.alloc(46);central.writeUInt32LE(0x02014b50);central.writeUInt16LE(0x800,8);central.writeUInt32LE(body.length,20);central.writeUInt32LE(body.length,24);central.writeUInt16LE(n.length,28);
  const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(46+n.length,12);end.writeUInt32LE(30+n.length+body.length,16);
  return {zip:Buffer.concat([local,n,body,central,n,end]),exe:body};
}
function sign({version=fixed.version,entry=binding.entry,url=binding.packageUrl,expires='2027-11-01T00:00:00Z',zip,exe}){
  const p=Buffer.from(`<componentUpdate format="2" channel="server-stable" component="remote-client" version="${version}" minProtocol="1" maxProtocol="1" expiresUtc="${expires}" packageUrl="${url}" packageSha256="${sha256(zip)}" packageBytes="${zip.length}" entry="${entry}"><files><file name="${entry}" sha256="${sha256(exe)}" bytes="${exe.length}" /></files></componentUpdate>`);
  return Buffer.from(`<signedComponentUpdate format="2"><payload>${p.toString('base64')}</payload><signature>${crypto.sign('RSA-SHA256',p,privateKey).toString('base64')}</signature></signedComponentUpdate>`);
}
// The request Codex writes after the build has exactly this shape.
function requestFor({manifestBytes,zip,exe}){
  return {schema:1,id:fixed.id,scope:fixed.scope,
    authorization:{date:'2026-11-01',server2:'authorized',server1:'unselected'},
    profile:'server2',version:fixed.version,sourceCommit:fixed.sourceCommit,previousVersion:fixed.previousVersion,previousManifestSha256:fixed.previousManifestSha256,
    unselected:{server1:{...unselected.server1}},
    signed:{...binding,manifestSha256:sha256(manifestBytes),packageSha256:sha256(zip),packageBytes:zip.length,exeSha256:sha256(exe),exeBytes:exe.length}};
}
function synthetic(opts={}){
  const {zip,exe}=zipFixture(opts.entry),manifestBytes=sign({zip,exe,...opts});
  return {manifestBytes,zip,exe,request:requestFor({manifestBytes,zip,exe})};
}
const good=synthetic();
const goodBundle=()=>verifyBundle(good.request,{manifestBytes:good.manifestBytes,packageBytes:good.zip,keyBytes:testKey},testOptions).bundle;
const req=()=>structuredClone(good.request);

test('fixed scope is server2-only 0.9.0.3 from the stated source with server1 unselected',()=>{
  assert.deepEqual({...fixed},{schema:1,id:'20261101T092310Z-8e0751cf',scope:'server2-only',profile:'server2',version:'0.9.0.3',sourceCommit:'40ec1d55f5bb09d40f3a81e57be06bb05d3dd67b',previousVersion:'0.9.0.1',previousManifestSha256:'5D2CA0ADEA7E0C24426BE709F6A3EB7AF2BADDB8808C13CFB538DB25E7312DC2'});
  assert.deepEqual({...unselected.server1},{version:'0.9.0.2',manifestSha256:'4234E10CC6989EFBC9E9173CB8C4EEB484266C2A44798C6B320B5B1A20AECEE4'});
  assert.deepEqual({...binding},{signerKeySha256:targets.server2.keyHash,tag:'server2-remote-0.9.0.3',packageName:'remote-0.9.0.3.zip',packageUrl:'https://github.com/jgohdapt/noranjip-updates/releases/download/server2-remote-0.9.0.3/remote-0.9.0.3.zip',entry:targets.server2.entry});
});

test('strict request: exact keys, fixed values and well-formed signed digests only',()=>{
  assertRequest(req());
  const mutations=[
    r=>{r.version='0.9.0.4';},r=>{r.profile='server1';},r=>{r.scope='both';},r=>{r.id='20261101T000000Z-00000000';},r=>{r.sourceCommit='0'.repeat(40);},
    r=>{r.previousVersion='0.9.0.2';},r=>{r.previousManifestSha256='0'.repeat(64);},r=>{r.servers={server1:{}};},r=>{delete r.authorization;},
    r=>{r.authorization.server1='authorized';},r=>{r.authorization.date='2026-10-30';},r=>{r.authorization.note='x';},
    r=>{r.unselected.server1.version='0.9.0.3';},r=>{r.unselected.server1.manifestSha256='0'.repeat(64);},r=>{r.unselected.server2={};},
    r=>{r.signed.tag='remote-v2-0.9.0.3';},r=>{r.signed.packageUrl=r.signed.packageUrl.replace('server2-remote','remote-v2');},r=>{r.signed.entry=targets.server1.entry;},
    r=>{r.signed.signerKeySha256=targets.server1.keyHash;},r=>{r.signed.packageName='remote-0.9.0.2.zip';},r=>{r.signed.extra=1;},
    r=>{r.signed.manifestSha256=r.signed.manifestSha256.toLowerCase();},r=>{r.signed.exeSha256='Z'.repeat(64);},r=>{r.signed.packageBytes=String(r.signed.packageBytes);},
    r=>{r.signed.exeBytes=0;},r=>{r.signed.manifestSha256=fixed.previousManifestSha256;},r=>{r.signed.manifestSha256=unselected.server1.manifestSha256;},r=>{delete r.signed.exeSha256;}
  ];
  for(const change of mutations){const r=req();change(r);assert.throws(()=>assertRequest(r),undefined,String(change));}
  assert.throws(()=>assertRequest(null));assert.throws(()=>assertRequest([]));
});

test('signed bundle binds pinned signer, manifest digest, tag/URL/entry, ZIP and exe',()=>{
  const {bundle:b,exe}=verifyBundle(good.request,{manifestBytes:good.manifestBytes,packageBytes:good.zip,keyBytes:testKey},testOptions);
  assert.equal(b.manifest.tag,binding.tag);assert.equal(b.manifest.packageUrl,binding.packageUrl);assert.equal(exe.sha256,sha256(good.exe));
  const check=(r,manifestBytes,packageBytes,pattern,options=testOptions)=>assert.throws(()=>verifyBundle(r,{manifestBytes,packageBytes,keyBytes:testKey},options),pattern);
  check(good.request,good.manifestBytes,good.zip,/Pinned/,{});
  const flipped=Buffer.from(good.manifestBytes);flipped[60]^=1;check(good.request,flipped,good.zip,/requested digest/);
  check({...req(),signed:{...req().signed,manifestSha256:sha256(flipped)}},flipped,good.zip,/signature|base64|envelope/);
  for(const k of ['packageSha256','exeSha256'])check({...req(),signed:{...req().signed,[k]:'A'.repeat(64)}},good.manifestBytes,good.zip,new RegExp(k));
  for(const k of ['packageBytes','exeBytes'])check({...req(),signed:{...req().signed,[k]:req().signed[k]+1}},good.manifestBytes,good.zip,new RegExp(k));
  const zip=Buffer.from(good.zip);zip[40]^=1;check(good.request,good.manifestBytes,zip,/Package hash/);
  const resigned=[synthetic({version:'0.9.0.4',url:binding.packageUrl.replaceAll('0.9.0.3','0.9.0.4')}),synthetic({url:binding.packageUrl.replace('server2-remote','remote-v2')}),synthetic({entry:targets.server1.entry}),synthetic({expires:'2026-01-01T00:00:00Z'})];
  for(const x of resigned)check(x.request,x.manifestBytes,x.zip,/./);
  // Signed manifest names a different executable hash than the ZIP really holds.
  const other=zipFixture(binding.entry,Buffer.from('synthetic executable, NOT a product')),lying=sign({zip:other.zip,exe:good.exe}),r=requestFor({manifestBytes:lying,zip:other.zip,exe:good.exe});
  check(r,lying,other.zip,/Executable hash/);
});

test('bundle directory must contain only the signed manifest and ZIP',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'server2-0903-'));
  try{
    fs.writeFileSync(path.join(dir,'remote-manifest.xml'),good.manifestBytes);fs.writeFileSync(path.join(dir,binding.packageName),good.zip);
    assert.throws(()=>loadBundle(dir,testKey,good.request),/Pinned/);
    fs.writeFileSync(path.join(dir,'receipt.json'),'{}');
    assert.throws(()=>loadBundle(dir,testKey,good.request),/only the manifest/);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

test('wrapper refuses every write outside the owned server2 tag/stable before the transport is reached',async()=>{
  const calls=[],t=server2Only({latest:async()=>calls.push('latest'),stable:async p=>calls.push('stable:'+p),ensureVersion:async()=>calls.push('ensure'),promote:async()=>calls.push('promote')},{readPackage:async()=>calls.push('read')});
  const b=goodBundle(),as=(m)=>({...b,manifest:{...b.manifest,...m}});
  for(const x of [as({profile:'server1'}),as({version:'0.9.0.2'}),as({tag:'remote-v2-0.9.0.3'}),as({stable:targets.server1.stable}),{}])assert.throws(()=>t.ensureVersion(x),/Refused/);
  assert.throws(()=>t.promote(as({profile:'server1'}),{},fixed.id),/Refused/);
  assert.throws(()=>t.promote(b,{},'20261030-server1-0902'),/Refused/);
  assert.throws(()=>t.stable('server3'),/Refused/);
  assert.throws(()=>t.readPackage(binding.packageUrl.replace('server2-remote','remote-v2'),10),/Unexpected/);
  assert.deepEqual(calls,[]);
  await t.stable('server1');assert.deepEqual(calls,['stable:server1']);
});

// In-memory transport following the githubTransport contract.
function fake(b,o={}){
  const events=[],saved=[],counts={};
  let s1={version:unselected.server1.version,manifestSha256:unselected.server1.manifestSha256,releaseId:10,assetId:11,bytes:Buffer.from('server1 manifest')};
  let s2={version:fixed.previousVersion,manifestSha256:fixed.previousManifestSha256,releaseId:20,assetId:21,bytes:Buffer.from('previous server2 manifest'),...o.server2};
  const set={server1:v=>{s1={...s1,...v};},server2:v=>{s2={...s2,...v};}};
  const hit=e=>{events.push(e);counts[e]=(counts[e]||0)+1;o.on?.(e,counts[e],set);};
  const inner={
    latest:async()=>{hit('latest');return {id:o.latestChanged&&counts.latest>1?2:1,tag_name:'other'};},
    stable:async p=>{hit('stable:'+p);const s=p==='server1'?s1:s2;return {...s,bytes:Buffer.from(s.bytes)};},
    ensureVersion:async x=>{hit('immutable:'+x.manifest.profile);if(o.failImmutable)throw new Error('Uploaded asset readback mismatch');},
    promote:async x=>{hit('promote:'+x.manifest.profile);if(o.failPromote)throw new Error('GitHub PATCH /releases/assets/21: HTTP 502');s2={version:x.manifest.version,manifestSha256:x.manifest.manifestSha256,releaseId:20,assetId:99,bytes:Buffer.from(o.promotedBytes??x.manifestBytes)};}
  };
  const readPackage=async()=>{hit('package');return o.packageBytes??b.packageBytes;};
  return {events,saved,save:s=>saved.push(s),transport:server2Only(inner,{readPackage})};
}
const run=(f,b=goodBundle())=>publishServer2Only(req(),b,f.transport,f.save);
const writes=f=>f.events.filter(e=>/^(immutable|promote)/.test(e));

test('success: server1 read-only before, before promotion and after; immutable precedes promotion',async()=>{
  const b=goodBundle(),f=fake(b),r=await run(f,b);
  assert.equal(r.status,'complete');assert.equal(r.server2,'published');assert.equal(r.immutable,'verified');
  assert.deepEqual(f.events,['latest','stable:server1','stable:server2','immutable:server2','stable:server2','stable:server1','promote:server2','stable:server2','package','stable:server1','latest']);
  assert.deepEqual(writes(f),['immutable:server2','promote:server2']);
  assert.equal(r.packageReadback.exeSha256,sha256(good.exe));
  for(const k of ['server1Before','server1BeforePromotion','server1After'])assert.deepEqual(r[k],{...unselected.server1,releaseId:10,assetId:11});
  const statuses=f.saved.map(s=>s.server2);assert.ok(statuses.indexOf('promotion-started')>=0&&statuses.indexOf('promotion-started')<statuses.indexOf('published'));
  assert.doesNotMatch(JSON.stringify(f.saved),/token|Bearer|RSAKeyValue|Modulus|PRIVATE/i);
});

test('bundle mutated after verification is refused before any transport call',async()=>{
  for(const change of [b=>{b.manifestBytes[50]^=1;},b=>{b.packageBytes[40]^=1;},b=>{b.sourceCommit='0'.repeat(40);},b=>{b.manifest={...b.manifest,profile:'server1'};}]){
    const b=goodBundle();change(b);const f=fake(b);
    await assert.rejects(run(f,b),/mismatch/);assert.deepEqual(f.events,[]);
  }
});

test('stable drift or unexpected server1 refuses before any write',async()=>{
  for(const o of [{server2:{manifestSha256:'A'.repeat(64)}},{server2:{version:'0.9.0.0'}},{on:(e,n,set)=>e==='stable:server1'&&set.server1({manifestSha256:'B'.repeat(64)})},{on:(e,n,set)=>e==='stable:server1'&&set.server1({version:'0.9.0.3'})}]){
    const f=fake(goodBundle(),o);
    await assert.rejects(run(f),/expected previous|server1/);
    assert.deepEqual(writes(f),[]);assert.equal(f.saved.at(-1).status,'failed-before-mutation');
  }
});

test('server1 or server2 change after the immutable step refuses promotion',async()=>{
  for(const o of [{on:(e,n,set)=>e==='stable:server2'&&n===2&&set.server2({assetId:77})},{on:(e,n,set)=>e==='stable:server1'&&n===2&&set.server1({assetId:12})},{on:(e,n,set)=>e==='stable:server1'&&n===2&&set.server1({manifestSha256:'C'.repeat(64)})}]){
    const f=fake(goodBundle(),o);
    await assert.rejects(run(f),/Concurrent|server1/);
    assert.ok(!f.events.includes('promote:server2'));assert.equal(f.saved.at(-1).status,'partial-version-only');
  }
});

test('version conflict in the immutable step stops before promotion and is reported partial',async()=>{
  const f=fake(goodBundle(),{failImmutable:true});
  await assert.rejects(run(f),/readback/);
  assert.ok(!f.events.includes('promote:server2'));
  const r=f.saved.at(-1);assert.equal(r.status,'partial-version-only');assert.equal(r.immutable,'started');assert.equal(r.server2,'pending');
});

test('failure during or after promotion is uncertain; failure after confirmed publication is published-with-error',async()=>{
  for(const o of [{failPromote:true},{promotedBytes:Buffer.from('other bytes')}]){
    const f=fake(goodBundle(),o);await assert.rejects(run(f));assert.equal(f.saved.at(-1).status,'uncertain');
  }
  for(const [o,pattern] of [[{packageBytes:Buffer.from('cached other zip')},/package readback/],[{latestChanged:true},/Latest/],[{on:(e,n,set)=>e==='stable:server1'&&n===3&&set.server1({manifestSha256:'D'.repeat(64)})},/server1/]]){
    const f=fake(goodBundle(),o);await assert.rejects(run(f),pattern);
    const r=f.saved.at(-1);assert.equal(r.status,'published-with-error');assert.equal(r.server2,'published');
  }
});

test('idempotent rerun: already matching stable verifies bytes and the immutable tag without promotion',async()=>{
  const b=goodBundle(),f=fake(b),first=await run(f,b);assert.equal(first.status,'complete');
  f.events.length=0;const again=await run(f,b);
  assert.equal(again.status,'complete');assert.equal(again.server2,'already-published');assert.equal(again.immutable,'verified');
  assert.deepEqual(f.events,['latest','stable:server1','stable:server2','immutable:server2','stable:server2','package','stable:server1','latest']);
});

test('already matching digest with different version or bytes is a conflict, never repaired',async()=>{
  const b=goodBundle();
  for(const server2 of [{manifestSha256:b.manifest.manifestSha256,version:'0.9.0.1',bytes:b.manifestBytes},{manifestSha256:b.manifest.manifestSha256,version:fixed.version,bytes:Buffer.from('different')}]){
    const f=fake(b,{server2});await assert.rejects(run(f,b),/version or bytes/);assert.deepEqual(writes(f),[]);
  }
  const f=fake(b,{server2:{manifestSha256:b.manifest.manifestSha256,version:fixed.version,bytes:b.manifestBytes},failImmutable:true});
  await assert.rejects(run(f,b),/readback/);assert.equal(f.saved.at(-1).status,'published-with-error');assert.ok(!f.events.includes('promote:server2'));
});

// The real common transport on a mocked GitHub network. Both stables are the
// committed, genuinely signed 0.9.0.2 server1 and 0.9.0.1 server2 manifests.
const server1File=path.join(here,'..','server1-0902','server1','remote-manifest.xml');
const server2File=path.join(here,'..','common','requests','20261023T093814Z-cbfde09f','server2','remote-manifest.xml');
const server1OldFile=path.join(here,'..','common','requests','20261023T093814Z-cbfde09f','server1','remote-manifest.xml');
function stablesUsable(){try{const k=realKeys();verifyManifest(fs.readFileSync(server1File),k.server1,'server1');verifyManifest(fs.readFileSync(server2File),k.server2,'server2');return true;}catch{return false;}}
function mockGitHub({server1Bytes=fs.readFileSync(server1File),server2Bytes=fs.readFileSync(server2File),existingZip=null}={}){
  const calls=[],writes=[],assets=new Map(),releases=new Map();let next=100;
  const addRelease=(tag,id)=>{const r={id,tag_name:tag,draft:false,prerelease:false};releases.set(tag,r);return r;};
  const tagOf=id=>[...releases.values()].find(r=>r.id===id).tag_name;
  const add=(releaseId,name,bytes)=>{const a={id:next++,releaseId,name,bytes:Buffer.from(bytes)};assets.set(a.id,a);return a;};
  const view=a=>({id:a.id,name:a.name,size:a.bytes.length,browser_download_url:`https://github.com/jgohdapt/noranjip-updates/releases/download/${tagOf(a.releaseId)}/${a.name}`});
  addRelease(targets.server1.stable,10);add(10,'remote-manifest.xml',server1Bytes);
  addRelease(targets.server2.stable,20);add(20,'remote-manifest.xml',server2Bytes);add(20,'unrelated.txt',Buffer.from('keep'));
  if(existingZip){addRelease(binding.tag,30);add(30,binding.packageName,existingZip);}
  const fetch=async(url,o={})=>{
    const u=new URL(url),method=o.method||'GET';calls.push(method+' '+url);
    if(u.hostname==='github.com'){
      assert.equal(o.headers?.Authorization,undefined);
      const parts=u.pathname.split('/'),name=decodeURIComponent(parts.pop()),tag=decodeURIComponent(parts.pop());
      const a=u.searchParams.has('asset_id')?assets.get(Number(u.searchParams.get('asset_id'))):[...assets.values()].find(a=>a.name===name&&tagOf(a.releaseId)===tag);
      return new Response(a?.bytes,{status:a?200:404});
    }
    if(u.pathname.endsWith('/releases/latest'))return Response.json({id:1,tag_name:'other-latest'});
    if(u.pathname.includes('/releases/tags/')){const r=releases.get(decodeURIComponent(u.pathname.split('/').pop()));return Response.json(r||{},{status:r?200:404});}
    if(method==='POST'&&u.pathname.endsWith('/releases')){const b=JSON.parse(o.body);assert.equal(b.make_latest,'false');writes.push(b.tag_name);return Response.json(addRelease(b.tag_name,300));}
    const ra=/\/releases\/(\d+)\/assets$/.exec(u.pathname);
    if(ra&&method==='GET')return Response.json([...assets.values()].filter(a=>a.releaseId===Number(ra[1])).map(view));
    if(ra&&method==='POST'){writes.push(tagOf(Number(ra[1])));return Response.json(view(add(Number(ra[1]),u.searchParams.get('name'),o.body)));}
    const pa=/\/releases\/assets\/(\d+)$/.exec(u.pathname);
    if(pa&&method==='PATCH'){const a=assets.get(Number(pa[1]));writes.push(tagOf(a.releaseId));a.name=JSON.parse(o.body).name;return Response.json(view(a));}
    return new Response('unexpected',{status:500});
  };
  return {calls,writes,assets,fetch};
}
async function withFetch(mock,run){const saved=globalThis.fetch;globalThis.fetch=mock.fetch;try{return await run();}finally{globalThis.fetch=saved;}}
const realTransport=()=>server2Only(githubTransport(realKeys(),'synthetic-token'));
const owned=g=>g.writes.every(t=>t===binding.tag||t===targets.server2.stable);
const skipStables=!stablesUsable()&&'committed signed stables expired';

test('real transport: existing version tag with a different ZIP is a conflict and nothing is overwritten',{skip:skipStables},async()=>{
  const g=mockGitHub({existingZip:Buffer.from('a different zip')}),saved=[];
  await assert.rejects(withFetch(g,()=>publishServer2Only(req(),goodBundle(),realTransport(),s=>saved.push(s))),/readback/);
  assert.deepEqual(g.writes,[]);assert.ok(!g.calls.some(c=>/^(PATCH|DELETE)/.test(c)));
  assert.equal(saved.at(-1).status,'partial-version-only');
  assert.deepEqual(saved.at(-1).server1Before,{...unselected.server1,releaseId:10,assetId:100});
});

test('real transport: unexpected signed server1 stable refuses before any write',{skip:skipStables},async()=>{
  const g=mockGitHub({server1Bytes:fs.readFileSync(server1OldFile)}),saved=[];
  await assert.rejects(withFetch(g,()=>publishServer2Only(req(),goodBundle(),realTransport(),s=>saved.push(s))),/server1/);
  assert.deepEqual(g.writes,[]);assert.equal(saved.at(-1).status,'failed-before-mutation');
});

test('real transport: unverifiable post-promotion readback is uncertain, wrote only server2, and preserved assets',{skip:skipStables},async()=>{
  // The synthetic manifest is not signed by the pinned key, so the final readback must fail.
  const g=mockGitHub(),saved=[];
  await assert.rejects(withFetch(g,()=>publishServer2Only(req(),goodBundle(),realTransport(),s=>saved.push(s))),/signature/);
  assert.equal(saved.at(-1).status,'uncertain');assert.ok(owned(g));assert.ok(g.writes.includes(targets.server2.stable));
  const live=[...g.assets.values()];
  assert.ok(live.some(a=>a.releaseId===20&&a.name===`remote-manifest-${fixed.previousVersion}-${fixed.id}.xml`));
  assert.ok(live.some(a=>a.releaseId===20&&a.name==='unrelated.txt'));
  assert.deepEqual(live.filter(a=>a.releaseId===10).map(a=>a.name),['remote-manifest.xml']);
  // A rerun cannot verify the live stable and stops before any further write.
  const before=g.writes.length;
  await assert.rejects(withFetch(g,()=>publishServer2Only(req(),goodBundle(),realTransport(),s=>saved.push(s))));
  assert.equal(g.writes.length,before);assert.equal(saved.at(-1).status,'failed-before-mutation');
});

// After Codex copies the signed bundle and writes request.json, the real files
// must verify here; on GitHub Actions their absence is a failure, never a skip.
const signedDir=path.join(here,'server2'),requestFile=path.join(here,'request.json');
const staged=fs.existsSync(requestFile)||fs.existsSync(signedDir),required=process.env.GITHUB_ACTIONS==='true';
const skipReal=!staged&&!required&&'signed bundle and request not staged yet';
test('real signed bundle: committed request, pinned key, manifest, ZIP and exe',{skip:skipReal},()=>{
  assert.deepEqual(fs.readdirSync(here).sort(),['publish.mjs','publish.test.mjs','request.json','server2']);
  const request=readJson(requestFile),{bundle:b,exe}=loadBundle(signedDir,realKeys().server2,request);
  assert.equal(b.manifest.manifestSha256,request.signed.manifestSha256);assert.equal(exe.sha256,request.signed.exeSha256);assert.equal(exe.bytes,request.signed.exeBytes);
});
test('real signed bundle: end-to-end server2 promotion preserves server1, previous archive and Latest; rerun is idempotent',{skip:skipReal||skipStables},async()=>{
  const request=readJson(requestFile),{bundle:b}=loadBundle(signedDir,realKeys().server2,request),g=mockGitHub(),saved=[];
  const r=await withFetch(g,()=>publishServer2Only(request,b,realTransport(),s=>saved.push(s)));
  assert.equal(r.status,'complete');assert.ok(owned(g));
  assert.deepEqual([...g.assets.values()].filter(a=>a.releaseId===10).map(a=>a.name),['remote-manifest.xml']);
  assert.ok([...g.assets.values()].some(a=>a.releaseId===20&&a.name===`remote-manifest-${fixed.previousVersion}-${fixed.id}.xml`));
  const before=g.writes.length,retry=await withFetch(g,()=>publishServer2Only(request,b,realTransport(),()=>{}));
  assert.equal(retry.server2,'already-published');assert.equal(g.writes.length,before);
});
