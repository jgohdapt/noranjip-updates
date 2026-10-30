import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {fixed,assertRequest,loadBundle,server1Only,publishServer1Only} from './publish.mjs';
import {githubTransport} from '../common/tools/github-publication.mjs';
import {readJson,verifyManifest} from '../common/tools/manifest.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
const keyFile=path.join(here,'..','common','keys','server1.xml');
const request=()=>readJson(path.join(here,'request.json'));
const bundle=()=>({sourceCommit:fixed.sourceCommit,manifest:{profile:'server1',version:fixed.version,tag:'remote-v2-'+fixed.version,packageName:`remote-${fixed.version}.zip`,manifestSha256:fixed.manifestSha256,packageSha256:'P'.repeat(64),exeSha256:'E'.repeat(64)},manifestBytes:Buffer.from('new'),packageBytes:Buffer.from('zip')});

function fake({stable=fixed.previousManifestSha256,version=fixed.previousVersion,failImmutable=false,changeBeforePromote=false}={}){
  const events=[],saved=[];let current={version,manifestSha256:stable,releaseId:10,assetId:11},reads=0;
  const inner={
    latest:async()=>{events.push('latest');return {id:1,tag_name:'other'};},
    stable:async p=>{events.push('stable:'+p);reads++;if(changeBeforePromote&&reads===2)current={...current,manifestSha256:'C'.repeat(64)};return {...current};},
    ensureVersion:async b=>{events.push('immutable:'+b.manifest.profile);if(failImmutable)throw new Error('Uploaded asset readback mismatch');},
    promote:async b=>{events.push('promote:'+b.manifest.profile);current={version:b.manifest.version,manifestSha256:b.manifest.manifestSha256,releaseId:10,assetId:99};}
  };
  return {events,saved,save:s=>saved.push(s),transport:server1Only(inner)};
}

test('committed request carries the explicit server1-only authorization and fixed hashes',()=>{
  assertRequest(request());
  for(const change of [r=>{r.servers={server2:{}};},r=>{r.version='0.9.0.3';},r=>{r.authorization.server2='authorized';},r=>{r.previousManifestSha256='0'.repeat(64);},r=>{delete r.authorization;}]){
    const r=request();change(r);assert.throws(()=>assertRequest(r));
  }
});

test('server1-only wrapper refuses every server2 operation before the transport is reached',async()=>{
  const calls=[],t=server1Only({latest:async()=>calls.push('latest'),stable:async()=>calls.push('stable'),ensureVersion:async()=>calls.push('ensure'),promote:async()=>calls.push('promote')});
  assert.throws(()=>t.stable('server2'));
  assert.throws(()=>t.ensureVersion({manifest:{profile:'server2'}}));
  assert.throws(()=>t.promote({manifest:{profile:'server2'}},{},'x'));
  assert.deepEqual(calls,[]);
});

test('success: immutable precedes promotion, result persisted before and after promotion',async()=>{
  const f=fake(),r=await publishServer1Only(request(),bundle(),f.transport,f.save);
  assert.equal(r.status,'complete');assert.equal(r.server1,'published');
  assert.deepEqual(f.events,['latest','stable:server1','immutable:server1','stable:server1','promote:server1','stable:server1','latest']);
  assert.ok(f.events.every(e=>!e.includes('server2')));
  const statuses=f.saved.map(s=>s.server1);
  assert.ok(statuses.indexOf('promotion-started')>=0&&statuses.indexOf('promotion-started')<statuses.indexOf('published'));
  assert.equal(r.server2,'not-touched-deferred');
  assert.doesNotMatch(JSON.stringify(f.saved),/token|Bearer|RSAKeyValue|Modulus/i);
});

test('mismatched previous stable refuses before any immutable or promotion step',async()=>{
  for(const opts of [{stable:'A'.repeat(64)},{version:'0.9.0.0'}]){
    const f=fake(opts);
    await assert.rejects(publishServer1Only(request(),bundle(),f.transport,f.save),/expected previous/);
    assert.deepEqual(f.events,['latest','stable:server1']);
    assert.equal(f.saved.at(-1).status,'failed-before-promotion');
  }
});

test('concurrent change after immutable verification refuses promotion',async()=>{
  const f=fake({changeBeforePromote:true});
  await assert.rejects(publishServer1Only(request(),bundle(),f.transport,f.save),/Concurrent/);
  assert.ok(!f.events.some(e=>e.startsWith('promote')));
  assert.equal(f.saved.at(-1).status,'failed-before-promotion');
});

test('immutable failure prevents promotion',async()=>{
  const f=fake({failImmutable:true});
  await assert.rejects(publishServer1Only(request(),bundle(),f.transport,f.save),/readback/);
  assert.ok(!f.events.some(e=>e.startsWith('promote')));
  assert.equal(f.saved.at(-1).status,'failed-before-promotion');
});

test('already-published exact hash verifies immutable bytes and finishes without promotion',async()=>{
  const f=fake({stable:fixed.manifestSha256,version:fixed.version}),r=await publishServer1Only(request(),bundle(),f.transport,f.save);
  assert.equal(r.status,'complete');assert.equal(r.server1,'already-published');assert.equal(r.immutable,'verified');
  assert.deepEqual(f.events,['latest','stable:server1','immutable:server1','stable:server1','latest']);
});

test('already-published hash with a different version is a conflict',async()=>{
  const f=fake({stable:fixed.manifestSha256,version:'0.9.0.1'});
  await assert.rejects(publishServer1Only(request(),bundle(),f.transport,f.save),/version differs/);
  assert.deepEqual(f.events,['latest','stable:server1']);
});

// Real existing transport on a mocked GitHub network, using the committed and
// genuinely signed 0.9.0.1 server1 manifest as the current stable.
const previousFile=path.join(here,'..','common','requests','20261023T093814Z-cbfde09f','server1','remote-manifest.xml');
function previousUsable(){try{verifyManifest(fs.readFileSync(previousFile),fs.readFileSync(keyFile),'server1');return true;}catch{return false;}}
function mockGitHub(previousBytes,{corruptUploads=false}={}){
  const calls=[],assets=new Map(),releases=new Map([['remote-v2-stable',{id:10,tag_name:'remote-v2-stable',draft:false,prerelease:false}]]);let next=100;
  const add=(releaseId,name,bytes)=>{const a={id:next++,releaseId,name,bytes:Buffer.from(bytes)};assets.set(a.id,a);return a;};
  const view=a=>({id:a.id,name:a.name,size:a.bytes.length,browser_download_url:`https://github.com/jgohdapt/noranjip-updates/releases/download/${[...releases.values()].find(r=>r.id===a.releaseId).tag_name}/${a.name}`});
  add(10,'remote-manifest.xml',previousBytes);
  const fetch=async(url,o={})=>{
    const u=new URL(url),method=o.method||'GET';calls.push(method+' '+url);
    if(u.hostname==='github.com'){assert.equal(o.headers?.Authorization,undefined);const a=assets.get(Number(u.searchParams.get('asset_id')));return new Response(a?.bytes,{status:a?200:404});}
    if(u.pathname.endsWith('/releases/latest'))return Response.json({id:1,tag_name:'other-latest'});
    if(u.pathname.includes('/releases/tags/')){const r=releases.get(decodeURIComponent(u.pathname.split('/').pop()));return Response.json(r||{},{status:r?200:404});}
    if(method==='POST'&&u.pathname.endsWith('/releases')){const b=JSON.parse(o.body);assert.equal(b.make_latest,'false');const r={...b,id:200};releases.set(b.tag_name,r);return Response.json(r);}
    const ra=/\/releases\/(\d+)\/assets$/.exec(u.pathname);
    if(ra&&method==='GET')return Response.json([...assets.values()].filter(a=>a.releaseId===Number(ra[1])).map(view));
    if(ra&&method==='POST')return Response.json(view(add(Number(ra[1]),u.searchParams.get('name'),corruptUploads?Buffer.from('corrupt'):o.body)));
    const pa=/\/releases\/assets\/(\d+)$/.exec(u.pathname);
    if(pa&&method==='PATCH'){const a=assets.get(Number(pa[1]));a.name=JSON.parse(o.body).name;return Response.json(view(a));}
    return new Response('unexpected',{status:500});
  };
  return {calls,assets,fetch};
}
async function withFetch(mock,run){const saved=globalThis.fetch;globalThis.fetch=mock.fetch;try{return await run();}finally{globalThis.fetch=saved;}}
const realTransport=()=>server1Only(githubTransport({server1:fs.readFileSync(keyFile)},'synthetic-token'));

test('real transport: immutable readback failure stops before any stable change and never addresses server2',{skip:!previousUsable()&&'committed 0.9.0.1 manifest expired'},async()=>{
  const g=mockGitHub(fs.readFileSync(previousFile),{corruptUploads:true}),saved=[];
  await assert.rejects(withFetch(g,()=>publishServer1Only(request(),bundle(),realTransport(),s=>saved.push(s))),/readback/);
  assert.ok(!g.calls.some(c=>c.startsWith('PATCH')));
  assert.ok(!g.calls.some(c=>/server2/i.test(c)));
  assert.ok([...g.assets.values()].some(a=>a.releaseId===10&&a.name==='remote-manifest.xml'));
  assert.equal(saved.at(-1).status,'failed-before-promotion');
});

// After the coordinator copies the signed manifest and ZIP, the real bundle must
// verify against the pinned key and publish end-to-end on the mocked network.
const signed=path.join(here,'server1');
const signedPresent=fs.existsSync(path.join(signed,'remote-manifest.xml'));
test('real signed bundle: pinned key, manifest hash, package and exe hash',{skip:!signedPresent&&process.env.GITHUB_ACTIONS!=='true'&&'signed files not copied yet'},()=>{
  const {bundle:b,exe}=loadBundle(signed,keyFile);
  assert.equal(b.manifest.manifestSha256,fixed.manifestSha256);assert.equal(exe.sha256,b.manifest.exeSha256);
});
test('real signed bundle: end-to-end server1 promotion preserves previous archive and Latest',{skip:!(signedPresent&&previousUsable())&&'signed files not copied yet or previous expired'},async()=>{
  const {bundle:b}=loadBundle(signed,keyFile),g=mockGitHub(fs.readFileSync(previousFile)),saved=[];
  const r=await withFetch(g,()=>publishServer1Only(request(),b,realTransport(),s=>saved.push(s)));
  assert.equal(r.status,'complete');
  assert.ok(!g.calls.some(c=>/server2/i.test(c)));
  assert.ok([...g.assets.values()].some(a=>a.releaseId===10&&a.name===`remote-manifest-${fixed.previousVersion}-${fixed.id}.xml`));
  const retry=await withFetch(g,()=>publishServer1Only(request(),b,realTransport(),()=>{}));
  assert.equal(retry.server1,'already-published');
});
