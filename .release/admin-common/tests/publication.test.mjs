import {test} from 'node:test';
import assert from 'node:assert/strict';
import {publishTogether} from '../tools/publication.mjs';
function fixture(){
 const commit='a'.repeat(40),events=[],saved=[];
 const current={server1:{version:'0.2.3.44',manifestSha256:'old1'},server2:{missing:true,version:'0.0.0.0',manifestSha256:null}};
 const request={schema:1,id:'20261015T120000Z-aaaaaaaa',sourceCommit:commit,servers:{server1:{version:'0.3.0.0',previousManifestSha256:'old1',manifestSha256:'new1'},server2:{version:'0.3.0.0',previousManifestSha256:null,manifestSha256:'new2'}}};
 const bundles=Object.fromEntries(['server1','server2'].map((p,i)=>[p,{sourceCommit:commit,manifest:{profile:p,version:'0.3.0.0',manifestSha256:'new'+(i+1)}}]));
 const transport={latest:async()=>({id:10}),stable:async p=>current[p],ensureVersion:async b=>events.push('verify:'+b.manifest.profile),promote:async b=>{events.push('promote:'+b.manifest.profile);current[b.manifest.profile]=b.manifest;}};
 return {request,bundles,transport,current,events,saved,save:async s=>saved.push(s)};
}
test('initial administrator publication verifies both before either channel changes',async()=>{const f=fixture();assert.equal((await publishTogether(f.request,f.bundles,f.transport,f.save)).status,'complete');assert.deepEqual(f.events,['verify:server1','verify:server2','promote:server1','promote:server2']);});
test('second validation failure leaves first stable unchanged',async()=>{const f=fixture();f.transport.ensureVersion=async b=>{if(b.manifest.profile==='server2')throw Error('bad package');};await assert.rejects(publishTogether(f.request,f.bundles,f.transport,f.save));assert.equal(f.current.server1.manifestSha256,'old1');assert.equal(f.saved.at(-1).status,'failed-before-promotion');});
test('new channel appearing concurrently prevents publication',async()=>{const f=fixture();f.current.server2={version:'0.3.0.0',manifestSha256:'other'};await assert.rejects(publishTogether(f.request,f.bundles,f.transport,f.save));assert.deepEqual(f.events,[]);});
test('partial initial rollout retries without overwriting the completed channel',async()=>{const f=fixture(),promote=f.transport.promote;f.transport.promote=async b=>{if(b.manifest.profile==='server2')throw Error('network');await promote(b);};await assert.rejects(publishTogether(f.request,f.bundles,f.transport,f.save));assert.equal(f.saved.at(-1).status,'partial-or-uncertain');f.transport.promote=promote;const r=await publishTogether(f.request,f.bundles,f.transport,f.save);assert.equal(r.status,'complete');assert.equal(r.servers.server1,'already-published');});
test('different source, different version and downgrade fail before mutations',async()=>{for(const mode of ['source','version','downgrade']){const f=fixture();if(mode==='source')f.bundles.server2.sourceCommit='b'.repeat(40);if(mode==='version')f.request.servers.server2.version='0.3.0.1';if(mode==='downgrade')f.current.server1.version='0.3.0.1';await assert.rejects(publishTogether(f.request,f.bundles,f.transport,f.save));assert.deepEqual(f.events,[]);}});
function server2Only(){
 const f=fixture(),reads=[];
 f.current.server1={version:'0.3.0.1',manifestSha256:'C'.repeat(64)};f.current.server2={version:'0.3.0.1',manifestSha256:'old2'};
 f.request={schema:1,id:'20261030T120000Z-bbbbbbbb',sourceCommit:f.request.sourceCommit,target:'server2',servers:{server2:{version:'0.3.0.2',previousManifestSha256:'old2',manifestSha256:'new2'}},preserved:{server1:{version:'0.3.0.1',manifestSha256:'C'.repeat(64)}}};
 f.bundles={server2:{...f.bundles.server2,manifest:{profile:'server2',version:'0.3.0.2',manifestSha256:'new2'}}};
 const stable=f.transport.stable;f.transport.stable=async p=>{reads.push(p);return stable(p);};
 return {...f,reads,server1Before:JSON.stringify(f.current.server1)};
}
test('server2-only target writes only server2 and proves server1 stable unchanged before and after',async()=>{
 const f=server2Only(),r=await publishTogether(f.request,f.bundles,f.transport,f.save);
 assert.equal(r.status,'complete');assert.equal(r.target,'server2');assert.deepEqual(r.servers,{server2:'published'});assert.deepEqual(r.untargeted,{server1:'unchanged-verified'});
 assert.deepEqual(f.events,['verify:server2','promote:server2']);assert.equal(JSON.stringify(f.current.server1),f.server1Before);
 assert.equal(f.reads.filter(p=>p==='server1').length,2);assert.ok(f.saved.every(s=>!('server1' in s.servers)));
});
test('server2-only retry is idempotent and never touches server1',async()=>{
 const f=server2Only();await publishTogether(f.request,f.bundles,f.transport,f.save);f.events.length=0;
 const r=await publishTogether(f.request,f.bundles,f.transport,f.save);assert.equal(r.servers.server2,'already-published');assert.deepEqual(f.events,['verify:server2']);assert.equal(JSON.stringify(f.current.server1),f.server1Before);
});
test('untargeted server1 change stops before mutation or is reported truthfully after',async()=>{
 const before=server2Only();before.current.server1={version:'0.3.0.2',manifestSha256:'X'.repeat(64)};
 await assert.rejects(publishTogether(before.request,before.bundles,before.transport,before.save),/Untargeted channel changed since preparation: server1/);
 assert.deepEqual(before.events,[]);assert.equal(before.saved.at(-1).status,'failed-before-promotion');assert.equal(before.saved.at(-1).untargeted.server1,'changed-outside-this-release');
 const during=server2Only(),promote=during.transport.promote;during.transport.promote=async(b,c,id)=>{await promote(b,c,id);during.current.server1={version:'0.3.0.2',manifestSha256:'X'.repeat(64)};};
 await assert.rejects(publishTogether(during.request,during.bundles,during.transport,during.save),/during publication: server1/);
 assert.equal(during.saved.at(-1).status,'partial-or-uncertain');assert.equal(during.saved.at(-1).servers.server2,'published');
});
test('server2-only partial failure and authentication failure keep both stables and record truthful status',async()=>{
 const auth=server2Only();auth.transport.ensureVersion=async()=>{throw Error('GitHub POST /releases: HTTP 401');};
 await assert.rejects(publishTogether(auth.request,auth.bundles,auth.transport,auth.save),/HTTP 401/);
 assert.equal(auth.saved.at(-1).status,'failed-before-promotion');assert.equal(auth.current.server2.manifestSha256,'old2');assert.equal(JSON.stringify(auth.current.server1),auth.server1Before);
 const partial=server2Only();partial.transport.promote=async()=>{throw Error('network');};
 await assert.rejects(publishTogether(partial.request,partial.bundles,partial.transport,partial.save));
 assert.equal(partial.saved.at(-1).status,'partial-or-uncertain');assert.equal(partial.saved.at(-1).servers.server2,'promotion-started');assert.equal(JSON.stringify(partial.current.server1),partial.server1Before);
});
test('invalid targets and inconsistent bundle, request or preservation sets fail before any mutation',async()=>{
 const cases=[
  f=>{f.request.target='server1';},f=>{f.request.target='all';},f=>{f.request.target=['server2'];},
  f=>{f.bundles.server1={sourceCommit:f.request.sourceCommit,manifest:{profile:'server1',version:'0.3.0.2',manifestSha256:'new1'}};},
  f=>{f.request.servers.server1={version:'0.3.0.2',previousManifestSha256:'old1',manifestSha256:'new1'};},
  f=>{delete f.request.preserved;},f=>{f.request.preserved.server1.manifestSha256='short';},f=>{f.request.preserved.server2=f.request.preserved.server1;},
  f=>{f.request.target='both';},f=>{f.bundles.server2.sourceCommit='b'.repeat(40);},f=>{f.bundles.server2.manifest.version='0.3.0.3';}
 ];
 for(const change of cases){const f=server2Only();change(f);await assert.rejects(publishTogether(f.request,f.bundles,f.transport,f.save));assert.deepEqual(f.events,[]);assert.equal(JSON.stringify(f.current.server1),f.server1Before);}
});
test('legacy request without target and explicit both target behave identically',async()=>{
 const legacy=fixture(),explicit=fixture();explicit.request.target='both';
 const a=await publishTogether(legacy.request,legacy.bundles,legacy.transport,legacy.save),b=await publishTogether(explicit.request,explicit.bundles,explicit.transport,explicit.save);
 assert.deepEqual(legacy.events,explicit.events);assert.deepEqual(a.servers,b.servers);assert.equal(a.target,'both');assert.equal(a.untargeted,undefined);
 const preserved=fixture();preserved.request.preserved={server1:{manifestSha256:'A'.repeat(64)}};await assert.rejects(publishTogether(preserved.request,preserved.bundles,preserved.transport,preserved.save));assert.deepEqual(preserved.events,[]);
});
