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
