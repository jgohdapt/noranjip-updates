import {compareVersions} from './manifest.mjs';
import {assertSameReleaseVersion} from './common-version.mjs';

// The transport implements GitHub operations. Keeping sequencing independent lets
// tests prove failure/retry behavior without changing a real update channel.
export async function publishTogether(request,bundles,transport,save){
  if(request.schema!==1||!/^[0-9a-f]{40}$/.test(request.sourceCommit)||!/^\d{8}T\d{6}Z-[0-9a-f]{8}$/.test(request.id))throw new Error('Invalid release request');
  if(Object.keys(bundles).sort().join(',')!=='server1,server2')throw new Error('Both server bundles are required');
  assertSameReleaseVersion(request.servers);
  const state={schema:1,id:request.id,sourceCommit:request.sourceCommit,status:'checking',servers:{server1:'pending',server2:'pending'},startedUtc:new Date().toISOString()};
  const write=async()=>save({...state,servers:{...state.servers}});
  await write();
  try{
    const latest=await transport.latest();
    for(const p of ['server1','server2']){
      const b=bundles[p],r=request.servers?.[p];
      if(!r||b.sourceCommit!==request.sourceCommit||b.manifest.profile!==p||b.manifest.version!==r.version||b.manifest.manifestSha256!==r.manifestSha256)throw new Error(`Bundle/request mismatch: ${p}`);
      const current=await transport.stable(p);
      // A retry may find one or both channels already promoted. Otherwise an
      // exact previous manifest and a strictly higher version are mandatory.
      if(current.manifestSha256===b.manifest.manifestSha256)state.servers[p]='already-published';
      else if(current.manifestSha256!==r.previousManifestSha256||compareVersions(b.manifest.version,current.version)<=0)throw new Error(`Stable changed since preparation: ${p}`);
    }
    state.status='immutable';await write();
    // Both immutable releases must be verified before either stable changes.
    for(const p of ['server1','server2'])await transport.ensureVersion(bundles[p]);
    state.status='promoting';await write();
    for(const p of ['server1','server2']){
      if(state.servers[p]==='already-published')continue;
      const current=await transport.stable(p);
      if(current.manifestSha256!==request.servers[p].previousManifestSha256)throw new Error(`Concurrent channel change: ${p}`);
      state.servers[p]='promotion-started';await write();
      await transport.promote(bundles[p],current,request.id);
      const after=await transport.stable(p);
      if(after.manifestSha256!==bundles[p].manifest.manifestSha256)throw new Error(`Stable readback failed: ${p}`);
      state.servers[p]='published';await write();
    }
    if((await transport.latest()).id!==latest.id)throw new Error('Global Latest release changed; investigate before reporting success');
    state.status='complete';state.completedUtc=new Date().toISOString();await write();return state;
  }catch(error){
    state.status=Object.values(state.servers).some(x=>['published','already-published','promotion-started'].includes(x))?'partial-or-uncertain':'failed-before-promotion';
    state.error=error.message;state.completedUtc=new Date().toISOString();await write();throw error;
  }
}
