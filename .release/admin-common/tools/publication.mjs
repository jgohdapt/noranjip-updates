import {compareVersions} from './manifest.mjs';
import {assertSameReleaseVersion,targetProfiles,untargetedProfiles} from './common-version.mjs';

// The transport implements GitHub operations. Keeping sequencing independent lets
// tests prove failure/retry behavior without changing a real update channel.
export async function publishTogether(request,bundles,transport,save){
  if(request.schema!==1||!/^[0-9a-f]{40}$/.test(request.sourceCommit)||!/^\d{8}T\d{6}Z-[0-9a-f]{8}$/.test(request.id))throw new Error('Invalid release request');
  const target=request.target??'both',profiles=targetProfiles(target),untargeted=untargetedProfiles(target);
  if(Object.keys(bundles).sort().join(',')!==profiles.join(','))throw new Error(target==='both'?'Both server bundles are required':'Bundle set does not match the release target');
  assertSameReleaseVersion(request.servers,target);
  const preserved=request.preserved??{};
  if(Object.keys(preserved).sort().join(',')!==untargeted.join(',')||untargeted.some(p=>!/^[A-F0-9]{64}$/.test(preserved[p]?.manifestSha256||'')))throw new Error('Untargeted channel proof does not match the release target');
  const state={schema:1,id:request.id,sourceCommit:request.sourceCommit,target,status:'checking',servers:Object.fromEntries(profiles.map(p=>[p,'pending'])),...(untargeted.length?{untargeted:Object.fromEntries(untargeted.map(p=>[p,'not-checked']))}:{}),startedUtc:new Date().toISOString()};
  const write=async()=>save({...state,servers:{...state.servers},...(state.untargeted?{untargeted:{...state.untargeted}}:{})});
  // Untargeted channels are only read: their signed stable manifest must stay byte-identical.
  const checkUntargeted=async label=>{for(const p of untargeted){if((await transport.stable(p)).manifestSha256!==preserved[p].manifestSha256){state.untargeted[p]='changed-outside-this-release';throw new Error(`Untargeted channel changed ${label}: ${p}`);}state.untargeted[p]='unchanged-verified';}};
  await write();
  try{
    const latest=await transport.latest();
    await checkUntargeted('since preparation');
    for(const p of profiles){
      const b=bundles[p],r=request.servers?.[p];
      if(!r||b.sourceCommit!==request.sourceCommit||b.manifest.profile!==p||b.manifest.version!==r.version||b.manifest.manifestSha256!==r.manifestSha256)throw new Error(`Bundle/request mismatch: ${p}`);
      const current=await transport.stable(p);
      // A retry may find one or both channels already promoted. Otherwise an
      // exact previous manifest and a strictly higher version are mandatory.
      if(current.manifestSha256===b.manifest.manifestSha256)state.servers[p]='already-published';
      else if(current.manifestSha256!==r.previousManifestSha256||(!current.missing&&compareVersions(b.manifest.version,current.version)<=0))throw new Error(`Stable changed since preparation: ${p}`);
    }
    state.status='immutable';await write();
    // Every targeted immutable release must be verified before any stable changes.
    for(const p of profiles)await transport.ensureVersion(bundles[p]);
    state.status='promoting';await write();
    for(const p of profiles){
      if(state.servers[p]==='already-published')continue;
      const current=await transport.stable(p);
      if(current.manifestSha256!==request.servers[p].previousManifestSha256)throw new Error(`Concurrent channel change: ${p}`);
      state.servers[p]='promotion-started';await write();
      await transport.promote(bundles[p],current,request.id);
      const after=await transport.stable(p);
      if(after.manifestSha256!==bundles[p].manifest.manifestSha256)throw new Error(`Stable readback failed: ${p}`);
      state.servers[p]='published';await write();
    }
    await checkUntargeted('during publication');
    if((await transport.latest()).id!==latest.id)throw new Error('Global Latest release changed; investigate before reporting success');
    state.status='complete';state.completedUtc=new Date().toISOString();await write();return state;
  }catch(error){
    state.status=Object.values(state.servers).some(x=>['published','already-published','promotion-started'].includes(x))?'partial-or-uncertain':'failed-before-promotion';
    state.error=error.message;state.completedUtc=new Date().toISOString();await write();throw error;
  }
}
