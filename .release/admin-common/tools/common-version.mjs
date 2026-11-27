import {compareVersions, versionParts, readJson} from './manifest.mjs';

export function assertCommonVersion(version){
  const parts=versionParts(version);
  if(parts.some(n=>n>65534)||compareVersions(version,'0.3.0.0')<0)throw new Error('Common version must be at least 0.3.0.0 with assembly-compatible components');
  return version;
}
export function readCommonVersion(file){
  const value=readJson(file);
  if(value.schema!==1)throw new Error('Invalid common version schema');
  return assertCommonVersion(value.version);
}
// A release changes both channels (default; older requests carry no target), only the
// server2 channel, or only the server1 channel as the later follow-up of a published
// server2-only release of the same version. An untargeted channel is read and proven unchanged.
export const releaseTargets={both:['server1','server2'],server2:['server2'],server1:['server1']};
export function targetProfiles(target='both'){
  if(typeof target!=='string'||!Object.hasOwn(releaseTargets,target))throw new Error('Unknown administrator release target');
  return releaseTargets[target];
}
export const untargetedProfiles=target=>['server1','server2'].filter(p=>!targetProfiles(target).includes(p));
export function assertSameReleaseVersion(servers,target='both'){
  const profiles=targetProfiles(target);
  if(!servers||Object.keys(servers).sort().join(',')!==profiles.join(','))throw new Error('Server set does not match the release target');
  const version=assertCommonVersion(servers[profiles[0]]?.version);
  if(profiles.some(p=>servers[p]?.version!==version))throw new Error('Both servers must use the same common version');
  return version;
}
// Only a server1-only release names the server2-only release it follows; the server2 stable it
// leaves in place must be exactly that release, at the same version.
export function followedRequest(request,version){
  if((request.target??'both')!=='server1'){if(request.follows!==undefined)throw new Error('Only a server1-only release follows another release');return null;}
  const f=request.follows,kept=request.preserved?.server2;
  if(!f||typeof f!=='object'||Object.keys(f).sort().join()!=='id,manifestSha256,sourceCommit'||!/^\d{8}T\d{6}Z-[0-9a-f]{8}$/.test(f.id)||f.id===request.id||!/^[0-9a-f]{40}$/.test(f.sourceCommit)||!/^[A-F0-9]{64}$/.test(f.manifestSha256)||kept?.manifestSha256!==f.manifestSha256||kept.version!==version)throw new Error('A server1-only release must follow the published server2-only release of the same version');
  return f;
}
// The followed public request, its server2 provenance and its signed manifest must all name the same release.
export function assertFollowedRelease(follows,version,followed,provenance,manifest){
  if(followed?.schema!==1||followed.id!==follows.id||followed.target!=='server2'||followed.sourceCommit!==follows.sourceCommit||followed.preserved?.server1===undefined||assertSameReleaseVersion(followed.servers,'server2')!==version||followed.servers.server2.manifestSha256!==follows.manifestSha256||
     manifest.profile!=='server2'||manifest.version!==version||manifest.manifestSha256!==follows.manifestSha256||
     provenance?.schema!==1||provenance.profile!=='server2'||provenance.version!==version||provenance.sourceCommit!==follows.sourceCommit||provenance.manifestSha256!==follows.manifestSha256||provenance.packageSha256!==manifest.packageSha256||provenance.fullValidation!==true)throw new Error('Followed server2-only release does not match');
  return follows;
}
