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
// A release changes both channels (default; older requests carry no target) or
// only the server2 channel. An untargeted channel is read and proven unchanged.
export const releaseTargets={both:['server1','server2'],server2:['server2']};
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
