import {compareVersions, versionParts, readJson} from './manifest.mjs';

export function assertCommonVersion(version){
  const parts=versionParts(version);
  if(parts.some(n=>n>65534)||compareVersions(version,'0.9.0.0')<0)throw new Error('Common version must be at least 0.9.0.0 with assembly-compatible components');
  return version;
}
export function readCommonVersion(file){
  const value=readJson(file);
  if(value.schema!==1)throw new Error('Invalid common version schema');
  return assertCommonVersion(value.version);
}
export function assertSameReleaseVersion(servers){
  const version=assertCommonVersion(servers?.server1?.version);
  if(version!==servers?.server2?.version)throw new Error('Both servers must use the same common version');
  return version;
}
