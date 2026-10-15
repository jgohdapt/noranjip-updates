import crypto from 'node:crypto';
import fs from 'node:fs';

export const targets={
  server1:{series:'0.2.3.',tagPrefix:'admin-v2-',stable:'admin-v2-stable',entry:'NoranJipAdmin.Admin.exe',remote:'노란집 원격PC.exe',keyHash:'D6245B3479BF7A997386F1A2BD4530FCA3887B5523A70B46191185E60CC90BA1'},
  server2:{series:'0.3.',tagPrefix:'server2-admin-',stable:'server2-admin-stable',entry:'노란집 서버2호기 관리자.exe',remote:'노란집 서버2호기 원격PC.exe',keyHash:'D778EE902C9E56592558B9A1AA3711EF0E6EE14F8745BE60990F057D7C7F3A48'}
};
export const distribution='jgohdapt/noranjip-updates';
export const sha256=bytes=>crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();
export const readJson=file=>JSON.parse(fs.readFileSync(file,'utf8').replace(/^\uFEFF/,''));
export function versionParts(value){
  if(!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value))throw new Error('Noncanonical version');
  const p=value.split('.').map(Number);if(p.some(x=>!Number.isSafeInteger(x)||x>2147483647))throw new Error('Version component out of range');return p;
}
export function compareVersions(a,b){const x=versionParts(a),y=versionParts(b);for(let i=0;i<4;i++)if(x[i]!==y[i])return x[i]>y[i]?1:-1;return 0;}
function decode(value){
  if(/&(?!amp;|quot;|apos;|lt;|gt;|#\d+;|#x[0-9A-Fa-f]+;)/.test(value)||/[<>\x00-\x1f]/.test(value))throw new Error('Invalid XML attribute');
  return value.replace(/&(amp|quot|apos|lt|gt|#\d+|#x[0-9A-Fa-f]+);/g,(_,x)=>{
    const named={amp:'&',quot:'"',apos:"'",lt:'<',gt:'>'};if(x in named)return named[x];
    const n=x.startsWith('#x')?parseInt(x.slice(2),16):Number(x.slice(1));if(n<32||n>0x10ffff||(n>=0xd800&&n<=0xdfff))throw new Error('Invalid XML character');return String.fromCodePoint(n);
  });
}
function attributes(text,names){
  const result={};let rest=text;
  while(rest.trim()){
    const m=/^\s+([A-Za-z][A-Za-z0-9]*)="([^"<>]*)"/.exec(rest);if(!m||Object.hasOwn(result,m[1]))throw new Error('Malformed or duplicate XML attribute');
    result[m[1]]=decode(m[2]);rest=rest.slice(m[0].length);
  }
  if(Object.keys(result).sort().join('|')!==[...names].sort().join('|'))throw new Error('Unexpected XML attributes');return result;
}
function base64(value){
  if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)||!value)throw new Error('Invalid base64');
  const b=Buffer.from(value,'base64');if(b.toString('base64')!==value)throw new Error('Noncanonical base64');return b;
}
function publicKey(xml){
  const m=/^\s*<RSAKeyValue><Modulus>([A-Za-z0-9+/=]+)<\/Modulus><Exponent>([A-Za-z0-9+/=]+)<\/Exponent><\/RSAKeyValue>\s*$/.exec(xml.replace(/^\uFEFF/,''));
  if(!m)throw new Error('Expected public-only RSA XML key');
  const modulus=base64(m[1]);if(modulus.length!==384)throw new Error('Expected existing RSA 3072 key');
  return crypto.createPublicKey({key:{kty:'RSA',n:modulus.toString('base64url'),e:base64(m[2]).toString('base64url')},format:'jwk'});
}
export function verifyManifest(bytes,keyBytes,profile,{now=Date.now(),expectedKeyHash=targets[profile]?.keyHash}={}){
  const target=targets[profile];if(!target)throw new Error('Unknown profile');
  if(sha256(keyBytes)!==expectedKeyHash)throw new Error('Pinned public key mismatch');
  if(bytes.length>65536)throw new Error('Manifest too large');
  const xml=Buffer.from(bytes).toString('utf8').replace(/^\uFEFF/,'').trim();
  // This intentionally accepts only the existing signed format, never general XML/DTD.
  const envelope=/^<signedComponentUpdate format="2">\s*<payload>([A-Za-z0-9+/=]+)<\/payload>\s*<signature>([A-Za-z0-9+/=]+)<\/signature>\s*<\/signedComponentUpdate>$/.exec(xml);
  if(!envelope)throw new Error('Unsupported signed manifest envelope');
  const payload=base64(envelope[1]),signature=base64(envelope[2]);
  if(!crypto.verify('RSA-SHA256',payload,publicKey(Buffer.from(keyBytes).toString('utf8')),signature))throw new Error('Invalid manifest signature');
  const m=/^<componentUpdate(\s[^<>]*)>\s*<files>([\s\S]*?)<\/files>\s*<\/componentUpdate>$/.exec(payload.toString('utf8'));
  if(!m)throw new Error('Unexpected manifest payload structure');
  const a=attributes(m[1],['format','channel','component','version','minProtocol','maxProtocol','expiresUtc','packageUrl','packageSha256','packageBytes','entry']);
  const files=[];let rest=m[2];
  while(rest.trim()){
    const f=/^\s*<file(\s[^<>]*)\s*\/>/.exec(rest);if(!f)throw new Error('Invalid file list');
    files.push(attributes(f[1],['name','sha256','bytes']));rest=rest.slice(f[0].length);
  }
  const expectedFiles=[target.entry,target.remote,'NoranJip.Foundation.Updates.dll','NoranJip.Foundation.Service.dll','NoranJip.ServicePersistence.dll','NoranJip.ServiceRuntime.dll'];
  if(files.length!==6||new Set(files.map(f=>f.name)).size!==6||files.map(f=>f.name).sort().join('|')!==expectedFiles.sort().join('|'))throw new Error('Administrator six-file allowlist mismatch');
  const file=files.find(f=>f.name===target.entry);
  versionParts(a.version);
  if(a.format!=='2'||a.channel!=='server-stable'||a.component!=='admin-ui'||a.minProtocol!=='1'||a.maxProtocol!=='1')throw new Error('Wrong component or protocol');
  if((!a.version.startsWith(target.series)&&compareVersions(a.version,'0.3.0.0')<0)||a.entry!==target.entry||file.name!==target.entry)throw new Error('Wrong server profile or entry');
  const expectedUrl=`https://github.com/${distribution}/releases/download/${target.tagPrefix}${a.version}/admin-${a.version}.zip`;
  if(a.packageUrl!==expectedUrl)throw new Error('Unexpected package URL');
  if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(a.expiresUtc)||!(Date.parse(a.expiresUtc)>now))throw new Error('Expired/invalid manifest');
  for(const h of [a.packageSha256,...files.map(f=>f.sha256)])if(!/^[A-F0-9]{64}$/.test(h))throw new Error('Invalid SHA256');
  for(const n of [a.packageBytes,...files.map(f=>f.bytes)])if(!/^[1-9]\d*$/.test(n)||!Number.isSafeInteger(Number(n))||Number(n)>100*1024*1024)throw new Error('Invalid package size');
  return {files:files.map(f=>({...f,bytes:Number(f.bytes)})),profile,version:a.version,tag:target.tagPrefix+a.version,stable:target.stable,manifestSha256:sha256(bytes),packageName:`admin-${a.version}.zip`,packageUrl:a.packageUrl,packageSha256:a.packageSha256,packageBytes:Number(a.packageBytes),entry:a.entry,exeSha256:file.sha256,exeBytes:Number(file.bytes),expiresUtc:a.expiresUtc};
}
