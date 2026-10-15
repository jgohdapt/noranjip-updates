import {test} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {targets,sha256,verifyManifest} from '../tools/manifest.mjs';
import {verifyPackage} from '../tools/package.mjs';
const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:3072}),jwk=publicKey.export({format:'jwk'});
const key=Buffer.from(`<RSAKeyValue><Modulus>${Buffer.from(jwk.n,'base64url').toString('base64')}</Modulus><Exponent>${Buffer.from(jwk.e,'base64url').toString('base64')}</Exponent></RSAKeyValue>`);
const options={expectedKeyHash:sha256(key),now:Date.parse('2026-10-15T00:00:00Z')};
function envelope(payload){return Buffer.from(`<signedComponentUpdate format="2"><payload>${Buffer.from(payload).toString('base64')}</payload><signature>${crypto.sign('RSA-SHA256',Buffer.from(payload),privateKey).toString('base64')}</signature></signedComponentUpdate>`);}
function fixture(profile='server1'){
 const t=targets[profile],names=[t.entry,t.remote,'NoranJip.Foundation.Updates.dll','NoranJip.Foundation.Service.dll','NoranJip.ServicePersistence.dll','NoranJip.ServiceRuntime.dll'];
 let offset=0;const local=[],central=[],files=[];
 for(const name of names){
  const nb=Buffer.from(name),bytes=Buffer.from('synthetic '+name);const h=Buffer.alloc(30);h.writeUInt32LE(0x04034b50);h.writeUInt16LE(20,4);h.writeUInt16LE(0x800,6);h.writeUInt32LE(bytes.length,18);h.writeUInt32LE(bytes.length,22);h.writeUInt16LE(nb.length,26);
  const c=Buffer.alloc(46);c.writeUInt32LE(0x02014b50);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(0x800,8);c.writeUInt32LE(bytes.length,20);c.writeUInt32LE(bytes.length,24);c.writeUInt16LE(nb.length,28);c.writeUInt32LE(offset,42);
  local.push(h,nb,bytes);central.push(c,nb);offset+=h.length+nb.length+bytes.length;files.push({name,bytes:bytes.length,sha256:sha256(bytes)});
 }
 const cd=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(6,8);end.writeUInt16LE(6,10);end.writeUInt32LE(cd.length,12);end.writeUInt32LE(offset,16);
 const zip=Buffer.concat([...local,cd,end]);
 const payload=`<componentUpdate format="2" channel="server-stable" component="admin-ui" version="0.3.0.0" minProtocol="1" maxProtocol="1" expiresUtc="2027-10-15T00:00:00Z" packageUrl="https://github.com/jgohdapt/noranjip-updates/releases/download/${t.tagPrefix}0.3.0.0/admin-0.3.0.0.zip" packageSha256="${sha256(zip)}" packageBytes="${zip.length}" entry="${t.entry}"><files>${files.map(f=>`<file name="${f.name}" sha256="${f.sha256}" bytes="${f.bytes}" />`).join('')}</files></componentUpdate>`;
 return {payload,zip};
}
test('both own-key six-file administrator packages verify',()=>{for(const p of ['server1','server2']){const f=fixture(p),m=verifyManifest(envelope(f.payload),key,p,options);assert.equal(verifyPackage(f.zip,m).length,6);assert.throws(()=>verifyManifest(envelope(f.payload),key,p==='server1'?'server2':'server1',options));}});
test('same authority cannot substitute a remote component or extra service file',()=>{const f=fixture();for(const payload of [f.payload.replace('component="admin-ui"','component="remote-client"'),f.payload.replace('NoranJip.ServiceRuntime.dll','NoranJip.ServiceHost.exe'),f.payload.replace('<files>','<files><file name="service-state.xml" sha256="'+'A'.repeat(64)+'" bytes="1" />'),f.payload.replace('2027-10-15','2025-10-15')])assert.throws(()=>verifyManifest(envelope(payload),key,'server1',options));});
test('signature, package and per-file hashes are enforced',()=>{const f=fixture(),m=verifyManifest(envelope(f.payload),key,'server1',options);assert.throws(()=>verifyManifest(envelope(f.payload),key,'server1'));const bad=Buffer.from(f.zip);bad[40]^=1;assert.throws(()=>verifyPackage(bad,m));assert.throws(()=>verifyPackage(bad,{...m,packageSha256:sha256(bad)}));});
