import {test} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {targets,sha256,verifyManifest,compareVersions} from '../tools/manifest.mjs';
const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:3072});
const jwk=publicKey.export({format:'jwk'});
const key=Buffer.from(`<RSAKeyValue><Modulus>${Buffer.from(jwk.n,'base64url').toString('base64')}</Modulus><Exponent>${Buffer.from(jwk.e,'base64url').toString('base64')}</Exponent></RSAKeyValue>`);
const options={expectedKeyHash:sha256(key),now:Date.parse('2026-10-15T00:00:00Z')};
function envelope(payload){return Buffer.from(`<signedComponentUpdate format="2"><payload>${Buffer.from(payload).toString('base64')}</payload><signature>${crypto.sign('RSA-SHA256',Buffer.from(payload),privateKey).toString('base64')}</signature></signedComponentUpdate>`);}
function payload(profile='server1',version='0.8.1.59'){
 const t=targets[profile];return `<componentUpdate format="2" channel="server-stable" component="remote-client" version="${version}" minProtocol="1" maxProtocol="1" expiresUtc="2027-10-15T00:00:00Z" packageUrl="https://github.com/jgohdapt/noranjip-updates/releases/download/${t.tagPrefix}${version}/remote-${version}.zip" packageSha256="${'A'.repeat(64)}" packageBytes="20" entry="${t.entry}"><files><file name="${t.entry}" sha256="${'B'.repeat(64)}" bytes="30" /></files></componentUpdate>`;
}
test('verifies existing manifest format and each isolated target',()=>{
 assert.equal(verifyManifest(envelope(payload()),key,'server1',options).version,'0.8.1.59');
 assert.equal(verifyManifest(envelope(payload('server2','0.8.2.9')),key,'server2',options).entry,targets.server2.entry);
});

test('both common versions are valid upgrades while channel and key isolation remain',()=>{
 for(const profile of ['server1','server2']){
  const m=envelope(payload(profile,'0.9.0.0'));
  assert.equal(verifyManifest(m,key,profile,options).version,'0.9.0.0');
  assert.throws(()=>verifyManifest(m,key,profile==='server1'?'server2':'server1',options),/Wrong server/);
 }
 assert.equal(compareVersions('0.9.0.0','0.8.1.58'),1);
 assert.equal(compareVersions('0.9.0.0','0.8.2.8'),1);
 assert.throws(()=>verifyManifest(envelope(payload('server1','0.8.2.9')),key,'server1',options),/Wrong server/);
});
test('rejects foreign channel, payload tampering, wrong key, expiry and extra executable',()=>{
 assert.throws(()=>verifyManifest(envelope(payload()),key,'server2',options),/Wrong server/);
 assert.throws(()=>verifyManifest(envelope(payload()),key,'server1'),/Pinned/);
 const m=envelope(payload()).toString().replace('<payload>','<payload>AAAA');
 assert.throws(()=>verifyManifest(Buffer.from(m),key,'server1',options),/signature/);
 for(const bad of [payload().replace('2027-10-15','2025-10-15'),payload().replace('remote-v2-0.8.1.59','other-0.8.1.59'),payload().replace('<files>','<files><file name="extra.exe" sha256="X" bytes="1" />'),payload().replace('format="2"','format="2" format="2"')])assert.throws(()=>verifyManifest(envelope(bad),key,'server1',options));
});
test('rejects external XML entities and untrusted envelopes',()=>{
 const m=envelope(payload());assert.throws(()=>verifyManifest(Buffer.concat([Buffer.from('<!DOCTYPE x SYSTEM "file:///secret">'),m]),key,'server1',options));
});
test('numeric versions preserve the server branch and reject ambiguous strings',()=>{
 assert.equal(compareVersions('0.8.1.59','0.8.1.58'),1);assert.equal(compareVersions('0.8.1.99','0.8.2.8'),-1);
 for(const v of ['1.2','0.8.01.59','0.8.1.-1','0.8.1.99999999999999999999'])assert.throws(()=>compareVersions(v,'0.8.1.58'));
});
