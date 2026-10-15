import {test} from 'node:test';
import assert from 'node:assert/strict';
import {verifyPackage} from '../tools/package.mjs';
import {sha256} from '../tools/manifest.mjs';
function zipFixture(name='노란집 원격PC.exe'){
 const n=Buffer.from(name),body=Buffer.from('synthetic executable, not a product');
 const local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50);local.writeUInt16LE(0x800,6);local.writeUInt32LE(body.length,18);local.writeUInt32LE(body.length,22);local.writeUInt16LE(n.length,26);
 const central=Buffer.alloc(46);central.writeUInt32LE(0x02014b50);central.writeUInt16LE(0x800,8);central.writeUInt32LE(body.length,20);central.writeUInt32LE(body.length,24);central.writeUInt16LE(n.length,28);
 const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(46+n.length,12);end.writeUInt32LE(30+n.length+body.length,16);
 const zip=Buffer.concat([local,n,body,central,n,end]);
 const manifest={entry:name,packageBytes:zip.length,packageSha256:sha256(zip),exeBytes:body.length,exeSha256:sha256(body)};
 return {zip,manifest};
}
test('only the signed canonical single executable can pass',()=>{const {zip,manifest}=zipFixture();assert.equal(verifyPackage(zip,manifest).name,manifest.entry);});
test('rejects traversal, extra entries, corrupted archive and executable',()=>{
 const bad=zipFixture('../secret.exe');assert.throws(()=>verifyPackage(bad.zip,bad.manifest),/Unexpected ZIP/);
 const {zip,manifest}=zipFixture();assert.throws(()=>verifyPackage(zip,{...manifest,exeSha256:'A'.repeat(64)}),/Executable hash/);
 const changed=Buffer.from(zip);changed.writeUInt16LE(2,changed.length-22+10);assert.throws(()=>verifyPackage(changed,{...manifest,packageSha256:sha256(changed)}),/Exactly one/);
 changed[30]^=1;assert.throws(()=>verifyPackage(changed,manifest),/Package hash/);
});
