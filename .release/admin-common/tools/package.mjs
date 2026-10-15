import zlib from 'node:zlib';
import {sha256} from './manifest.mjs';
const decoder=new TextDecoder('utf-8',{fatal:true});
export function verifyPackage(zip,manifest){
 if(zip.length!==manifest.packageBytes||sha256(zip)!==manifest.packageSha256)throw new Error('Package hash/size mismatch');
 const end=zip.length-22;
 if(end<0||zip.readUInt32LE(end)!==0x06054b50||zip.readUInt16LE(end+20)!==0||zip.readUInt16LE(end+4)!==0||zip.readUInt16LE(end+6)!==0||zip.readUInt16LE(end+8)!==6||zip.readUInt16LE(end+10)!==6)throw new Error('Expected six-entry ZIP');
 const cd=zip.readUInt32LE(end+16);
 if(cd+zip.readUInt32LE(end+12)!==end)throw new Error('Invalid directory bounds');
 let at=cd,lastEnd=0;const seen=new Set();const results=[];
 for(let index=0;index<6;index++){
  if(at+46>end||zip.readUInt32LE(at)!==0x02014b50)throw new Error('Central directory invalid');
  const flags=zip.readUInt16LE(at+8),method=zip.readUInt16LE(at+10),compressed=zip.readUInt32LE(at+20),size=zip.readUInt32LE(at+24),nl=zip.readUInt16LE(at+28),el=zip.readUInt16LE(at+30),cl=zip.readUInt16LE(at+32),off=zip.readUInt32LE(at+42);
  if(flags&~0x808||![0,8].includes(method)||at+46+nl+el+cl>end||size>100*1024*1024||off<lastEnd||off+30>cd)throw new Error('ZIP entry bounds invalid');
  const name=decoder.decode(zip.subarray(at+46,at+46+nl)),file=manifest.files.find(f=>f.name===name);
  if(!file||seen.has(name)||/[\\/]/.test(name)||file.bytes!==size)throw new Error('File allowlist mismatch');seen.add(name);
  if(zip.readUInt32LE(off)!==0x04034b50||zip.readUInt16LE(off+6)!==flags||zip.readUInt16LE(off+8)!==method)throw new Error('Local header mismatch');
  const localName=zip.readUInt16LE(off+26),localExtra=zip.readUInt16LE(off+28),start=off+30+localName+localExtra;
  if(decoder.decode(zip.subarray(off+30,off+30+localName))!==name||start+compressed>cd)throw new Error('Local entry mismatch');
  const raw=zip.subarray(start,start+compressed),bytes=method===8?zlib.inflateRawSync(raw,{maxOutputLength:size+1}):raw;
  if(bytes.length!==size||sha256(bytes)!==file.sha256)throw new Error('File hash mismatch');
  results.push({name,bytes:size,sha256:file.sha256});lastEnd=start+compressed;at+=46+nl+el+cl;
 }
 if(at!==end||seen.size!==6)throw new Error('ZIP has unexpected entries');return results;
}
