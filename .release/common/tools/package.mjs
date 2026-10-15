import zlib from 'node:zlib';
import {sha256} from './manifest.mjs';
const decoder=new TextDecoder('utf-8',{fatal:true});
export function verifyPackage(zip,manifest){
  if(zip.length!==manifest.packageBytes||sha256(zip)!==manifest.packageSha256)throw new Error('Package hash/size mismatch');
  if(zip.length<22||zip.readUInt32LE(zip.length-22)!==0x06054b50)throw new Error('Expected bounded ZIP without comment');
  const e=zip.length-22;
  if(zip.readUInt16LE(e+4)!==0||zip.readUInt16LE(e+6)!==0||zip.readUInt16LE(e+8)!==1||zip.readUInt16LE(e+10)!==1)throw new Error('Exactly one ZIP entry is required');
  const cdSize=zip.readUInt32LE(e+12),cd=zip.readUInt32LE(e+16);
  if(cd+cdSize!==e||cd+46>e||zip.readUInt32LE(cd)!==0x02014b50)throw new Error('Invalid ZIP central directory');
  const flags=zip.readUInt16LE(cd+8),method=zip.readUInt16LE(cd+10),compressed=zip.readUInt32LE(cd+20),size=zip.readUInt32LE(cd+24),nameLength=zip.readUInt16LE(cd+28),extra=zip.readUInt16LE(cd+30),comment=zip.readUInt16LE(cd+32),offset=zip.readUInt32LE(cd+42);
  if(flags&~0x808||![0,8].includes(method)||offset!==0||size!==manifest.exeBytes||size>100*1024*1024||cd+46+nameLength+extra+comment!==e)throw new Error('Unsupported ZIP entry');
  const name=decoder.decode(zip.subarray(cd+46,cd+46+nameLength));
  if(name!==manifest.entry||/[\\/]/.test(name))throw new Error('Unexpected ZIP executable');
  if(zip.readUInt32LE(0)!==0x04034b50||zip.readUInt16LE(6)!==flags||zip.readUInt16LE(8)!==method)throw new Error('ZIP local header mismatch');
  const localNameLength=zip.readUInt16LE(26),localExtra=zip.readUInt16LE(28),start=30+localNameLength+localExtra;
  if(decoder.decode(zip.subarray(30,30+localNameLength))!==name||start+compressed>cd)throw new Error('ZIP local entry mismatch');
  const data=zip.subarray(start,start+compressed),exe=method===8?zlib.inflateRawSync(data,{maxOutputLength:Math.max(1,size+1)}):data;
  if(exe.length!==size||sha256(exe)!==manifest.exeSha256)throw new Error('Executable hash/size mismatch');
  return {name,bytes:exe.length,sha256:sha256(exe)};
}
