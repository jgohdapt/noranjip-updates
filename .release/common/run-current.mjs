import fs from 'node:fs';
import path from 'node:path';
import {readJson,distribution} from './tools/manifest.mjs';
import {loadPublication,githubTransport} from './tools/github-publication.mjs';
import {publishTogether} from './tools/publication.mjs';

const output=process.env.PUBLICATION_RESULT||'publication-result.json';
try{
 if(process.env.GITHUB_REPOSITORY!==distribution||process.env.GITHUB_REF!=='refs/heads/main'||!/^[0-9a-f]{40}$/.test(process.env.GITHUB_SHA||''))throw new Error('Expected distribution main workflow');
 const base='.release/common',current=readJson(path.join(base,'current.json'));
 if(current.schema!==1||!/^\d{8}T\d{6}Z-[0-9a-f]{8}$/.test(current.id)||!/^[0-9a-f]{40}$/.test(current.sourceCommit))throw new Error('Invalid current release selector');
 const {request,keys,bundles}=loadPublication(path.join(base,'requests',current.id),path.join(base,'keys'));
 if(request.id!==current.id||request.sourceCommit!==current.sourceCommit)throw new Error('Release selector mismatch');
 await publishTogether(request,bundles,githubTransport(keys,process.env.GH_TOKEN),state=>fs.writeFileSync(output,JSON.stringify({...state,distributionCommit:process.env.GITHUB_SHA},null,2)+'\n'));
 console.log(fs.readFileSync(output,'utf8'));
}catch(error){
 if(!fs.existsSync(output))fs.writeFileSync(output,JSON.stringify({status:'failed-before-promotion',error:error.message,distributionCommit:process.env.GITHUB_SHA,completedUtc:new Date().toISOString()},null,2)+'\n');
 console.error(error.message);process.exitCode=1;
}
