"""Publish only the main agent's verified, signed public remote 0.8.1.53 package."""
import base64, hashlib, io, json, os, re, urllib.error, urllib.parse, urllib.request, xml.etree.ElementTree as ET, zipfile
REPO='jgohdapt/noranjip-updates'
TAG='remote-v2-0.8.1.53'
STABLE='remote-v2-stable'
ROOT='.release/remote53/'
OLD_ID=570021330
OLD_SHA='2855D17D3DE9CE45C897C89DF7E6DE36829C827070725DA0E9AFB785A5F2C204'
def require(value,code):
    if not value: raise RuntimeError(code)
def sha(data): return hashlib.sha256(data).hexdigest().upper()
def get(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'NoranJipRemote53'}),timeout=45) as r:return r.read()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl): return None
def api(path,method='GET',body=None,raw=False):
    url=path if path.startswith('https://uploads.github.com/repos/'+REPO+'/') else 'https://api.github.com/repos/'+REPO+path
    require(url.startswith(('https://api.github.com/repos/'+REPO+'/', 'https://uploads.github.com/repos/'+REPO+'/')),'API_TARGET')
    data=body if raw else (json.dumps(body).encode() if body is not None else None)
    headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','User-Agent':'NoranJipRemote53','Content-Type':'application/octet-stream' if raw else 'application/json'}
    with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url,data=data,headers=headers,method=method),timeout=60) as r:
        content=r.read();return json.loads(content) if content else None
def release(tag):
    try:return api('/releases/tags/'+tag)
    except urllib.error.HTTPError as e:
        if e.code==404:return None
        raise
def assets(r): return {a['name']:a for a in api('/releases/'+str(r['id'])+'/assets?per_page=100')}
def verify_asset(asset,data):require(asset['size']==len(data) and sha(get(asset['browser_download_url']))==sha(data),'ASSET_READBACK')
def upload(r,name,data):
    found=assets(r).get(name)
    if found:verify_asset(found,data);return found
    item=api('https://uploads.github.com/repos/'+REPO+'/releases/'+str(r['id'])+'/assets?name='+urllib.parse.quote(name), 'POST',data,True)
    verify_asset(item,data);return item
def rename(asset,name):return api('/releases/assets/'+str(asset['id']),'PATCH',{'name':name})
def run():
    commit=os.environ.get('GITHUB_SHA','')
    require(os.environ.get('GITHUB_REPOSITORY')==REPO and os.environ.get('GITHUB_REF')=='refs/heads/main' and re.fullmatch('[0-9a-f]{40}',commit),'WORKFLOW_CONTEXT')
    raw='https://raw.githubusercontent.com/'+REPO+'/'+commit+'/'+ROOT
    phase=json.loads(get(raw+'phase.json'));frozen_bytes=get(raw+'frozen.json')
    require(phase['frozen_sha256']==sha(frozen_bytes),'FROZEN_HASH')
    f=json.loads(frozen_bytes)
    require(f['version']=='0.8.1.53' and f['signature_verified'] is True and f['fixture_count']==35 and f['ui_dpi_checks']==4,'MAIN_VALIDATION_REQUIRED')
    manifest=get(raw+'remote-manifest.xml');package=get(raw+'remote-0.8.1.53.zip')
    require(sha(manifest)==f['manifest_sha256'] and sha(package)==f['package_sha256'],'PUBLIC_INPUT_PINS')
    payload=ET.fromstring(base64.b64decode(ET.fromstring(manifest).findtext('payload'),validate=True))
    require(payload.tag=='componentUpdate' and payload.get('component')=='remote-client' and payload.get('version')=='0.8.1.53','MANIFEST_IDENTITY')
    require(payload.get('packageUrl')=='https://github.com/'+REPO+'/releases/download/'+TAG+'/remote-0.8.1.53.zip' and payload.get('packageSha256')==sha(package),'MANIFEST_PACKAGE')
    with zipfile.ZipFile(io.BytesIO(package)) as z:
        require(len(z.infolist())==1 and z.infolist()[0].filename==payload.get('entry'),'PACKAGE_CONTENTS')
        exe=z.read(z.infolist()[0]);require(sha(exe)==f['exe_sha256'],'EXECUTABLE_PIN')
    latest=api('/releases/latest');require(latest['id']==f['latest_id'] and latest['tag_name']==f['latest_tag'],'LATEST_CHANGED')
    r=release(TAG)
    if phase['phase']=='immutable':
        if r is None:r=api('/releases','POST',{'tag_name':TAG,'target_commitish':commit,'name':'Remote 0.8.1.53 connection error guidance','body':'Explain how staff can power-cycle the office server router when multiple users cannot connect: unplug power, reconnect after 30 seconds, wait 2-3 minutes, and retry. Warn against the RESET button. Connection, VPN, session, and display behavior remain unchanged from 0.8.1.52.','draft':False,'prerelease':False,'make_latest':'false'})
        upload(r,'remote-0.8.1.53.zip',package);upload(r,'remote-manifest.xml',manifest)
    elif phase['phase']=='promote':
        require(phase.get('immutable_verified') is True and phase.get('rsa_verified') is True and re.fullmatch('[0-9A-F]{64}',phase.get('proof_sha256','')) and r is not None,'IMMUTABLE_VERIFICATION_REQUIRED')
        immutable=assets(r);verify_asset(immutable['remote-0.8.1.53.zip'],package);verify_asset(immutable['remote-manifest.xml'],manifest)
        stable=release(STABLE);require(stable and stable['id']==387511440,'STABLE_ID')
        before=assets(stable);fixed=before.get('remote-manifest.xml')
        if fixed and sha(get(fixed['browser_download_url']))==sha(manifest):
            verify_asset(fixed,manifest);return
        archive=before.get('remote-manifest-0.8.1.52.xml')
        old=fixed or archive
        require(old and old['id']==OLD_ID and sha(get(old['browser_download_url']))==OLD_SHA,'OLD_FIXED_CHANGED')
        require(not archive or archive['id']==OLD_ID,'ARCHIVE_CONFLICT')
        stage=upload(stable,'remote-manifest-0.8.1.53.xml',manifest)
        if fixed:rename(old,'remote-manifest-0.8.1.52.xml')
        try:rename(stage,'remote-manifest.xml')
        except Exception:
            rename(old,'remote-manifest.xml');raise
        after=assets(stable);verify_asset(after['remote-manifest.xml'],manifest)
        require(after['remote-manifest-0.8.1.52.xml']['id']==OLD_ID,'OLD_NOT_PRESERVED')
        for name,a in before.items():
            if name not in ('remote-manifest.xml','remote-manifest-0.8.1.53.xml'):
                require(name in after and after[name]['id']==a['id'],'OTHER_ASSET_CHANGED')
    else:raise RuntimeError('UNKNOWN_PHASE')
    latest=api('/releases/latest');require(latest['id']==f['latest_id'],'LATEST_NOT_PRESERVED')
    print(json.dumps({'result':'PASS','phase':phase['phase'],'version':'0.8.1.53','manifest_sha256':sha(manifest),'package_sha256':sha(package)}))
if __name__=='__main__':run()
