"""Publish only signed, verified Server2 public artifacts; keep Server1 untouched."""
import base64, hashlib, io, json, os, re, time, urllib.error, urllib.parse, urllib.request, xml.etree.ElementTree as ET, zipfile
REPO='jgohdapt/noranjip-updates'
TAG='server2-remote-0.8.2.6'
STABLE='server2-remote-stable'
ROOT='.release/server2-0826/'
FILES=('remote-0.8.2.6.zip','remote-manifest.xml','server2-update-public-key.xml')
def require(value,code):
    if not value: raise RuntimeError(code)
def sha(data): return hashlib.sha256(data).hexdigest().upper()
def get(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'NoranJipServer2Release'}),timeout=45) as response:
        data=response.read(16*1024*1024+1)
    require(len(data)<=16*1024*1024,'DOWNLOAD_BOUND');return data
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def api(path,method='GET',body=None,raw=False):
    url=path if path.startswith('https://uploads.github.com/repos/'+REPO+'/') else 'https://api.github.com/repos/'+REPO+path
    require(url.startswith(('https://api.github.com/repos/'+REPO+'/', 'https://uploads.github.com/repos/'+REPO+'/')),'API_TARGET')
    data=body if raw else (json.dumps(body).encode() if body is not None else None)
    headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','User-Agent':'NoranJipServer2Release','Content-Type':'application/octet-stream' if raw else 'application/json'}
    with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url,data=data,headers=headers,method=method),timeout=60) as response:
        content=response.read();return json.loads(content) if content else None
def release(tag):
    require(tag in (TAG,STABLE),'RELEASE_SCOPE')
    try:return api('/releases/tags/'+tag)
    except urllib.error.HTTPError as e:
        if e.code==404:return None
        raise
def assets(r):return {a['name']:a for a in api('/releases/'+str(r['id'])+'/assets?per_page=100')}
def read_asset(asset):
    # Renaming a release asset can leave the old name's redirect cached at an
    # edge. Read the new asset with a unique query while retaining hash checks.
    return get(asset['browser_download_url']+'?asset='+str(asset['id'])+'&verify='+str(time.time_ns()))

def verify(asset,data):
    require(asset['size']==len(data),'ASSET_SIZE')
    for attempt in range(6):
        try:
            if sha(read_asset(asset))==sha(data):return
        except urllib.error.HTTPError as e:
            if e.code not in (404,502,503):raise
        if attempt<5:time.sleep(2)
    raise RuntimeError('ASSET_READBACK')
def upload(r,name,data):
    require(r['tag_name'] in (TAG,STABLE) and name in FILES,'ASSET_SCOPE')
    found=assets(r).get(name)
    if found:verify(found,data);return found
    item=api('https://uploads.github.com/repos/'+REPO+'/releases/'+str(r['id'])+'/assets?name='+urllib.parse.quote(name),'POST',data,True)
    verify(item,data);return item
def create(tag,commit):
    require(tag in (TAG,STABLE),'CREATE_SCOPE')
    body='개별 PC에서 폴더로 돌아올 때 중복 배치와 원격 화면 크기 변경을 줄였습니다. 폭 조절 안내선을 별도로 합성해 잔상을 줄이고 폴더·PC 이름의 좌우 여백을 맞췄습니다. 기존 접속권, PC 순서, 이름과 정상 연결은 유지됩니다.'
    return api('/releases','POST',{'tag_name':tag,'target_commitish':commit,'name':'Server2 Remote 0.8.2.6' if tag==TAG else 'Server2 Remote stable update channel','body':body,'draft':False,'prerelease':False,'make_latest':'false'})
def verify_signed(data,f):
    require(sha(data['server2-update-public-key.xml'])==f['files']['server2-update-public-key.xml'],'PUBLIC_KEY_PIN')
    key=ET.fromstring(data['server2-update-public-key.xml']);n=int.from_bytes(base64.b64decode(key.findtext('Modulus'),validate=True),'big');e=int.from_bytes(base64.b64decode(key.findtext('Exponent'),validate=True),'big')
    envelope=ET.fromstring(data['remote-manifest.xml']);payload=base64.b64decode(envelope.findtext('payload'),validate=True);signature=base64.b64decode(envelope.findtext('signature'),validate=True)
    require(n.bit_length()==3072 and e==65537 and len(signature)==384,'RSA_KEY')
    digest=bytes.fromhex('3031300d060960864801650304020105000420')+hashlib.sha256(payload).digest()
    expected=b'\x00\x01'+b'\xff'*(384-len(digest)-3)+b'\x00'+digest
    require(pow(int.from_bytes(signature,'big'),e,n).to_bytes(384,'big')==expected,'RSA_SIGNATURE')
    p=ET.fromstring(payload);package=data['remote-0.8.2.6.zip']
    require(p.tag=='componentUpdate' and p.get('component')=='remote-client' and p.get('version')=='0.8.2.6' and p.get('entry')=='노란집 서버2호기 원격PC.exe','MANIFEST_IDENTITY')
    require(p.get('packageUrl')=='https://github.com/'+REPO+'/releases/download/'+TAG+'/remote-0.8.2.6.zip' and p.get('packageSha256')==sha(package) and int(p.get('packageBytes'))==len(package),'MANIFEST_PACKAGE')
    with zipfile.ZipFile(io.BytesIO(package)) as z:
        require(len(z.infolist())==1 and z.infolist()[0].filename==p.get('entry'),'PACKAGE_CONTENTS')
        exe=z.read(z.infolist()[0]);require(sha(exe)==f['exe_sha256'],'EXECUTABLE_PIN')
        item=p.find('files/file');require(item.get('name')==p.get('entry') and item.get('sha256')==sha(exe) and int(item.get('bytes'))==len(exe),'SIGNED_ENTRY')
def run():
    commit=os.environ.get('GITHUB_SHA','')
    require(os.environ.get('GITHUB_REPOSITORY')==REPO and os.environ.get('GITHUB_REF')=='refs/heads/main' and re.fullmatch('[0-9a-f]{40}',commit),'WORKFLOW_CONTEXT')
    raw='https://raw.githubusercontent.com/'+REPO+'/'+commit+'/'+ROOT
    phase=json.loads(get(raw+'phase.json'));frozen=get(raw+'frozen.json');require(phase['frozen_sha256']==sha(frozen),'FROZEN_HASH');f=json.loads(frozen)
    require(f['version']=='0.8.2.6' and f['signature_verified'] is True and f['checks']==512,'VALIDATION_REQUIRED')
    data={name:get(raw+name) for name in FILES}
    for name,value in data.items():require(sha(value)==f['files'][name],'PUBLIC_FILE_PIN')
    verify_signed(data,f)
    latest=api('/releases/latest');require(latest['id']==f['latest_id'] and latest['tag_name']==f['latest_tag'],'LATEST_CHANGED')
    r=release(TAG)
    if phase['phase']=='immutable':
        if r is None:r=create(TAG,commit)
        for name in FILES:upload(r,name,data[name])
    elif phase['phase']=='promote':
        require(phase.get('immutable_verified') is True and phase.get('rsa_verified') is True and re.fullmatch('[0-9A-F]{64}',phase.get('proof_sha256','')) and r is not None,'IMMUTABLE_VERIFICATION_REQUIRED')
        stored=assets(r)
        for name in FILES:verify(stored[name],data[name])
        stable=release(STABLE)
        require(stable is not None and stable['id']==412699392,'STABLE_ID')
        old=assets(stable)
        for name,aid in [('server2-remote-update.exe',640339759),('server2-update-public-key.xml',640339842)]:
            require(name in old and old[name]['id']==aid,'PRESERVE_CHANNEL_ASSET')
        current=old.get('remote-manifest.xml')
        if current and sha(read_asset(current))==sha(data['remote-manifest.xml']):
            verify(current,data['remote-manifest.xml'])
        else:
            require(current is not None and current['id']==640639688 and sha(read_asset(current))=='450BDA2697B0308A1B458304D60E23953F6AD82898D8ED8F8E57F76E9EF54903','OLD_STABLE_MANIFEST')
            stage='remote-manifest-0.8.2.6.xml'
            staged=old.get(stage)
            if staged is None:
                staged=api('https://uploads.github.com/repos/'+REPO+'/releases/'+str(stable['id'])+'/assets?name='+stage,'POST',data['remote-manifest.xml'],True)
            verify(staged,data['remote-manifest.xml'])
            require('remote-manifest-0.8.2.5.xml' not in old,'ARCHIVE_EXISTS')
            api('/releases/assets/'+str(current['id']),'PATCH',{'name':'remote-manifest-0.8.2.5.xml'})
            try:
                promoted=api('/releases/assets/'+str(staged['id']),'PATCH',{'name':'remote-manifest.xml'})
                verify(promoted,data['remote-manifest.xml'])
            except Exception:
                now=assets(stable)
                if now.get('remote-manifest.xml',{}).get('id')==staged['id']:
                    api('/releases/assets/'+str(staged['id']),'PATCH',{'name':stage})
                require('remote-manifest.xml' not in assets(stable),'ROLLBACK_CONCURRENT_ASSET')
                api('/releases/assets/'+str(current['id']),'PATCH',{'name':'remote-manifest.xml'})
                raise
        after=assets(stable)
        require(after['server2-remote-update.exe']['id']==640339759 and after['server2-update-public-key.xml']['id']==640339842,'CHANNEL_ASSETS_PRESERVED')
    else:raise RuntimeError('UNKNOWN_PHASE')
    require(api('/releases/latest')['id']==f['latest_id'],'LATEST_NOT_PRESERVED')
    print(json.dumps({'result':'PASS','phase':phase['phase'],'version':'0.8.2.6','manifest_sha256':sha(data['remote-manifest.xml'])}))
if __name__=='__main__':run()
