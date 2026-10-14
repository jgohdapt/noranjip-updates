"""Publish only signed, verified Server2 public artifacts; keep Server1 untouched."""
import base64, hashlib, io, json, os, re, urllib.error, urllib.parse, urllib.request, xml.etree.ElementTree as ET, zipfile
REPO='jgohdapt/noranjip-updates'
TAG='server2-remote-0.8.2.1'
STABLE='server2-remote-stable'
ROOT='.release/server2-0821/'
FILES=('remote-0.8.2.1.zip','remote-manifest.xml','server2-remote-update.exe','server2-update-public-key.xml')
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
def verify(asset,data):require(asset['size']==len(data) and sha(get(asset['browser_download_url']))==sha(data),'ASSET_READBACK')
def upload(r,name,data):
    require(r['tag_name'] in (TAG,STABLE) and name in FILES,'ASSET_SCOPE')
    found=assets(r).get(name)
    if found:verify(found,data);return found
    item=api('https://uploads.github.com/repos/'+REPO+'/releases/'+str(r['id'])+'/assets?name='+urllib.parse.quote(name),'POST',data,True)
    verify(item,data);return item
def create(tag,commit):
    require(tag in (TAG,STABLE),'CREATE_SCOPE')
    body='PC 목록을 위아래로 드래그해 순서를 바꾸고 자동 저장합니다. 새 기능 사용법은 기존 말풍선 모양으로 해당 PC의 Windows 사용자별 한 번만 표시합니다.\n\n2호기 전용 서명 업데이트 채널입니다. 사용 중에는 업데이트 버튼이 나타나고, 완전히 종료 후 재실행하면 최신 버전을 적용합니다. 기존 0.8.2.0은 업데이트 주소가 없어 최초 한 번 전환이 필요합니다.\n\n기존 2호기 원격을 닫고 server2-remote-update.exe를 실행한 다음 바탕화면의 새 노란집2 원격PC (자동 업데이트) 바로가기를 사용하세요. 기존 접속권·배정·VPN 정보는 보존합니다. 원본 접속 파일과 이전 캐시는 남습니다. 일반 ZIP은 관리자용 공통 템플릿이며 개인 접속 파일이 아닙니다.\n\n1호기 채널과 배포 파일은 변경하지 않습니다.'
    return api('/releases','POST',{'tag_name':tag,'target_commitish':commit,'name':'Server2 Remote 0.8.2.1' if tag==TAG else 'Server2 Remote stable update channel','body':body,'draft':False,'prerelease':False,'make_latest':'false'})
def verify_signed(data,f):
    require(sha(data['server2-update-public-key.xml'])==f['files']['server2-update-public-key.xml'],'PUBLIC_KEY_PIN')
    key=ET.fromstring(data['server2-update-public-key.xml']);n=int.from_bytes(base64.b64decode(key.findtext('Modulus'),validate=True),'big');e=int.from_bytes(base64.b64decode(key.findtext('Exponent'),validate=True),'big')
    envelope=ET.fromstring(data['remote-manifest.xml']);payload=base64.b64decode(envelope.findtext('payload'),validate=True);signature=base64.b64decode(envelope.findtext('signature'),validate=True)
    require(n.bit_length()==3072 and e==65537 and len(signature)==384,'RSA_KEY')
    digest=bytes.fromhex('3031300d060960864801650304020105000420')+hashlib.sha256(payload).digest()
    expected=b'\x00\x01'+b'\xff'*(384-len(digest)-3)+b'\x00'+digest
    require(pow(int.from_bytes(signature,'big'),e,n).to_bytes(384,'big')==expected,'RSA_SIGNATURE')
    p=ET.fromstring(payload);package=data['remote-0.8.2.1.zip']
    require(p.tag=='componentUpdate' and p.get('component')=='remote-client' and p.get('version')=='0.8.2.1' and p.get('entry')=='노란집 서버2호기 원격PC.exe','MANIFEST_IDENTITY')
    require(p.get('packageUrl')=='https://github.com/'+REPO+'/releases/download/'+TAG+'/remote-0.8.2.1.zip' and p.get('packageSha256')==sha(package) and int(p.get('packageBytes'))==len(package),'MANIFEST_PACKAGE')
    with zipfile.ZipFile(io.BytesIO(package)) as z:
        require(len(z.infolist())==1 and z.infolist()[0].filename==p.get('entry'),'PACKAGE_CONTENTS')
        exe=z.read(z.infolist()[0]);require(sha(exe)==f['exe_sha256'],'EXECUTABLE_PIN')
        item=p.find('files/file');require(item.get('name')==p.get('entry') and item.get('sha256')==sha(exe) and int(item.get('bytes'))==len(exe),'SIGNED_ENTRY')
def run():
    commit=os.environ.get('GITHUB_SHA','')
    require(os.environ.get('GITHUB_REPOSITORY')==REPO and os.environ.get('GITHUB_REF')=='refs/heads/main' and re.fullmatch('[0-9a-f]{40}',commit),'WORKFLOW_CONTEXT')
    raw='https://raw.githubusercontent.com/'+REPO+'/'+commit+'/'+ROOT
    phase=json.loads(get(raw+'phase.json'));frozen=get(raw+'frozen.json');require(phase['frozen_sha256']==sha(frozen),'FROZEN_HASH');f=json.loads(frozen)
    require(f['version']=='0.8.2.1' and f['signature_verified'] is True and f['checks']==229,'VALIDATION_REQUIRED')
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
        if stable is None:stable=create(STABLE,commit)
        # First Server2 channel publication: existing assets must match exactly.
        # Never replace an asset or alter a Server1 release in this bootstrap.
        for name in FILES:
            if name!='remote-0.8.2.1.zip':upload(stable,name,data[name])
    else:raise RuntimeError('UNKNOWN_PHASE')
    require(api('/releases/latest')['id']==f['latest_id'],'LATEST_NOT_PRESERVED')
    print(json.dumps({'result':'PASS','phase':phase['phase'],'version':'0.8.2.1','manifest_sha256':sha(data['remote-manifest.xml'])}))
if __name__=='__main__':run()
