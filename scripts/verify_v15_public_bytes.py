#!/usr/bin/env python3
"""Proposed public-only preflight. No cookies/credentials and no product bytes retained."""
import hashlib,json,pathlib,urllib.request
ORIGIN='https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site'
ENTRY='/lab-v15/dist/assets/index-C3FLjX54.js'
EXPECTED='aca842c376c4711adbfef638afca7142639645015f839f03051c01b37a60e30a'
def fetch(path,limit):
    with urllib.request.urlopen(ORIGIN+path,timeout=20) as response:
        if response.status!=200 or not response.url.startswith(ORIGIN+'/'):raise ValueError('Unexpected origin/status')
        b=response.read(limit+1)
        if len(b)>limit:raise ValueError('Byte cap exceeded')
        return b,{'path':path,'finalURL':response.url,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'contentType':response.headers.get('Content-Type')}
def main():
    manifest,mp=fetch('/v15/manifest.webmanifest',32768);m=json.loads(manifest)
    assert m['id']=='/v15/audio-pwa'and m['start_url']=='/nqa?candidate=v15&experiment=nqa'and m['scope']=='/'and m['short_name']=='V15 Audio Lab'
    _,ep=fetch(ENTRY,16*1024*1024);assert ep['sha256']==EXPECTED
    pathlib.Path('evidence/v15-public-byte-proof.json').write_text(json.dumps({'pass':True,'manifest':m,'manifestResponse':mp,'entryResponse':ep,'compiledProductBytesRetained':False,'productSourceUploaded':False},indent=2)+'\n')
if __name__=='__main__':main()
