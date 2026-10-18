#!/usr/bin/env python3
"""Anonymous strict V16 byte check with bounded failure receipts; no retries or auth."""
import datetime
import hashlib
import html
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ORIGIN='https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site'
ENTRY='/lab-v16/dist/assets/index-ojoFR-wi.js'
EXPECTED='e7ab13f79d01a5784c7879f9a02a2f9b8a0078e3281dbb6cfda01d36a0467641'
OUTPUT=Path('evidence/v16-public-byte-proof.json')
SAFE_HEADERS=['content-type','content-length','server','cf-ray','cf-mitigated','retry-after','cache-control','x-content-type-options']
class CheckFailure(Exception):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):return None

def safe_location(value):
    if not value:return None
    try:
        parsed=urllib.parse.urlsplit(urllib.parse.urljoin(ORIGIN,value))
        if parsed.scheme not in ['https','http'] or not parsed.hostname:return 'INVALID_LOCATION'
        host=parsed.hostname+(':'+str(parsed.port) if parsed.port else '')
        return urllib.parse.urlunsplit((parsed.scheme,host,parsed.path[:512],'',''))
    except ValueError:return 'INVALID_LOCATION'

def response_diagnostic(response,path,body,limited,elapsed):
    headers=response.headers
    row={'path':path,'status':response.status,'elapsedSeconds':round(elapsed,6),'bytesCaptured':len(body),'captureLimited':limited,'sha256Captured':hashlib.sha256(body).hexdigest(),'headers':{k:headers.get(k) for k in SAFE_HEADERS if headers.get(k)},'setCookiePresent':bool(headers.get('set-cookie'))}
    if headers.get('location'):row['redirectLocationWithoutQueryOrCredentials']=safe_location(headers.get('location'))
    if headers.get('www-authenticate'):row['authenticationScheme']=headers.get('www-authenticate').split()[0][:32]
    code=re.search(rb'error\s*code\s*:\s*(\d{4,5})',body,re.I)
    row['cloudflareErrorCode']=code.group(1).decode() if code else None
    title=re.search(rb'<title[^>]*>(.*?)</title>',body,re.S|re.I)
    if title:row['HTMLTitle']=html.unescape(title.group(1).decode('utf-8',errors='replace'))[:160]
    if re.fullmatch(rb'\s*error code: \d{4,5}\s*',body,re.I):row['knownErrorText']=body.decode('ascii').strip()
    row['challengeMarkers']={'cfMitigatedChallenge':headers.get('cf-mitigated')=='challenge','cfChallengeBody':b'cf-chl' in body.lower(),'signInBody':b'sign in' in body.lower() or b'sign-in' in body.lower()}
    return row

def fetch(path,limit,report,opener):
    import time
    if path not in ['/v16/manifest.webmanifest',ENTRY]:raise CheckFailure('UNREVIEWED_PATH')
    request=urllib.request.Request(ORIGIN+path)
    # Keep normal urllib identity. No browser impersonation, cookies or authorization headers.
    started=time.monotonic()
    try:response=opener.open(request,timeout=20)
    except urllib.error.HTTPError as error:response=error
    except urllib.error.URLError as error:
        report['requests'].append({'path':path,'status':'TRANSPORT_ERROR','reasonClass':type(error.reason).__name__})
        raise CheckFailure('TRANSPORT_FAILURE')
    with response:
        status=response.status
        allowed=limit if status==200 else 4096
        body=response.read(allowed+1);limited=len(body)>allowed
        diagnostic=response_diagnostic(response,path,body[:allowed],limited,time.monotonic()-started)
        report['requests'].append(diagnostic)
        if response.geturl()!=ORIGIN+path:raise CheckFailure('UNEXPECTED_FINAL_URL')
        if status!=200:
            if status==403 and diagnostic['cloudflareErrorCode']=='1010':raise CheckFailure('EDGE_CLIENT_SIGNATURE_BLOCK_1010')
            if 300<=status<400:raise CheckFailure('REDIRECT_REFUSED')
            raise CheckFailure('HTTP_STATUS_'+str(status))
        if limited:raise CheckFailure('BYTE_CAP_EXCEEDED')
        return body,diagnostic

def verify(opener=None):
    report={'schema':'v16-anonymous-public-byte-preflight-v2','pass':False,'requests':[],'retries':0,'cookiesOrCredentialsUsed':False,'browserImpersonation':False,'compiledProductBytesRetained':False,'productSourceUploaded':False,'proxyConfigured':{k:bool(v) for k,v in urllib.request.getproxies().items() if k in ['http','https','all']},'observedAtUTC':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    opener=opener or urllib.request.build_opener(NoRedirect())
    try:
        body,mp=fetch('/v16/manifest.webmanifest',32768,report,opener)
        try:m=json.loads(body)
        except (ValueError,UnicodeError):raise CheckFailure('MANIFEST_NOT_JSON')
        expected={'id':'/v16/audio-pwa','start_url':'/nqa?candidate=v16&experiment=nqa','scope':'/','short_name':'V16 Audio Lab'}
        if not isinstance(m,dict) or any(m.get(k)!=v for k,v in expected.items()):raise CheckFailure('MANIFEST_FIELDS_MISMATCH')
        report['manifest']=m;report['manifestResponse']=mp
        body,ep=fetch(ENTRY,16*1024*1024,report,opener)
        if hashlib.sha256(body).hexdigest()!=EXPECTED:raise CheckFailure('ENTRY_SHA256_MISMATCH')
        if (ep['headers'].get('content-type') or '').split(';')[0].strip().lower() not in ['text/javascript','application/javascript']:raise CheckFailure('ENTRY_CONTENT_TYPE_MISMATCH')
        report['entryResponse']=ep;report['pass']=True;report['status']='PASS_ANONYMOUS_STRICT_V16_BYTES'
    except CheckFailure as error:report['status']='REFUSED_PUBLIC_PREFLIGHT';report['failureCode']=str(error)
    except Exception as error:report['status']='REFUSED_PUBLIC_PREFLIGHT';report['failureCode']='UNEXPECTED_CHECKER_FAILURE';report['errorClass']=type(error).__name__
    return report

def main():
    report=verify();OUTPUT.parent.mkdir(parents=True,exist_ok=True);OUTPUT.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'pass':report['pass'],'failureCode':report.get('failureCode'),'requests':len(report['requests']),'retries':0}))
    return 0 if report['pass'] else 2
if __name__=='__main__':sys.exit(main())
