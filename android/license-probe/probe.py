#!/usr/bin/env python3
"""Fetch two official XML metadata files; use only existing SDK Java parser jars."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

HERE=Path(__file__).resolve().parent
OUT=Path('evidence/android-license-parser')
SDK=Path('/usr/local/lib/android/sdk')
URLS=[('repository.xml','https://dl.google.com/android/repository/repository2-3.xml'),('play.xml','https://dl.google.com/android/repository/sys-img/google_apis_playstore/sys-img2-3.xml')]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('REDIRECT_REFUSED')
def accepted():
    rows={}
    directory=SDK/'licenses'
    if directory.is_dir():
        for f in sorted(directory.iterdir()):
            if f.is_file() and not f.is_symlink() and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',f.name) and f.stat().st_size<16384:
                data=f.read_bytes()
                rows[f.name]={'sha256':hashlib.sha256(data).hexdigest(),'mode':f.stat().st_mode & 0o7777,'acceptedHashes':[x for x in data.decode('ascii').splitlines() if re.fullmatch(r'[0-9a-f]{40}',x)]}
    return rows

def diagnostic(name,data):
    # Only own compiler/official parser child output; no subprocess environment or arbitrary exception text.
    text=data[:16384].decode('utf-8',errors='replace')
    text=''.join(c if c in '\n\t' or ord(c)>=32 else '?' for c in text)
    text=re.sub(r'(https?://[^\s?]+)\?[^\s]+',r'\1?QUERY_REDACTED',text)
    path=OUT/(name+'.txt');path.write_text(text)
    return {'file':path.name,'retainedBytes':len(text.encode()),'inputBytes':len(data),'truncated':len(data)>16384}

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    receipt={'schema':'readonly-hosted-sdk-parser-receipt-v1','metadataOnly':True,'licenseAcceptanceInvoked':False,'softwareInstalled':False,'emulatorLaunched':False,'existingAcceptedHashesBefore':accepted(),'metadata':[]}
    try:
        lib=(SDK/'cmdline-tools/latest/lib').resolve(strict=True)
        if SDK.resolve() not in lib.parents:raise ValueError('SDK_LIBRARY_SCOPE')
        jars=sorted(lib.rglob('*.jar'))
        if not jars or len(jars)>1024:raise ValueError('EXISTING_SDK_JARS_REQUIRED')
        classpath=os.pathsep.join(str(p) for p in jars)
        if len(classpath.encode())>120000:raise ValueError('CLASSPATH_BOUND')
        receipt['existingParserJars']=[{'relative':str(p.relative_to(lib)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in jars]
        opener=urllib.request.build_opener(NoRedirect())
        for name,url in URLS:
            with opener.open(urllib.request.Request(url,headers={'User-Agent':'Existing-SDK-License-ReadOnly-Probe/1'}),timeout=20) as response:
                if response.status!=200 or response.geturl()!=url:raise ValueError('METADATA_RESPONSE')
                data=response.read(8*1024*1024+1)
            if len(data)>8*1024*1024 or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():raise ValueError('METADATA_XML_BOUND')
            (OUT/name).write_bytes(data);receipt['metadata'].append({'url':url,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        classes=OUT/'classes';classes.mkdir(exist_ok=True)
        compiled=subprocess.run(['javac','-d',str(classes),str(HERE/'LicenseProbe.java')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        if compiled.returncode:
            receipt['javacDiagnostic']=diagnostic('javac-diagnostic',compiled.stderr+compiled.stdout)
            raise ValueError('JAVA_COMPILATION_REFUSED')
        flags=['-Djavax.xml.accessExternalDTD=','-Djavax.xml.accessExternalSchema=']
        result=subprocess.run(['java',*flags,'-cp',str(classes)+os.pathsep+classpath,'LicenseProbe',str(SDK),str(OUT/'repository.xml'),str(OUT/'play.xml')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        if result.returncode or result.stderr:
            receipt['parserDiagnostic']=diagnostic('sdk-parser-diagnostic',result.stderr)
        if len(result.stdout)>65536:raise ValueError('PARSER_OUTPUT_BOUND')
        try:parsed=json.loads(result.stdout.decode('utf-8'))
        except (ValueError,UnicodeError):
            receipt['parserOutputDiagnostic']=diagnostic('sdk-parser-output-diagnostic',result.stdout)
            raise ValueError('PARSER_NON_JSON_OUTPUT')
        (OUT/'sdk-result.json').write_text(json.dumps(parsed,indent=2)+'\n')
        receipt['SDKParserExitCode']=result.returncode;receipt['SDKResult']=parsed
        receipt['status']='READONLY_PROBE_COMPLETE' if result.returncode==0 else 'REFUSED_SDK_PARSER'
    except Exception as error:
        # Never print arbitrary exception messages, network bodies, process stderr or environment.
        receipt['status']='REFUSED_READONLY_PROBE';receipt['errorClass']=type(error).__name__
        known={'REDIRECT_REFUSED','SDK_LIBRARY_SCOPE','EXISTING_SDK_JARS_REQUIRED','CLASSPATH_BOUND','METADATA_RESPONSE','METADATA_XML_BOUND','JAVA_COMPILATION_REFUSED','PARSER_OUTPUT_BOUND','PARSER_NON_JSON_OUTPUT'}
        receipt['errorCode']=str(error) if type(error) is ValueError and str(error) in known else 'NON_ENUMERATED_FAILURE'
        if isinstance(error,subprocess.TimeoutExpired):receipt['errorCode']='OWN_CHILD_PROCESS_TIMEOUT';receipt['timeoutDiagnostic']=diagnostic('child-timeout-diagnostic',(error.stderr or b'')+(error.stdout or b''))
    receipt['existingAcceptedHashesAfter']=accepted();receipt['licenseFilesUnchanged']=receipt['existingAcceptedHashesBefore']==receipt['existingAcceptedHashesAfter'];receipt['installationAuthorizedByThisProbe']=False
    (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'licenseFilesUnchanged':receipt['licenseFilesUnchanged'],'installationAuthorized':False}))
    return 0 if receipt['status']=='READONLY_PROBE_COMPLETE' and receipt['licenseFilesUnchanged'] else 2
if __name__=='__main__':sys.exit(main())
