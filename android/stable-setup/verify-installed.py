#!/usr/bin/env python3
"""After a separately reviewed install, refuse any version/license-file drift."""
import importlib.util
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owned_readonly_probe',HERE/'license-probe/probe.py');probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
SDK=Path('/usr/local/lib/android/sdk')
def main():
    out=Path('evidence/android-stable-setup/post-install.json');out.parent.mkdir(parents=True,exist_ok=True)
    result={'status':'REFUSED_POST_INSTALL_BINDING','newTermsAcceptedByScript':False}
    try:
        plan=json.loads(Path('evidence/android-stable-setup/plan.json').read_text())
        if plan['status']!='STABLE_ROWS_BOUND_FOR_OWNER_REVIEW' or probe.accepted()!=plan['licenseStateBeforeSetup']:raise ValueError('LICENSE_FILES_CHANGED')
        rows=[]
        for row in plan['selected']:
            path=SDK.joinpath(*row['package'].split(';'))/'package.xml'
            data=path.read_bytes()
            if len(data)>4*1024*1024 or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():raise ValueError('XML_BOUND')
            tree=ET.fromstring(data);packages=[x for x in tree.iter() if x.tag.rsplit('}',1)[-1]=='localPackage']
            if len(packages)!=1 or packages[0].get('path')!=row['package']:raise ValueError('PACKAGE_BINDING')
            p=packages[0];revision=next(x for x in p if x.tag.rsplit('}',1)[-1]=='revision');actual={k:0 for k in ['major','minor','micro','preview']}
            for field in revision:
                key=field.tag.rsplit('}',1)[-1]
                if key not in actual or not (field.text or '').isdigit():raise ValueError('REVISION_TYPE')
                actual[key]=int(field.text)
            if actual!=row['revision']:raise ValueError('REVISION_DRIFT')
            refs=[x.get('ref') for x in p if x.tag.rsplit('}',1)[-1]=='uses-license']
            if refs!=['android-sdk-license']:raise ValueError('LICENSE_REFERENCE_DRIFT')
            rows.append({'package':row['package'],'actualRevision':actual,'licenseRef':refs[0]})
        result={'status':'PASS_INSTALLED_EXACT_STABLE_BINDINGS','installed':rows,'licenseFilesBytesAndModesUnchanged':True,'newTermsAcceptedByScript':False,'emulatorLaunched':False}
        code=0
    except Exception as e:
        result['errorClass']=type(e).__name__
        known={'LICENSE_FILES_CHANGED','XML_BOUND','PACKAGE_BINDING','REVISION_TYPE','REVISION_DRIFT','LICENSE_REFERENCE_DRIFT'}
        result['errorCode']=str(e) if type(e) is ValueError and str(e) in known else 'NON_ENUMERATED_FAILURE'
        code=2
    out.write_text(json.dumps(result,indent=2)+'\n');print(result['status']);return code
if __name__=='__main__':sys.exit(main())
