#!/usr/bin/env python3
"""Select only already-accepted stable SDK rows. No package or permission operations."""
import json
from pathlib import Path
import sys
EXPECTED='24333f8a63b6825ea9c5514f83c2829b004d1fee'
TARGETS=['emulator','system-images;android-35;google_apis_playstore;x86_64']
def select(receipt):
    if receipt.get('status')!='READONLY_PROBE_COMPLETE' or receipt.get('licenseFilesUnchanged') is not True:
        raise ValueError('FRESH_PARSER_OR_LICENSE_STATE_REQUIRED')
    result=receipt.get('SDKResult',{})
    if result.get('status')!='READ_ONLY_SDK_PARSE_COMPLETED':raise ValueError('SDK_PARSE_REQUIRED')
    rows=result.get('packages',[]);selected=[]
    for target in TARGETS:
        matches=[r for r in rows if r.get('package')==target and r.get('channelRef')=='channel-0']
        if len(matches)!=1:raise ValueError('EXACTLY_ONE_STABLE_VARIANT_REQUIRED')
        row=matches[0];rev=row.get('revision',{})
        if set(rev)!={'major','minor','micro','preview'} or any(type(v) is not int or v<0 for v in rev.values()) or rev['preview']!=0:raise ValueError('EXACT_NONPREVIEW_REVISION_REQUIRED')
        if row.get('licenseRef')!='android-sdk-license' or row.get('SDKGetLicenseHash')!=EXPECTED or row.get('SDKCheckAccepted') is not True:raise ValueError('EXISTING_EXACT_ACCEPTANCE_REQUIRED')
        if row.get('parserLogCounts',{}):raise ValueError('PARSER_DIAGNOSTICS_REQUIRE_REVIEW')
        selected.append(row)
    return {'schema':'already-accepted-stable-sdk-plan-v1','status':'STABLE_ROWS_BOUND_FOR_OWNER_REVIEW','selected':selected,'acceptedLicenseHash':EXPECTED,'metadata':receipt.get('metadata',[]),'licenseStateBeforeSetup':receipt['existingAcceptedHashesAfter'],'SDKCommandPackages':TARGETS,'SDKCommandChannel':0,'SDKCommandStdin':'DEVNULL','acceptNewTerms':False,'emulatorLaunchAuthorized':False}
def main():
    receipt=Path(sys.argv[1]);out=Path(sys.argv[2]);out.parent.mkdir(parents=True,exist_ok=True)
    try:result=select(json.loads(receipt.read_text()));code=0
    except (ValueError,KeyError,TypeError):result={'status':'REFUSED_STABLE_SETUP_SELECTION','acceptNewTerms':False};code=2
    out.write_text(json.dumps(result,indent=2)+'\n');print(result['status']);return code
if __name__=='__main__':sys.exit(main())
