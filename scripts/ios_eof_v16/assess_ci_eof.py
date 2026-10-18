"""Mandatory hosted EOF proof from exact officially exported native attachments.
No UI, subprocess, browser, network, device, product or source mutation.
"""
from pathlib import Path
import hashlib,importlib.util,json,os,re,sys

PINS={'assess_ios_eof.py':'244293cc0d947d83a5a9ca782fd1b8591ed6323ab8438085b50b71ff10d37679','eof_contract.py':'692d37312b66a2492d2b94d37462e0cc02ad2df817c7443a8ac258cfbd91d3b1','frame_acceptance_ios.py':'3a6bb26178d817efb19f9de8cce9f54d574c5e9f3d41edee3526ee5ab7d4cfa9'}
TEST='V16InstalledUITests/testV16InstalledNaturalEOFContinuation()'
BUNDLE='evidence/v16-native-eof.xcresult'
FOLDER='v16-native-eof-attachments'
LABELS={'report':'v16-nf-three-natural-EOF-observation-AX-json_','carrier':'v16-nf-wide-natural-EOF-complete-full-carrier_','frozenStatus':'v16-nf-wide-natural-EOF-complete-original-status_','packedStatus':'v16-nf-wide-natural-EOF-complete-packed-status_','pending':'v16-nf-EOF-offline-acceptance-pending_'}
def need(ok,reason):
    if not ok:raise ValueError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def raw(path,cap):
    need(path.is_file()and not path.is_symlink(),'REGULAR_ORIGINAL_EVIDENCE_REQUIRED')
    before=path.stat();need(0<before.st_size<=cap,'BOUNDED_ORIGINAL_EVIDENCE_REQUIRED');data=path.read_bytes();after=path.stat()
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)and len(data)==after.st_size,'ORIGINAL_EVIDENCE_CHANGED')
    return data
def parsed(data):return json.loads(data,parse_constant=lambda _:(_ for _ in()).throw(ValueError('NONFINITE_JSON_REFUSED')))
def load_assessor():
    directory=Path(__file__).resolve().parent
    for name,digest in PINS.items():need(sha(raw(directory/name,128*1024))==digest,'PINNED_EOF_ASSSESSOR_CLOSURE_REQUIRED')
    sys.path.insert(0,str(directory))
    spec=importlib.util.spec_from_file_location('pinned_ios_eof_assessor',directory/'assess_ios_eof.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
def clean(command):
    cleanup=command.get('cleanup')or{}
    return command.get('ok')is True and command.get('timedOut')is False and cleanup.get('leaderReaped')is True and cleanup.get('ownedGroupAbsent')is True and type(cleanup.get('returnCode'))is int and cleanup.get('returnCode')==0
def assess(root,udid,run_id,run_attempt):
    need(root.is_dir()and not root.is_symlink(),'OWNED_EVIDENCE_DIRECTORY_REQUIRED')
    need(isinstance(udid,str)and re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',udid),'EXACT_SELECTED_SIMULATOR_REQUIRED')
    need(all(isinstance(v,str)and re.fullmatch(r'[1-9][0-9]*',v)for v in [run_id,run_attempt]),'EXACT_HOSTED_RUN_ID_ATTEMPT_REQUIRED')
    selected=parsed(raw(root/'selected-simulator.json',65536));need(selected['udid']==udid,'SELECTED_SIMULATOR_RECEIPT_MISMATCH')
    case=parsed(raw(root/'bounded-native-eof.json',1024*1024))
    need(case['schema']=='bounded-fixed-apple-ci-command-v1'and case['operation']=='native-eof'and case['selectedSimulatorUDID']==udid and case['runId']==run_id and case['runAttempt']==run_attempt and clean(case),'CURRENT_CLEAN_SUCCESSFUL_NATIVE_EOF_ACQUISITION_REQUIRED')
    command=case['command'];need(isinstance(command,list)and command[0]=='/usr/bin/xcodebuild'and command[command.index('-destination')+1]=='platform=iOS Simulator,id='+udid and command[command.index('-resultBundlePath')+1]==BUNDLE and '-only-testing:CIProbeUITests/V16InstalledUITests/testV16InstalledNaturalEOFContinuation'in command,'FIXED_NATIVE_EOF_CASE_REQUIRED')
    export=parsed(raw(root/'xcresult-attachment-export.json',16*1024*1024));need(export['schema']=='bounded-xcresult-attachment-export-v2','ORIGINAL_OFFICIAL_EXPORT_RECEIPT_REQUIRED')
    matching=[row for row in export['exports']if row.get('bundle')==BUNDLE]
    need(len(matching)==1 and matching[0].get('exportCompleted')is True and clean(matching[0]['commandReceipt']),'COMPLETE_CLEAN_OFFICIAL_EOF_EXPORT_REQUIRED')
    item=matching[0];by_path={row['path']:row for row in item['files']};need(len(by_path)==len(item['files']),'UNIQUE_EXPORTED_FILE_PATHS_REQUIRED')
    def verified(relative,cap):
        need(relative in by_path and re.fullmatch(re.escape(FOLDER)+r'/(?:[0-9A-Fa-f-]+\.txt|manifest\.json)',relative),'FIXED_EOF_TEXT_ATTACHMENT_PATH_REQUIRED')
        content=raw(root/relative,cap);receipt=by_path[relative];need(type(receipt['bytes'])is int and receipt['bytes']==len(content)and receipt['sha256']==sha(content),'OFFICIAL_ATTACHMENT_BYTE_HASH_MISMATCH');return content
    manifest=parsed(verified(FOLDER+'/manifest.json',8*1024*1024));need(type(manifest)is list and len(manifest)<=100,'BOUNDED_NATIVE_ATTACHMENT_MANIFEST_REQUIRED')
    groups=[group for group in manifest if group.get('testIdentifier')==TEST];need(len(groups)==1,'EXACT_NATIVE_EOF_TEST_MANIFEST_REQUIRED')
    descriptors={};contents={}
    for role,label in LABELS.items():
        found=[a for a in groups[0]['attachments']if a.get('suggestedHumanReadableName','').startswith(label)]
        need(len(found)==1 and found[0].get('deviceId')==udid,'UNIQUE_CURRENT_NATIVE_EOF_ATTACHMENT_REQUIRED:'+role)
        name=found[0]['exportedFileName'];relative=FOLDER+'/'+name
        contents[role]=verified(relative,32*1024*1024 if role=='report'else 16*1024*1024)
        descriptors[role]={'path':relative,'bytes':len(contents[role]),'sha256':sha(contents[role])}
    report=parsed(contents['report']);pending=parsed(contents['pending']);last=report['freezes'][-1]
    need(pending['schema']=='v16-ios-eof-acquisition-pending-v1'and pending['status']=='PENDING_MANDATORY_OFFLINE_EOF_FRAME_ASSESSMENT','EXPLICIT_PENDING_NOT_PASS_ACQUISITION_REQUIRED')
    count=len([e for e in report['events']if e.get('kind')=='native:ended'and e.get('trusted')is True])
    need(pending['documentInstance']==last['documentInstance']and pending['timeOrigin']==last['timeOrigin']and pending['nativeOwner']==last['native']['owner']and pending['loadId']==last['driveVideo']['loadId']and pending['config']==last['config']and pending['trustedEndedCount']==count,'PENDING_RECEIPT_NOT_SAME_NF_ACQUISITION')
    assessor=load_assessor()
    original,payload=assessor.contract.unpack(contents['carrier'],contents['packedStatus'].decode().strip(),contents['frozenStatus'].decode().strip(),last['timeOrigin'])
    result=assessor.assess_payload(payload,report)
    need(result['frameAcceptancePending']is False,'EOF_FRAME_ACCEPTANCE_STILL_PENDING')
    result.update(schema='mandatory-native-ios-eof-ci-assessment-v1',selectedSimulatorUDID=udid,runId=run_id,runAttempt=run_attempt,officialOriginalAttachments=descriptors,originalBytes=len(original),originalSHA256=sha(original),nativeXCTestAcquisitionSucceeded=True,pendingReceiptIsNotAcceptance=True,assessorClosure=PINS)
    return result
def main():
    root=Path('evidence');code=2
    try:
        need(os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('RUNNER_OS')=='macOS'and os.environ.get('RUNNER_ARCH')=='ARM64','OWNED_HOSTED_MACOS_ARM64_CI_REQUIRED')
        result=assess(root,os.environ.get('SIMULATOR_UDID'),os.environ.get('GITHUB_RUN_ID'),os.environ.get('GITHUB_RUN_ATTEMPT'));code=0
    except (ValueError,KeyError,TypeError,IndexError,OSError,ImportError)as error:
        result={'schema':'mandatory-native-ios-eof-ci-assessment-v1','status':'NOT_QUALIFIED_OR_INCOMPLETE','frameAcceptancePending':True,'errorClass':type(error).__name__,'reason':str(error),'wholeBugFixed':False,'audioMeasured':False}
    need(root.is_dir()and not root.is_symlink(),'OWNED_EVIDENCE_DIRECTORY_REQUIRED')
    with (root/'v16-eof-assessment.json').open('x')as file:file.write(json.dumps(result,indent=2,allow_nan=False)+'\n')
    return code
if __name__=='__main__':raise SystemExit(main())
