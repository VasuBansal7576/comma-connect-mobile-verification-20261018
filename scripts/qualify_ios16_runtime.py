#!/usr/bin/env python3
"""Exact official16.4 runtime and one newly owned device; no product/PWA/audio test."""
import hashlib,importlib.util,json,os,pathlib,re,shutil,sys,time,uuid

BASE_SHA='77821ad5b2066b8dd732463849b442c71e84237adfe084a721f2e5d04253f5a4'
ARCHIVE_SHA='054c728fe7baf368a58f06b056b450d04e6fc271b51c11346bf1a0f0ac43a898'
ARCHIVE_BYTES=6182486138
RUNTIME='com.apple.CoreSimulator.SimRuntime.iOS-16-4'
DEVICE_TYPE='com.apple.CoreSimulator.SimDeviceType.iPhone-14'
OUT=pathlib.Path('evidence/ios16-runtime-qualification')
START=None;CLIENT=None;SAFE=True;OWNED_UUID=None;NAME=None;BASELINE_IDS=set()
R={'schema':'owned-ios16-runtime-qualification-v1','status':'STARTING','commands':[],'requestedVersion':'16.4','requestedBuild':'20E247','agreementAcceptedByScript':False,'accountInputByScript':False,'productTestPerformed':False,'nativeHTTPVerified':False,'physicalDeviceEquivalent':False,'archiveSignatureIndependentlyVerified':False,'archiveArchitectureIndependentlyVerified':False,'ownedDeviceCleanupVerified':False}
class Refused(Exception):pass

def save():OUT.mkdir(parents=True,exist_ok=True);(OUT/'receipt.json').write_text(json.dumps(R,indent=2)+'\n')
def sha(path):
    digest=hashlib.sha256()
    with path.open('rb')as f:
        while True:
            if time.monotonic()>=START+900:raise Refused('ACTIVE_WORK_CUTOFF')
            data=f.read(1024*1024)
            if not data:break
            digest.update(data)
    return digest.hexdigest()

def command_limit(now,seconds,cleanup=False):
    # Existing supervisor may spend6s in cleanup and2s retaining logs.
    value=min(seconds,START+(1020 if cleanup else 900)-now-9)
    if value<=0:raise Refused('OWNED_CLEANUP_RESERVE_OR_OUTER_DEADLINE')
    return value

def call(phase,args,seconds,cleanup=False,scan=False,export=None):
    global SAFE
    if not SAFE:raise Refused('PRIOR_COMMAND_CLEANUP_UNVERIFIED_NO_MORE_COMMANDS')
    limit=command_limit(time.monotonic(),seconds,cleanup);R['phase']=phase;save()
    CLIENT.OUT=OUT/phase;CLIENT.OUT.mkdir(parents=True,exist_ok=False);before=len(R['commands'])
    try:
        # Phase directories preserve both command logs; the original guarded
        # label enables the unchanged supervisor's consent/auth prompt scanner.
        result=CLIENT.execute('exact-client-operation'if scan else phase,args,limit,export)
        row=R['commands'][before];cleanup_result=row.get('cleanup',{})
        if cleanup_result.get('leaderReaped')is not True or cleanup_result.get('ownedGroupAbsent')is not True:raise Refused('OWNED_COMMAND_CLEANUP_UNVERIFIED')
        if row.get('rawOutputCompleteAtRetentionObservation')is not True:raise Refused('COMMAND_FULL_OUTPUT_NOT_RETAINED')
        return result
    except CLIENT.Refused as error:raise Refused(str(error))
    finally:
        if len(R['commands'])>before:
            row=R['commands'][before];row['qualificationPhase']=phase
            c=row.get('cleanup',{});SAFE=c.get('leaderReaped')is True and c.get('ownedGroupAbsent')is True
        else:SAFE=False
        save()

def parsed(text,key):
    if len(text.encode())>2*1024*1024:raise Refused('SIMCTL_JSON_BOUND')
    try:value=json.loads(text)
    except ValueError:raise Refused('SIMCTL_JSON_INVALID')
    if not isinstance(value,dict)or key not in value:raise Refused('SIMCTL_JSON_SCHEMA')
    return value[key]

def exact_runtime(text):
    rows=parsed(text,'runtimes')
    if not isinstance(rows,list)or len(rows)>256:raise Refused('RUNTIME_LIST_SCHEMA')
    matches=[r for r in rows if isinstance(r,dict)and r.get('identifier')==RUNTIME and r.get('version')=='16.4'and r.get('buildversion')=='20E247'and r.get('isAvailable')is True]
    if len(matches)>1:raise Refused('AMBIGUOUS_EXACT_RUNTIME')
    return matches[0]if matches else None

def device_rows(text):
    groups=parsed(text,'devices')
    if not isinstance(groups,dict)or len(groups)>256:raise Refused('DEVICE_GROUP_SCHEMA')
    rows=[]
    for runtime,values in groups.items():
        if not isinstance(runtime,str)or not isinstance(values,list)or len(values)>512:raise Refused('DEVICE_LIST_SCHEMA')
        for value in values:
            if not isinstance(value,dict):raise Refused('DEVICE_ROW_SCHEMA')
            rows.append((runtime,value))
    if len(rows)>2048:raise Refused('DEVICE_LIST_BOUND')
    return rows

def uuid_text(value):
    return isinstance(value,str)and re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',value)is not None

def bind_created(text,returned=None):
    matches=[(runtime,row)for runtime,row in device_rows(text)if row.get('name')==NAME]
    if len(matches)!=1:raise Refused('UNIQUE_NEW_OWN_MARKER_REQUIRED')
    runtime,row=matches[0];ident=row.get('udid')
    if runtime!=RUNTIME or not uuid_text(ident)or ident.lower()in BASELINE_IDS or row.get('isAvailable')is not True or row.get('deviceTypeIdentifier')!=DEVICE_TYPE:raise Refused('EXACT_NEW_OWN_DEVICE_SCHEMA_REQUIRED')
    if returned is not None and ident.lower()!=returned.lower():raise Refused('CREATE_RETURNED_UUID_MISMATCH')
    return ident,row

def require_help(text,words):
    if any(word.lower()not in text.lower()for word in words):raise Refused('ACTUAL_SIMCTL_HELP_REQUIRED')

def require_simctl_commands(text):
    # Public general help omits hidden bootstatus; inspect its actual help next.
    commands=set(re.findall(r'^\s+([a-z_]+)\s{2,}\S',text,re.MULTILINE))
    if not {'list','create','boot','shutdown','delete','io'}<=commands:raise Refused('ACTUAL_SIMCTL_HELP_REQUIRED')

def require_bootstatus_help(text):
    usage=re.search(r'^\s*usage:\s*simctl\s+bootstatus\b[^\r\n]*<device>[^\r\n]*',text,re.IGNORECASE|re.MULTILINE)
    option=re.search(r'(?<![\w-])-b(?![\w-])',usage.group(0))if usage else None
    if usage is None or(option is None and re.search(r'^\s*-b(?:\s|$)',text,re.MULTILINE)is None):raise Refused('ACTUAL_SIMCTL_BOOTSTATUS_HELP_REQUIRED')

def runtime_support(runtime):
    evidence={'scope':'Actual simctl declarations, not independent archive signature/architecture verification.'}
    arch=runtime.get('supportedArchitectures')
    if arch is not None:
        if not isinstance(arch,list)or len(arch)>16 or any(not isinstance(v,str)for v in arch)or'arm64'not in arch:raise Refused('RUNTIME_ARM64_SUPPORT_NOT_DECLARED')
        evidence['supportedArchitectures']=arch
    types=runtime.get('supportedDeviceTypes')
    if types is not None:
        if not isinstance(types,list)or len(types)>512 or any(not isinstance(v,dict)for v in types)or not any(v.get('identifier')==DEVICE_TYPE for v in types):raise Refused('RUNTIME_IPHONE14_SUPPORT_NOT_DECLARED')
        evidence['requestedDeviceTypeListed']=True
    evidence['architectureMetadataStatus']='DECLARED_ARM64'if arch is not None else'NOT_ADVERTISED_BOOT_COMPATIBILITY_PENDING'
    evidence['deviceTypeMetadataStatus']='DECLARED_IPHONE14'if types is not None else'NOT_ADVERTISED_BOOT_COMPATIBILITY_PENDING'
    return evidence

def runtime_list(phase):return call(phase,['/usr/bin/xcrun','simctl','list','runtimes','--json'],90 if phase=='runtimes-before'else 60)
def devices(phase,cleanup=False):return call(phase,['/usr/bin/xcrun','simctl','list','devices','--json'],20,cleanup)

def qualify():
    global NAME,BASELINE_IDS,OWNED_UUID
    runtime=exact_runtime(runtime_list('runtimes-before'))
    require_simctl_commands(call('simctl-help',['/usr/bin/xcrun','simctl','help'],20))
    require_bootstatus_help(call('help-bootstatus',['/usr/bin/xcrun','simctl','help','bootstatus'],20))
    if runtime is None:
        export=(OUT/'export').resolve();export.mkdir(exist_ok=False);R['ownedExportCreated']=True;save()
        call('official-exact-download',CLIENT.fixed_command(export),720,scan=True,export=export)
        files=list(export.rglob('*'))
        if any(p.is_symlink()for p in files):raise Refused('ARCHIVE_SYMLINK_REFUSED')
        files=[p for p in files if p.is_file()]
        if len(files)!=1 or files[0].suffix.lower()!='.dmg'or files[0].stat().st_size!=ARCHIVE_BYTES:raise Refused('EXACT_ORIGINAL_ARCHIVE_REQUIRED')
        digest=sha(files[0])
        if digest!=ARCHIVE_SHA:raise Refused('PREVIOUS_EXACT_OFFICIAL_ARCHIVE_HASH_REQUIRED')
        R['archive']={'name':files[0].name,'bytes':ARCHIVE_BYTES,'sha256':digest,'scope':'Matches original official-client export; not independent signature or architecture proof.'};save()
        runtime=exact_runtime(runtime_list('runtimes-after-client'))
        if runtime is None:
            require_help(call('help-runtime',['/usr/bin/xcrun','simctl','help','runtime'],15),['runtime','add','path'])
            call('official-runtime-add',['/usr/bin/xcrun','simctl','runtime','add',str(files[0])],180,scan=True)
            runtime=exact_runtime(runtime_list('runtimes-after-add'))
        if runtime is None:raise Refused('EXACT_AVAILABLE_RUNTIME_NOT_ACQUIRED')
    else:R['archive']={'status':'NOT_USED_EXISTING_EXACT_AVAILABLE_RUNTIME'}
    R['selectedRuntime']={k:runtime.get(k)for k in ['identifier','name','version','buildversion','isAvailable']};R['runtimeSupport']=runtime_support(runtime);save()
    types=parsed(call('device-types',['/usr/bin/xcrun','simctl','list','devicetypes','--json'],20),'devicetypes')
    if not isinstance(types,list)or len(types)>512:raise Refused('DEVICE_TYPE_SCHEMA')
    selected=[row for row in types if isinstance(row,dict)and row.get('name')=='iPhone 14'and row.get('identifier')==DEVICE_TYPE]
    if len(selected)!=1:raise Refused('UNIQUE_ACTUAL_IPHONE14_TYPE_REQUIRED')
    R['selectedDeviceType']={k:selected[0].get(k)for k in ['name','identifier','minRuntimeVersionString','maxRuntimeVersionString']}
    require_help(call('help-create',['/usr/bin/xcrun','simctl','help','create'],15),['create','name','device','runtime'])
    require_help(call('help-io',['/usr/bin/xcrun','simctl','help','io'],15),['io','screenshot'])
    NAME='rea-ios16-qualification-'+uuid.uuid4().hex;R['creation']={'unique128BitMarker':NAME,'attempted':False};save()
    baseline=device_rows(devices('devices-baseline'))
    if any(not uuid_text(row.get('udid'))for _,row in baseline):raise Refused('BASELINE_DEVICE_UUID_SCHEMA_REQUIRED')
    BASELINE_IDS={row['udid'].lower()for _,row in baseline}
    if any(row.get('name')==NAME for _,row in baseline):raise Refused('OWN_MARKER_ALREADY_EXISTS')
    R['creation'].update(baselineMarkerAbsent=True,baselineDeviceCount=len(BASELINE_IDS),baselineIDsSHA256=hashlib.sha256(json.dumps(sorted(BASELINE_IDS)).encode()).hexdigest(),attempted=True);save()
    try:
        response=call('create-own-device',['/usr/bin/xcrun','simctl','create',NAME,DEVICE_TYPE,RUNTIME],30).strip()
        if not uuid_text(response):raise Refused('CREATE_UUID_OUTPUT_REQUIRED')
        OWNED_UUID,row=bind_created(devices('devices-after-create'),response)
    except Refused:
        # One bounded readonly reconciliation only; never repeat create or guess
        # a UUID. A newly owned exact marker can be bound solely for cleanup.
        if SAFE:
            try:
                OWNED_UUID,row=bind_created(devices('devices-reconcile-create'))
                R['creation'].update(outcome='EXACT_NEW_MARKER_RECONCILED_FOR_CLEANUP_ONLY',udid=OWNED_UUID);save()
            except Refused:R['creation']['outcome']='UNKNOWN_NO_BOUND_UUID_EPHEMERAL_TEARDOWN_REQUIRED';save()
        raise
    R['creation'].update(outcome='EXACT_NEW_DEVICE_BOUND',udid=OWNED_UUID);save()
    call('boot-own-device',['/usr/bin/xcrun','simctl','boot',OWNED_UUID],30)
    call('bootstatus-own-device',['/usr/bin/xcrun','simctl','bootstatus',OWNED_UUID,'-b'],180)
    ident,row=bind_created(devices('devices-after-boot'),OWNED_UUID)
    if row.get('state')!='Booted':raise Refused('EXACT_OWN_DEVICE_BOOTED_REQUIRED')
    screenshot=(OUT/'owned-ios16-home.png').resolve()
    call('screenshot-own-device',['/usr/bin/xcrun','simctl','io',OWNED_UUID,'screenshot',str(screenshot)],15)
    if not screenshot.is_file()or not 24<=screenshot.stat().st_size<=8*1024*1024:raise Refused('OWN_SCREENSHOT_BOUND')
    with screenshot.open('rb')as f:header=f.read(24)
    if header[:8]!=b'\x89PNG\r\n\x1a\n'or header[12:16]!=b'IHDR':raise Refused('OWN_SCREENSHOT_PNG_REQUIRED')
    dimensions=[int.from_bytes(header[16:20],'big'),int.from_bytes(header[20:24],'big')]
    if any(not 1<=n<=16384 for n in dimensions):raise Refused('OWN_SCREENSHOT_DIMENSIONS_REQUIRED')
    R['bootProof']={'udid':ident,'name':NAME,'runtime':RUNTIME,'version':'16.4','build':'20E247','state':row['state'],'screenshotSHA256':sha(screenshot),'screenshotDimensions':dimensions,'scope':'Official bootstatus + exact own Booted record + original screenshot. No Safari/product/nativeHTTP/physical-device proof.'};save()

def cleanup_device():
    if OWNED_UUID is None:
        R['ownedDeviceCleanupStatus']='NO_BOUND_DEVICE'if not R.get('creation',{}).get('attempted')else'UNBOUND_CREATE_OUTCOME_EPHEMERAL_TEARDOWN_REQUIRED';save();return
    R['cleanupDevice']={'udid':OWNED_UUID,'name':NAME,'operations':[]};save()
    try:bind_created(devices('cleanup-identity-readback',cleanup=True),OWNED_UUID)
    except Refused as error:
        R['ownedDeviceCleanupStatus']='IDENTITY_NOT_RECONFIRMED_NO_MUTATION_EPHEMERAL_TEARDOWN_REQUIRED';R['cleanupDevice']['identityRefusal']=str(error);save();return
    for operation in ['shutdown','delete']:
        try:call('cleanup-'+operation,['/usr/bin/xcrun','simctl',operation,OWNED_UUID],20,cleanup=True);status='EXITED_ZERO'
        except Refused as error:status=str(error)
        R['cleanupDevice']['operations'].append({'operation':operation,'status':status});save()
    try:
        rows=device_rows(devices('cleanup-absence-readback',cleanup=True));absent=not any(isinstance(row.get('udid'),str)and row['udid'].lower()==OWNED_UUID.lower()for _,row in rows)
        R['ownedDeviceCleanupVerified']=absent and SAFE;R['ownedDeviceCleanupStatus']='EXACT_OWN_UUID_ABSENCE_VERIFIED'if absent and SAFE else'NOT_VERIFIED_EPHEMERAL_TEARDOWN_REQUIRED'
    except Refused as error:R['ownedDeviceCleanupStatus']='NOT_VERIFIED_EPHEMERAL_TEARDOWN_REQUIRED';R['cleanupDevice']['readbackRefusal']=str(error)
    save()

def main():
    global START,CLIENT
    START=time.monotonic();save()
    try:
        if sys.argv[1:]!=['--reviewed-ephemeral-ios16-qualification']:raise Refused('EXPLICIT_QUALIFICATION_REQUIRED')
        if os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_OS')!='macOS'or os.environ.get('RUNNER_ARCH')!='ARM64':raise Refused('OWN_EPHEMERAL_MAC_REQUIRED')
        path=pathlib.Path(__file__).with_name('probe_ios16_official_client.py')
        if not path.is_file()or hashlib.sha256(path.read_bytes()).hexdigest()!=BASE_SHA:raise Refused('EXACT_REVIEWED_SUPERVISOR_REQUIRED')
        spec=importlib.util.spec_from_file_location('exact_apple_supervisor',path);CLIENT=importlib.util.module_from_spec(spec);spec.loader.exec_module(CLIENT)
        if os.environ.get('DEVELOPER_DIR')!=CLIENT.DEVELOPER or not pathlib.Path(CLIENT.DEVELOPER).is_dir():raise Refused('EXISTING_SELECTED_XCODE_REQUIRED')
        if (CLIENT.TOTAL_SECONDS,CLIENT.CLIENT_SECONDS,CLIENT.EXPORT_CAP,CLIENT.MIN_FREE,CLIENT.MAX_DISK_DELTA)!=(1020,720,6200000000,18*1024**3,20*1024**3):raise Refused('ORIGINAL_SUPERVISOR_CAPS_REQUIRED')
        CLIENT.START=START;CLIENT.R=R;CLIENT.save=save;R['supervisorSHA256']=BASE_SHA;R['helperSHA256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest();save()
        version=call('xcode-version',['/usr/bin/xcodebuild','-version'],15)
        if version.strip()!='Xcode 16.4\nBuild version 16F6':raise Refused('EXACT_EXISTING_XCODE164_REQUIRED')
        CLIENT.require_help(call('xcode-help',['/usr/bin/xcodebuild','-help'],20))
        call('firstlaunch-status',['/usr/bin/xcodebuild','-checkFirstLaunchStatus'],20)
        qualify();R['status']='EXACT_RUNTIME_OWN_DEVICE_BOOT_QUALIFIED_PENDING_CLEANUP';save()
    except Exception as error:
        R['status']='REFUSED_OR_INCOMPLETE';R['refusalCode']=str(error)if isinstance(error,Refused)else type(error).__name__;save()
    finally:
        if CLIENT is not None:
            try:cleanup_device()
            except Exception as error:R['ownedDeviceCleanupStatus']='NOT_VERIFIED_EPHEMERAL_TEARDOWN_REQUIRED';R['cleanupExceptionType']=type(error).__name__
        export=OUT/'export'
        if R.get('ownedExportCreated')and export.is_dir():
            try:shutil.rmtree(export)
            except OSError:R['ownedExportRemovalError']='OWNED_EXPORT_REMOVE_FAILED'
        R['ownedExportRemoved']=bool(R.get('ownedExportCreated')and not export.exists());R['elapsedSeconds']=time.monotonic()-START
        export_clean=not R.get('ownedExportCreated')or R.get('ownedExportRemoved')is True
        R['qualified']=bool(R.get('bootProof')and R.get('ownedDeviceCleanupVerified')and SAFE and export_clean and R['status']=='EXACT_RUNTIME_OWN_DEVICE_BOOT_QUALIFIED_PENDING_CLEANUP')
        if R['qualified']:R['status']='EXACT_RUNTIME_OWNED_BOOT_AND_CLEANUP_QUALIFIED_NO_PRODUCT_TEST'
        R['hostRuntimeCacheDaemonCleanupScope']='Ephemeral host teardown; no runtime uninstall, existing device mutation or global service kill.';save()
    return 0 if R.get('qualified')else 2

if __name__=='__main__':raise SystemExit(main())
