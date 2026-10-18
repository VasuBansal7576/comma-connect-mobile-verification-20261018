#!/usr/bin/env python3
"""One exact official runtime operation on an ephemeral hosted Mac; no consent input."""
import hashlib,json,os,pathlib,re,shutil,signal,subprocess,sys,time,urllib.parse

OUT=pathlib.Path('evidence/ios16-official-client')
EXPECTED_SIZE=6182486138
EXPORT_CAP=6200000000
MIN_FREE=18*1024**3
MAX_DISK_DELTA=20*1024**3
TOTAL_SECONDS=1020
CLIENT_SECONDS=720
DEVELOPER='/Applications/Xcode_16.4.app/Contents/Developer'
OFFICIAL_URI='https://download.developer.apple.com/Developer_Tools/iOS_16.4_Simulator_Runtime/iOS_16.4_Simulator_Runtime.dmg'
R={'schema':'exact-ios16-official-client-probe-v1','status':'NOT_STARTED','requestedVersion':'16.4','requestedBuild':'20E247','expectedArchiveBytes':EXPECTED_SIZE,'officialIndexURI':OFFICIAL_URI,'agreementAcceptedByScript':False,'accountInputByScript':False,'runtimeUsableVerified':False,'nativeHTTPVerified':False,'commands':[]}
START=None

class Refused(Exception):pass

def save():OUT.mkdir(parents=True,exist_ok=True);(OUT/'receipt.json').write_text(json.dumps(R,indent=2)+'\n')
def group_exists(pid):
    try:os.killpg(pid,0);return True
    except ProcessLookupError:return False
    except PermissionError:return True

def stop(proc):
    events=[]
    # A normal-completion poll may already have reaped this PID. Its numeric
    # group is no longer bound; refuse signaling even if that group exists.
    if proc.returncode is not None:
        return {'leaderReaped':True,'ownedGroupAbsent':not group_exists(proc.pid),'returnCode':proc.returncode,'signals':[],'signalScope':'NO_SIGNAL_AFTER_LEADER_REAP'}
    for sig,grace in [(signal.SIGTERM,3),(signal.SIGKILL,3)]:
        if group_exists(proc.pid):
            try:os.killpg(proc.pid,sig);events.append(signal.Signals(sig).name)
            except ProcessLookupError:pass
            except PermissionError:events.append('SIGNAL_PERMISSION_DENIED')
        end=time.monotonic()+grace
        # No poll/wait here: our direct child remains alive or an unreaped
        # zombie, reserving its PID/PGID until the final signal has completed.
        while time.monotonic()<end and group_exists(proc.pid):time.sleep(.05)
    try:proc.wait(timeout=.2)
    except subprocess.TimeoutExpired:pass
    return {'leaderReaped':proc.returncode is not None,'ownedGroupAbsent':not group_exists(proc.pid),'returnCode':proc.returncode,'signals':events,'signalScope':'UNREAPED_OWN_DIRECT_CHILD_THROUGH_FINAL_SIGNAL'}

def retain_raw(raw,cleanup,deadline):
    cap=2*1024*1024;prefix=bytearray();observed_size=0;eof=False;size_stable=False
    try:
        if raw.exists():
            with raw.open('rb')as f:
                observed_size=os.fstat(f.fileno()).st_size
                while len(prefix)<min(observed_size,cap)and time.monotonic()<deadline:
                    data=f.read(min(65536,min(observed_size,cap)-len(prefix)))
                    if not data:break
                    prefix.extend(data)
                if len(prefix)==observed_size and observed_size<=cap and time.monotonic()<deadline:
                    eof=f.read(1)==b'';size_stable=os.fstat(f.fileno()).st_size==observed_size
        complete=bool(eof and size_stable and cleanup.get('leaderReaped')is True and cleanup.get('ownedGroupAbsent')is True)
        return prefix.decode(errors='replace'),{'rawOutputBytesObserved':observed_size,'retainedPrefixBytes':len(prefix),'retainedPrefixSHA256':hashlib.sha256(prefix).hexdigest(),'rawOutputSHA256':hashlib.sha256(prefix).hexdigest()if complete else None,'rawOutputCompleteAtRetentionObservation':complete,'rawOutputTruncatedOrCompletenessUnknown':not complete,'retentionByteCap':cap,'retentionDeadlineSeconds':2}
    finally:raw.unlink(missing_ok=True)

def sanitize(text):
    def url(m):
        try:
            p=urllib.parse.urlsplit(m.group());return urllib.parse.urlunsplit((p.scheme,p.hostname or '',p.path,'',''))
        except ValueError:return '[URL_REDACTED]'
    lines=[]
    for line in text.splitlines():
        if re.search(r'token|authorization:|cookie|password|apple.?id',line,re.I):lines.append('[SENSITIVE_LINE_REDACTED]')
        else:lines.append(re.sub(r'https?://[^\s<>"\']+',url,line))
    return '\n'.join(lines)

def prompt_code(text):
    if re.search(r'license agreement|must agree|accept the.*agreement|agree.{0,80}terms|terms.{0,80}agree',text,re.I):return 'NEW_AGREEMENT_OR_CONSENT_REQUIRED'
    if re.search(r'sign in|authentication required|unauthorized|enter.{0,30}(password|apple.?id)',text,re.I):return 'ACCOUNT_OR_AUTHORIZATION_REQUIRED'

def exported_bytes(export):
    total=0
    for p in export.rglob('*'):
        if p.is_symlink():raise Refused('EXPORTED_SYMLINK_REFUSED')
        if p.is_file():total+=p.stat().st_size
    return total

def resource_code(now,deadline,free,initial_free,export_size,log_size):
    if now>=deadline:return 'ABSOLUTE_DEADLINE'
    if free<MIN_FREE:return 'DISK_FREE_FLOOR'
    if initial_free-free>MAX_DISK_DELTA:return 'DISK_DELTA_CAP'
    if export_size>EXPORT_CAP:return 'EXPORTED_ARCHIVE_BYTE_CAP'
    if log_size>2*1024*1024:return 'CLIENT_LOG_BYTE_CAP'

def execute(label,argv,seconds,export=None):
    if START is None:raise Refused('PROBE_START_REQUIRED')
    raw=OUT/(label+'.private');row={'label':label,'argv':argv,'stdin':'DEVNULL','usesPipes':False,'mayInstallRuntime':label=='exact-client-operation'};R['commands'].append(row);save()
    began=time.monotonic();deadline=min(START+TOTAL_SECONDS,began+seconds);initial_free=shutil.disk_usage(OUT).free;proc=None;code=None
    try:
        with raw.open('wb')as log:
            proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            while True:
                now=time.monotonic();size=raw.stat().st_size;free=shutil.disk_usage(OUT).free
                code=resource_code(now,deadline,free,initial_free,exported_bytes(export)if export else 0,size)
                if not code and label=='exact-client-operation':
                    with raw.open('rb')as f:f.seek(max(0,size-65536));code=prompt_code(f.read(65536).decode(errors='replace'))
                if code or proc.poll()is not None:break
                time.sleep(.25)
    finally:
        cleanup=stop(proc)if proc else {'leaderReaped':True,'ownedGroupAbsent':True,'returnCode':None,'signals':[]};row['cleanup']=cleanup;row['elapsedSeconds']=time.monotonic()-began
        text,retention=retain_raw(raw,cleanup,min(START+TOTAL_SECONDS,time.monotonic()+2));row.update(retention);(OUT/(label+'.log')).write_text(sanitize(text));row['refusalCode']=code;save()
    if code:raise Refused(code)
    if not cleanup['leaderReaped']or not cleanup['ownedGroupAbsent']:raise Refused('OWNED_CLIENT_CLEANUP_UNVERIFIED')
    if cleanup['returnCode']!=0:raise Refused(prompt_code(text)or('OFFICIAL_CLIENT_EXIT_NONZERO_'+label))
    return text

def require_help(text):
    for option in ['-downloadPlatform','-buildVersion','-exportPath','-architectureVariant','-checkFirstLaunchStatus']:
        if option not in text:raise Refused('REQUIRED_ACTUAL_HELP_OPTION_MISSING')

def fixed_command(export):
    return ['/usr/bin/xcodebuild','-downloadPlatform','iOS','-buildVersion','20E247','-architectureVariant','universal','-exportPath',str(export)]

def main():
    global START
    START=time.monotonic();owned_export=False;R['helperSHA256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest();save()
    try:
        if sys.argv[1:]!=['--reviewed-ephemeral-official-client-probe']:raise Refused('EXPLICIT_REVIEWED_PROBE_REQUIRED')
        if os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_OS')!='macOS'or os.environ.get('RUNNER_ARCH')!='ARM64':raise Refused('EPHEMERAL_HOSTED_MAC_REQUIRED')
        if os.environ.get('DEVELOPER_DIR')!=DEVELOPER or not pathlib.Path(DEVELOPER).is_dir():raise Refused('EXISTING_XCODE164_REQUIRED')
        version=execute('version',['/usr/bin/xcodebuild','-version'],15)
        if version.strip()!='Xcode 16.4\nBuild version 16F6':raise Refused('EXACT_XCODE164_BUILD_REQUIRED')
        require_help(execute('actual-help',['/usr/bin/xcodebuild','-help'],20))
        execute('existing-firstlaunch-status',['/usr/bin/xcodebuild','-checkFirstLaunchStatus'],20)
        before=execute('runtimes-before',['/usr/bin/xcrun','simctl','list','runtimes','--json'],20);json.loads(before)
        export=(OUT/'export').resolve();export.mkdir(exist_ok=False);owned_export=True
        if shutil.disk_usage(OUT).free<MIN_FREE:raise Refused('DISK_FREE_FLOOR')
        R['status']='ONE_OFFICIAL_CLIENT_OPERATION';R['scope']='May download, install and export exact20E247; no consent/account response, runtime import, boot or product test is requested.';save()
        execute('exact-client-operation',fixed_command(export),CLIENT_SECONDS,export)
        R['status']='CLIENT_EXIT_ZERO_ARCHIVE_NOT_YET_QUALIFIED';save()
        after=execute('runtimes-after',['/usr/bin/xcrun','simctl','list','runtimes','--json'],20);json.loads(after)
        files=[p for p in export.rglob('*')if p.is_file()]
        if len(files)!=1 or files[0].suffix.lower()!='.dmg'or files[0].stat().st_size!=EXPECTED_SIZE:raise Refused('EXACT_ORIGINAL_ARCHIVE_SHAPE_SIZE_REQUIRED')
        digest=hashlib.sha256()
        with files[0].open('rb')as f:
            while True:
                if time.monotonic()>=START+TOTAL_SECONDS:raise Refused('ARCHIVE_HASH_DEADLINE')
                data=f.read(1024*1024)
                if not data:break
                digest.update(data)
        R['archive']={'name':files[0].name,'bytes':EXPECTED_SIZE,'sha256':digest.hexdigest(),'identityScope':'Exact requested build and original index size; SHA is observed, not an upstream expected digest/signature or boot proof.'}
        R['status']='OFFICIAL_CLIENT_EXACT_REQUEST_EXPORTED_ARCHIVE_HASH_RETAINED_NO_USE';save()
    except (Refused,ValueError,OSError)as error:
        R['status']='REFUSED_OR_INCOMPLETE';R['refusalCode']=str(error)if isinstance(error,Refused)else type(error).__name__;save();return 2
    finally:
        export=OUT/'export'
        if owned_export and export.is_dir():shutil.rmtree(export)
        R['ownedExportCreatedByThisRun']=owned_export;R['ownedExportRemoved']=owned_export and not export.exists();save()
    return 0

if __name__=='__main__':raise SystemExit(main())
