#!/usr/bin/env python3
"""Manual hosted Linux calibration only: private null-sink, no Android/UI/microphone."""
import hashlib,json,os,pathlib,shlex,shutil,signal,subprocess,sys,tempfile,time
import calibration_support as pattern
import routing
import validate_native
HERE=pathlib.Path(__file__).resolve().parent
OUT=pathlib.Path('evidence/native-pulse-calibration')
DEADLINE=None
COMMANDS=[]

def require_ci(env=None):
    e=os.environ if env is None else env
    if any(e.get(k)!=v for k,v in {'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','RUNNER_ARCH':'X64'}.items()):raise routing.Refused('Hosted Linux X64 GitHub Actions only')
def remaining():
    if DEADLINE is None or time.monotonic()>=DEADLINE:raise TimeoutError('Independent native gate deadline')
    return DEADLINE-time.monotonic()
def watchdog(sig,frame):raise TimeoutError('Independent native gate watchdog')
def digest(path):
    h=hashlib.sha256()
    with pathlib.Path(path).open('rb')as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def save(name,obj):
    with(OUT/name).open('x')as f:json.dump(obj,f,indent=2);f.write('\n')
def launch(cmd,label,env=None):
    remaining();log=(OUT/(label+'.log')).open('xb')
    try:p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=env)
    finally:log.close()
    return p

def bounded(cmd,label,limit,env=None):
    p=None;r={'command':cmd,'label':label,'limitSeconds':limit,'usesPipes':False};COMMANDS.append(r);began=time.monotonic()
    try:
        p=launch(cmd,label,env);p.wait(timeout=min(limit,remaining()))
    except Exception as e:r['error']={'name':type(e).__name__,'message':str(e)}
    finally:r['cleanup']=pattern.stop(p);r['elapsedSeconds']=time.monotonic()-began
    c=r['cleanup'];r['ok']=not r.get('error')and c.get('returnCode')==0 and c['leaderReaped']and c['ownedGroupAbsent']and not c.get('signals')
    if not r['ok']:raise routing.Refused('Owned bounded command failed: '+label)
    path=OUT/(label+'.log')
    if path.stat().st_size>2*1024*1024:raise routing.Refused('Command output exceeds bound')
    r['logSHA256']=digest(path);return path.read_bytes()

def provision():
    # Fixed official Ubuntu packages only, on this disposable remote runner. No SDK/licenses.
    bounded(['/usr/bin/sudo','-n','/usr/bin/apt-get','update'],'apt-update',90)
    bounded(['/usr/bin/sudo','-n','/usr/bin/env','DEBIAN_FRONTEND=noninteractive','/usr/bin/apt-get','-y','--no-install-recommends','install','pulseaudio','pulseaudio-utils','libpulse-dev','gcc','pkg-config'],'apt-install',180)

def tools():
    found={n:shutil.which(n)for n in ['pulseaudio','pactl','paplay','gcc','pkg-config','dpkg-query']}
    if not all(found.values()):raise routing.Refused('Reviewed installed tools absent')
    return found

def list_json(tool,kind,label,env):
    data=json.loads(bounded([tool,'--format=json','list',kind],label,4,env))
    if not isinstance(data,list):raise routing.Refused('Actual Pulse JSON array required')
    return data

def fs_identity(path):
    x=pathlib.Path(path).lstat();return {'device':x.st_dev,'inode':x.st_ino,'uid':x.st_uid,'mode':x.st_mode}

def private_graph(tool,boot,env,label,recorder=None,player=None,expect_empty=False):
    routing.remote_private(boot,env)
    private=pathlib.Path(boot['privatePulseRuntime']['path'])
    for key,path in [('directoryIdentity',private),('socketIdentity',private/'native')]:
        if boot['privatePulseRuntime'].get(key)!=fs_identity(path):raise routing.Refused('Original private socket/directory identity changed')
    sinks=list_json(tool,'sinks',label+'-sinks',env);sources=list_json(tool,'sources',label+'-sources',env)
    si,mo=routing.private_devices(sinks,sources)
    ins=list_json(tool,'sink-inputs',label+'-inputs',env);outs=list_json(tool,'source-outputs',label+'-outputs',env)
    result={'hostMonotonicSeconds':time.monotonic(),'sinkIndex':si,'monitorIndex':mo}
    if expect_empty:
        if ins or outs:raise routing.Refused('No clients allowed outside owned calibration')
        result['clientsEmpty']=True
    else:
        result['inputs']=routing.input_bindings(ins,si,player,routing.proc_record)
        result['recorder']=routing.recorder_binding(outs,mo,recorder,routing.proc_record)
    routing.remote_private(boot,env)
    for key,path in [('directoryIdentity',private),('socketIdentity',private/'native')]:
        if boot['privatePulseRuntime'][key]!=fs_identity(path):raise routing.Refused('Private socket/directory replaced during graph observation')
    return result

def wait_marker(p,label,marker,seconds):
    deadline=time.monotonic()+min(seconds,remaining());path=OUT/(label+'.log')
    while time.monotonic()<deadline:
        if path.stat().st_size>1024*1024:raise routing.Refused('Readiness log exceeds bound')
        if marker in path.read_bytes():return
        if p.poll()is not None:raise routing.Refused('Owned collector exited before readiness')
        time.sleep(.02)
    raise routing.Refused('Owned collector readiness deadline')

def calibration_support(journal,frames):
    ready=[r for r in journal if r.get('kind')=='capture-data-ready']
    if len(ready)!=1:raise routing.Refused('Unique actual data readiness required')
    start=ready[0]['fileFrameOffset'];end=frames-48000
    if type(start)is not int or end-start<9*48000:raise routing.Refused('Insufficient post-ready calibrated coverage')
    return [start,end]

def assessment(raw,summary,journal,record,player_ok,cleanup_ok):
    if len(raw)>13*48000*8:raise routing.Refused('Calibration raw exceeds bound')
    support=calibration_support(journal,summary['frames'])
    native=validate_native.validate(raw,summary,journal,[support])
    host_pattern=pattern.assess_host_pattern(raw[support[0]*8:support[1]*8])
    routes=record['routeObservations'];rr=record['recorderIdentity']
    binding=bool(routes)and all(x['recorder']['pid']==summary['capturePID']==rr['pid']and x['recorder']['index']==summary['pulseSourceOutputIndex']and x['monitorIndex']==summary['pulseMonitorIndex']for x in routes)
    before=record['emptyGraphBeforeCapture'];after=record['emptyGraphAfterCapture']
    stable_devices=all(x['sinkIndex']==before['sinkIndex']==after['sinkIndex']and x['monitorIndex']==before['monitorIndex']==after['monitorIndex']for x in routes)
    checks={'sameOriginalMonitorThroughout':stable_devices,'nativeDeliveryChecks':native['nativeCaptureChecksPass'],'wholeCalibrationSupportConfirmed':native['allRequestedSupportsHaveValidRawTiming'],'knownBothChannelPattern':host_pattern['bothChannelPatternObserved'],'originalRecorderIndexesMatch':binding,'knownPlayerCompletedCleanly':player_ok,'ownedCleanupVerified':cleanup_ok}
    return {'schema':'hosted-native-pulse-calibration-gate-v1','checks':checks,'calibrationPass':all(checks.values()),'nativeCoverage':native,'hostPattern':host_pattern,'calibrationSupport':support,'calibrationSupportMeaning':'Actual native data-ready file offset through one second before end; not fitted source nonce or PWA phases. Pattern rows are relative to this raw slice.','rawSHA256':hashlib.sha256(raw).hexdigest(),'independentPerPacketPTSProvided':False,'PWAVerified':False,'functionalPWAQualificationClaimed':False}

def calibrate():
    daemon=collector=player=None;record={'githubRunId':os.environ.get('GITHUB_RUN_ID'),'githubRunAttempt':os.environ.get('GITHUB_RUN_ATTEMPT'),'githubCommit':os.environ.get('GITHUB_SHA'),'startedMonotonicSeconds':time.monotonic(),'schema':'hosted-native-pulse-runtime-v1','routeObservations':[],'PWAVerified':False,'actualMicrophoneRequested':False,'productOrMeasurementGatesChanged':False};error=None;cleanup={};answer=None
    try:
        if any((OUT/n).exists()for n in ['runtime.json','system.f32','native-journal.jsonl','native-summary.json','capture_monitor','pulse.pa','private-daemon.json']):raise routing.Refused('Fresh calibration outputs required')
        record['helperSourceSHA256']={n:digest(HERE/n)for n in ['native_gate.py','capture_monitor.c','validate_native.py','routing.py','calibration_support.py']}
        t=tools();record['toolPaths']=t
        bounded([t['dpkg-query'],'-W','-f=${Package}\t${Version}\n','pulseaudio','pulseaudio-utils','libpulse-dev','gcc','pkg-config'],'package-versions',4)
        for name,flags in [('pactl',['--format']),('paplay',['--device'])]:
            help_text=bounded([t[name],'--help'],name+'-help',4).decode()
            if not all(f in help_text for f in flags):raise routing.Refused('Installed tool flags unverified: '+name)
        bounded([t['gcc'],'--version'],'gcc-version',4)
        bounded([t['pkg-config'],'--modversion','libpulse'],'libpulse-version',4)
        pkg=bounded([t['pkg-config'],'--cflags','--libs','libpulse'],'pkg-config',4).decode()
        if len(pkg)>8192:raise routing.Refused('Compiler flags exceed bound')
        binary=OUT/'capture_monitor'
        source=HERE/'capture_monitor.c';record['collectorSourceSHA256']=digest(source)
        bounded([t['gcc'],'-std=c11','-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(binary)]+shlex.split(pkg)+['-lm'],'compile-link',30)
        if record['collectorSourceSHA256']!=digest(source):raise routing.Refused('Collector source changed during compilation')
        record['collectorBinarySHA256']=digest(binary)
        private=pathlib.Path(tempfile.mkdtemp(prefix='v15pa-',dir='/tmp'));private.chmod(0o700)
        config=OUT/'pulse.pa';config.write_text('.fail\nload-module module-native-protocol-unix socket='+str(private/'native')+' auth-anonymous=1\nload-module module-null-sink sink_name=ci_silent rate=48000 channels=2\nset-default-sink ci_silent\nset-default-source ci_silent.monitor\n')
        env=os.environ.copy();env.update(XDG_RUNTIME_DIR=str(private),PULSE_SERVER='unix:'+str(private/'native'),PULSE_SINK='ci_silent',PULSE_SOURCE='ci_silent.monitor')
        # No module-udev-detect/default script/autospawn: this config has only own Unix socket + null sink.
        daemon=launch([t['pulseaudio'],'-n','--daemonize=no','--exit-idle-time=-1','--file='+str(config.resolve())],'daemon',env)
        daemon_id=routing.proc_record(daemon.pid);daemon_id['kind']='pulse'
        boot={'privatePulseRuntime':{'path':str(private)},'children':[daemon_id]};record['privateDaemonReceipt']=boot
        until=time.monotonic()+6
        while not(private/'native').exists():
            if daemon.poll()is not None or time.monotonic()>until:raise routing.Refused('Private daemon socket not ready')
            remaining();time.sleep(.05)
        boot['privatePulseRuntime'].update(directoryIdentity=fs_identity(private),socketIdentity=fs_identity(private/'native'))
        save('private-daemon.json',boot);record['pulseConfigSHA256']=digest(config)
        record['emptyGraphBeforeCapture']=private_graph(t['pactl'],boot,env,'before',expect_empty=True)
        wave=OUT/'known-tone-zero-tone.wav';pattern.tone_file(wave);record['knownWaveSHA256']=digest(wave)
        collector=launch([str(binary.resolve()),'calibration',str(OUT/'system.f32'),str(OUT/'native-journal.jsonl'),str(OUT/'native-summary.json')],'collector',env)
        rr=routing.proc_record(collector.pid);record['recorderIdentity']=rr
        wait_marker(collector,'collector',b'CAPTURE_DATA_READY\n',8)
        # Start known source only after data readiness. The owned eight-second WAV leaves tail timing witnesses inside the fixed12s capture.
        player=launch([t['paplay'],'--device=ci_silent',str(wave)],'player',env);pr=routing.proc_record(player.pid);record['playerIdentity']=pr
        # One fresh full graph near source start and one while still active, with immutable PID/startTicks.
        for i in range(2):
            if i:time.sleep(min(2,remaining()))
            route=private_graph(t['pactl'],boot,env,'during-'+str(i),rr,pr);record['routeObservations'].append(route)
        player.wait(timeout=min(12,remaining()));record['playerReturnCode']=player.returncode
        collector.wait(timeout=min(30,remaining()));record['collectorReturnCode']=collector.returncode
        record['emptyGraphAfterCapture']=private_graph(t['pactl'],boot,env,'after',expect_empty=True)
        if player.returncode or collector.returncode:raise routing.Refused('Native collector or known player failed; retain originals')
    except Exception as e:error={'name':type(e).__name__,'message':str(e)}
    finally:
        signal.alarm(20)  # Independent cleanup/report allowance after acquisition watchdog.
        # Each resource is an original Popen group owned by this gate, never a name/foreign PID kill.
        for name,p in [('player',player),('collector',collector),('daemon',daemon)]:cleanup[name]=pattern.stop(p)
        record['ownedCleanup']=cleanup;record['cleanupVerified']=all(c['leaderReaped']and c['ownedGroupAbsent']for c in cleanup.values())
        record['normalClientCompletion']=all(cleanup[n].get('returnCode')==0 and not cleanup[n].get('signals')for n in ['player','collector'])
        if error:record['error']=error
        if not error:
            try:
                if(OUT/'system.f32').stat().st_size>13*48000*8 or(OUT/'native-journal.jsonl').stat().st_size>16*1024*1024:raise routing.Refused('Calibration input exceeds explicit bound')
                raw=(OUT/'system.f32').read_bytes();summary=json.loads((OUT/'native-summary.json').read_bytes());journal_bytes=(OUT/'native-journal.jsonl').read_bytes()
                if len(journal_bytes)>16*1024*1024:raise routing.Refused('Calibration journal exceeds bound')
                journal=[json.loads(x)for x in journal_bytes.splitlines()]
                answer=assessment(raw,summary,journal,record,record['playerReturnCode']==0 and record['normalClientCompletion'],record['cleanupVerified'])
                answer['summarySHA256']=digest(OUT/'native-summary.json');answer['journalSHA256']=hashlib.sha256(journal_bytes).hexdigest()
            except Exception as e:record['error']={'name':type(e).__name__,'message':str(e)}
        record['sourceFilesUnchanged']=bool(record.get('helperSourceSHA256'))and all(digest(HERE/n)==sha for n,sha in record.get('helperSourceSHA256',{}).items())
        if record.get('helperSourceSHA256')and not record['sourceFilesUnchanged']:record['error']={'name':'SourceIdentityChanged','message':'Helper changed during calibration'}
        if answer:
            answer['checks']['helperSourcesUnchanged']=record['sourceFilesUnchanged'];answer['calibrationPass']=all(answer['checks'].values());save('assessment.json',answer)
        record['calibrationPass']=bool(answer and answer['calibrationPass']and not record.get('error'));record['commands']=COMMANDS;record['elapsedSeconds']=time.monotonic()-record['startedMonotonicSeconds'];save('runtime.json',record)
    return record['calibrationPass']

def main():
    global DEADLINE
    require_ci()
    if len(sys.argv)!=2 or sys.argv[1]not in ['provision','calibrate']:raise SystemExit('Fixed operation: provision|calibrate')
    OUT.mkdir(parents=True,exist_ok=True)
    if OUT.is_symlink():raise SystemExit('No symlink evidence directory')
    signal.signal(signal.SIGALRM,watchdog);seconds=360 if sys.argv[1]=='provision'else 120;DEADLINE=time.monotonic()+seconds;signal.alarm(seconds)
    try:
        if sys.argv[1]=='provision':
            receipt={'complete':False}
            try:provision();receipt['complete']=True
            except Exception as e:receipt['error']={'name':type(e).__name__,'message':str(e)}
            finally:receipt['commands']=COMMANDS;save('provision.json',receipt)
            ok=receipt['complete']
        else:ok=calibrate()
    finally:signal.alarm(0)
    raise SystemExit(0 if ok else 2)
if __name__=='__main__':main()
