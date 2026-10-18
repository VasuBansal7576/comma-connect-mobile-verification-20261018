#!/usr/bin/env python3
"""Fixed hosted-CI Apple command allowlist. Direct log file; owned process groups only."""
import argparse,hashlib,json,os,pathlib,re,signal,subprocess,sys,time
CASES={
 'install':('testInstallV16FromSafari','v16-install.xcresult','v16-install-ui.log'),
 'native-eof':('testV16InstalledNaturalEOFContinuation','v16-native-eof.xcresult','v16-native-eof.log'),
 'native-failure':('testV16InstalledNativeFailureContinuation','v16-native-failure.xcresult','v16-native-failure.log'),
 'native-url':('testV16InstalledURLStateAndHistory','v16-url.xcresult','v16-url.log')}
LIMITS={**{k:450 for k in CASES},'install':600,'native-url':600,'screenshot':8,'shutdown':8,'list-selected':8,'open-lab-url':30}
TERM_SECONDS=3;KILL_REAP_SECONDS=3
LAB='https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site/nqa?candidate=v16&experiment=nqa'

def owned_ci(udid,env=None):
    env=os.environ if env is None else env
    if env.get('GITHUB_ACTIONS')!='true'or env.get('RUNNER_OS')!='macOS'or env.get('RUNNER_ARCH')!='ARM64':raise ValueError('Hosted macOS ARM64 GitHub Actions only')
    if not isinstance(udid,str)or not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',udid)or udid!=env.get('SIMULATOR_UDID'):raise ValueError('Exact selected simulator UDID required; no booted/all aliases')

def specification(action,udid):
    if action not in LIMITS:raise ValueError('Unsupported fixed operation')
    if action in CASES:
        case,bundle,log=CASES[action]
        cmd=['/usr/bin/xcodebuild','test-without-building','-project','CIProbeV16.xcodeproj','-scheme','CIProbeV16','-destination',f'platform=iOS Simulator,id={udid}','-derivedDataPath','DerivedData','-resultBundlePath','evidence/'+bundle,'-only-testing:CIProbeUITests/V16InstalledUITests/'+case,'CODE_SIGNING_ALLOWED=NO']
    else:
        prefix=['/usr/bin/xcrun','simctl']
        cmd={'screenshot':prefix+['io',udid,'screenshot','evidence/final-simulator.png'],'shutdown':prefix+['shutdown',udid],'list-selected':prefix+['list','devices','--json'],'open-lab-url':prefix+['openurl',udid,LAB]}[action]
        log={'screenshot':'final-screenshot.log','shutdown':'selected-shutdown.log','list-selected':'selected-devices.json','open-lab-url':'open-lab-url.log'}[action]
    return cmd,pathlib.Path('evidence')/log,LIMITS[action]

def group_exists(pgid):
    try:os.killpg(pgid,0);return True
    except ProcessLookupError:return False
    except PermissionError:return True  # Unknown/existing, never falsely absent.

def stop_group(proc,term=TERM_SECONDS,reap=KILL_REAP_SECONDS):
    """Never communicate()/PIPE: a descendant retaining stdout cannot extend waits."""
    events=[]
    if group_exists(proc.pid):
        try:os.killpg(proc.pid,signal.SIGTERM);events.append('SIGTERM')
        except ProcessLookupError:pass
        except PermissionError:events.append('SIGTERM-PERMISSION-DENIED')
        deadline=time.monotonic()+term
        while time.monotonic()<deadline and(proc.poll()is None or group_exists(proc.pid)):time.sleep(min(.02,max(0,deadline-time.monotonic())))
    if proc.poll()is None or group_exists(proc.pid):
        try:os.killpg(proc.pid,signal.SIGKILL);events.append('SIGKILL')
        except ProcessLookupError:pass
        except PermissionError:events.append('SIGKILL-PERMISSION-DENIED')
    deadline=time.monotonic()+reap
    try:proc.wait(timeout=max(.001,deadline-time.monotonic()))
    except subprocess.TimeoutExpired:events.append('leader-reap-timeout')
    # Descendants are not direct children; retain unknown group state rather than pretend reaped.
    while time.monotonic()<deadline and group_exists(proc.pid):time.sleep(min(.02,max(0,deadline-time.monotonic())))
    return {'signals':events,'leaderReaped':proc.poll()is not None,'ownedGroupAbsent':not group_exists(proc.pid),'returnCode':proc.returncode}

def _execute_owned(command,logpath,limit,term=TERM_SECONDS,reap=KILL_REAP_SECONDS):
    """Private process primitive, used by the fixed public operations and offline models."""
    began=time.monotonic();proc=None;result={'limitSeconds':limit,'termGraceSeconds':term,'killReapSeconds':reap,'startedMonotonic':began,'timedOut':False,'command':command,'stdoutAndStderr':str(logpath),'usesPipes':False}
    logpath.parent.mkdir(parents=True,exist_ok=True)
    try:
        with logpath.open('wb')as log:
            proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            result['ownedProcessGroup']=proc.pid
            try:proc.wait(timeout=max(.001,began+limit-time.monotonic()))
            except subprocess.TimeoutExpired:result['timedOut']=True
            if time.monotonic()>began+limit:result['timedOut']=True
    except Exception as error:result['error']={'name':type(error).__name__,'message':str(error)}
    finally:
        if proc is not None:result['cleanup']=stop_group(proc,term,reap)
        else:result['cleanup']={'leaderReaped':True,'ownedGroupAbsent':True,'returnCode':None,'signals':[]}
        result['elapsedSeconds']=time.monotonic()-began
        result['ok']=not result['timedOut']and not result.get('error')and result['cleanup']['returnCode']==0 and result['cleanup']['leaderReaped']and result['cleanup']['ownedGroupAbsent']
    return result

def open_lab_url_with_recovery(udid):
    # Only this observed openurl exit60 with verified cleanup qualifies for one recovery.
    command,log,limit=specification('open-lab-url',udid)
    began=time.monotonic();deadline=began+80;attempts=[]
    def retain(label,result):
        attempts.append({'label':label,'result':result})
        (pathlib.Path('evidence')/('bounded-'+label+'.json')).write_text(json.dumps(result,indent=2)+'\n')
    def finish(result,code):
        outer=dict(result)
        elapsed=time.monotonic()-began
        if elapsed>80:outer['ok']=False;outer['timedOut']=True;code='RECOVERY_ABSOLUTE_DEADLINE_CROSSED'
        outer.update({'recoveryCode':code,'recoveryAttempts':attempts,'totalElapsedSeconds':elapsed,'lastCommandElapsedSeconds':result.get('elapsedSeconds'),'elapsedSeconds':elapsed,'startedMonotonic':began,'recoveryAbsoluteLimitSeconds':80,'UIOrTestRetries':0})
        return outer
    def remaining_step(cap):
        return min(cap,deadline-time.monotonic()-TERM_SECONDS-KILL_REAP_SECONDS)
    first=_execute_owned(command,log,limit);retain('open-lab-url-attempt-1',first)
    cleanup=first.get('cleanup',{})
    eligible=first.get('ok') is False and first.get('timedOut') is False and not first.get('error') and cleanup.get('returnCode')==60 and cleanup.get('leaderReaped') is True and cleanup.get('ownedGroupAbsent') is True
    if not eligible:return finish(first,'NOT_ELIGIBLE_NO_RECOVERY')
    budget=remaining_step(10)
    if budget<=0:return finish(first,'RECOVERY_ABSOLUTE_DEADLINE_NO_LAUNCH')
    launch=_execute_owned(['/usr/bin/xcrun','simctl','launch',udid,'com.apple.mobilesafari'],pathlib.Path('evidence/launch-safari-recovery.log'),budget)
    retain('launch-safari-recovery',launch)
    launch_cleanup=launch.get('cleanup',{})
    launch_ok=launch.get('ok') is True and launch.get('timedOut') is False and not launch.get('error') and launch_cleanup.get('returnCode')==0 and launch_cleanup.get('leaderReaped') is True and launch_cleanup.get('ownedGroupAbsent') is True
    if not launch_ok:
        failure=dict(launch);failure['ok']=False
        return finish(failure,'SAFARI_LAUNCH_FAILED_NO_URL_RETRY')
    budget=remaining_step(limit)
    if budget<=0:
        result=dict(launch);result['ok']=False
        return finish(result,'RECOVERY_ABSOLUTE_DEADLINE_NO_URL_RETRY')
    retry=_execute_owned(command,pathlib.Path('evidence/open-lab-url-retry.log'),budget)
    retain('open-lab-url-attempt-2',retry)
    if time.monotonic()>deadline:
        retry=dict(retry);retry['ok']=False
        return finish(retry,'RECOVERY_ABSOLUTE_DEADLINE_CROSSED')
    return finish(retry,'ONE_FIXED_URL_RETRY_SUCCEEDED' if retry.get('ok') else 'ONE_FIXED_URL_RETRY_FAILED')

def run_action(action,udid):
    owned_ci(udid);command,log,limit=specification(action,udid)
    result=open_lab_url_with_recovery(udid) if action=='open-lab-url' else _execute_owned(command,log,limit);result.update({'schema':'bounded-fixed-apple-ci-command-v1','operation':action,'selectedSimulatorUDID':udid,'runId':os.environ.get('GITHUB_RUN_ID'),'runAttempt':os.environ.get('GITHUB_RUN_ATTEMPT','1')})
    if action=='list-selected'and result['ok']:
        try:
            if log.stat().st_size>8*1024*1024:raise ValueError('Device listing exceeds bound')
            rows=[x for group in json.loads(log.read_bytes())['devices'].values()for x in group if x.get('udid')==udid]
            if len(rows)!=1:raise ValueError('Exact one selected simulator state required')
            result['selectedState']=rows[0]['state']
        except Exception as error:result['ok']=False;result['parseError']={'name':type(error).__name__,'message':str(error)}
    if action=='screenshot':
        p=pathlib.Path('evidence/final-simulator.png');result['acceptanceEvidence']=False;result['pngSHA256']=hashlib.sha256(p.read_bytes()).hexdigest()if result['ok']and p.is_file()else None
    receipt=pathlib.Path('evidence')/('bounded-'+action+'.json');receipt.write_text(json.dumps(result,indent=2)+'\n');return result

def main():
    p=argparse.ArgumentParser();p.add_argument('operation',choices=sorted(LIMITS));p.add_argument('selected_udid');args=p.parse_args();r=run_action(args.operation,args.selected_udid);print(json.dumps({'operation':args.operation,'ok':r['ok'],'timedOut':r['timedOut'],'elapsedSeconds':r['elapsedSeconds'],'selectedState':r.get('selectedState')}));raise SystemExit(0 if r['ok']else 124 if r['timedOut']else 2)
if __name__=='__main__':main()
