#!/usr/bin/env python3
"""Fixed hosted-CI Apple command allowlist. Direct log file; owned process groups only."""
import argparse,hashlib,json,os,pathlib,re,signal,subprocess,sys,time
CASES={
 'install':('testInstallV15FromSafari','v15-install.xcresult','v15-install-ui.log'),
 'native-eof':('testV15InstalledNaturalEOFContinuation','v15-native-eof.xcresult','v15-native-eof.log'),
 'native-failure':('testV15InstalledNativeFailureContinuation','v15-native-failure.xcresult','v15-native-failure.log'),
 'native-url':('testV15InstalledURLStateAndHistory','v15-url.xcresult','v15-url.log')}
LIMITS={**{k:450 for k in CASES},'native-url':600,'screenshot':8,'shutdown':8,'list-selected':8,'open-lab-url':30}
TERM_SECONDS=3;KILL_REAP_SECONDS=3
LAB='https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site/nqa?candidate=v15&experiment=nqa'

def owned_ci(udid,env=None):
    env=os.environ if env is None else env
    if env.get('GITHUB_ACTIONS')!='true'or env.get('RUNNER_OS')!='macOS'or env.get('RUNNER_ARCH')!='ARM64':raise ValueError('Hosted macOS ARM64 GitHub Actions only')
    if not isinstance(udid,str)or not re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',udid)or udid!=env.get('SIMULATOR_UDID'):raise ValueError('Exact selected simulator UDID required; no booted/all aliases')

def specification(action,udid):
    if action not in LIMITS:raise ValueError('Unsupported fixed operation')
    if action in CASES:
        case,bundle,log=CASES[action]
        cmd=['/usr/bin/xcodebuild','test-without-building','-project','CIProbeV15.xcodeproj','-scheme','CIProbeV15','-destination',f'platform=iOS Simulator,id={udid}','-derivedDataPath','DerivedData','-resultBundlePath','evidence/'+bundle,'-only-testing:CIProbeUITests/V15InstalledUITests/'+case,'CODE_SIGNING_ALLOWED=NO']
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

def run_action(action,udid):
    owned_ci(udid);command,log,limit=specification(action,udid)
    result=_execute_owned(command,log,limit);result.update({'schema':'bounded-fixed-apple-ci-command-v1','operation':action,'selectedSimulatorUDID':udid,'runId':os.environ.get('GITHUB_RUN_ID'),'runAttempt':os.environ.get('GITHUB_RUN_ATTEMPT','1')})
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
