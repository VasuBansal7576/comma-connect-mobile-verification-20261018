#!/usr/bin/env python3
"""PROPOSALv3: native READY → owned OS capture ACK → actual protocol → native DONE.
Remote hostedCI only; startup/tail are separate from unchanged150s capture window.
"""
import hashlib,json,os,pathlib,select,signal,subprocess,sys,time
from ci_handshake import RunState,serve
from bounded_official import run_action,stop_group

def terminate_owned(proc):
    if proc is None:return {'leaderReaped':True,'ownedGroupAbsent':True,'returnCode':None,'signals':[]}
    return stop_group(proc)

def wait_signal(event,deadline,test,state,label):
    while not event.is_set():
        if state.snapshot()['stage']=='FAILED':raise RuntimeError('Native acquisition aborted: '+label)
        if test.poll()is not None:raise RuntimeError('xcodebuild ended before '+label)
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError(label+' deadline exceeded')
        event.wait(min(.1,remaining))
    if time.monotonic()>deadline:raise TimeoutError('Late '+label+' refused')

def finalize_acquisition(result,complete):
    result['protocolAcquisitionComplete']=complete
    result['cleanupVerified']=result['ownedProcessesReaped']and result['ownedProcessGroupsAbsent']and result['ownServerStopped']and not result['processCleanupErrors']and result['simulatorShutdownVerified']
    result['acquired']=complete and result['cleanupVerified']and result['handshake']['stage']=='DONE'and not result['handshake']['errors']
    return result['acquired']

def main():
    if os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_OS')!='macOS'or os.environ.get('RUNNER_ARCH')!='ARM64':raise SystemExit('Hosted macOS ARM64 CI only')
    udid=sys.argv[1]
    if udid!=os.environ.get('SIMULATOR_UDID')or not udid:raise SystemExit('Exact owned selected simulator required')
    out=pathlib.Path('evidence/v15-installed-output');out.mkdir()
    state=RunState(os.environ['GITHUB_RUN_ID'],os.environ.get('GITHUB_RUN_ATTEMPT','1'),udid)
    collector=test=server=None;serverThread=None;began=time.monotonic();complete=False
    result={'scope':'Actual installed simulator WebClip + hosted ScreenCaptureKit system output; no physicalPhone equivalence','version':'native-loopback-handshake-v3','captureWindowSeconds':150,'xcodebuildLimitSeconds':450,'readinessLimitSeconds':180,'activeProtocolLimitSeconds':130,'tailLimitSeconds':180,'runId':os.environ['GITHUB_RUN_ID'],'simulatorUDID':udid}
    try:
        server,serverThread=serve(state)
        command=['xcodebuild','test-without-building','-project','CIProbeV15.xcodeproj','-scheme','CIProbeV15','-destination',f'platform=iOS Simulator,id={udid}','-derivedDataPath','DerivedData','-resultBundlePath','evidence/v15-output.xcresult','-only-testing:CIProbeUITests/V15InstalledUITests/testV15InstalledAudioProtocol','CODE_SIGNING_ALLOWED=NO']
        with (out/'ui-test.log').open('w')as log,(out/'collector-stderr.txt').open('w')as errors:
            test=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            testStart=time.monotonic();result['xcodebuildStartedMonotonic']=testStart;globalDeadline=testStart+450
            wait_signal(state.ready,testStart+180,test,state,'actual Pin/Prepare READY')
            if state.snapshot()['stage']!='READY':raise RuntimeError('Current native READY required')
            collector=subprocess.Popen(['./capture-system-audio150','capture',str(out/'system.f32'),'150',str(out/'capture.json')],stdout=subprocess.PIPE,stderr=errors,text=True,start_new_session=True)
            readable,_,_=select.select([collector.stdout],[],[],8)
            if not readable or collector.stdout.readline().strip()!='CAPTURE_STARTED':raise RuntimeError('No actual OS capture acknowledgment within8s')
            if test.poll()is not None:raise RuntimeError('Native client exited before capture ACK')
            state.acknowledge_capture();result['captureAckMonotonic']=state.ackAt
            wait_signal(state.done,min(globalDeadline,state.ackAt+130),test,state,'full native carrier DONE')
            doneAt=next(e['hostMonotonic']for e in state.snapshot()['events']if e['kind']=='native-done');result['nativeDoneMonotonic']=doneAt
            result['uiReturnCode']=test.wait(timeout=max(.001,min(globalDeadline,doneAt+180)-time.monotonic()))
            if time.monotonic()>min(globalDeadline,doneAt+180):raise TimeoutError('Actual xcodebuild/tail deadline exceeded')
            if result['uiReturnCode']:raise RuntimeError('Actual V15 UI test failed after DONE')
            result['collectorReturnCode']=collector.wait(timeout=max(.001,state.ackAt+160-time.monotonic()))
            if result['collectorReturnCode']:raise RuntimeError('OS collector failed/cleanup incomplete')
            result['captureReceiptSHA256']=hashlib.sha256((out/'capture.json').read_bytes()).hexdigest();result['rawPCMSHA256']=hashlib.sha256((out/'system.f32').read_bytes()).hexdigest();complete=True
    except Exception as error:result['error']={'name':type(error).__name__,'message':str(error)}
    finally:
        result['processCleanupErrors']=[]
        result['ownedProcessGroupCleanup']={}
        for name,owned in [('uiTest',test),('collector',collector)]:
            try:
                clean=terminate_owned(owned);result['ownedProcessGroupCleanup'][name]=clean
                if not clean['leaderReaped']or not clean['ownedGroupAbsent']:result['processCleanupErrors'].append({'owned':name,'message':'Owned process group cleanup not verified'})
            except Exception as error:result['processCleanupErrors'].append({'owned':name,'name':type(error).__name__,'message':str(error)})
        # Close this observer; no late native request can start/reset a second acquisition.
        with state.lock:state.closed=True
        if server is not None:server.shutdown();server.server_close();serverThread.join(timeout=1)
        result['ownServerStopped']=serverThread is None or not serverThread.is_alive()
        result['handshake']=state.snapshot();result['ownedProcessesReaped']=all(p is None or p.poll()is not None for p in [test,collector])
        result['ownedProcessGroupsAbsent']=len(result['ownedProcessGroupCleanup'])==2 and all(x['ownedGroupAbsent']for x in result['ownedProcessGroupCleanup'].values())
        result['simulatorShutdownVerified']=False
        result['boundedOfficialCommands']=[]
        try:
            shot=run_action('screenshot',udid);result['boundedOfficialCommands'].append(shot)
            result['diagnosticScreenshot']={'returnCode':shot['cleanup']['returnCode'],'sha256':shot.get('pngSHA256'),'boundedCommandOK':shot['ok'],'acceptanceEvidence':False}
        except Exception as error:
            result['diagnosticScreenshot']={'errorClass':type(error).__name__,'acceptanceEvidence':False}
            result['processCleanupErrors'].append({'owned':'official-screenshot','message':'Command cleanup receipt unavailable'})
        try:
            stopped=run_action('shutdown',udid);result['boundedOfficialCommands'].append(stopped);result['simulatorShutdownReturnCode']=stopped['cleanup']['returnCode']
            listed=run_action('list-selected',udid);result['boundedOfficialCommands'].append(listed)
            result['selectedSimulatorFinalState']=listed.get('selectedState');result['simulatorShutdownVerified']=listed['ok']and listed.get('selectedState')=='Shutdown'
        except Exception as error:result['simulatorCleanupError']={'name':type(error).__name__,'message':str(error)}
        for commandReceipt in result['boundedOfficialCommands']:
            clean=commandReceipt['cleanup']
            if not clean['leaderReaped']or not clean['ownedGroupAbsent']:
                result['processCleanupErrors'].append({'owned':'official-'+commandReceipt['operation'],'message':'Owned command group cleanup not verified'})
        finalize_acquisition(result,complete)
        result['elapsedSeconds']=time.monotonic()-began;(out/'command.json').write_text(json.dumps(result,indent=2)+'\n')
    if not result['acquired']:raise SystemExit(2)
if __name__=='__main__':main()
