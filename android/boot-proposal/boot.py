#!/usr/bin/env python3
"""Owned ephemeral CI Chrome witness. One fresh launcher-icon tap, no consent continuation."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
import tempfile
import xml.etree.ElementTree as ET

OUT=Path('evidence/android-boot')
SDK=Path('/usr/local/lib/android/sdk')
SERIAL='emulator-5554'
ADB=str(SDK/'platform-tools/adb')
START=time.monotonic()
CAP=360
CHILDREN=[]
TRACE=[]
SCREEN_SEQUENCE=0
STATE={'schema':'hosted-android-firstscreen-capability-v1','status':'STARTING','serial':SERIAL,'termsAcceptedByScript':False,'UIInputCommands':0,'PWAVerified':False,'audioMeasured':False,'children':[]}
class Refused(Exception):pass

def save():
    OUT.mkdir(parents=True,exist_ok=True)
    STATE['trace']=TRACE
    (OUT/'receipt.json').write_text(json.dumps(STATE,indent=2)+'\n')
def remaining(limit):
    value=min(limit,CAP-(time.monotonic()-START))
    if value<=0:raise Refused('BOOT_PHASE_DEADLINE')
    return value

def run(args,label,timeout=20,limit=65536,allowed_failure=False,env=None,retain_stdout=True,reject_stderr_patterns=()):
    timeout=remaining(timeout)
    p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=env)
    buffers=[bytearray(),bytearray()];counts=[0,0]
    def drain(stream,index):
        while True:
            b=stream.read(4096)
            if not b:break
            counts[index]+=len(b);buffers[index].extend(b)
            if len(buffers[index])>limit:del buffers[index][:-limit]
    threads=[threading.Thread(target=drain,args=(p.stdout,0),daemon=True),threading.Thread(target=drain,args=(p.stderr,1),daemon=True)]
    for t in threads:t.start()
    try:p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL);p.wait();raise Refused('OWN_COMMAND_TIMEOUT_'+label)
    finally:
        for t in threads:t.join(timeout=2)
    stdout,stderr=map(bytes,buffers)
    # No process environment, arbitrary command lines or possible token-bearing emulator output is retained.
    diagnostic=(stdout if retain_stdout and label not in ['screen_png','ui_xml'] else b'')+stderr
    text=diagnostic[-65536:].decode('utf-8',errors='replace')
    text='\n'.join('[TOKEN_LINE_REDACTED]' if re.search(r'token|authorization|password|cookie',line,re.I) else line for line in text.splitlines())
    (OUT/(label+'.log')).write_text(text)
    TRACE.append({'operation':label,'exitCode':p.returncode,'stdoutBytes':counts[0],'stderrBytes':counts[1],'retainedAtMostPerStream':limit})
    save()
    if any(re.search(pattern,stderr.decode(errors='replace'),re.I) for pattern in reject_stderr_patterns):raise Refused('UI_DUMP_REPORTED_ERROR')
    if p.returncode and not allowed_failure:raise Refused('OWN_COMMAND_FAILED_'+label)
    return stdout,p.returncode,counts[0]>limit

def process_ticks(pid):
    try:return Path('/proc/'+str(pid)+'/stat').read_text().split(') ',1)[1].split()[19]
    except (OSError,IndexError):return None

def own_process(args,kind,env=None):
    # Foreground children only. No daemon pid discovery or broad process-name killing.
    log=open(OUT/(kind+'-private.raw'),'wb')
    p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=env)
    CHILDREN.append((p,log));row={'pid':p.pid,'startTicks':process_ticks(p.pid),'kind':kind}
    STATE['children'].append(row);save();return p

def cleanup():
    results=[]
    for row in reversed(STATE.get('children',[])):
        pid=row['pid'];matched=bool(row.get('startTicks') and process_ticks(pid)==row['startTicks'])
        try:group_matches=matched and os.getpgid(pid)==pid
        except ProcessLookupError:group_matches=False
        if group_matches:
            try:os.killpg(pid,signal.SIGTERM)
            except ProcessLookupError:pass
            until=time.monotonic()+8
            while process_ticks(pid)==row['startTicks'] and time.monotonic()<until:
                try:os.waitpid(pid,os.WNOHANG)
                except ChildProcessError:pass
                time.sleep(.1)
            if process_ticks(pid)==row['startTicks']:
                try:os.killpg(pid,signal.SIGKILL)
                except ProcessLookupError:pass
        results.append({'kind':row['kind'],'boundPIDMatchedAtCleanup':matched,'sameProcessStillPresent':bool(row.get('startTicks') and process_ticks(pid)==row['startTicks'])})
    if STATE.get('ownedADBServerStarted'):
        p=subprocess.run([ADB,'kill-server'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        STATE['ownedADBServerCleanupExitCode']=p.returncode
    acl=OUT/'kvm-original.acl'
    if acl.exists() and STATE.get('KVMACLRestoreArmed'):
        p=subprocess.run(['sudo','-n','setfacl','--restore='+str(acl)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        STATE['KVMACLRestoreExitCode']=p.returncode
        if p.returncode==0:STATE['KVMACLChanged']=False;STATE['KVMACLRestoreArmed']=False
    for p,log in CHILDREN:
        try:p.wait(timeout=1)
        except subprocess.TimeoutExpired:pass
        log.close()
    STATE.setdefault('cleanupAttempts',[]).append(results)
    STATE['cleanup']=results
    # Raw own-process logs may contain generated emulator auth tokens; sanitize before artifact upload.
    for f in OUT.glob('*-private.raw'):
        with f.open('rb') as stream:
            stream.seek(max(0,f.stat().st_size-65536));data=stream.read(65536).decode('utf-8',errors='replace')
        data='\n'.join('[TOKEN_LINE_REDACTED]' if re.search(r'token|authorization|password|cookie',line,re.I) else line for line in data.splitlines())
        f.with_name(f.stem.replace('-private','')+'.log').write_text(data)
        f.unlink()
    save()

def screen(label, observation_deadline=None):
    global SCREEN_SEQUENCE
    if not re.fullmatch(r'[a-z0-9-]+',label):raise Refused('OWN_SCREEN_LABEL_REQUIRED')
    def screen_timeout(limit):
        if observation_deadline is None:return limit
        left=observation_deadline-time.monotonic()
        if left<=0:raise Refused('CHROME_SCREEN_OBSERVATION_DEADLINE')
        return min(limit,left)
    SCREEN_SEQUENCE+=1
    remote='/sdcard/ci-firstscreen-'+str(os.getpid())+'-'+str(SCREEN_SEQUENCE)+'.xml'
    row={'label':label,'sequence':SCREEN_SEQUENCE,'captureStartBootSeconds':time.monotonic()-START,'remotePath':remote,'xmlFreshnessVerified':False}
    STATE.setdefault('screenCaptures',[]).append(row);save()
    xml_path=OUT/(label+'.xml');xml_path.unlink(missing_ok=True)
    # Delete only this process/capture-owned path; never read the historical fixed XML.
    run([ADB,'-s',SERIAL,'shell','rm','-f',remote],'remove_owned_capture_xml',timeout=screen_timeout(5))
    xml_failure=None
    try:
        marker,_,cut=run([ADB,'-s',SERIAL,'shell','uiautomator','dump',remote],'ui_dump',timeout=screen_timeout(25),reject_stderr_patterns=(r'ERROR:',r'could not get idle state',r'null root node'))
        if cut or marker.strip()!=('UI hierchary dumped to: '+remote).encode():raise Refused('UI_DUMP_SUCCESS_MARKER_REQUIRED')
        data,_,truncated=run([ADB,'-s',SERIAL,'exec-out','cat',remote],'ui_xml',timeout=screen_timeout(15),limit=2*1024*1024)
        if truncated or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():raise Refused('UI_XML_INVALID')
        try:tree=ET.fromstring(data)
        except ET.ParseError:raise Refused('UI_XML_INVALID')
        xml_path.write_bytes(data);row['xmlFreshnessVerified']=True;row['xmlSHA256']=hashlib.sha256(data).hexdigest();row['dumpSuccessMarkerVerified']=True
    except Refused as error:
        xml_failure=error;row['xmlFailureCode']=str(error)
    data,_,truncated=run([ADB,'-s',SERIAL,'exec-out','screencap','-p'],'screen_png',timeout=screen_timeout(15),limit=8*1024*1024)
    if truncated or not data.startswith(b'\x89PNG\r\n\x1a\n'):raise Refused('SCREENSHOT_INVALID')
    (OUT/(label+'.png')).write_bytes(data);row['pngSHA256']=hashlib.sha256(data).hexdigest();row['captureEndBootSeconds']=time.monotonic()-START
    row['status']='FRESH_XML_AND_SCREENSHOT_RETAINED' if not xml_failure else 'CURRENT_SCREENSHOT_XML_UNAVAILABLE';save()
    if xml_failure:raise xml_failure
    return {e.get('package') for e in tree.iter() if e.get('package')}

def chrome_meaningful_text(xml):
    tree=ET.fromstring(xml)
    return [e for e in tree.iter() if e.get('package')=='com.android.chrome' and (e.get('text','').strip() or e.get('content-desc','').strip())]

def observe_chrome_screen():
    # Read-only first-run observation; meaningful text requires human review, never consent.
    observation_start=time.monotonic();deadline=min(observation_start+90,START+CAP);rows=[]
    STATE['chromeScreenObservations']=rows
    for attempt in range(1,4):
        delay=observation_start+(attempt-1)*20-time.monotonic()
        if delay>0:time.sleep(min(delay,max(0,deadline-time.monotonic())))
        label='chrome-first-screen' if attempt==1 else 'chrome-observation-'+str(attempt)
        try:packages=screen(label,observation_deadline=deadline)
        except Refused as error:
            if str(error) in {'UI_DUMP_REPORTED_ERROR','UI_DUMP_SUCCESS_MARKER_REQUIRED','UI_XML_INVALID','OWN_COMMAND_FAILED_ui_dump','OWN_COMMAND_FAILED_ui_xml'}:
                rows.append({'attempt':attempt,'status':'FRESH_XML_UNAVAILABLE','code':str(error)});save();continue
            if str(error) not in ['CHROME_SCREEN_OBSERVATION_DEADLINE','OWN_COMMAND_TIMEOUT_ui_dump','OWN_COMMAND_TIMEOUT_ui_xml','OWN_COMMAND_TIMEOUT_screen_png']:raise
            rows.append({'attempt':attempt,'status':'INCOMPLETE_BOUNDED_CAPTURE','code':str(error)})
            STATE['chromeObservationOutcome']='UNKNOWN_AT_OBSERVATION_DEADLINE';return
        data=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
        count=len(chrome_meaningful_text(data))
        rows.append({'attempt':attempt,'label':label,'elapsedBootSeconds':time.monotonic()-START,'chromeNonemptyTextOrDescriptionCount':count,'xmlSHA256':hashlib.sha256(data).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'packages':sorted(packages)})
        STATE['chromeFirstScreenPackages']=sorted(packages);save()
        if count:
            STATE['chromeObservationOutcome']='MEANINGFUL_CHROME_UI_REQUIRES_REVIEW';return
    STATE['chromeObservationOutcome']='UNKNOWN_AFTER_BOUNDED_OBSERVATION'

def launcher_chrome_target(xml,png):
    if len(xml)>2*1024*1024 or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():raise Refused('LAUNCHER_XML_INVALID')
    tree=ET.fromstring(xml)
    packages={e.get('package') for e in tree.iter() if e.get('package')}
    launcher='com.google.android.apps.nexuslauncher'
    if launcher not in packages or not packages.issubset({launcher,'android','com.android.systemui'}):raise Refused('EXACT_LAUNCHER_FOREGROUND_REQUIRED')
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n' or png[12:16]!=b'IHDR':raise Refused('LAUNCHER_SCREEN_DIMENSIONS_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big')
    if not(0<width<=16384 and 0<height<=16384):raise Refused('LAUNCHER_SCREEN_DIMENSIONS_REQUIRED')
    candidates=[]
    def walk(e,eligible=True):
        eligible=eligible and e.get('enabled')!='false' and e.get('visible-to-user')!='false' and e.get('displayed')!='false'
        if e.get('package')==launcher and e.get('text')=='Chrome' and e.get('content-desc')=='Chrome':
            if not eligible or e.get('enabled')!='true' or e.get('clickable')!='true' or e.get('class')!='android.widget.TextView':raise Refused('CHROME_ICON_NOT_ELIGIBLE')
            match=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
            if not match:raise Refused('CHROME_ICON_BOUNDS_REQUIRED')
            x0,y0,x1,y1=map(int,match.groups())
            if not(0<=x0<x1<=width and 0<=y0<y1<=height):raise Refused('CHROME_ICON_BOUNDS_REQUIRED')
            candidates.append({'x':(x0+x1)//2,'y':(y0+y1)//2,'bounds':[x0,y0,x1,y1],'screen':[width,height]})
        for child in e:walk(child,eligible)
    walk(tree)
    if len(candidates)!=1:raise Refused('UNIQUE_CHROME_ICON_REQUIRED')
    return candidates[0]

def launch_chrome_from_fresh_icon():
    capture_start=time.monotonic();screen('android-pre-chrome-launch')
    xml=(OUT/'android-pre-chrome-launch.xml').read_bytes();png=(OUT/'android-pre-chrome-launch.png').read_bytes()
    target=launcher_chrome_target(xml,png)
    if time.monotonic()-capture_start>10:raise Refused('LAUNCHER_ICON_SNAPSHOT_TOO_OLD')
    STATE['chromeLaunchInput']={'kind':'single-native-launcher-icon-tap','xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'target':target,'snapshotAgeUpperBoundSeconds':time.monotonic()-capture_start,'attempts':1}
    STATE['UIInputCommands']=1;save()
    run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_fresh_chrome_launcher_icon',timeout=5)

def chrome_diagnostic_categories(text):
    lines=[line for line in text.splitlines() if re.search(r'chrome|chromium|\bcr_',line,re.I)]
    patterns={'firstRunOrPolicy':r'first.?run|fre_|policy','nativeLibrary':r'native.?library|libraryloader','chromiumError':r'\berror\b|\bfatal\b','chromeANROrCrash':r'ANR in com\.android\.chrome|Process: com\.android\.chrome|com\.android\.chrome.*(?:crash|has died)','networkError':r'net::ERR_[A-Z_]+'}
    return {key:sum(bool(re.search(pattern,line,re.I)) for line in lines) for key,pattern in patterns.items()}

def retain_chrome_readonly_diagnostics():
    row={'rawLogcatRetained':False,'categoryCountsAreNotCausalVerdicts':True}
    STATE['chromeReadonlyDiagnostics']=row
    try:
        data,code,cut=run([ADB,'-s',SERIAL,'shell','pidof','com.android.chrome'],'chrome_pid_presence',timeout=3,allowed_failure=True,retain_stdout=False)
        row['pidCommandExitCode']=code;row['chromePIDCount']=len(data.split()) if not cut and all(v.isdigit() for v in data.split()) else None
        data,code,cut=run([ADB,'-s',SERIAL,'logcat','-d','-t','300','-v','brief'],'chrome_selected_logcat_categories',timeout=3,allowed_failure=True,limit=65536,retain_stdout=False)
        row['logcatCommandExitCode']=code;row['captureTailLimited']=cut;row['categories']=chrome_diagnostic_categories(data.decode(errors='replace'))
    except Refused as error:row['incompleteCode']=str(error) if str(error).startswith(('BOOT_PHASE_DEADLINE','OWN_COMMAND_TIMEOUT_')) else 'READONLY_DIAGNOSTICS_REFUSED'
    save()

CHROME_TERMS_APPROVAL_FLAG='--approve-chrome-124-terms-without-account'
CHROME_TERMS_FOOTER='By continuing, you agree to the Terms of Service. To help improve the app, Chrome sends usage and crash data to Google. Manage'

def chrome_terms_target(xml,png,version_lines):
    versions={line.removeprefix('versionName=') for line in version_lines if line.startswith('versionName=')}
    if versions!={'124.0.6367.219'}:raise Refused('REVIEWED_CHROME_VERSION_REQUIRED_FOR_TERMS_ACTION')
    if len(xml)>2*1024*1024 or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():raise Refused('CHROME_TERMS_XML_INVALID')
    tree=ET.fromstring(xml);package='com.android.chrome';prefix=package+':id/'
    packages={e.get('package') for e in tree.iter() if e.get('package')}
    if package not in packages or not packages.issubset({package,'android','com.android.systemui'}):raise Refused('CHROME_TERMS_FOREGROUND_REQUIRED')
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n' or png[12:16]!=b'IHDR':raise Refused('CHROME_TERMS_DIMENSIONS_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big')
    if not(0<width<=16384 and 0<height<=16384):raise Refused('CHROME_TERMS_DIMENSIONS_REQUIRED')
    eligible={}
    def walk(e,visible=True):
        visible=visible and e.get('enabled')!='false' and e.get('visible-to-user')!='false' and e.get('displayed')!='false'
        eligible[id(e)]=visible
        for child in e:walk(child,visible)
    walk(tree)
    def one(suffix,text,klass,clickable):
        nodes=[e for e in tree.iter() if e.get('resource-id')==prefix+suffix]
        if len(nodes)!=1:raise Refused('UNIQUE_REVIEWED_CHROME_TERMS_NODE_REQUIRED')
        e=nodes[0]
        if not eligible[id(e)] or e.get('package')!=package or e.get('text')!=text or e.get('content-desc','')!='' or e.get('class')!=klass or e.get('enabled')!='true' or e.get('clickable')!=clickable:raise Refused('REVIEWED_CHROME_TERMS_SCREEN_MISMATCH')
        match=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
        if not match:raise Refused('CHROME_TERMS_BOUNDS_REQUIRED')
        bounds=list(map(int,match.groups()));x0,y0,x1,y1=bounds
        if not(0<=x0<x1<=width and 0<=y0<y1<=height):raise Refused('CHROME_TERMS_BOUNDS_REQUIRED')
        return e,bounds
    one('title','Welcome to Chrome','android.widget.TextView','false')
    one('subtitle','Sign in to browse easier across devices','android.widget.TextView','false')
    one('signin_fre_footer',CHROME_TERMS_FOOTER,'android.widget.TextView','false')
    one('signin_fre_continue_button','Add account to device','android.widget.Button','true')
    target,bounds=one('signin_fre_dismiss_button','Use without an account','android.widget.Button','true')
    clickables=[e for e in tree.iter() if e.get('clickable')=='true' and eligible[id(e)]]
    if len(clickables)!=2 or {e.get('resource-id') for e in clickables}!={prefix+'signin_fre_continue_button',prefix+'signin_fre_dismiss_button'}:raise Refused('UNREVIEWED_CHROME_TERMS_CONTROLS_PRESENT')
    reviewed_texts={'Welcome to Chrome','Sign in to browse easier across devices','Add account to device','Use without an account',CHROME_TERMS_FOOTER}
    labels=[e.get('text') or e.get('content-desc') for e in tree.iter() if eligible[id(e)] and (e.get('text') or e.get('content-desc'))]
    if len(labels)!=5 or set(labels)!=reviewed_texts:raise Refused('UNREVIEWED_CHROME_TERMS_TEXT_PRESENT')
    x0,y0,x1,y1=bounds
    return {'x':(x0+x1)//2,'y':(y0+y1)//2,'bounds':bounds,'screen':[width,height],'resourceId':target.get('resource-id'),'label':target.get('text')}

def maybe_approved_chrome_terms_action(version_lines,argv):
    if CHROME_TERMS_APPROVAL_FLAG not in argv:return False
    if argv!=[CHROME_TERMS_APPROVAL_FLAG]:raise Refused('EXACT_SINGLE_TERMS_APPROVAL_FLAG_REQUIRED')
    capture_start=time.monotonic();screen('chrome-before-approved-terms-action')
    xml=(OUT/'chrome-before-approved-terms-action.xml').read_bytes();png=(OUT/'chrome-before-approved-terms-action.png').read_bytes()
    target=chrome_terms_target(xml,png,version_lines)
    age=time.monotonic()-capture_start
    if not(0<=age<=10):raise Refused('CHROME_TERMS_SNAPSHOT_TOO_OLD')
    STATE['chromeTermsAction']={'explicitOptInFlagProvided':True,'reviewedVersion':'124.0.6367.219','acceptsDisplayedTermsOfService':True,'displayedUsageAndCrashDataDisclosure':True,'createsOrSignsIntoAccount':False,'target':target,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'snapshotAgeUpperBoundSeconds':age,'attempts':1,'postScreenRequired':True}
    STATE['UIInputCommands']=STATE.get('UIInputCommands',0)+1;save()
    run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_approved_chrome_use_without_account',timeout=5)
    STATE['termsAcceptedByScript']=None;STATE['termsAcceptanceActionDispatched']=True;STATE['termsAcceptanceOutcome']='UNVERIFIED_PENDING_POST_SCREEN_REVIEW';save()
    observe_post_terms_readiness()
    STATE['status']='STOP_AFTER_APPROVED_CHROME_TERMS_ACTION_REQUIRES_REVIEW'
    return True

def post_terms_is_new_meaningful_ui(xml):
    if not chrome_meaningful_text(xml):return False
    tree=ET.fromstring(xml)
    if any(e.get('package') not in {None,'','com.android.chrome','com.android.systemui','android'} for e in tree.iter()):raise Refused('UNEXPECTED_POST_TERMS_PACKAGE')
    # A newly dumped Welcome screen is not evidence that the Terms transition completed.
    return not any(e.get('resource-id')=='com.android.chrome:id/title' and e.get('text')=='Welcome to Chrome' for e in tree.iter())

def observe_post_terms_readiness():
    start=time.monotonic();deadline=min(start+70,START+CAP);rows=[]
    STATE['postTermsObservations']=rows
    transient={'UI_DUMP_REPORTED_ERROR','UI_DUMP_SUCCESS_MARKER_REQUIRED','UI_XML_INVALID','OWN_COMMAND_FAILED_ui_xml','OWN_COMMAND_TIMEOUT_ui_dump','OWN_COMMAND_TIMEOUT_ui_xml','OWN_COMMAND_TIMEOUT_screen_png','CHROME_SCREEN_OBSERVATION_DEADLINE'}
    for attempt in range(1,4):
        delay=start+(attempt-1)*20-time.monotonic()
        if delay>0:time.sleep(min(delay,max(0,deadline-time.monotonic())))
        if time.monotonic()>=deadline:break
        label='chrome-post-terms-observation-'+str(attempt)
        row={'attempt':attempt,'label':label};rows.append(row)
        try:screen(label,observation_deadline=deadline)
        except Refused as error:
            if str(error) not in transient:raise
            row['status']='FRESH_XML_UNAVAILABLE';row['code']=str(error);save();continue
        data=(OUT/(label+'.xml')).read_bytes()
        row['xmlFreshnessVerified']=True;row['xmlSHA256']=hashlib.sha256(data).hexdigest();row['pngSHA256']=hashlib.sha256((OUT/(label+'.png')).read_bytes()).hexdigest()
        row['newMeaningfulChromeUI']=post_terms_is_new_meaningful_ui(data);save()
        if row['newMeaningfulChromeUI']:
            STATE['postTermsObservationOutcome']='FRESH_NEW_CHROME_UI_REQUIRES_REVIEW';return
    STATE['postTermsObservationOutcome']='UNKNOWN_AFTER_BOUNDED_FRESH_POST_TERMS_OBSERVATION'

def listener_guard():
    data,_,_=run(['ss','-ltn'],'selected_listeners')
    selected=[]
    for line in data.decode().splitlines()[1:]:
        parts=line.split()
        if len(parts)<4:continue
        addr=parts[3]
        if any(addr.endswith(':'+str(port)) for port in [5037,5554,5555,8554]):
            selected.append(addr)
            if not(addr.startswith('127.') or addr.startswith('[::1]:')):raise Refused('NONLOOPBACK_CONTROL_PORT')
    (OUT/'selected_listeners.log').write_text('\n'.join(selected)+'\n')
    STATE['selectedControlListeners']=selected

def verified_flags(help_text):
    def supported(flag):return bool(re.search(r'(?m)^\s*'+re.escape(flag)+r'(?:\s|$)',help_text))
    required=['-avd','-no-window','-no-snapshot','-accel','-camera-back','-camera-front','-port']
    audio_flag=next((f for f in ['-no-audio','-noaudio'] if supported(f)),None)
    if not audio_flag or not all(supported(f) for f in required):raise Refused('PLANNED_EMULATOR_FLAGS_NOT_IN_ACTUAL_HELP')
    return audio_flag

def firstscreen_can_launch_chrome(packages):
    launcher={'com.google.android.apps.nexuslauncher','com.android.launcher3','com.google.android.googlequicksearchbox'}
    return bool(packages.intersection(launcher)) and packages.issubset(launcher|{'com.android.systemui','android'})

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    if '--cleanup' in sys.argv:
        global STATE,TRACE
        if (OUT/'receipt.json').exists():
            STATE=json.loads((OUT/'receipt.json').read_text());TRACE=STATE.get('trace',[]);cleanup()
        return 0
    for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,lambda *_:(_ for _ in ()).throw(Refused('OWN_PROCESS_INTERRUPTED')))
    save()
    try:
        installed=json.loads(Path('evidence/android-stable-setup/post-install.json').read_text())
        if installed.get('status')!='PASS_INSTALLED_EXACT_STABLE_BINDINGS':raise Refused('INSTALLED_STABLE_BINDING_REQUIRED')
        if os.uname().sysname!='Linux' or os.uname().machine!='x86_64':raise Refused('HOST_SCOPE')
        help_bytes,_,_=run([str(SDK/'emulator/emulator'),'-help-all'],'emulator_help',timeout=20,limit=2*1024*1024)
        help_text=help_bytes.decode(errors='replace')
        audio_flag=verified_flags(help_text)
        STATE['verifiedAudioDisableFlag']=audio_flag
        data,_,_=run(['getfacl','--absolute-names','/dev/kvm'],'kvm_acl_before');(OUT/'kvm-original.acl').write_bytes(data)
        STATE['KVMACLRestoreArmed']=True;save()
        run(['sudo','-n','setfacl','-m','u:'+str(os.getuid())+':rw','/dev/kvm'],'kvm_uid_acl')
        STATE['KVMACLChanged']=True;save()
        if not os.access('/dev/kvm',os.R_OK|os.W_OK):raise Refused('KVM_USER_ACCESS_NOT_AVAILABLE')
        run([str(SDK/'emulator/emulator'),'-accel-check'],'acceleration_check')
        # Linux sockaddr_un.sun_path holds108 bytes including its terminator.
        # The real hosted checkout's old absolute socket was138 bytes long.
        # Keep the socket in a fresh private short directory; no shared daemon.
        private=Path(tempfile.mkdtemp(prefix='v15pa-',dir='/tmp'));private.chmod(0o700)
        socket=private/'native';config=private/'only-null.pa'
        if len(os.fsencode(socket))>=108:raise Refused('PRIVATE_UNIX_SOCKET_PATH_TOO_LONG')
        STATE['privatePulseRuntime']={'path':str(private),'uid':private.stat().st_uid,'mode':private.stat().st_mode&0o777,'socketBytes':len(os.fsencode(socket))}
        save()
        config.write_text('.fail\nload-module module-native-protocol-unix socket='+str(socket)+' auth-anonymous=1\nload-module module-null-sink sink_name=ci_silent rate=48000 channels=2\nset-default-sink ci_silent\nset-default-source ci_silent.monitor\n')
        env=os.environ.copy();env['XDG_RUNTIME_DIR']=str(private)
        env['PULSE_SERVER']='unix:'+str(socket);env['PULSE_SINK']='ci_silent';env['PULSE_SOURCE']='ci_silent.monitor'
        pulse=own_process(['pulseaudio','-n','--daemonize=no','--exit-idle-time=-1','--file='+str(config.resolve())],'pulse',env=env)
        until=time.monotonic()+10
        while not socket.exists() and pulse.poll() is None and time.monotonic()<until:time.sleep(.1)
        if not socket.exists():raise Refused('PRIVATE_PULSE_NOT_READY')
        sinks,_,_=run(['pactl','list','short','sinks'],'pulse_sinks',env=env);sources,_,_=run(['pactl','list','short','sources'],'pulse_sources',env=env)
        sink_names=[x.split()[1] for x in sinks.decode().splitlines() if x.split()];source_names=[x.split()[1] for x in sources.decode().splitlines() if x.split()]
        if sink_names!=['ci_silent'] or source_names!=['ci_silent.monitor']:raise Refused('PRIVATE_OUTPUT_ONLY_PULSE_REQUIRED')
        STATE['privatePulseOnlySinkAndMonitor']=True
        prior,_,_=run(['ss','-ltn'],'control_ports_before')
        if any(re.search(r':(?:5037|5554|5555|8554)\s',line) for line in prior.decode().splitlines()):raise Refused('PREEXISTING_CONTROL_LISTENER_REFUSED')
        run([ADB,'start-server'],'start_owned_adb_server');STATE['ownedADBServerStarted']=True;save()
        devices,_,_=run([ADB,'devices'],'adb_devices_before')
        if any(line.strip() for line in devices.decode().splitlines()[1:]):raise Refused('EXISTING_ADB_DEVICE_REFUSED')
        name='ci_firstscreen_'+str(os.getpid());STATE['ownedAVD']=name
        # Bind avdmanager and emulator to the same explicit private discovery root.
        # Hosted tools otherwise disagreed about the implicit Android home.
        avd_home=Path(tempfile.mkdtemp(prefix='v15avd-',dir='/tmp'));avd_home.chmod(0o700)
        env['ANDROID_AVD_HOME']=str(avd_home);STATE['ownedAVDHome']=str(avd_home);save()
        device_list,_,_=run([str(SDK/'cmdline-tools/latest/bin/avdmanager'),'list','device'],'actual_device_profiles')
        if not re.search(r'id:\s*\d+\s+or\s+"pixel_6"',device_list.decode(errors='replace')):raise Refused('EXPECTED_DEVICE_PROFILE_NOT_IN_ACTUAL_LIST')
        run([str(SDK/'cmdline-tools/latest/bin/avdmanager'),'create','avd','--name',name,'--package','system-images;android-35;google_apis_playstore;x86_64','--device','pixel_6'],'create_owned_avd',timeout=30,env=env)
        if not(avd_home/(name+'.ini')).is_file():raise Refused('CREATED_AVD_DISCOVERY_INI_MISSING')
        listed,_,_=run([str(SDK/'emulator/emulator'),'-list-avds'],'owned_avd_list',env=env)
        if listed.decode().splitlines()!=[name]:raise Refused('CREATED_AVD_NOT_UNIQUELY_DISCOVERABLE')
        command=[str(SDK/'emulator/emulator'),'-avd',name,'-no-window','-no-snapshot','-accel','on','-camera-back','none','-camera-front','none','-port','5554',audio_flag]
        emu=own_process(command,'emulator',env=env);deadline=time.monotonic()+180
        while time.monotonic()<deadline and emu.poll() is None:
            data,code,_=run([ADB,'-s',SERIAL,'shell','getprop','sys.boot_completed'],'boot_poll',timeout=5,allowed_failure=True)
            if code==0 and data.strip()==b'1':break
            time.sleep(1)
        else:
            if emu.poll() is not None:
                STATE['emulatorEarlyExitCode']=emu.returncode;save();raise Refused('EMULATOR_EXITED_BEFORE_BOOT')
            raise Refused('BOOT_NOT_COMPLETE_WITHIN_180S')
        listener_guard();packages=screen('android-first-screen');STATE['androidFirstScreenPackages']=sorted(packages)
        if not firstscreen_can_launch_chrome(packages):STATE['status']='STOP_ANDROID_FIRST_RUN_OR_NONLAUNCHER_UI_REQUIRES_REVIEW';return 0
        data,_,_=run([ADB,'-s',SERIAL,'shell','pm','list','packages','com.android.chrome'],'chrome_package')
        if b'package:com.android.chrome' not in data:raise Refused('ANDROID_CHROME_NOT_PRESENT')
        launch_chrome_from_fresh_icon()
        observe_chrome_screen()
        retain_chrome_readonly_diagnostics()
        version,_,cut=run([ADB,'-s',SERIAL,'shell','dumpsys','package','com.android.chrome'],'chrome_version',limit=2*1024*1024)
        lines=[line.strip() for line in version.decode(errors='replace').splitlines() if re.match(r'\s*version(?:Name|Code)=',line)]
        (OUT/'chrome_version.log').write_text('\n'.join(lines)+'\n');STATE['androidChromeVersionLines']=lines
        if cut or not any(line.startswith('versionName=') for line in lines):raise Refused('ANDROID_CHROME_VERSION_UNVERIFIED')
        if maybe_approved_chrome_terms_action(lines,sys.argv[1:]):return 0
        STATE['status']='STOP_CHROME_FIRST_SCREEN_REQUIRES_REVIEW_NO_CONTINUATION'
        return 0
    except Refused as e:STATE['status']='REFUSED_CAPABILITY';STATE['refusalCode']=str(e);return 2
    except Exception as e:STATE['status']='REFUSED_CAPABILITY';STATE['errorClass']=type(e).__name__;return 2
    finally:cleanup()
if __name__=='__main__':sys.exit(main())
