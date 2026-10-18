#!/usr/bin/env python3
"""Owned ephemeral CI boot/Chrome first-screen witness. No UI taps or consent continuation."""
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

def run(args,label,timeout=20,limit=65536,allowed_failure=False,env=None):
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
    diagnostic=(stdout if label not in ['screen_png','ui_xml'] else b'')+stderr
    text=diagnostic[-65536:].decode('utf-8',errors='replace')
    text='\n'.join('[TOKEN_LINE_REDACTED]' if re.search(r'token|authorization|password|cookie',line,re.I) else line for line in text.splitlines())
    (OUT/(label+'.log')).write_text(text)
    TRACE.append({'operation':label,'exitCode':p.returncode,'stdoutBytes':counts[0],'stderrBytes':counts[1],'retainedAtMostPerStream':limit})
    save()
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
    def screen_timeout(limit):
        if observation_deadline is None:return limit
        left=observation_deadline-time.monotonic()
        if left<=0:raise Refused('CHROME_SCREEN_OBSERVATION_DEADLINE')
        return min(limit,left)
    run([ADB,'-s',SERIAL,'shell','uiautomator','dump','/sdcard/ci-firstscreen.xml'],'ui_dump',timeout=screen_timeout(25))
    data,_,truncated=run([ADB,'-s',SERIAL,'exec-out','cat','/sdcard/ci-firstscreen.xml'],'ui_xml',timeout=screen_timeout(15),limit=2*1024*1024)
    if truncated or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():raise Refused('UI_XML_INVALID')
    try:tree=ET.fromstring(data)
    except ET.ParseError:raise Refused('UI_XML_INVALID')
    (OUT/(label+'.xml')).write_bytes(data)
    data,_,truncated=run([ADB,'-s',SERIAL,'exec-out','screencap','-p'],'screen_png',timeout=screen_timeout(15),limit=8*1024*1024)
    if truncated or not data.startswith(b'\x89PNG\r\n\x1a\n'):raise Refused('SCREENSHOT_INVALID')
    (OUT/(label+'.png')).write_bytes(data)
    return {e.get('package') for e in tree.iter() if e.get('package')}

def chrome_meaningful_text(xml):
    tree=ET.fromstring(xml)
    return [e for e in tree.iter() if e.get('package')=='com.android.chrome' and (e.get('text','').strip() or e.get('content-desc','').strip())]

def observe_chrome_screen():
    # Read-only first-run observation; meaningful text requires human review, never consent.
    deadline=min(time.monotonic()+30,START+CAP);rows=[]
    STATE['chromeScreenObservations']=rows
    for attempt in range(1,4):
        label='chrome-first-screen' if attempt==1 else 'chrome-observation-'+str(attempt)
        try:packages=screen(label,observation_deadline=deadline)
        except Refused as error:
            if str(error) not in ['CHROME_SCREEN_OBSERVATION_DEADLINE','OWN_COMMAND_TIMEOUT_ui_dump','OWN_COMMAND_TIMEOUT_ui_xml','OWN_COMMAND_TIMEOUT_screen_png']:raise
            rows.append({'attempt':attempt,'status':'INCOMPLETE_BOUNDED_CAPTURE','code':str(error)})
            STATE['chromeObservationOutcome']='UNKNOWN_AT_OBSERVATION_DEADLINE';return
        data=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
        count=len(chrome_meaningful_text(data))
        rows.append({'attempt':attempt,'label':label,'elapsedBootSeconds':time.monotonic()-START,'chromeNonemptyTextOrDescriptionCount':count,'xmlSHA256':hashlib.sha256(data).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'packages':sorted(packages)})
        STATE['chromeFirstScreenPackages']=sorted(packages);save()
        if count:
            STATE['chromeObservationOutcome']='MEANINGFUL_CHROME_UI_REQUIRES_REVIEW';return
        if attempt<3:
            left=deadline-time.monotonic()
            if left<=0:break
            time.sleep(min(8,left))
    STATE['chromeObservationOutcome']='UNKNOWN_AFTER_BOUNDED_OBSERVATION'

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
        run([ADB,'-s',SERIAL,'shell','am','start','-W','-n','com.android.chrome/com.google.android.apps.chrome.Main'],'launch_chrome_firstscreen',timeout=30)
        observe_chrome_screen()
        version,_,cut=run([ADB,'-s',SERIAL,'shell','dumpsys','package','com.android.chrome'],'chrome_version',limit=2*1024*1024)
        lines=[line.strip() for line in version.decode(errors='replace').splitlines() if re.match(r'\s*version(?:Name|Code)=',line)]
        (OUT/'chrome_version.log').write_text('\n'.join(lines)+'\n');STATE['androidChromeVersionLines']=lines
        if cut or not any(line.startswith('versionName=') for line in lines):raise Refused('ANDROID_CHROME_VERSION_UNVERIFIED')
        STATE['status']='STOP_CHROME_FIRST_SCREEN_REQUIRES_REVIEW_NO_CONTINUATION'
        return 0
    except Refused as e:STATE['status']='REFUSED_CAPABILITY';STATE['refusalCode']=str(e);return 2
    except Exception as e:STATE['status']='REFUSED_CAPABILITY';STATE['errorClass']=type(e).__name__;return 2
    finally:cleanup()
if __name__=='__main__':sys.exit(main())
