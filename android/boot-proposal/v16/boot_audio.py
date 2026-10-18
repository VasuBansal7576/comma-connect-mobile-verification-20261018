#!/usr/bin/env python3
"""Owned ephemeral CI Chrome witness. One fresh launcher-icon tap, no consent continuation."""
import hashlib
import ctypes
import json
import os
from pathlib import Path
import re
import signal
import shlex
import subprocess
import sys
import threading
import time
import tempfile
import xml.etree.ElementTree as ET
import audio_acquire

OUT=Path('evidence/android-boot')
SDK=Path('/usr/local/lib/android/sdk')
SERIAL='emulator-5554'
ADB=str(SDK/'platform-tools/adb')
START=time.monotonic()
CAP=900
AUDIO_CLEANUP_RESERVE=80
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
    value=min(limit,CAP-AUDIO_CLEANUP_RESERVE-(time.monotonic()-START))
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

def group_member(pid,proc_root=Path('/proc')):
    # Retain only OS identity/ownership fields, never argv, environment or process names.
    directory=proc_root/str(pid)
    data=(directory/'stat').read_bytes()
    if len(data)>4096:raise ValueError('BOUNDED_PROC_STAT_REQUIRED')
    lead,fields=data.decode('utf-8').rsplit(') ',1);fields=fields.split()
    if int(lead.split(' (',1)[0])!=pid:raise ValueError('PROC_PID_IDENTITY_REQUIRED')
    if fields[0] not in ['R','S','D','Z','T','t','X','x','K','W','P','I'] or not fields[19].isdecimal():raise ValueError('PROC_IDENTITY_FIELDS_REQUIRED')
    return {'pid':pid,'ppid':int(fields[1]),'pgid':int(fields[2]),'sid':int(fields[3]),'state':fields[0],'startTicks':fields[19],'uid':directory.stat().st_uid}

def group_snapshot(pgid,proc_root=Path('/proc')):
    members=[];complete=True;count=0
    try:
        for entry in proc_root.iterdir():
            if not entry.name.isdecimal():continue
            count+=1
            if count>8192:complete=False;break
            try:member=group_member(int(entry.name),proc_root)
            except FileNotFoundError:continue
            except (OSError,ValueError,IndexError,UnicodeError):complete=False;continue
            if member['pgid']==pgid:
                if len(members)>=128:complete=False;break
                members.append(member)
    except OSError:complete=False
    return {'complete':complete,'scannedPIDs':count,'members':sorted(members,key=lambda m:m['pid'])}

def same_group_identity(a,b):
    return all(a.get(k)==b.get(k) for k in ['pid','startTicks','pgid','sid','uid'])

def bound_group_anchor(row,snapshot):
    provenance=row.get('ownedGroupProvenance',{})
    if not provenance.get('complete') or not snapshot.get('complete'):return None
    members=snapshot['members'];pid=row['pid'];uid=os.getuid()
    if not members or any(m['pgid']!=pid or m['sid']!=pid or m['uid']!=uid for m in members):return None
    for member in members:
        if member['state'] not in ['Z','X','x'] and any(same_group_identity(member,old) for old in provenance['members']+row.get('adoptedGroupMembers',[])):
            try:fresh=group_member(member['pid'])
            except (OSError,ValueError,IndexError,UnicodeError):continue
            if fresh['state'] not in ['Z','X','x'] and same_group_identity(member,fresh):return fresh
    return None

def finish_owned_group(row,result):
    # A surviving bound descendant can prove group continuity after its original leader exits.
    result['descendantGroupSignals']=[]
    for sig in [signal.SIGTERM,signal.SIGKILL]:
        snapshot=group_snapshot(row['pid']);bind_adopted_group_members(row,snapshot);reap_owned_group_children(row,result)
        if current_owned_subreaper():snapshot=group_snapshot(row['pid'])
        anchor=bound_group_anchor(row,snapshot)
        if anchor is None:break
        try:os.killpg(row['pid'],sig)
        except ProcessLookupError:break
        except PermissionError:result['descendantSignalRefused']='PERMISSION_DENIED';break
        result['descendantGroupSignals'].append({'signal':int(sig),'anchorPID':anchor['pid'],'anchorStartTicks':anchor['startTicks']})
        until=time.monotonic()+1.5
        while time.monotonic()<until:
            reap_owned_group_children(row,result);current=group_snapshot(row['pid'])
            if current['complete'] and not any(m['state'] not in ['Z','X','x'] for m in current['members']):break
            time.sleep(.1)
    reap_owned_group_children(row,result);final=group_snapshot(row['pid']);result['finalGroupSnapshot']=final
    if not final['complete']:classification='UNKNOWN_INCOMPLETE_SCAN'
    elif not final['members']:classification='NO_MEMBERS_OBSERVED_REQUIRES_GROUP_ABSENCE_CHECK'
    elif all(m['state'] in ['Z','X','x'] for m in final['members']):classification='INERT_ZOMBIE_ONLY_OBSERVED_NOT_ABSENT'
    else:classification='LIVE_MEMBERS_OBSERVED'
    result['finalGroupClassification']=classification

def enable_owned_subreaper():
    if os.uname().sysname!='Linux' or CHILDREN:raise Refused('SUBREAPER_BEFORE_OWN_CHILDREN_REQUIRED')
    header=Path('/usr/include/linux/prctl.h').read_text()
    values={}
    for name in ['PR_SET_CHILD_SUBREAPER','PR_GET_CHILD_SUBREAPER']:
        hits=re.findall(r'(?m)^#define\s+'+name+r'\s+(\d+)\s*$',header)
        if len(hits)!=1:raise Refused('ACTUAL_LINUX_SUBREAPER_CONSTANT_REQUIRED')
        values[name]=int(hits[0])
    libc=ctypes.CDLL(None,use_errno=True);libc.prctl.restype=ctypes.c_int
    if libc.prctl(ctypes.c_int(values['PR_SET_CHILD_SUBREAPER']),ctypes.c_ulong(1),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0))!=0:raise Refused('SUBREAPER_SET_REFUSED')
    value=ctypes.c_int()
    if libc.prctl(ctypes.c_int(values['PR_GET_CHILD_SUBREAPER']),ctypes.byref(value),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0))!=0 or value.value!=1:raise Refused('SUBREAPER_READBACK_REQUIRED')
    ticks=process_ticks(os.getpid())
    if not ticks:raise Refused('SUBREAPER_OWN_PROCESS_IDENTITY_REQUIRED')
    STATE['ownedSubreaper']={'verified':True,'pid':os.getpid(),'startTicks':ticks,'uid':os.getuid(),'constants':values,'enabledBeforeOwnedChildren':True};save()

def current_owned_subreaper():
    proof=STATE.get('ownedSubreaper',{})
    return proof.get('verified') is True and proof.get('enabledBeforeOwnedChildren') is True and proof.get('pid')==os.getpid() and proof.get('uid')==os.getuid() and bool(proof.get('startTicks')) and proof.get('startTicks')==process_ticks(os.getpid())

def bind_adopted_group_members(row,snapshot):
    original=row.get('ownedGroupProvenance',{})
    if not current_owned_subreaper() or not original.get('complete') or not snapshot.get('complete'):return
    pid=row['pid'];uid=os.getuid()
    if not str(row.get('startTicks','')).isdecimal():return
    if not any(m['pid']==pid and m['startTicks']==row.get('startTicks') and m['sid']==pid and m['pgid']==pid and m['uid']==uid for m in original.get('members',[])):return
    known=original['members']+row.get('adoptedGroupMembers',[])
    for member in snapshot['members']:
        if member['ppid']!=os.getpid() or member['sid']!=pid or member['pgid']!=pid or member['uid']!=uid or not str(member['startTicks']).isdecimal() or int(member['startTicks'])<int(row['startTicks']):continue
        try:fresh=group_member(member['pid'])
        except (OSError,ValueError,IndexError,UnicodeError):continue
        if fresh['ppid']!=os.getpid() or not same_group_identity(member,fresh):continue
        if not any(same_group_identity(member,old) for old in known):
            if len(row.get('adoptedGroupMembers',[]))>=128:row['adoptedMemberBoundExceeded']=True;return
            row.setdefault('adoptedGroupMembers',[]).append(fresh);known.append(fresh)

def reap_owned_group_children(row,result):
    if not current_owned_subreaper():return
    snapshot=group_snapshot(row['pid']);bind_adopted_group_members(row,snapshot)
    if not snapshot['complete']:return
    known=row.get('ownedGroupProvenance',{}).get('members',[])+row.get('adoptedGroupMembers',[])
    for member in snapshot['members']:
        if member['ppid']!=os.getpid() or member['state'] not in ['Z','X','x'] or not any(same_group_identity(member,old) for old in known):continue
        try:
            fresh=group_member(member['pid'])
            if fresh['ppid']!=os.getpid() or not same_group_identity(member,fresh):continue
            waited,status=os.waitpid(member['pid'],os.WNOHANG)
            if waited==member['pid']:result.setdefault('reapedOwnedChildren',[]).append({'pid':waited,'startTicks':member['startTicks'],'waitStatus':status})
        except ChildProcessError:result.setdefault('reapRefusals',[]).append({'pid':member['pid'],'code':'NO_LONGER_WAITABLE_OWN_CHILD'})
        except (OSError,ValueError,IndexError,UnicodeError):result.setdefault('reapRefusals',[]).append({'pid':member['pid'],'code':'OWN_CHILD_RECHECK_OR_WAIT_REFUSED'})

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
        try:group_matches=matched and os.getpgid(pid)==pid and os.getsid(pid)==pid
        except ProcessLookupError:group_matches=False
        if group_matches:
            snapshot=group_snapshot(pid)
            leaders=[m for m in snapshot['members'] if m['pid']==pid and m['startTicks']==row['startTicks'] and m['sid']==pid and m['uid']==os.getuid()]
            group_matches=snapshot['complete'] and len(leaders)==1 and all(m['sid']==pid and m['uid']==os.getuid() for m in snapshot['members'])
            if group_matches:row['ownedGroupProvenance']=snapshot
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
                until=time.monotonic()+2
                while process_ticks(pid)==row['startTicks'] and time.monotonic()<until:
                    try:os.waitpid(pid,os.WNOHANG)
                    except ChildProcessError:pass
                    time.sleep(.05)
        results.append({'kind':row['kind'],'boundPIDMatchedAtCleanup':matched})
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
    # Final readback follows bounded termination and CHILDREN.wait/reap, not the pre-reap state.
    for row,result in zip(reversed(STATE.get('children',[])),results):
        finish_owned_group(row,result)
        pid=row['pid'];bound=row.get('startTicks');ticks=process_ticks(pid);reused=bool(bound and ticks and ticks!=bound)
        if ticks is not None:pid_present=True
        else:
            try:os.kill(pid,0);pid_present=True
            except ProcessLookupError:pid_present=False
            except PermissionError:pid_present=None
        same=bool(bound and ticks==bound) if ticks is not None or pid_present is False else None
        group_present=None
        if bound and not reused:
            try:os.killpg(pid,0);group_present=True
            except ProcessLookupError:group_present=False
            except PermissionError:group_present=None
        verified=bool(bound and same is False and pid_present is False and group_present is False and not reused and result['finalGroupSnapshot']['complete'] and not result['finalGroupSnapshot']['members'])
        result.update({'sameProcessStillPresent':same,'pidStillPresent':pid_present,'pidReusedBeforeFinalReadback':reused,'ownedProcessGroupStillPresent':group_present,'exitAndGroupAbsenceVerified':verified,'readbackAfterBoundedReap':True})
    STATE['ownedChildCleanupVerified']=all(result['exitAndGroupAbsenceVerified'] for result in results)
    STATE['ownedChildCleanupStatus']='VERIFIED_EXIT_AND_GROUP_ABSENCE' if STATE['ownedChildCleanupVerified'] else 'UNVERIFIED_OR_STILL_PRESENT'
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

def fresh_input_snapshot(label):
    if not re.fullmatch(r'[a-z0-9-]+',label):raise Refused('OWN_INPUT_SNAPSHOT_LABEL_REQUIRED')
    helper_start=time.monotonic();deadline=min(helper_start+30,START+CAP)
    row={'phase':label,'deadlineBootSeconds':deadline-START,'attempts':[]};STATE.setdefault('inputSnapshotReadiness',[]).append(row);save()
    transient={'UI_DUMP_REPORTED_ERROR','UI_DUMP_SUCCESS_MARKER_REQUIRED','UI_XML_INVALID','OWN_COMMAND_FAILED_ui_dump','OWN_COMMAND_FAILED_ui_xml','OWN_COMMAND_TIMEOUT_ui_dump','OWN_COMMAND_TIMEOUT_ui_xml','OWN_COMMAND_TIMEOUT_screen_png','CHROME_SCREEN_OBSERVATION_DEADLINE'}
    for attempt in range(1,4):
        capture_start=time.monotonic()
        if capture_start>=deadline:break
        actual_label=label+'-input-attempt-'+str(attempt)
        item={'attempt':attempt,'label':actual_label,'captureStartBootSeconds':capture_start-START};row['attempts'].append(item)
        try:packages=screen(actual_label,observation_deadline=deadline)
        except Refused as error:
            if str(error) not in transient:raise
            item['status']='FRESH_XML_UNAVAILABLE';item['code']=str(error);save();continue
        complete=time.monotonic()
        if complete<capture_start or complete>=deadline:
            item['status']='READINESS_DEADLINE_CROSSED';save();raise Refused('INPUT_SNAPSHOT_READINESS_DEADLINE')
        item['captureCompleteBootSeconds']=complete-START;item['ageAtCompletionSeconds']=complete-capture_start
        if complete-capture_start>10:
            item['status']='FRESH_BUT_AGED_OUT_NO_INPUT';save();continue
        item['status']='FRESH_SNAPSHOT_RETAINED';row['successfulLabel']=actual_label;save()
        return {'label':actual_label,'captureStartMonotonic':capture_start,'captureCompleteMonotonic':complete,'packages':packages}
    row['status']='EXHAUSTED_NO_INPUT_PERMITTED';save();raise Refused('INPUT_SNAPSHOT_READINESS_EXHAUSTED')

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
    fresh=fresh_input_snapshot('android-pre-chrome-launch');capture_start=fresh['captureStartMonotonic']
    xml=(OUT/(fresh['label']+'.xml')).read_bytes();png=(OUT/(fresh['label']+'.png')).read_bytes()
    target=launcher_chrome_target(xml,png)
    age=time.monotonic()-capture_start
    if not(0<=age<=10):raise Refused('LAUNCHER_ICON_SNAPSHOT_TOO_OLD')
    STATE['chromeLaunchInput']={'inputSnapshotLabel':fresh['label'],'kind':'single-native-launcher-icon-tap','xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'target':target,'snapshotAgeUpperBoundSeconds':age,'attempts':1}
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
    if argv not in [[CHROME_TERMS_APPROVAL_FLAG],[CHROME_TERMS_APPROVAL_FLAG,OWNED_LAB_CONTINUATION_FLAG],[CHROME_TERMS_APPROVAL_FLAG,OWNED_LAB_CONTINUATION_FLAG,OWNED_MENU_OBSERVATION_FLAG],[CHROME_TERMS_APPROVAL_FLAG,OWNED_LAB_CONTINUATION_FLAG,OWNED_MENU_OBSERVATION_FLAG,OWNED_ADD_HOME_FLAG],[CHROME_TERMS_APPROVAL_FLAG,OWNED_LAB_CONTINUATION_FLAG,OWNED_MENU_OBSERVATION_FLAG,OWNED_ADD_HOME_FLAG,OWNED_INSTALL_OPTION_FLAG],[CHROME_TERMS_APPROVAL_FLAG,OWNED_LAB_CONTINUATION_FLAG,OWNED_MENU_OBSERVATION_FLAG,OWNED_ADD_HOME_FLAG,OWNED_INSTALL_OPTION_FLAG,OWNED_CONFIRM_INSTALL_FLAG]]:raise Refused('EXACT_REVIEWED_CONTINUATION_FLAGS_REQUIRED')
    STATE['ownedFinalInstallRequested']=OWNED_CONFIRM_INSTALL_FLAG in argv
    fresh=fresh_input_snapshot('chrome-before-approved-terms-action');capture_start=fresh['captureStartMonotonic']
    xml=(OUT/(fresh['label']+'.xml')).read_bytes();png=(OUT/(fresh['label']+'.png')).read_bytes()
    target=chrome_terms_target(xml,png,version_lines)
    age=time.monotonic()-capture_start
    if not(0<=age<=10):raise Refused('CHROME_TERMS_SNAPSHOT_TOO_OLD')
    STATE['chromeTermsAction']={'inputSnapshotLabel':fresh['label'],'explicitOptInFlagProvided':True,'reviewedVersion':'124.0.6367.219','acceptsDisplayedTermsOfService':True,'displayedUsageAndCrashDataDisclosure':True,'createsOrSignsIntoAccount':False,'target':target,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'snapshotAgeUpperBoundSeconds':age,'attempts':1,'postScreenRequired':True}
    STATE['UIInputCommands']=STATE.get('UIInputCommands',0)+1;save()
    run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_approved_chrome_use_without_account',timeout=5)
    STATE['termsAcceptedByScript']=None;STATE['termsAcceptanceActionDispatched']=True;STATE['termsAcceptanceOutcome']='UNVERIFIED_PENDING_POST_SCREEN_REVIEW';save()
    observe_post_terms_readiness()
    if OWNED_LAB_CONTINUATION_FLAG in argv:
        if OWNED_INSTALL_OPTION_FLAG in argv:continue_owned_lab_after_reviewed_privacy_notice(version_lines,observe_menu=True,add_home=True,install_option=True)
        elif OWNED_ADD_HOME_FLAG in argv:continue_owned_lab_after_reviewed_privacy_notice(version_lines,observe_menu=True,add_home=True)
        elif OWNED_MENU_OBSERVATION_FLAG in argv:continue_owned_lab_after_reviewed_privacy_notice(version_lines,observe_menu=True)
        else:continue_owned_lab_after_reviewed_privacy_notice(version_lines)
    else:STATE['status']='STOP_AFTER_APPROVED_CHROME_TERMS_ACTION_REQUIRES_REVIEW'
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

OWNED_LAB_CONTINUATION_FLAG='--continue-owned-v16-lab-after-privacy-notice'
OWNED_LAB_URL='https://comma-connect-fix-lab-20261016.zippy17.chatgpt.site/nqa?candidate=v16&experiment=nqa'
REVIEWED_PRIVACY_TEXTS=['Enhanced ad privacy in Chrome', 'We’re launching new privacy features that give you more choice over the ads you see.', 'Chrome notes topics of interest based on your recent browsing history. Also, sites you visit can determine what you like. Later, sites can ask for this information to show you personalized ads. You can choose which topics and sites are used to show you ads.', 'To measure the performance of an ad, limited types of data are shared between sites, such as whether you made a purchase after visiting a site.', 'More about ads in Chrome', 'You can make changes in Chrome settings']

def privacy_notice_target(xml,png,version_lines):
    versions={line.removeprefix('versionName=') for line in version_lines if line.startswith('versionName=')}
    if versions!={'124.0.6367.219'}:raise Refused('REVIEWED_CHROME_VERSION_REQUIRED_FOR_PRIVACY_NOTICE')
    if len(xml)>2*1024*1024 or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():raise Refused('PRIVACY_NOTICE_XML_INVALID')
    tree=ET.fromstring(xml);package='com.android.chrome';prefix=package+':id/'
    packages={e.get('package') for e in tree.iter() if e.get('package')}
    if package not in packages or not packages.issubset({package,'android','com.android.systemui'}):raise Refused('PRIVACY_NOTICE_FOREGROUND_REQUIRED')
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n' or png[12:16]!=b'IHDR':raise Refused('PRIVACY_NOTICE_SCREEN_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big')
    if not(0<width<=16384 and 0<height<=16384):raise Refused('PRIVACY_NOTICE_SCREEN_REQUIRED')
    eligible={}
    def walk(e,visible=True):
        visible=visible and e.get('enabled')!='false' and e.get('visible-to-user')!='false' and e.get('displayed')!='false';eligible[id(e)]=visible
        for child in e:walk(child,visible)
    walk(tree)
    def rect(e,klass,clickable):
        if not eligible[id(e)] or e.get('package')!=package or e.get('class')!=klass or e.get('enabled')!='true' or e.get('clickable')!=clickable or e.get('content-desc','')!='':raise Refused('PRIVACY_NOTICE_NODE_MISMATCH')
        match=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
        if not match:raise Refused('PRIVACY_NOTICE_BOUNDS_REQUIRED')
        r=list(map(int,match.groups()));x0,y0,x1,y1=r
        if not(0<=x0<x1<=width and 0<=y0<y1<=height):raise Refused('PRIVACY_NOTICE_BOUNDS_REQUIRED')
        return r
    for text in REVIEWED_PRIVACY_TEXTS:
        nodes=[e for e in tree.iter() if e.get('text')==text]
        if len(nodes)!=1:raise Refused('EXACT_PRIVACY_DISCLOSURE_REQUIRED')
        rect(nodes[0],'android.widget.TextView','false')
    nodes_by_id={}
    for suffix,text,klass in [('settings_button','Settings','android.widget.Button'),('ack_button','Got it','android.widget.Button'),('dropdown_element','','android.widget.LinearLayout')]:
        nodes=[e for e in tree.iter() if e.get('resource-id')==prefix+suffix]
        if len(nodes)!=1 or nodes[0].get('text','')!=text:raise Refused('UNIQUE_REVIEWED_PRIVACY_CONTROL_REQUIRED')
        nodes_by_id[suffix]=(nodes[0],rect(nodes[0],klass,'true'))
    labels=[e.get('text') or e.get('content-desc') for e in tree.iter() if e.get('package')==package and eligible[id(e)] and (e.get('text') or e.get('content-desc'))]
    if len(labels)!=8 or set(labels)!=set(REVIEWED_PRIVACY_TEXTS+['Settings','Got it']):raise Refused('UNREVIEWED_PRIVACY_NOTICE_TEXT_PRESENT')
    clicks=[e for e in tree.iter() if e.get('package')==package and eligible[id(e)] and e.get('clickable')=='true']
    if len(clicks)!=3 or {e.get('resource-id') for e in clicks}!={prefix+k for k in nodes_by_id}:raise Refused('UNREVIEWED_PRIVACY_NOTICE_CONTROLS_PRESENT')
    _,bounds=nodes_by_id['ack_button'];x0,y0,x1,y1=bounds;x=(x0+x1)//2;y=(y0+y1)//2
    if any(a<=x<b and c<=y<d for _,(a,c,b,d) in [v for k,v in nodes_by_id.items() if k!='ack_button']):raise Refused('PRIVACY_ACK_TARGET_OVERLAPPED')
    return {'x':x,'y':y,'bounds':bounds,'screen':[width,height],'resourceId':prefix+'ack_button','label':'Got it'}

def owned_lab_view_command():
    # Android's documented unqualified package argument restricts this VIEW intent.
    return shlex.join(['am','start','-W','-a','android.intent.action.VIEW','-d',OWNED_LAB_URL,'com.android.chrome'])

def observe_owned_lab_native_ui():
    start=time.monotonic();deadline=min(start+70,START+CAP);rows=[];STATE['ownedLabNativeObservations']=rows
    transient={'UI_DUMP_REPORTED_ERROR','UI_DUMP_SUCCESS_MARKER_REQUIRED','UI_XML_INVALID','OWN_COMMAND_FAILED_ui_dump','OWN_COMMAND_FAILED_ui_xml','OWN_COMMAND_TIMEOUT_ui_dump','OWN_COMMAND_TIMEOUT_ui_xml','OWN_COMMAND_TIMEOUT_screen_png','CHROME_SCREEN_OBSERVATION_DEADLINE'}
    for attempt in range(1,4):
        delay=start+(attempt-1)*20-time.monotonic()
        if delay>0:time.sleep(min(delay,max(0,deadline-time.monotonic())))
        if time.monotonic()>=deadline:break
        label='owned-v16-native-observation-'+str(attempt);row={'attempt':attempt,'label':label};rows.append(row)
        try:screen(label,observation_deadline=deadline)
        except Refused as error:
            if str(error) not in transient:raise
            row['status']='FRESH_XML_UNAVAILABLE';row['code']=str(error);save();continue
        data=(OUT/(label+'.xml')).read_bytes();tree=ET.fromstring(data)
        row['xmlFreshnessVerified']=True;row['xmlSHA256']=hashlib.sha256(data).hexdigest();row['pngSHA256']=hashlib.sha256((OUT/(label+'.png')).read_bytes()).hexdigest()
        row['packages']=sorted({e.get('package') for e in tree.iter() if e.get('package')})
        row['ownedHostVisibleInText']=any('comma-connect-fix-lab-20261016.zippy17.chatgpt.site' in (e.get('text','')+' '+e.get('content-desc','')) for e in tree.iter())
        row['scope']='Native UI observation only; URL/page readiness, helper pins and installed status require separate review.';save()
    STATE['ownedLabNativeObservationOutcome']='STOP_NATIVE_LAB_OBSERVATIONS_REQUIRE_REVIEW_NO_INSTALL_OR_AUDIO_VERDICT'

def continue_owned_lab_after_reviewed_privacy_notice(version_lines,observe_menu=False,add_home=False,install_option=False):
    # Optional owned-test continuation only; no Settings/dropdown/account/legal action.
    if add_home and not observe_menu or install_option and not add_home:raise Refused('ADD_HOME_REQUIRES_CURRENT_MENU_ACTION')
    view_command=owned_lab_view_command()
    fresh=fresh_input_snapshot('chrome-before-reviewed-privacy-ack');capture_start=fresh['captureStartMonotonic']
    xml=(OUT/(fresh['label']+'.xml')).read_bytes();png=(OUT/(fresh['label']+'.png')).read_bytes()
    target=privacy_notice_target(xml,png,version_lines);age=time.monotonic()-capture_start
    if not(0<=age<=10):raise Refused('PRIVACY_NOTICE_SNAPSHOT_TOO_OLD')
    STATE['privacyNoticeAcknowledgement']={'inputSnapshotLabel':fresh['label'],'explicitOwnedContinuationFlag':True,'attempts':1,'target':target,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'snapshotAgeUpperBoundSeconds':age,'actionScope':'Acknowledge exact reviewed notice; no Settings/dropdown/account interaction. No further agreement accepted.'}
    STATE['UIInputCommands']=STATE.get('UIInputCommands',0)+1;save()
    run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_reviewed_privacy_got_it',timeout=5)
    STATE['privacyNoticeAcknowledgement']['tapCommandCompleted']=True;STATE['ownedLabNavigation']={'action':'android.intent.action.VIEW','package':'com.android.chrome','url':OWNED_LAB_URL,'attempts':1};save()
    run([ADB,'-s',SERIAL,'shell',view_command],'navigate_owned_v16_with_action_view',timeout=15)
    STATE['ownedLabNavigation']['commandCompleted']=True
    if STATE.get('ownedFinalInstallRequested'):
        if not observe_known_owned_page(version_lines,'owned-v16-ready-for-menu'):
            STATE['status']='STOP_OWNED_PAGE_NOT_READY_NO_MENU_INPUT';save();return
    else:observe_owned_lab_native_ui()
    if install_option:open_owned_chrome_menu_and_observe(version_lines,add_home=True,install_option=True)
    elif add_home:open_owned_chrome_menu_and_observe(version_lines,add_home=True)
    elif observe_menu:open_owned_chrome_menu_and_observe(version_lines)
    else:STATE['status']='STOP_AFTER_OWNED_LAB_NATIVE_OBSERVATIONS_REQUIRES_REVIEW'

OWNED_MENU_OBSERVATION_FLAG='--observe-owned-v16-chrome-menu'
OWNED_CANONICAL_ADDRESS='comma-connect-fix-lab-20261016.zippy17.chatgpt.site/acced17acced1701/0000010a--a51155e496/1.001/3.999?candidate=v16&experiment=nqa'

def owned_chrome_menu_target(xml,png,version_lines):
    if {line.removeprefix('versionName=') for line in version_lines if line.startswith('versionName=')}!={'124.0.6367.219'}:raise Refused('REVIEWED_MENU_CHROME_VERSION_REQUIRED')
    if len(xml)>2*1024*1024 or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():raise Refused('OWNED_MENU_XML_INVALID')
    tree=ET.fromstring(xml);package='com.android.chrome';prefix=package+':id/'
    packages={e.get('package') for e in tree.iter() if e.get('package')}
    if package not in packages or not packages.issubset({package,'android','com.android.systemui'}):raise Refused('OWNED_MENU_FOREGROUND_REQUIRED')
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n' or png[12:16]!=b'IHDR':raise Refused('OWNED_MENU_SCREEN_DIMENSIONS_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big')
    if not(0<width<=16384 and 0<height<=16384):raise Refused('OWNED_MENU_SCREEN_DIMENSIONS_REQUIRED')
    eligible={}
    def walk(e,visible=True):
        visible=visible and e.get('enabled')!='false' and e.get('visible-to-user')!='false' and e.get('displayed')!='false';eligible[id(e)]=visible
        for child in e:walk(child,visible)
    walk(tree)
    def one(nodes,klass,clickable):
        if len(nodes)!=1:raise Refused('UNIQUE_OWNED_MENU_CONTEXT_NODE_REQUIRED')
        e=nodes[0]
        if not eligible[id(e)] or e.get('package')!=package or e.get('class')!=klass or e.get('enabled')!='true' or e.get('clickable')!=clickable:raise Refused('OWNED_MENU_CONTEXT_NODE_MISMATCH')
        m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
        if not m:raise Refused('OWNED_MENU_CONTEXT_BOUNDS_REQUIRED')
        r=list(map(int,m.groups()));x0,y0,x1,y1=r
        if not(0<=x0<x1<=width and 0<=y0<y1<=height):raise Refused('OWNED_MENU_CONTEXT_BOUNDS_REQUIRED')
        return e,r
    address,_=one([e for e in tree.iter() if e.get('resource-id')==prefix+'url_bar'],'android.widget.EditText','true')
    if address.get('text') not in [OWNED_CANONICAL_ADDRESS,'https://'+OWNED_CANONICAL_ADDRESS] or address.get('content-desc','')!='':raise Refused('EXACT_OWNED_CANONICAL_ADDRESS_REQUIRED')
    webview,web_rect=one([e for e in tree.iter() if e.get('class')=='android.webkit.WebView'],'android.webkit.WebView','false')
    if webview.get('text')!='Candidate native integrated · healthy':raise Refused('REVIEWED_OWNED_WEBVIEW_CONTEXT_REQUIRED')
    one([e for e in tree.iter() if e.get('text')=='V16 e7ab13f79d01'],'android.view.View','false')
    menu,r=one([e for e in tree.iter() if e.get('resource-id')==prefix+'menu_button'],'android.widget.ImageButton','true')
    if menu.get('text','')!='' or menu.get('content-desc')!='Customize and control Google Chrome':raise Refused('EXACT_NATIVE_CHROME_MENU_REQUIRED')
    x0,y0,x1,y1=r;x=(x0+x1)//2;y=(y0+y1)//2
    if web_rect[0]<=x<web_rect[2] and web_rect[1]<=y<web_rect[3]:raise Refused('CHROME_MENU_OVERLAPS_WEB_CONTENT')
    return {'x':x,'y':y,'bounds':r,'screen':[width,height],'resourceId':prefix+'menu_button','contentDescription':menu.get('content-desc'),'observedAddress':address.get('text'),'badge':'V16 e7ab13f79d01','webViewClass':webview.get('class'),'scope':'Native context only; badge is not a full byte-pin or installed-PWA proof.'}

def open_owned_chrome_menu_and_observe(version_lines,add_home=False,install_option=False):
    fresh=fresh_input_snapshot('owned-v16-before-native-chrome-menu');capture_start=fresh['captureStartMonotonic']
    xml=(OUT/(fresh['label']+'.xml')).read_bytes();png=(OUT/(fresh['label']+'.png')).read_bytes()
    target=owned_chrome_menu_target(xml,png,version_lines);age=time.monotonic()-capture_start
    if not(0<=age<=10):raise Refused('OWNED_MENU_SNAPSHOT_TOO_OLD')
    STATE['ownedChromeMenuInput']={'inputSnapshotLabel':fresh['label'],'explicitObservationFlag':True,'attempts':1,'target':target,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'snapshotAgeUpperBoundSeconds':age,'installOrAddHomeActions':0}
    STATE['UIInputCommands']=STATE.get('UIInputCommands',0)+1;save()
    run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_owned_native_chrome_menu',timeout=5)
    menu_action=STATE['ownedChromeMenuInput'];menu_action['tapCommandCompleted']=True;menu_action['tapCompletionBootSeconds']=time.monotonic()-START;save()
    start=time.monotonic();deadline=min(start+70,START+CAP);rows=[];STATE['ownedChromeMenuObservations']=rows
    transient={'UI_DUMP_REPORTED_ERROR','UI_DUMP_SUCCESS_MARKER_REQUIRED','UI_XML_INVALID','OWN_COMMAND_FAILED_ui_dump','OWN_COMMAND_FAILED_ui_xml','OWN_COMMAND_TIMEOUT_ui_dump','OWN_COMMAND_TIMEOUT_ui_xml','OWN_COMMAND_TIMEOUT_screen_png','CHROME_SCREEN_OBSERVATION_DEADLINE'}
    for attempt in range(1,4):
        delay=start+(attempt-1)*20-time.monotonic()
        if delay>0:time.sleep(min(delay,max(0,deadline-time.monotonic())))
        if time.monotonic()>=deadline:break
        label='owned-v16-native-chrome-menu-'+str(attempt);row={'attempt':attempt,'label':label};rows.append(row)
        try:screen(label,observation_deadline=deadline)
        except Refused as error:
            if str(error) not in transient:raise
            row['status']='FRESH_XML_UNAVAILABLE';row['code']=str(error);save();continue
        row['xmlFreshnessVerified']=True;row['xmlSHA256']=hashlib.sha256((OUT/(label+'.xml')).read_bytes()).hexdigest();row['pngSHA256']=hashlib.sha256((OUT/(label+'.png')).read_bytes()).hexdigest();save()
        if add_home:break  # Separate fresh-input capture still guards the row; default keeps all3frames.
    if add_home:
        if install_option:tap_owned_add_home_and_observe(version_lines,menu_action,install_option=True)
        else:tap_owned_add_home_and_observe(version_lines,menu_action)
        return
    STATE['ownedChromeMenuOutcome']='OBSERVATIONS_REQUIRE_REVIEW_NO_POPUP_ROW_OR_INSTALL_VERDICT'
    STATE['status']='STOP_AFTER_CHROME_MENU_OBSERVATIONS_REQUIRES_REVIEW'

OWNED_ADD_HOME_FLAG='--observe-owned-v16-add-home-dialog'

def verified_current_menu_action(version_lines,proof,expected_inputs=4):
    if not isinstance(proof,dict) or proof is not STATE.get('ownedChromeMenuInput') or proof.get('tapCommandCompleted') is not True or proof.get('attempts')!=1 or STATE.get('UIInputCommands')!=expected_inputs:raise Refused('CURRENT_OWN_MENU_ACTION_REQUIRED')
    age=time.monotonic()-START-proof.get('tapCompletionBootSeconds',float('-inf'))
    if not(0<=age<=90):raise Refused('OWN_MENU_ACTION_PROOF_EXPIRED')
    nav=STATE.get('ownedLabNavigation',{})
    if nav.get('url')!=OWNED_LAB_URL or nav.get('commandCompleted') is not True:raise Refused('OWNED_CURRENT_NAVIGATION_PROOF_REQUIRED')
    label=proof.get('inputSnapshotLabel','')
    if not re.fullmatch(r'owned-v16-before-native-chrome-menu-input-attempt-[1-3]',label):raise Refused('CURRENT_MENU_SNAPSHOT_LABEL_REQUIRED')
    try:xml=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
    except OSError:raise Refused('CURRENT_MENU_CONTEXT_BYTES_REQUIRED')
    if hashlib.sha256(xml).hexdigest()!=proof.get('xmlSHA256') or hashlib.sha256(png).hexdigest()!=proof.get('pngSHA256') or owned_chrome_menu_target(xml,png,version_lines)!=proof.get('target'):raise Refused('CURRENT_MENU_CONTEXT_PIN_MISMATCH')

def add_home_popup_target(xml,png,version_lines):
    if {line.removeprefix('versionName=') for line in version_lines if line.startswith('versionName=')}!={'124.0.6367.219'}:raise Refused('REVIEWED_ADD_HOME_CHROME_VERSION_REQUIRED')
    if len(xml)>2*1024*1024 or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():raise Refused('ADD_HOME_XML_INVALID')
    tree=ET.fromstring(xml);package='com.android.chrome';prefix=package+':id/';parents={id(c):e for e in tree.iter() for c in e}
    packages={e.get('package') for e in tree.iter() if e.get('package')}
    if package not in packages or not packages.issubset({package,'android','com.android.systemui'}):raise Refused('ADD_HOME_POPUP_FOREGROUND_REQUIRED')
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n' or png[12:16]!=b'IHDR':raise Refused('ADD_HOME_SCREEN_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big')
    if not(0<width<=16384 and 0<height<=16384):raise Refused('ADD_HOME_SCREEN_REQUIRED')
    nodes=[e for e in tree.iter() if e.get('text')=='Add to Home screen']
    if len(nodes)!=1:raise Refused('UNIQUE_REVIEWED_ADD_HOME_LABEL_REQUIRED')
    text=nodes[0];row=parents.get(id(text));listing=parents.get(id(row))
    if row is None or listing is None:raise Refused('EXACT_REVIEWED_ADD_HOME_HIERARCHY_REQUIRED')
    for e in [text,row,listing]:
        ancestor=e
        while ancestor is not None:
            if ancestor.get('enabled')=='false' or ancestor.get('visible-to-user')=='false' or ancestor.get('displayed')=='false':raise Refused('ADD_HOME_NODE_HIDDEN_OR_DISABLED')
            ancestor=parents.get(id(ancestor))
    def rect(e,suffix,klass,clickable):
        if e.get('resource-id')!=prefix+suffix or e.get('package')!=package or e.get('class')!=klass or e.get('enabled')!='true' or e.get('clickable')!=clickable or e.get('content-desc','')!='':raise Refused('REVIEWED_ADD_HOME_NODE_MISMATCH')
        m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
        if not m:raise Refused('ADD_HOME_BOUNDS_REQUIRED')
        r=list(map(int,m.groups()));x0,y0,x1,y1=r
        if not(0<=x0<x1<=width and 0<=y0<y1<=height):raise Refused('ADD_HOME_BOUNDS_REQUIRED')
        return r
    tr=rect(text,'menu_item_text','android.widget.TextView','false');rr=rect(row,'universal_install','android.widget.LinearLayout','true');lr=rect(listing,'app_menu_list','android.widget.ListView','false')
    if len([e for e in tree.iter() if e.get('resource-id')==prefix+'universal_install'])!=1 or len([e for e in tree.iter() if e.get('resource-id')==prefix+'app_menu_list'])!=1:raise Refused('UNIQUE_ADD_HOME_ROW_AND_LIST_REQUIRED')
    if not(rr[0]<=tr[0]<tr[2]<=rr[2] and rr[1]<=tr[1]<tr[3]<=rr[3] and lr[0]<=rr[0]<rr[2]<=lr[2] and lr[1]<=rr[1]<rr[3]<=lr[3]):raise Refused('ADD_HOME_HIERARCHY_BOUNDS_MISMATCH')
    if any(e.get('clickable')=='true' for e in row.iter() if e is not row):raise Refused('ADD_HOME_UNREVIEWED_NESTED_CLICK_TARGET')
    return {'x':(tr[0]+tr[2])//2,'y':(tr[1]+tr[3])//2,'textBounds':tr,'rowBounds':rr,'screen':[width,height],'label':'Add to Home screen','textResourceId':prefix+'menu_item_text','clickableAncestorResourceId':prefix+'universal_install','listResourceId':prefix+'app_menu_list'}

def tap_owned_add_home_and_observe(version_lines,menu_action,install_option=False):
    verified_current_menu_action(version_lines,menu_action)
    fresh=fresh_input_snapshot('owned-v16-before-add-home');xml=(OUT/(fresh['label']+'.xml')).read_bytes();png=(OUT/(fresh['label']+'.png')).read_bytes()
    target=add_home_popup_target(xml,png,version_lines);verified_current_menu_action(version_lines,menu_action);age=time.monotonic()-fresh['captureStartMonotonic']
    if not(0<=age<=10):raise Refused('ADD_HOME_INPUT_SNAPSHOT_TOO_OLD')
    STATE['ownedAddHomeInput']={'inputSnapshotLabel':fresh['label'],'attempts':1,'target':target,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'snapshotAgeUpperBoundSeconds':age,'menuActionSnapshotLabel':menu_action['inputSnapshotLabel'],'finalConfirmationActions':0};STATE['UIInputCommands']+=1;save()
    run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_owned_add_home_menu_row',timeout=5)
    add_action=STATE['ownedAddHomeInput'];add_action['tapCommandCompleted']=True;add_action['tapCompletionBootSeconds']=time.monotonic()-START;save()
    start=time.monotonic();deadline=min(start+70,START+CAP);rows=[];STATE['ownedAddHomeDialogObservations']=rows
    transient={'UI_DUMP_REPORTED_ERROR','UI_DUMP_SUCCESS_MARKER_REQUIRED','UI_XML_INVALID','OWN_COMMAND_FAILED_ui_dump','OWN_COMMAND_FAILED_ui_xml','OWN_COMMAND_TIMEOUT_ui_dump','OWN_COMMAND_TIMEOUT_ui_xml','OWN_COMMAND_TIMEOUT_screen_png','CHROME_SCREEN_OBSERVATION_DEADLINE'}
    for attempt in range(1,4):
        delay=start+(attempt-1)*20-time.monotonic()
        if delay>0:time.sleep(min(delay,max(0,deadline-time.monotonic())))
        if time.monotonic()>=deadline:break
        label='owned-v16-add-home-dialog-'+str(attempt);entry={'attempt':attempt,'label':label};rows.append(entry)
        try:screen(label,observation_deadline=deadline)
        except Refused as error:
            if str(error) not in transient:raise
            entry['status']='FRESH_XML_UNAVAILABLE';entry['code']=str(error);save();continue
        entry['xmlFreshnessVerified']=True;entry['xmlSHA256']=hashlib.sha256((OUT/(label+'.xml')).read_bytes()).hexdigest();entry['pngSHA256']=hashlib.sha256((OUT/(label+'.png')).read_bytes()).hexdigest();save()
        if install_option:break
    if install_option:
        tap_owned_install_option_and_observe(version_lines,add_action);return
    STATE['status']='STOP_AFTER_ADD_HOME_DIALOG_OBSERVATIONS_NO_CONFIRMATION';STATE['ownedAddHomeOutcome']='DIALOG_REQUIRES_REVIEW_NO_INSTALLED_PWA_VERDICT'

OWNED_INSTALL_OPTION_FLAG='--observe-owned-v16-install-option-dialog'

def verified_current_add_home_action(version_lines,proof,expected_inputs=5):
    if not isinstance(proof,dict) or proof is not STATE.get('ownedAddHomeInput') or proof.get('tapCommandCompleted') is not True or proof.get('attempts')!=1 or STATE.get('UIInputCommands')!=expected_inputs:raise Refused('CURRENT_OWN_ADD_HOME_ACTION_REQUIRED')
    age=time.monotonic()-START-proof.get('tapCompletionBootSeconds',float('-inf'))
    if not(0<=age<=90):raise Refused('OWN_ADD_HOME_ACTION_PROOF_EXPIRED')
    verified_current_menu_action(version_lines,STATE.get('ownedChromeMenuInput'),expected_inputs=expected_inputs)
    label=proof.get('inputSnapshotLabel','')
    if not re.fullmatch(r'owned-v16-before-add-home-input-attempt-[1-3]',label) or proof.get('menuActionSnapshotLabel')!=STATE['ownedChromeMenuInput']['inputSnapshotLabel']:raise Refused('CURRENT_ADD_HOME_SNAPSHOT_LABEL_REQUIRED')
    try:xml=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
    except OSError:raise Refused('CURRENT_ADD_HOME_CONTEXT_BYTES_REQUIRED')
    if hashlib.sha256(xml).hexdigest()!=proof.get('xmlSHA256') or hashlib.sha256(png).hexdigest()!=proof.get('pngSHA256') or add_home_popup_target(xml,png,version_lines)!=proof.get('target'):raise Refused('CURRENT_ADD_HOME_CONTEXT_PIN_MISMATCH')

def install_option_target(xml,png,version_lines):
    if {v.removeprefix('versionName=') for v in version_lines if v.startswith('versionName=')}!={'124.0.6367.219'}:raise Refused('REVIEWED_INSTALL_OPTION_VERSION_REQUIRED')
    if len(xml)>2*1024*1024 or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():raise Refused('INSTALL_OPTION_XML_INVALID')
    tree=ET.fromstring(xml);package='com.android.chrome';prefix=package+':id/';parents={id(c):e for e in tree.iter() for c in e}
    packages={e.get('package') for e in tree.iter() if e.get('package')}
    if package not in packages or not packages.issubset({package,'android','com.android.systemui'}):raise Refused('INSTALL_OPTION_FOREGROUND_REQUIRED')
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n' or png[12:16]!=b'IHDR':raise Refused('INSTALL_OPTION_SCREEN_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big')
    if not(0<width<=16384 and 0<height<=16384):raise Refused('INSTALL_OPTION_SCREEN_REQUIRED')
    def one(suffix):
        nodes=[e for e in tree.iter() if e.get('resource-id')==prefix+suffix]
        if len(nodes)!=1:raise Refused('UNIQUE_INSTALL_OPTION_NODE_REQUIRED')
        return nodes[0]
    def rect(e,klass,clickable):
        if e is None:raise Refused('INSTALL_OPTION_HIERARCHY_REQUIRED')
        a=e
        while a is not None:
            if a.get('enabled')=='false' or a.get('visible-to-user')=='false' or a.get('displayed')=='false':raise Refused('INSTALL_OPTION_HIDDEN_OR_DISABLED')
            a=parents.get(id(a))
        if e.get('package')!=package or e.get('class')!=klass or e.get('enabled')!='true' or e.get('clickable')!=clickable:raise Refused('INSTALL_OPTION_NODE_MISMATCH')
        m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
        if not m:raise Refused('INSTALL_OPTION_BOUNDS_REQUIRED')
        r=list(map(int,m.groups()));a,b,c,d=r
        if not(0<=a<c<=width and 0<=b<d<=height):raise Refused('INSTALL_OPTION_BOUNDS_REQUIRED')
        return r
    address=one('url_bar');rect(address,'android.widget.EditText','true')
    if address.get('text') not in [OWNED_CANONICAL_ADDRESS,'https://'+OWNED_CANONICAL_ADDRESS]:raise Refused('INSTALL_OPTION_OWN_CANONICAL_ADDRESS_REQUIRED')
    sheet=one('bottom_sheet');sr=rect(sheet,'android.widget.FrameLayout','false')
    if sheet.get('content-desc')!='Choose how to add the app to the home screen. Swipe down to close.':raise Refused('REVIEWED_INSTALL_OPTION_SHEET_REQUIRED')
    content=one('bottom_sheet_content');rect(content,'android.widget.FrameLayout','false')
    if parents.get(id(content)) is not sheet:raise Refused('INSTALL_OPTION_HIERARCHY_REQUIRED')
    title=one('title');rect(title,'android.widget.TextView','false')
    if title.get('text')!='Add to home screen' or title not in set(sheet.iter()):raise Refused('INSTALL_OPTION_TITLE_REQUIRED')
    labels=[e.get('text') for e in sheet.iter() if e.get('text')]
    if len(labels)!=4 or set(labels)!={'Add to home screen','Install','Create shortcut','Shortcuts open in Chrome'}:raise Refused('UNREVIEWED_INSTALL_OPTION_TEXT_PRESENT')
    visible_labels=[e.get('text') for e in tree.iter() if e.get('package')==package and e.get('text')]
    if len(visible_labels)!=5 or set(visible_labels)!={'Add to home screen','Install','Create shortcut','Shortcuts open in Chrome',address.get('text')}:raise Refused('UNREVIEWED_INSTALL_OPTION_GLOBAL_TEXT')
    text=one('option_text_install');tr=rect(text,'android.widget.TextView','false')
    if text.get('text')!='Install':raise Refused('EXACT_INSTALL_OPTION_LABEL_REQUIRED')
    inner=parents.get(id(text));rect(inner,'android.widget.LinearLayout','false')
    row=one('option_install');rr=rect(row,'android.widget.LinearLayout','true');wrapper=parents.get(id(row));rect(wrapper,'android.widget.LinearLayout','false')
    if inner.get('resource-id','')!='' or wrapper.get('resource-id','')!='' or parents.get(id(inner)) is not row or parents.get(id(wrapper)) is not content:raise Refused('INSTALL_OPTION_HIERARCHY_REQUIRED')
    if not(rr[0]<=tr[0]<tr[2]<=rr[2] and rr[1]<=tr[1]<tr[3]<=rr[3] and sr[0]<=rr[0]<rr[2]<=sr[2] and sr[1]<=rr[1]<rr[3]<=sr[3]):raise Refused('INSTALL_OPTION_NESTED_BOUNDS_REQUIRED')
    x=(tr[0]+tr[2])//2;y=(tr[1]+tr[3])//2
    for child in row.iter():
        if child is not row and child.get('clickable')=='true':
            r=rect(child,'android.widget.ImageView','true')
            if child.get('resource-id')!=prefix+'arrow_install' or r[0]<=x<r[2] and r[1]<=y<r[3]:raise Refused('INSTALL_OPTION_TARGET_OVERLAPPED')
    return {'x':x,'y':y,'textBounds':tr,'rowBounds':rr,'screen':[width,height],'label':'Install','resourceId':prefix+'option_text_install','clickableAncestorResourceId':prefix+'option_install','ownedAddress':address.get('text'),'scope':'Observed option only; next dialog unknown and no final confirmation.'}

def tap_owned_install_option_and_observe(version_lines,add_action):
    verified_current_add_home_action(version_lines,add_action);fresh=fresh_input_snapshot('owned-v16-before-install-option')
    xml=(OUT/(fresh['label']+'.xml')).read_bytes();png=(OUT/(fresh['label']+'.png')).read_bytes();target=install_option_target(xml,png,version_lines);verified_current_add_home_action(version_lines,add_action);age=time.monotonic()-fresh['captureStartMonotonic']
    if not(0<=age<=10):raise Refused('INSTALL_OPTION_INPUT_SNAPSHOT_TOO_OLD')
    STATE['ownedInstallOptionInput']={'inputSnapshotLabel':fresh['label'],'attempts':1,'target':target,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'snapshotAgeUpperBoundSeconds':age,'addHomeActionSnapshotLabel':add_action['inputSnapshotLabel'],'finalConfirmationActions':0};STATE['UIInputCommands']+=1;save()
    run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_owned_install_option',timeout=5)
    option_action=STATE['ownedInstallOptionInput'];option_action['tapCommandCompleted']=True;option_action['tapCompletionBootSeconds']=time.monotonic()-START;save()
    start=time.monotonic();deadline=min(start+70,START+CAP);rows=[];STATE['ownedInstallOptionDialogObservations']=rows;known_final_dialog=False
    transient={'UI_DUMP_REPORTED_ERROR','UI_DUMP_SUCCESS_MARKER_REQUIRED','UI_XML_INVALID','OWN_COMMAND_FAILED_ui_dump','OWN_COMMAND_FAILED_ui_xml','OWN_COMMAND_TIMEOUT_ui_dump','OWN_COMMAND_TIMEOUT_ui_xml','OWN_COMMAND_TIMEOUT_screen_png','CHROME_SCREEN_OBSERVATION_DEADLINE'}
    for attempt in range(1,4):
        delay=start+(attempt-1)*20-time.monotonic()
        if delay>0:time.sleep(min(delay,max(0,deadline-time.monotonic())))
        if time.monotonic()>=deadline:break
        label='owned-v16-install-option-dialog-'+str(attempt);entry={'attempt':attempt,'label':label};rows.append(entry)
        try:screen(label,observation_deadline=deadline)
        except Refused as error:
            if str(error) not in transient:raise
            entry['status']='FRESH_XML_UNAVAILABLE';entry['code']=str(error);save();continue
        entry['xmlFreshnessVerified']=True;entry['xmlSHA256']=hashlib.sha256((OUT/(label+'.xml')).read_bytes()).hexdigest();entry['pngSHA256']=hashlib.sha256((OUT/(label+'.png')).read_bytes()).hexdigest();save()
        if STATE.get('ownedFinalInstallRequested'):
            try:final_install_target((OUT/(label+'.xml')).read_bytes(),(OUT/(label+'.png')).read_bytes(),version_lines)
            except Refused as error:entry['nextContextRefusal']=str(error);save();continue
            known_final_dialog=True;break
    if STATE.get('ownedFinalInstallRequested'):
        if not known_final_dialog:
            STATE['status']='STOP_FINAL_INSTALL_DIALOG_NOT_RECOGNIZED_NO_CONFIRMATION';save();return
        confirm_owned_install_and_observe(version_lines,option_action);return
    STATE['status']='STOP_AFTER_INSTALL_OPTION_DIALOG_OBSERVATIONS_NO_CONFIRMATION';STATE['ownedInstallOptionOutcome']='NEXT_DIALOG_REQUIRES_REVIEW_NO_INSTALLED_PWA_VERDICT'

OWNED_CONFIRM_INSTALL_FLAG='--confirm-owned-v16-install-and-observe'
OWNED_MANIFEST_NAME='Connect V16 Audio Lab'
OWNED_MANIFEST_SHORT_NAME='V16 Audio Lab'
OWNED_ORIGIN='comma-connect-fix-lab-20261016.zippy17.chatgpt.site'

def verified_current_install_option_action(version_lines,proof):
    if not isinstance(proof,dict) or proof is not STATE.get('ownedInstallOptionInput') or proof.get('tapCommandCompleted') is not True or proof.get('attempts')!=1 or STATE.get('UIInputCommands')!=6:raise Refused('CURRENT_OWN_INSTALL_OPTION_ACTION_REQUIRED')
    if not(0<=time.monotonic()-START-proof.get('tapCompletionBootSeconds',float('-inf'))<=90):raise Refused('OWN_INSTALL_OPTION_PROOF_EXPIRED')
    verified_current_add_home_action(version_lines,STATE.get('ownedAddHomeInput'),expected_inputs=6)
    label=proof.get('inputSnapshotLabel','')
    if not re.fullmatch(r'owned-v16-before-install-option-input-attempt-[1-3]',label):raise Refused('CURRENT_INSTALL_OPTION_SNAPSHOT_REQUIRED')
    xml=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
    if hashlib.sha256(xml).hexdigest()!=proof.get('xmlSHA256') or hashlib.sha256(png).hexdigest()!=proof.get('pngSHA256') or install_option_target(xml,png,version_lines)!=proof.get('target'):raise Refused('OWN_INSTALL_OPTION_CONTEXT_PIN_MISMATCH')

def final_install_target(xml,png,version_lines):
    if {v.removeprefix('versionName=') for v in version_lines if v.startswith('versionName=')}!={'124.0.6367.219'}:raise Refused('REVIEWED_FINAL_INSTALL_VERSION_REQUIRED')
    if len(xml)>2*1024*1024 or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():raise Refused('FINAL_INSTALL_XML_INVALID')
    tree=ET.fromstring(xml);package='com.android.chrome';prefix=package+':id/';parents={id(c):e for e in tree.iter() for c in e}
    packages={e.get('package') for e in tree.iter() if e.get('package')}
    if package not in packages or not packages.issubset({package,'android','com.android.systemui'}):raise Refused('FINAL_INSTALL_FOREGROUND_REQUIRED')
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n' or png[12:16]!=b'IHDR':raise Refused('FINAL_INSTALL_SCREEN_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big')
    if not(0<width<=16384 and 0<height<=16384):raise Refused('FINAL_INSTALL_SCREEN_REQUIRED')
    def one(suffix,klass,clickable,text=None):
        nodes=[e for e in tree.iter() if e.get('resource-id')==prefix+suffix]
        if len(nodes)!=1:raise Refused('UNIQUE_FINAL_INSTALL_NODE_REQUIRED')
        e=nodes[0];a=e
        while a is not None:
            if a.get('enabled')=='false' or a.get('visible-to-user')=='false' or a.get('displayed')=='false':raise Refused('FINAL_INSTALL_HIDDEN_OR_DISABLED')
            a=parents.get(id(a))
        if e.get('package')!=package or e.get('class')!=klass or e.get('enabled')!='true' or e.get('clickable')!=clickable or text is not None and e.get('text')!=text:raise Refused('FINAL_INSTALL_CONTEXT_NODE_MISMATCH')
        m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
        if not m:raise Refused('FINAL_INSTALL_BOUNDS_REQUIRED')
        r=list(map(int,m.groups()));x0,y0,x1,y1=r
        if not(0<=x0<x1<=width and 0<=y0<y1<=height):raise Refused('FINAL_INSTALL_BOUNDS_REQUIRED')
        return e,r
    address,_=one('url_bar','android.widget.EditText','true')
    if address.get('text') not in [OWNED_CANONICAL_ADDRESS,'https://'+OWNED_CANONICAL_ADDRESS]:raise Refused('FINAL_INSTALL_OWN_ADDRESS_REQUIRED')
    container,_=one('tab_modal_dialog_container','android.widget.FrameLayout','true');dialog,dr=one('modal_dialog_view','android.widget.LinearLayout','false')
    if parents.get(id(dialog)) is not container:raise Refused('FINAL_INSTALL_DIALOG_HIERARCHY_REQUIRED')
    title,_=one('title','android.widget.TextView','false','Install app');name,_=one('app_name','android.widget.TextView','true',OWNED_MANIFEST_NAME);origin,_=one('origin','android.widget.TextView','false',OWNED_ORIGIN)
    bar,_=one('button_bar','android.view.ViewGroup','false');cancel,_=one('negative_button','android.widget.Button','true','Cancel');install,r=one('positive_button','android.widget.Button','true','Install')
    if parents.get(id(bar)) is not dialog or parents.get(id(cancel)) is not bar or parents.get(id(install)) is not bar or not all(e in set(dialog.iter()) for e in [title,name,origin]):raise Refused('FINAL_INSTALL_DIALOG_HIERARCHY_REQUIRED')
    labels=[e.get('text') for e in tree.iter() if e.get('package')==package and e.get('text')]
    if len(labels)!=6 or set(labels)!={address.get('text'),'Install app',OWNED_MANIFEST_NAME,OWNED_ORIGIN,'Cancel','Install'}:raise Refused('UNREVIEWED_FINAL_INSTALL_TEXT')
    x0,y0,x1,y1=r
    if not(dr[0]<=x0<x1<=dr[2] and dr[1]<=y0<y1<=dr[3]):raise Refused('FINAL_INSTALL_NESTED_BOUNDS_REQUIRED')
    x=(x0+x1)//2;y=(y0+y1)//2;ancestors=set();a=install
    while a is not None:ancestors.add(id(a));a=parents.get(id(a))
    for e in tree.iter():
        if id(e) in ancestors or e.get('clickable')!='true':continue
        m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
        if not m:raise Refused('FINAL_INSTALL_OTHER_CONTROL_BOUNDS_REQUIRED')
        a,b,c,d=map(int,m.groups())
        if a<=x<c and b<=y<d:raise Refused('FINAL_INSTALL_TARGET_OVERLAPPED')
    return {'x':x,'y':y,'bounds':r,'screen':[width,height],'resourceId':prefix+'positive_button','title':'Install app','name':OWNED_MANIFEST_NAME,'origin':OWNED_ORIGIN,'label':'Install'}

def known_owned_chrome_without_dialog(xml,png,version_lines):
    owned_chrome_menu_target(xml,png,version_lines)
    tree=ET.fromstring(xml);webviews=[e for e in tree.iter() if e.get('class')=='android.webkit.WebView']
    webnodes={id(e) for v in webviews for e in v.iter()}
    for e in tree.iter():
        if e.get('resource-id') in ['com.android.chrome:id/tab_modal_dialog_container','com.android.chrome:id/bottom_sheet']:raise Refused('UNKNOWN_NATIVE_OVERLAY_NO_HOME_INPUT')
        if e.get('package')=='com.android.chrome' and id(e) not in webnodes and e.get('text') and e.get('text') not in [OWNED_CANONICAL_ADDRESS,'https://'+OWNED_CANONICAL_ADDRESS]:raise Refused('UNKNOWN_NATIVE_TEXT_NO_HOME_INPUT')

def owned_pwa_launcher_target(xml,png):
    # Same observed Nexus launcher contract as the original Chrome icon; manifest labels only.
    if len(xml)>2*1024*1024 or b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():raise Refused('OWNED_PWA_ICON_XML_INVALID')
    tree=ET.fromstring(xml);package='com.google.android.apps.nexuslauncher';names={OWNED_MANIFEST_NAME,OWNED_MANIFEST_SHORT_NAME}
    packages={e.get('package') for e in tree.iter() if e.get('package')}
    if package not in packages or not packages.issubset({package,'android','com.android.systemui'}):raise Refused('EXACT_OWNED_PWA_LAUNCHER_REQUIRED')
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n' or png[12:16]!=b'IHDR':raise Refused('OWNED_PWA_ICON_SCREEN_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big');candidates=[]
    if not(0<width<=16384 and 0<height<=16384):raise Refused('OWNED_PWA_ICON_SCREEN_REQUIRED')
    def walk(e,eligible=True):
        eligible=eligible and e.get('enabled')!='false' and e.get('visible-to-user')!='false' and e.get('displayed')!='false'
        if e.get('package')==package and e.get('text') in names and e.get('content-desc') in names:
            if not eligible or e.get('enabled')!='true' or e.get('clickable')!='true' or e.get('class')!='android.widget.TextView':raise Refused('OWNED_PWA_ICON_NOT_ELIGIBLE')
            m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
            if not m:raise Refused('OWNED_PWA_ICON_BOUNDS_REQUIRED')
            r=list(map(int,m.groups()));a,b,c,d=r
            if not(0<=a<c<=width and 0<=b<d<=height):raise Refused('OWNED_PWA_ICON_BOUNDS_REQUIRED')
            candidates.append({'x':(a+c)//2,'y':(b+d)//2,'bounds':r,'name':e.get('text'),'description':e.get('content-desc'),'screen':[width,height]})
        for child in e:walk(child,eligible)
    walk(tree)
    if len(candidates)!=1:raise Refused('UNIQUE_OBSERVED_OWNED_PWA_ICON_REQUIRED')
    return candidates[0]

def retained_fresh_input(label):
    fresh=fresh_input_snapshot(label);xml=(OUT/(fresh['label']+'.xml')).read_bytes();png=(OUT/(fresh['label']+'.png')).read_bytes()
    return fresh,xml,png

def input_age(fresh):
    age=time.monotonic()-fresh['captureStartMonotonic']
    if not(0<=age<=10):raise Refused('OWNED_INSTALL_CONTINUATION_SNAPSHOT_TOO_OLD')
    return age

def observe_known_owned_page(version_lines,phase):
    began=time.monotonic();deadline=min(began+70,START+CAP);rows=[];STATE.setdefault('knownOwnedPageObservations',{})[phase]=rows
    for attempt in range(1,4):
        delay=began+(attempt-1)*20-time.monotonic()
        if delay>0:time.sleep(min(delay,max(0,deadline-time.monotonic())))
        if time.monotonic()>=deadline:break
        label=phase+'-'+str(attempt);entry={'label':label};rows.append(entry)
        try:
            screen(label,observation_deadline=deadline);xml=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
            entry.update(xmlSHA256=hashlib.sha256(xml).hexdigest(),pngSHA256=hashlib.sha256(png).hexdigest());known_owned_chrome_without_dialog(xml,png,version_lines)
        except Refused as error:entry['readinessCode']=str(error);save();continue
        entry['knownOwnedContext']=True;save();return True
    save();return False

def confirm_owned_install_and_observe(version_lines,option_action):
    verified_current_install_option_action(version_lines,option_action);native_package_presence('before-final-install');begin_native_install_diagnostic_window();fresh,xml,png=retained_fresh_input('owned-v16-before-final-install')
    target=final_install_target(xml,png,version_lines);verified_current_install_option_action(version_lines,option_action);age=input_age(fresh)
    STATE['ownedFinalInstallInput']={'inputSnapshotLabel':fresh['label'],'attempts':1,'target':target,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'snapshotAgeUpperBoundSeconds':age,'optionSnapshotLabel':option_action['inputSnapshotLabel'],'outcome':'DISPATCH_ONLY_NO_INSTALLED_VERDICT'};STATE['UIInputCommands']+=1;save()
    run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_owned_final_install',timeout=5)
    STATE['ownedFinalInstallInput']['tapCommandCompleted']=True;STATE['ownedFinalInstallInput']['completedInputOrdinal']=STATE['UIInputCommands'];save()
    start=time.monotonic();deadline=min(start+70,START+CAP);rows=[];STATE['ownedFinalInstallObservations']=rows
    for attempt in range(1,4):
        delay=start+(attempt-1)*20-time.monotonic()
        if delay>0:time.sleep(min(delay,max(0,deadline-time.monotonic())))
        if time.monotonic()>=deadline:break
        label='owned-v16-after-final-install-'+str(attempt);row={'attempt':attempt,'label':label};rows.append(row)
        try:screen(label,observation_deadline=deadline)
        except Refused as error:row['readinessCode']=str(error);save();continue
        current_xml=(OUT/(label+'.xml')).read_bytes();current_png=(OUT/(label+'.png')).read_bytes();row.update(xmlSHA256=hashlib.sha256(current_xml).hexdigest(),pngSHA256=hashlib.sha256(current_png).hexdigest());save()
        try:
            if observed_placement_marker(current_xml):
                nexus_placement_target(current_xml,current_png,version_lines);kind='OBSERVED_EXACT_NATIVE_PLACEMENT'
            else:
                known_owned_chrome_without_dialog(current_xml,current_png,version_lines);row['knownChromeObserved']=True;save()
                # Chrome reappearing is not installation completion; retain the existing0/20/40s readonly slots.
                if attempt<3 or time.monotonic()-start<40:continue
                kind='FINITE_CHROME_OBSERVATION_NO_COMPLETION_VERDICT'
        except (Refused,ET.ParseError)as error:
            row['readinessCode']=str(error)if isinstance(error,Refused)else'POST_INSTALL_XML_INVALID';STATE['status']='STOP_UNKNOWN_POST_INSTALL_NATIVE_CONTEXT_NO_HOME_INPUT';save();return
        row['readinessKind']=kind;STATE['ownedPostInstallReadiness']={'kind':kind,'label':label,'xmlSHA256':row['xmlSHA256'],'pngSHA256':row['pngSHA256'],'observationAttempt':attempt,'elapsedSinceFinalDispatchSeconds':time.monotonic()-start,'finalInstallSnapshotLabel':STATE['ownedFinalInstallInput']['inputSnapshotLabel'],'completedInputOrdinal':7,'scope':'Exact placement or finite readonly Chrome observation only; no install/placement completion is inferred.'};save()
        launch_observed_owned_pwa(version_lines);return
    STATE['status']='STOP_POST_INSTALL_UNKNOWN_NO_HOME_INPUT';save()

def verified_post_install_readiness(version_lines):
    proof=STATE.get('ownedPostInstallReadiness',{});kind=proof.get('kind');label=proof.get('label','');attempt=proof.get('observationAttempt');elapsed=proof.get('elapsedSinceFinalDispatchSeconds')
    if proof.get('finalInstallSnapshotLabel')!=STATE.get('ownedFinalInstallInput',{}).get('inputSnapshotLabel')or proof.get('completedInputOrdinal')!=7 or type(attempt)is not int or attempt not in [1,2,3]or label!='owned-v16-after-final-install-'+str(attempt):raise Refused('CURRENT_POST_INSTALL_READINESS_REQUIRED')
    xml=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
    if hashlib.sha256(xml).hexdigest()!=proof.get('xmlSHA256')or hashlib.sha256(png).hexdigest()!=proof.get('pngSHA256'):raise Refused('POST_INSTALL_READINESS_PIN_MISMATCH')
    if kind=='OBSERVED_EXACT_NATIVE_PLACEMENT':nexus_placement_target(xml,png,version_lines);return kind
    if kind=='FINITE_CHROME_OBSERVATION_NO_COMPLETION_VERDICT':
        if attempt!=3 or type(elapsed)not in[int,float]or not 40<=elapsed<=70:raise Refused('FINITE_POST_INSTALL_CHROME_WINDOW_REQUIRED')
        known_owned_chrome_without_dialog(xml,png,version_lines);return kind
    raise Refused('UNKNOWN_POST_INSTALL_READINESS_NO_HOME_INPUT')


def observed_bodyless_chrome_after_placement(xml,png,version_lines):
    # Exact actual39122783965 native-only state: permits a readonly retry, NEVER input.
    if {line.removeprefix('versionName=')for line in version_lines if line.startswith('versionName=')}!={'124.0.6367.219'}:return False
    if len(xml)>2*1024*1024 or b'<!DOCTYPE'in xml.upper()or b'<!ENTITY'in xml.upper():return False
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n'or png[12:16]!=b'IHDR'or [int.from_bytes(png[16:20],'big'),int.from_bytes(png[20:24],'big')]!=[1080,2400]:return False
    try:tree=ET.fromstring(xml)
    except ET.ParseError:return False
    def shape(e):return [e.tag,dict(e.attrib),[shape(c)for c in e]]
    canonical=json.dumps(shape(tree),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    return hashlib.sha256(canonical).hexdigest()=='4b1420738880857e758ea6db1c695e10f7dba46e2bca78529ac207c37224715d'

def post_placement_ready_snapshot(version_lines):
    start=time.monotonic();deadline=min(start+30,START+CAP);rows=[];STATE['postPlacementContextReadiness']={'deadlineBootSeconds':deadline-START,'attempts':rows,'inputRetries':0};save()
    transient={'UI_DUMP_REPORTED_ERROR','UI_DUMP_SUCCESS_MARKER_REQUIRED','UI_XML_INVALID','OWN_COMMAND_FAILED_ui_dump','OWN_COMMAND_FAILED_ui_xml','OWN_COMMAND_TIMEOUT_ui_dump','OWN_COMMAND_TIMEOUT_ui_xml','OWN_COMMAND_TIMEOUT_screen_png','CHROME_SCREEN_OBSERVATION_DEADLINE'}
    for attempt in range(1,4):
        began=time.monotonic()
        if began>=deadline:break
        label='owned-v16-after-owned-placement-input-attempt-'+str(attempt);row={'attempt':attempt,'label':label,'captureStartBootSeconds':began-START};rows.append(row);save()
        try:packages=screen(label,observation_deadline=deadline)
        except Refused as error:
            if str(error)not in transient:raise
            row.update(status='FRESH_XML_UNAVAILABLE',code=str(error));save();continue
        complete=time.monotonic()
        if complete<began or complete>=deadline:row['status']='READINESS_DEADLINE_CROSSED';save();raise Refused('POST_PLACEMENT_READINESS_DEADLINE')
        row.update(captureCompleteBootSeconds=complete-START,ageAtCompletionSeconds=complete-began)
        if complete-began>10:row['status']='FRESH_BUT_AGED_OUT_NO_INPUT';save();continue
        xml=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes();row.update(xmlSHA256=hashlib.sha256(xml).hexdigest(),pngSHA256=hashlib.sha256(png).hexdigest())
        try:
            if observed_home_workspace(xml):launcher_workspace_context(xml,png);kind='ORIGINAL_KNOWN_HOME_READY'
            else:known_owned_chrome_without_dialog(xml,png,version_lines);kind='ORIGINAL_FULL_CHROME_CONTEXT_READY'
        except Refused as error:
            if not observed_bodyless_chrome_after_placement(xml,png,version_lines):row.update(status='UNKNOWN_CONTEXT_NO_MORE_READS_OR_INPUT',code=str(error));save();raise
            row.update(status='EXACT_OBSERVED_BODYLESS_CHROME_READONLY_WAIT',code=str(error));save();continue
        row['status']=kind;STATE['postPlacementContextReadiness']['successfulLabel']=label;save()
        return {'label':label,'captureStartMonotonic':began,'captureCompleteMonotonic':complete,'packages':packages},xml,png
    STATE['postPlacementContextReadiness']['status']='EXHAUSTED_NO_HOME_INPUT';save();raise Refused('POST_PLACEMENT_CONTEXT_READINESS_EXHAUSTED')

def launch_observed_owned_pwa(version_lines):
    if STATE.get('UIInputCommands')!=7 or not STATE.get('ownedFinalInstallInput',{}).get('tapCommandCompleted'):raise Refused('CURRENT_OWN_FINAL_INSTALL_REQUIRED')
    verified_final_install_context(version_lines);readiness_kind=verified_post_install_readiness(version_lines)
    fresh,xml,png=retained_fresh_input('owned-v16-before-home-after-install')
    if readiness_kind=='OBSERVED_EXACT_NATIVE_PLACEMENT'and not observed_placement_marker(xml):raise Refused('OBSERVED_PLACEMENT_DISAPPEARED_WITHOUT_OWN_ACTION_NO_HOME')
    if observed_placement_marker(xml):
        target=nexus_placement_target(xml,png,version_lines);age=input_age(fresh)
        placement={'inputSnapshotLabel':fresh['label'],'snapshotAgeUpperBoundSeconds':age,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'target':target,'attempts':1,'inputOrdinalBefore':7,'inputOrdinal':8,'tapCommandCompleted':False,'finalInstallSnapshotLabel':STATE['ownedFinalInstallInput']['inputSnapshotLabel']};STATE['ownedPWAPlacementInput']=placement;STATE['UIInputCommands']+=1;save();input_age(fresh)
        run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_owned_pwa_placement',timeout=5)
        placement['tapCommandCompleted']=True;save();fresh,xml,png=post_placement_ready_snapshot(version_lines)
        if observed_home_workspace(xml):
            launcher_workspace_context(xml,png);age=input_age(fresh)
            STATE['ownedHomeAfterInstallInput']={'kind':'OBSERVED_HOME_AFTER_PLACEMENT_NO_KEY','transitionCompleted':True,'inputSnapshotLabel':fresh['label'],'snapshotAgeUpperBoundSeconds':age,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'keyCode':None,'tapCommandCompleted':False,'completedInputOrdinal':STATE['UIInputCommands']};save()
        else:dispatch_known_home_key(fresh,xml,png,version_lines)
    else:dispatch_known_home_key(fresh,xml,png,version_lines)
    native_package_presence('after-home')
    try:fresh,xml,png,target=find_observed_pwa_on_launcher()
    except Refused:
        native_package_presence('after-page-search');retain_post_install_error_categories();raise
    age=input_age(fresh)
    STATE['ownedPWAIconInput']={'inputSnapshotLabel':fresh['label'],'target':target,'snapshotAgeUpperBoundSeconds':age,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'manifestLabels':[OWNED_MANIFEST_NAME,OWNED_MANIFEST_SHORT_NAME],'inputOrdinalBefore':STATE['UIInputCommands'],'pageSearchCount':len(STATE.get('ownedPWAPageSearchInputs',[]))};STATE['UIInputCommands']+=1;save()
    run([ADB,'-s',SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'tap_observed_owned_pwa_icon',timeout=5)
    STATE['ownedPWAIconInput']['tapCommandCompleted']=True;STATE['ownedPWAIconInput']['completedInputOrdinal']=STATE['UIInputCommands'];save()
    native_package_presence('after-page-search')
    # No further native input; actual page/socket schema is observed below, never assumed.
    screen('owned-v16-after-installed-icon',observation_deadline=min(time.monotonic()+30,START+CAP))
    STATE['status']='STOP_OWNED_ICON_LAUNCHED_STANDALONE_NOT_YET_PROVED';save()
    observe_installed_pwa_readonly()
    audio_acquire.acquire(sys.modules[__name__])

def observe_installed_pwa_readonly():
    if OWNED_MANIFEST_NAME!='Connect V16 Audio Lab':
        STATE['readonlyInstalledObservation']={'status':'V15_REFERENCE_ONLY_USE_SEPARATE_V16_SUCCESSOR'};save();return
    verified_current_icon_launch()
    emulators=[r for r in STATE.get('children',[]) if r.get('kind')=='emulator' and r.get('startTicks') and process_ticks(r['pid'])==r['startTicks']]
    if len(emulators)!=1 or not STATE.get('ownedADBServerStarted'):raise Refused('CURRENT_OWNED_EMULATOR_ADB_BINDING_REQUIRED')
    if remaining(60)<60:
        STATE['readonlyInstalledObservation']={'status':'NO_NEW_CDP_READ_INSUFFICIENT_ORIGINAL_CAP'};save();return
    import importlib.util,shutil
    here=Path(__file__).resolve().parent;bridge=here/'readonly_bridge_v16.py';reader=here/'read_dom_v16.mjs'
    if hashlib.sha256(bridge.read_bytes()).hexdigest()!='b82f1cc19465fa492d596b97a89a8e0ed27c485789116f410521e4766ca8144e' or hashlib.sha256(reader.read_bytes()).hexdigest()!='d5a6139345fa5df962ca8690842bf0f07d99304ecb474c1ab8ce25866f8153e3':raise Refused('PINNED_READONLY_OBSERVER_REQUIRED')
    node=shutil.which('node')
    if not node:raise Refused('EXISTING_NODE_REQUIRED_NO_INSTALL')
    spec=importlib.util.spec_from_file_location('owned_readonly_v16',bridge);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    count=[0]
    def adb(args):
        count[0]+=1
        data,_,cut=run([ADB]+args,'owned_readonly_adb_'+str(count[0]),timeout=5,limit=1024*1024,retain_stdout=False)
        if cut:raise Refused('READONLY_ADB_BODY_LIMIT')
        return data
    def http(port,path):remaining(3);return module.local_http_get(port,path)
    def evaluate(endpoint):
        data,_,cut=run([node,str(reader),endpoint],'owned_fixed_readonly_dom',timeout=12,limit=32*1024*1024,retain_stdout=False)
        if cut:raise Refused('READONLY_DOM_BODY_LIMIT')
        return data
    listener_guard()
    result=module.observe_owned_pwa(adb,http,evaluate,OUT/'installed-readonly-v16',owned_vm_guard=True,require_carrier=False)
    STATE['readonlyInstalledObservation']=result
    STATE['installedPWAStandaloneObserved']=result.get('status')=='CURRENT_DOCUMENT_OBSERVATION_RETAINED_NO_CARRIER' and result.get('cleanupVerified') is True
    STATE['status']='STOP_AFTER_ACTUAL_INSTALLED_READONLY_OBSERVATION_NO_AUDIO_VERDICT';save()


def selected_phase_cap(argv):
    final=[CHROME_TERMS_APPROVAL_FLAG,OWNED_LAB_CONTINUATION_FLAG,OWNED_MENU_OBSERVATION_FLAG,OWNED_ADD_HOME_FLAG,OWNED_INSTALL_OPTION_FLAG,OWNED_CONFIRM_INSTALL_FLAG]
    if OWNED_CONFIRM_INSTALL_FLAG in argv and argv!=final:raise Refused('FINAL_MODE_EXACT_FLAG_SEQUENCE_REQUIRED')
    return 480 if argv==final else 360

def native_package_presence(phase):
    if phase not in ['before-final-install','after-home','after-page-search']:raise Refused('EXACT_NATIVE_PACKAGE_DIAGNOSTIC_PHASE_REQUIRED')
    row={'phase':phase,'atBootSeconds':time.monotonic()-START,'scope':'Native package presence only; no assumed manifest/app mapping or installed-PWA verdict.'};STATE.setdefault('nativePackagePresence',[]).append(row)
    try:
        raw,code,cut=run([ADB,'-s',SERIAL,'shell','pm','list','packages'],'native_packages_'+phase,timeout=3,limit=1024*1024,allowed_failure=True,retain_stdout=False)
        if code or cut:row.update(status='NOT_ACQUIRED',reasonCode='COMMAND_EXIT_OR_TRUNCATED',exitCode=code,truncated=cut)
        else:
            lines=[line for line in raw.decode('ascii').splitlines() if line]
            if not lines:raise ValueError('EMPTY_PACKAGE_LIST')
            if any(line!='package:android'and not re.fullmatch(r'package:[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+',line) for line in lines):raise ValueError('PACKAGE_SCHEMA_UNKNOWN')
            names=sorted(line.removeprefix('package:') for line in lines)
            selected=[name for name in names if name=='com.android.chrome' or name.startswith('org.chromium.webapk.')]
            if len(selected)>128:raise ValueError('PACKAGE_LIMIT')
            row.update(status='OBSERVED',chromePresent='com.android.chrome'in selected,observedWebAPKPackages=[name for name in selected if name.startswith('org.chromium.webapk.')],packageListSHA256=hashlib.sha256(raw).hexdigest())
    except Refused:row.update(status='NOT_ACQUIRED_BOUNDED_READONLY_DIAGNOSTIC',reasonCode='BOUNDED_READONLY_COMMAND_REFUSED')
    except UnicodeError:row.update(status='NOT_ACQUIRED_BOUNDED_READONLY_DIAGNOSTIC',reasonCode='PACKAGE_ASCII_SCHEMA_UNKNOWN')
    except ValueError as error:row.update(status='NOT_ACQUIRED_BOUNDED_READONLY_DIAGNOSTIC',reasonCode=str(error)if str(error)in ['EMPTY_PACKAGE_LIST','PACKAGE_SCHEMA_UNKNOWN','PACKAGE_LIMIT']else'BOUNDED_READONLY_COMMAND_REFUSED')
    save()

def observed_launcher_foreground(xml):
    if len(xml)>2*1024*1024 or b'<!DOCTYPE'in xml.upper()or b'<!ENTITY'in xml.upper():raise Refused('WORKSPACE_XML_INVALID')
    tree=ET.fromstring(xml);package='com.google.android.apps.nexuslauncher'
    if {e.get('package')for e in tree.iter()if e.get('package')}!={package}:raise Refused('SOLE_OBSERVED_NEXUS_FOREGROUND_REQUIRED')
    forbidden={'parentPanel','alertTitle','permission_message','tab_modal_dialog_container','bottom_sheet'}
    if any(e.get('resource-id','').rsplit('/',1)[-1]in forbidden for e in tree.iter()):raise Refused('UNKNOWN_NATIVE_MODAL_NO_LAUNCHER_INPUT')
    return tree

def launcher_workspace_context(xml,png):
    if len(xml)>2*1024*1024 or b'<!DOCTYPE'in xml.upper()or b'<!ENTITY'in xml.upper():raise Refused('WORKSPACE_XML_INVALID')
    tree=observed_launcher_foreground(xml);package='com.google.android.apps.nexuslauncher';prefix=package+':id/';parents={id(c):e for e in tree.iter() for c in e}
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n'or png[12:16]!=b'IHDR':raise Refused('WORKSPACE_SCREEN_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big')
    if not(0<width<=16384 and 0<height<=16384):raise Refused('WORKSPACE_SCREEN_REQUIRED')
    def rect(e):
        m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
        if not m:raise Refused('WORKSPACE_BOUNDS_REQUIRED')
        r=list(map(int,m.groups()));a,b,c,d=r
        if not(0<=a<c<=width and 0<=b<d<=height):raise Refused('WORKSPACE_POSITIVE_BOUNDS_REQUIRED')
        return r
    def eligible(e):
        a=e
        while a is not None:
            if a.get('enabled')=='false'or a.get('visible-to-user')=='false'or a.get('displayed')=='false':return False
            a=parents.get(id(a))
        return e.get('enabled')=='true'
    nodes=[e for e in tree.iter() if e.get('resource-id')==prefix+'workspace']
    if len(nodes)!=1:raise Refused('UNIQUE_OBSERVED_WORKSPACE_REQUIRED')
    workspace=nodes[0];wr=rect(workspace)
    if workspace.get('class')!='android.widget.ScrollView'or workspace.get('clickable')!='false'or not eligible(workspace):raise Refused('OBSERVED_WORKSPACE_CLASS_REQUIRED')
    children=list(workspace)
    if len(children)!=1 or children[0].get('class')!='android.view.ViewGroup'or children[0].get('package')!=package or children[0].get('clickable')!='false'or not eligible(children[0]):raise Refused('OBSERVED_WORKSPACE_CHILD_REQUIRED')
    child=children[0];cr=rect(child)
    if not(wr[0]<=cr[0]<cr[2]<=wr[2]and wr[1]<=cr[1]<cr[3]<=wr[3]):raise Refused('WORKSPACE_VIEWPORT_NESTING_REQUIRED')
    signature=hashlib.sha256(json.dumps([{k:e.get(k,'') for k in ['class','resource-id','text','content-desc','bounds','clickable','enabled','scrollable','visible-to-user','displayed']}for e in child.iter()],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    ignored=set();a=child
    while a is not None:ignored.add(id(a));a=parents.get(id(a))
    blockers=[]
    for e in tree.iter():
        if id(e)in ignored or not eligible(e)or e.get('clickable')!='true'and e.get('long-clickable')!='true':continue
        if e.get('bounds')=='[0,0][0,0]':continue  # Offscreen nodes cannot receive this on-screen path.
        blockers.append(rect(e))
    names={OWNED_MANIFEST_NAME,OWNED_MANIFEST_SHORT_NAME};count=sum(e.get('package')==package and e.get('text')in names and e.get('content-desc')in names for e in tree.iter())
    return {'workspaceBounds':wr,'viewportBounds':cr,'screen':[width,height],'scrollable':workspace.get('scrollable')=='true','signature':signature,'blockerRects':blockers,'matchingManifestIconNodes':count}

def launcher_left_swipe_target(xml,png):
    context=launcher_workspace_context(xml,png);a,b,c,d=context['viewportBounds']
    if not context['scrollable']or c-a<200 or d-b<200:raise Refused('FRESH_SCROLLABLE_WORKSPACE_REQUIRED')
    left=a+(c-a)//5;right=c-(c-a)//5
    for numerator,denominator in [(1,2),(3,5),(2,5)]:
        y=b+(d-b)*numerator//denominator
        if not any(x0<=right and x1>=left and y0<=y<y1 for x0,y0,x1,y1 in context['blockerRects']):
            return {'from':[right,y],'to':[left,y],'durationMs':300,'workspaceBounds':context['workspaceBounds'],'viewportBounds':context['viewportBounds'],'screen':context['screen'],'signature':context['signature'],'scope':'Observed empty horizontal workspace band; no assumed page number or icon position.'}
    raise Refused('NO_CLEAR_NATIVE_WORKSPACE_GESTURE_BAND')

def find_observed_pwa_on_launcher():
    base=verified_home_transition(STATE.get('androidChromeVersionLines',[]))
    if STATE.get('UIInputCommands')!=base:raise Refused('CURRENT_COMPLETED_OWN_HOME_REQUIRED')
    rows=[];STATE['ownedPWAPageSearchInputs']=rows;previous=None
    for page in range(3):
        label='owned-v16-before-installed-icon'+('-page-'+str(page)if page else '')
        fresh,xml,png=retained_fresh_input(label)
        for settled_read in range(2):
            observed_launcher_foreground(xml)
            try:target=owned_pwa_launcher_target(xml,png);return fresh,xml,png,target
            except Refused as error:
                if str(error)!='UNIQUE_OBSERVED_OWNED_PWA_ICON_REQUIRED':raise
            context=launcher_workspace_context(xml,png)
            if context['matchingManifestIconNodes']:raise Refused('AMBIGUOUS_OWN_PWA_ICON_NO_PAGE_GESTURE')
            if previous is None or context['signature']!=previous:break
            if settled_read:raise Refused('WORKSPACE_UNCHANGED_AFTER_ONE_GESTURE_NO_REPEAT')
            fresh,xml,png=retained_fresh_input(label+'-settled')  # One extra readonly transition observation.
        if page==2:raise Refused('OWN_PWA_ICON_ABSENT_AFTER_TWO_BOUNDED_PAGE_GESTURES')
        target=launcher_left_swipe_target(xml,png);age=input_age(fresh)
        row={'inputSnapshotLabel':fresh['label'],'target':target,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'snapshotAgeUpperBoundSeconds':age,'attempts':1,'inputOrdinal':STATE['UIInputCommands']+1,'tapCommandCompleted':False};rows.append(row);STATE['UIInputCommands']+=1;save()
        run([ADB,'-s',SERIAL,'shell','input','swipe',*[str(v)for v in target['from']+target['to']],str(target['durationMs'])],'owned_workspace_left_'+str(page+1),timeout=5)
        row['tapCommandCompleted']=True;row['completionBootSeconds']=time.monotonic()-START;save();previous=target['signature']
    raise Refused('BOUNDED_OWN_PWA_ICON_SEARCH_EXHAUSTED')

def verified_current_icon_launch():
    icon=STATE.get('ownedPWAIconInput',{});rows=STATE.get('ownedPWAPageSearchInputs',[]);base=verified_home_transition(STATE.get('androidChromeVersionLines',[]))
    if not isinstance(rows,list)or len(rows)>2:raise Refused('CURRENT_OWN_HOME_AND_BOUNDED_SEARCH_REQUIRED')
    expected=base+1+len(rows)
    if STATE.get('UIInputCommands')!=expected or icon.get('tapCommandCompleted')is not True or icon.get('completedInputOrdinal')!=expected or icon.get('inputOrdinalBefore')!=expected-1 or icon.get('pageSearchCount')!=len(rows):raise Refused('CURRENT_NATIVE_OWNED_ICON_LAUNCH_REQUIRED')
    for index,row in enumerate(rows):
        if row.get('inputOrdinal')!=base+1+index or row.get('attempts')!=1 or row.get('tapCommandCompleted')is not True:raise Refused('CURRENT_WORKSPACE_INPUT_CHAIN_REQUIRED')
        label=row.get('inputSnapshotLabel','')
        if not re.fullmatch(r'owned-v16-before-installed-icon(?:-page-[1-2])?(?:-settled)?-input-attempt-[1-3]',label):raise Refused('OWNED_WORKSPACE_CONTEXT_LABEL_REQUIRED')
        xml=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
        if hashlib.sha256(xml).hexdigest()!=row.get('xmlSHA256')or hashlib.sha256(png).hexdigest()!=row.get('pngSHA256')or launcher_left_swipe_target(xml,png)!=row.get('target'):raise Refused('OWNED_WORKSPACE_CONTEXT_PIN_MISMATCH')
    label=icon.get('inputSnapshotLabel','')
    if not re.fullmatch(r'owned-v16-before-installed-icon(?:-page-[1-2])?(?:-settled)?-input-attempt-[1-3]',label):raise Refused('OWNED_ICON_CONTEXT_LABEL_REQUIRED')
    xml=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
    observed_launcher_foreground(xml)
    if hashlib.sha256(xml).hexdigest()!=icon.get('xmlSHA256')or hashlib.sha256(png).hexdigest()!=icon.get('pngSHA256')or owned_pwa_launcher_target(xml,png)!=icon.get('target'):raise Refused('OWNED_ICON_CONTEXT_PIN_MISMATCH')



def observed_placement_marker(xml):
    if len(xml)>2*1024*1024 or b'<!DOCTYPE'in xml.upper()or b'<!ENTITY'in xml.upper():raise Refused('PLACEMENT_XML_INVALID')
    return any(e.get('resource-id')=='com.google.android.apps.nexuslauncher:id/add_item_drag_layer'for e in ET.fromstring(xml).iter())

def observed_home_workspace(xml):
    return any(e.get('resource-id')=='com.google.android.apps.nexuslauncher:id/workspace'for e in ET.fromstring(xml).iter())

def nexus_placement_target(xml,png,version_lines):
    if {line.removeprefix('versionName=')for line in version_lines if line.startswith('versionName=')}!={'124.0.6367.219'}:raise Refused('EXACT_PLACEMENT_CHROME_VERSION_REQUIRED')
    tree=observed_launcher_foreground(xml);package='com.google.android.apps.nexuslauncher';prefix=package+':id/';nodes=list(tree.iter());parents={c:p for p in nodes for c in p}
    if len(png)<24 or png[:8]!=b'\x89PNG\r\n\x1a\n'or png[12:16]!=b'IHDR':raise Refused('PLACEMENT_SCREEN_REQUIRED')
    width=int.from_bytes(png[16:20],'big');height=int.from_bytes(png[20:24],'big')
    if not(0<width<=16384 and 0<height<=16384):raise Refused('PLACEMENT_SCREEN_REQUIRED')
    def rect(e):
        m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',e.get('bounds',''))
        if not m:raise Refused('PLACEMENT_BOUNDS_REQUIRED')
        a,b,c,d=map(int,m.groups())
        if not(0<=a<c<=width and 0<=b<d<=height):raise Refused('PLACEMENT_POSITIVE_BOUNDS_REQUIRED')
        return [a,b,c,d]
    def one(rid,kind,text=None,desc=None,clickable='false'):
        matches=[e for e in nodes if e.get('resource-id')==prefix+rid]
        if len(matches)!=1:raise Refused('UNIQUE_PLACEMENT_CONTEXT_REQUIRED')
        e=matches[0];a=e
        while a is not None:
            if a.get('enabled')=='false'or a.get('visible-to-user')=='false'or a.get('displayed')=='false':raise Refused('PLACEMENT_CONTEXT_INELIGIBLE')
            a=parents.get(a)
        if e.get('package')!=package or e.get('enabled')!='true'or e.get('class')!=kind or e.get('clickable')!=clickable or text is not None and e.get('text')!=text or desc is not None and e.get('content-desc')!=desc:raise Refused('EXACT_PLACEMENT_CONTEXT_REQUIRED')
        rect(e);return e
    layer=one('add_item_drag_layer','android.widget.FrameLayout');sheet=one('add_item_bottom_sheet_content','android.widget.LinearLayout')
    if parents.get(sheet)is not layer:raise Refused('PLACEMENT_SHEET_PARENT_REQUIRED')
    app=one('widget_appName','android.widget.TextView','Chrome');instruction='Touch & hold the widget to move it around the home screen';hint=one('widget_drag_instruction','android.widget.TextView',instruction)
    cell=one('widget_cell','com.android.launcher3.widget.WidgetCell',desc=OWNED_MANIFEST_SHORT_NAME+' widget, 1 wide by 1 high');name=one('widget_name','android.widget.TextView',OWNED_MANIFEST_SHORT_NAME);dims=one('widget_dims','android.widget.TextView','1 × 1');actions=one('actions_container','android.widget.LinearLayout')
    if any(e not in set(sheet.iter())for e in [app,hint,cell,name,dims,actions])or name not in set(cell.iter())or dims not in set(cell.iter())or parents.get(actions)is not sheet:raise Refused('PLACEMENT_CONTEXT_HIERARCHY_REQUIRED')
    allowed={'Chrome',instruction,OWNED_MANIFEST_SHORT_NAME,'1 × 1','Cancel','Add to home screen'}
    if any(e.get('text','')and e.get('text')not in allowed for e in nodes)or any(e.get('content-desc','')and e is not cell for e in nodes):raise Refused('UNKNOWN_PLACEMENT_TEXT')
    buttons=list(actions)
    if len(buttons)!=2 or {e.get('text')for e in buttons}!={'Cancel','Add to home screen'}:raise Refused('EXACT_PLACEMENT_ACTION_PAIR_REQUIRED')
    for button in buttons:
        if button.get('package')!=package or button.get('class')!='android.widget.Button'or button.get('enabled')!='true'or button.get('visible-to-user')=='false'or button.get('displayed')=='false'or button.get('clickable')!='true'or button.get('resource-id','')!=''or button.get('content-desc','')!='':raise Refused('EXACT_PLACEMENT_BUTTON_REQUIRED')
        rect(button)
    if [e for e in nodes if e.get('clickable')=='true']!=buttons:raise Refused('UNKNOWN_PLACEMENT_INPUT_CONTROL')
    target=next(e for e in buttons if e.get('text')=='Add to home screen');r=rect(target);x=(r[0]+r[2])//2;y=(r[1]+r[3])//2;family=set();a=target
    while a is not None:family.add(a);a=parents.get(a)
    for e in nodes:
        if e in family or list(e):continue
        b=rect(e)
        if b[0]<=x<b[2]and b[1]<=y<b[3]:raise Refused('PLACEMENT_TARGET_OCCLUDED')
    return {'x':x,'y':y,'bounds':r,'screen':[width,height],'label':'Add to home screen','package':package,'manifestShortName':OWNED_MANIFEST_SHORT_NAME,'widgetDescription':cell.get('content-desc'),'scope':'Exact actual native Nexus own-PWA placement confirmation; no drag, account or agreement input.'}

def retained_context(proof,pattern):
    label=proof.get('inputSnapshotLabel','')
    if not re.fullmatch(pattern,label):raise Refused('RETAINED_CURRENT_CONTEXT_LABEL_REQUIRED')
    xml=(OUT/(label+'.xml')).read_bytes();png=(OUT/(label+'.png')).read_bytes()
    if hashlib.sha256(xml).hexdigest()!=proof.get('xmlSHA256')or hashlib.sha256(png).hexdigest()!=proof.get('pngSHA256'):raise Refused('RETAINED_CURRENT_CONTEXT_PIN_MISMATCH')
    return xml,png

def verified_final_install_context(version_lines):
    final=STATE.get('ownedFinalInstallInput',{})
    if final.get('tapCommandCompleted')is not True or final.get('completedInputOrdinal')!=7:raise Refused('CURRENT_FINAL_INSTALL_PROVENANCE_REQUIRED')
    xml,png=retained_context(final,r'owned-v16-before-final-install-input-attempt-[1-3]')
    if final_install_target(xml,png,version_lines)!=final.get('target'):raise Refused('OWNED_FINAL_INSTALL_CONTEXT_TARGET_MISMATCH')

def dispatch_known_home_key(fresh,xml,png,version_lines):
    known_owned_chrome_without_dialog(xml,png,version_lines);age=input_age(fresh)
    STATE['ownedHomeAfterInstallInput']={'kind':'NATIVE_HOME_KEY','transitionCompleted':False,'inputSnapshotLabel':fresh['label'],'snapshotAgeUpperBoundSeconds':age,'xmlSHA256':hashlib.sha256(xml).hexdigest(),'pngSHA256':hashlib.sha256(png).hexdigest(),'keyCode':3,'tapCommandCompleted':False};STATE['UIInputCommands']+=1;save();input_age(fresh)
    run([ADB,'-s',SERIAL,'shell','input','keyevent','3'],'home_after_owned_install',timeout=5)
    STATE['ownedHomeAfterInstallInput'].update(transitionCompleted=True,tapCommandCompleted=True,completedInputOrdinal=STATE['UIInputCommands']);save()

def verified_home_transition(version_lines):
    verified_final_install_context(version_lines);home=STATE.get('ownedHomeAfterInstallInput',{});placement=STATE.get('ownedPWAPlacementInput');extra=0
    if placement is not None:
        if placement.get('tapCommandCompleted')is not True or placement.get('attempts')!=1 or placement.get('inputOrdinalBefore')!=7 or placement.get('inputOrdinal')!=8 or placement.get('finalInstallSnapshotLabel')!=STATE['ownedFinalInstallInput']['inputSnapshotLabel']:raise Refused('CURRENT_OWN_PLACEMENT_PROVENANCE_REQUIRED')
        xml,png=retained_context(placement,r'owned-v16-before-home-after-install-input-attempt-[1-3]')
        if nexus_placement_target(xml,png,version_lines)!=placement.get('target'):raise Refused('OWN_PLACEMENT_CONTEXT_TARGET_MISMATCH')
        extra=1
    if home.get('transitionCompleted')is not True:raise Refused('CURRENT_HOME_TRANSITION_REQUIRED')
    if home.get('kind')=='NATIVE_HOME_KEY':
        if home.get('keyCode')!=3 or home.get('tapCommandCompleted')is not True or home.get('completedInputOrdinal')!=8+extra:raise Refused('CURRENT_NATIVE_HOME_KEY_PROVENANCE_REQUIRED')
        pattern=r'owned-v16-after-owned-placement-input-attempt-[1-3]'if extra else r'owned-v16-before-home-after-install-input-attempt-[1-3]'
        xml,png=retained_context(home,pattern);known_owned_chrome_without_dialog(xml,png,version_lines);return 8+extra
    if home.get('kind')=='OBSERVED_HOME_AFTER_PLACEMENT_NO_KEY':
        if not extra or home.get('keyCode')is not None or home.get('tapCommandCompleted')is not False or home.get('completedInputOrdinal')!=8:raise Refused('CURRENT_OBSERVED_HOME_PLACEMENT_REQUIRED')
        xml,png=retained_context(home,r'owned-v16-after-owned-placement-input-attempt-[1-3]');launcher_workspace_context(xml,png);return 8
    raise Refused('UNKNOWN_HOME_TRANSITION_NO_ICON_INPUT')

def begin_native_install_diagnostic_window():
    try:
        raw,code,cut=run([ADB,'-s',SERIAL,'shell','date','+%s'],'native_install_epoch_anchor',timeout=3,limit=128,allowed_failure=True,retain_stdout=False)
        if code or cut or not re.fullmatch(rb'[1-9]\d{8,12}\s*',raw):raise ValueError('EPOCH_NOT_ACQUIRED')
        STATE['nativeInstallDiagnosticWindow']={'deviceEpochSecondsBeforeFinalInputSnapshot':int(raw),'scope':'Read before final fresh snapshot, not an exact tap timestamp; no device clock changes.'}
    except (Refused,ValueError):STATE['nativeInstallDiagnosticWindow']={'status':'NO_NATIVE_TIME_ANCHOR'}
    save()

def webapk_install_error_categories(text,start_epoch):
    parsed=[]
    for line in text.splitlines():
        m=re.match(r'^\s*(\d{9,13}(?:\.\d+)?)\s',line)
        if m and float(m.group(1))>=start_epoch:parsed.append(line)
    related=[line for line in parsed if re.search(r'webapk|web.?app.*(?:install|packag)',line,re.I)]
    return {'parsedLinesSinceAnchor':len(parsed),'webAPKRelatedLines':len(related),'webAPKInstallOrDownloadError':sum(bool(re.search(r'(?:install|update|download|fetch|request).{0,120}(?:fail|error|reject|timeout)|(?:fail|error|reject|timeout).{0,120}(?:install|download|fetch)',line,re.I))for line in related),'webAPKNetworkError':sum(bool(re.search(r'net::ERR_|HTTP.{0,20}[45]\d\d|network.{0,80}(?:fail|error)|connection.{0,80}(?:fail|refused|timeout)',line,re.I))for line in related),'packageManagerFailureNotNecessarilyThisApp':sum(bool(re.search(r'INSTALL_(?:FAILED|PARSE_FAILED)_[A-Z_]+',line))for line in parsed)}

def retain_post_install_error_categories():
    row={'atBootSeconds':time.monotonic()-START,'rawLogcatRetained':False,'tailAtMostLines':300,'scope':'Post-own-Install bounded native log tail, filtered after pre-input device-time anchor; categories are not causal verdicts or proof installation failed.'};STATE['postInstallNativeErrorCategories']=row
    anchor=STATE.get('nativeInstallDiagnosticWindow',{}).get('deviceEpochSecondsBeforeFinalInputSnapshot')
    if type(anchor)is not int:row['status']='NOT_ACQUIRED_NO_NATIVE_TIME_ANCHOR';save();return
    try:
        raw,code,cut=run([ADB,'-s',SERIAL,'logcat','-d','-t','300','-v','epoch'],'post_install_native_categories',timeout=3,limit=65536,allowed_failure=True,retain_stdout=False)
        row.update(exitCode=code,tailByteLimited=cut)
        if code:row['status']='NOT_ACQUIRED'
        else:
            categories=webapk_install_error_categories(raw.decode(errors='replace'),anchor)
            row.update(status='BOUNDED_POST_INSTALL_CATEGORIES_OBSERVED' if categories['parsedLinesSinceAnchor'] else 'NO_PARSEABLE_POST_INPUT_ROWS_IN_BOUNDED_TAIL',deviceEpochStart=anchor,categories=categories,rawTailBytes=len(raw),rawTailSHA256=hashlib.sha256(raw).hexdigest())
    except Refused:row['status']='NOT_ACQUIRED_BOUNDED_READONLY_FAILURE'
    save()


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

def selected_audio_phase_cap(argv):
    if argv==['--cleanup']:return 900
    if len(argv)!=7 or argv.count('--explicit-v16-audio')!=1:raise Refused('EXACT_EXPLICIT_AUDIO_PLUS_SIX_FLAGS_REQUIRED')
    original=[arg for arg in argv if arg!='--explicit-v16-audio']
    if selected_phase_cap(original)!=480:raise Refused('EXACT_REVIEWED_INSTALL_SEQUENCE_REQUIRED')
    return 900

def main():
    global STATE,TRACE,CAP
    OUT.mkdir(parents=True,exist_ok=True)
    if '--cleanup' in sys.argv and sys.argv[1:]!=['--cleanup']:raise Refused('EXACT_CLEANUP_ONLY_REQUIRED')
    if '--cleanup' in sys.argv:
        if (OUT/'receipt.json').exists():
            STATE=json.loads((OUT/'receipt.json').read_text());TRACE=STATE.get('trace',[]);cleanup()
        return 0
    for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,lambda *_:(_ for _ in ()).throw(Refused('OWN_PROCESS_INTERRUPTED')))
    save()
    try:
        CAP=selected_audio_phase_cap(sys.argv[1:]);STATE['phaseCapSeconds']=CAP;STATE['phaseCapScope']='EXPLICIT_AUDIO_900_WORK_820_CLEANUP_80';save()
        installed=json.loads(Path('evidence/android-stable-setup/post-install.json').read_text())
        if installed.get('status')!='PASS_INSTALLED_EXACT_STABLE_BINDINGS':raise Refused('INSTALLED_STABLE_BINDING_REQUIRED')
        if os.uname().sysname!='Linux' or os.uname().machine!='x86_64':raise Refused('HOST_SCOPE')
        enable_owned_subreaper()
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
        avd_home=Path(tempfile.mkdtemp(prefix='v16avd-',dir='/tmp'));avd_home.chmod(0o700)
        env['ANDROID_AVD_HOME']=str(avd_home);STATE['ownedAVDHome']=str(avd_home);save()
        device_list,_,_=run([str(SDK/'cmdline-tools/latest/bin/avdmanager'),'list','device'],'actual_device_profiles')
        if not re.search(r'id:\s*\d+\s+or\s+"pixel_6"',device_list.decode(errors='replace')):raise Refused('EXPECTED_DEVICE_PROFILE_NOT_IN_ACTUAL_LIST')
        run([str(SDK/'cmdline-tools/latest/bin/avdmanager'),'create','avd','--name',name,'--package','system-images;android-35;google_apis_playstore;x86_64','--device','pixel_6'],'create_owned_avd',timeout=30,env=env)
        if not(avd_home/(name+'.ini')).is_file():raise Refused('CREATED_AVD_DISCOVERY_INI_MISSING')
        listed,_,_=run([str(SDK/'emulator/emulator'),'-list-avds'],'owned_avd_list',env=env)
        if listed.decode().splitlines()!=[name]:raise Refused('CREATED_AVD_NOT_UNIQUELY_DISCOVERABLE')
        command=[str(SDK/'emulator/emulator'),'-avd',name,'-no-window','-no-snapshot','-accel','on','-camera-back','none','-camera-front','none','-port','5554',audio_flag]
        command=audio_acquire.before_emulator_launch(sys.modules[__name__],command,help_text,env)
        emu=own_process(command,'emulator',env=env);deadline=time.monotonic()+180
        while time.monotonic()<deadline and emu.poll() is None:
            data,code,_=run([ADB,'-s',SERIAL,'shell','getprop','sys.boot_completed'],'boot_poll',timeout=5,allowed_failure=True)
            if code==0 and data.strip()==b'1':break
            time.sleep(1)
        else:
            if emu.poll() is not None:
                STATE['emulatorEarlyExitCode']=emu.returncode;save();raise Refused('EMULATOR_EXITED_BEFORE_BOOT')
            raise Refused('BOOT_NOT_COMPLETE_WITHIN_180S')
        listener_guard();first=fresh_input_snapshot('android-first-screen');packages=first['packages'];STATE['androidFirstScreenLabel']=first['label'];STATE['androidFirstScreenPackages']=sorted(packages)
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
        if maybe_approved_chrome_terms_action(lines,[arg for arg in sys.argv[1:] if arg!='--explicit-v16-audio']):return 0
        STATE['status']='STOP_CHROME_FIRST_SCREEN_REQUIRES_REVIEW_NO_CONTINUATION'
        return 0
    except Refused as e:STATE['status']='REFUSED_CAPABILITY';STATE['refusalCode']=str(e);return 2
    except Exception as e:STATE['status']='REFUSED_CAPABILITY';STATE['errorClass']=type(e).__name__;return 2
    finally:cleanup()
if __name__=='__main__':sys.exit(main())
