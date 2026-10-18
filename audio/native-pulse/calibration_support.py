"""Hosted calibration support only; derived from retained parent raw prototype. No commands on import."""
import array,math,os,pathlib,signal,subprocess,sys,time,wave
from routing import Refused,RATE

def stop(p):
    if p is None:return {'leaderReaped':True,'ownedGroupAbsent':True}
    def exists():
        try:os.killpg(p.pid,0);return True
        except ProcessLookupError:return False
        except PermissionError:return True
    signals=[]
    if exists():
        try:os.killpg(p.pid,signal.SIGTERM);signals.append('TERM')
        except ProcessLookupError:pass
        except PermissionError:signals.append('TERM_DENIED')
        end=time.monotonic()+2
        while time.monotonic()<end and(p.poll()is None or exists()):time.sleep(.01)
    if p.poll()is None or exists():
        try:os.killpg(p.pid,signal.SIGKILL);signals.append('KILL')
        except ProcessLookupError:pass
        except PermissionError:signals.append('KILL_DENIED')
    try:p.wait(timeout=2)
    except subprocess.TimeoutExpired:pass
    return {'leaderReaped':p.poll()is not None,'ownedGroupAbsent':not exists(),'signals':signals,'returnCode':p.returncode}

def tone_file(path):
    x=array.array('h',(round(0.2*32767*math.sin(2*math.pi*440*i/RATE))if i<3*RATE or i>=5*RATE else 0 for i in range(8*RATE)for _ in range(2)))
    if sys.byteorder!='little':x.byteswap()
    with wave.open(str(path),'wb')as f:f.setnchannels(2);f.setsampwidth(2);f.setframerate(RATE);f.writeframes(x.tobytes())

def assess_host_pattern(raw):
    # Known host calibration only: no source clock fit, no arbitrary PCM/product verdict.
    if not raw or len(raw)%8 or len(raw)>45*RATE*8:raise Refused('Bounded complete stereo f32 required')
    x=array.array('f');x.frombytes(raw)
    if sys.byteorder!='little':x.byteswap()
    if not all(math.isfinite(v)for v in x):raise Refused('Nonfinite calibration PCM')
    n=RATE//2;cos=[math.cos(2*math.pi*440*i/RATE)for i in range(n)];sin=[math.sin(2*math.pi*440*i/RATE)for i in range(n)];rows=[]
    for start in range(0,len(x)//2-n+1,n):
        channels=[]
        for ch in range(2):
            z=x[2*start+ch:2*(start+n):2];ms=sum(v*v for v in z)/n;fraction=2*(sum(v*c for v,c in zip(z,cos))**2+sum(v*t for v,t in zip(z,sin))**2)/(n*n*ms)if ms else 0
            channels.append({'rms':math.sqrt(ms),'powerFraction440':fraction,'exactZero':all(v==0 for v in z),'knownPositive':.12<=math.sqrt(ms)<=.16 and fraction>=.8})
        rows.append({'startFrame':start,'endFrameExclusive':start+n,'channels':channels,'state':'positive'if all(c['knownPositive']for c in channels)else'zero'if all(c['exactZero']for c in channels)else'other'})
    runs=[]
    for i,row in enumerate(rows):
        if runs and runs[-1]['state']==row['state']:runs[-1]['windows']+=1;runs[-1]['endFrameExclusive']=row['endFrameExclusive']
        else:runs.append({'state':row['state'],'windows':1,'startFrame':row['startFrame'],'endFrameExclusive':row['endFrameExclusive']})
    # A native capture starts at an arbitrary waveform offset: one half-second
    # window straddling each known source boundary is explicitly 'other', not zero.
    candidates=[]
    for i,a in enumerate(runs):
        if a['state']!='positive'or not 4<=a['windows']<=6:continue
        k=i+1;edges=[]
        if k<len(runs)and runs[k]['state']=='other'and runs[k]['windows']==1:edges.append(runs[k]);k+=1
        if k>=len(runs)or runs[k]['state']!='zero'or not 2<=runs[k]['windows']<=4:continue
        b=runs[k];k+=1
        if k<len(runs)and runs[k]['state']=='other'and runs[k]['windows']==1:edges.append(runs[k]);k+=1
        if k<len(runs)and runs[k]['state']=='positive'and 4<=runs[k]['windows']<=6:
            candidates.append({'positiveBefore':a,'zero':b,'positiveAfter':runs[k],'unqualifiedBoundaryWindows':edges})
    found=bool(candidates)
    return {'scope':'Known hosted440/silence/440 pattern only; not emulator/PWA/captureclock qualification','bothChannelPatternObserved':found,'rows':rows,'runs':runs,'sourceOffsetFitted':False,'knownPatternCandidates':candidates,'boundaryWindowPolicy':'At most one unknown500ms window per known tone/silence transition; never counted as silence or positive.'}
