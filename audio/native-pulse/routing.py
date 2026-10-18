"""Pure fail-closed private-Pulse routing checks. No audio/commands on import."""
import os,pathlib,re,stat
SINK='ci_silent';MONITOR=SINK+'.monitor';RATE=48000;CHANNELS=2
class Refused(ValueError):pass

def proc_record(pid,read=None):
    if type(pid)is not int or pid<=1:raise Refused('Positive selected process PID required')
    text=(read or(lambda p:pathlib.Path('/proc/'+str(p)+'/stat').read_text()))(pid)
    end=text.rfind(') ')
    if end<0:raise Refused('Malformed proc stat')
    fields=text[end+2:].split()
    if len(fields)<20 or not fields[1].isdigit()or not fields[19].isdigit():raise Refused('Complete proc identity required')
    return {'pid':pid,'parentPID':int(fields[1]),'startTicks':fields[19]}

def require_owned(row,process):
    if type(row.get('pid'))is not int or not re.fullmatch(r'[0-9]+',str(row.get('startTicks',''))):raise Refused('Original owned PID/startTicks required')
    now=process(row['pid'])
    if now['pid']!=row['pid']or now['startTicks']!=str(row['startTicks']):raise Refused('Owned PID absent/reused')
    return now

def descendant(pid,root,process):
    require_owned(root,process);seen=set()
    for _ in range(32):
        if pid in seen or pid<=1:raise Refused('Stream PID outside owned ancestry')
        seen.add(pid);row=process(pid)
        if pid==root['pid']:
            if row['startTicks']!=str(root['startTicks']):raise Refused('Root reused while checking ancestry')
            return True
        pid=row['parentPID']
    raise Refused('Ancestry bound exceeded')

def input_bindings(inputs,sink_index,root,process,require_nonempty=True):
    if not isinstance(inputs,list)or (require_nonempty and not inputs):raise Refused('Actual output stream required')
    out=[]
    for row in inputs:
        props=row.get('properties')or{};pid=props.get('application.process.id')
        if not isinstance(pid,str)or not pid.isdigit()or row.get('sink')!=sink_index:raise Refused('Exact sink and original stream PID required')
        descendant(int(pid),root,process)
        if row.get('mute')is not False:raise Refused('Actual output stream must be unmuted')
        identity=process(int(pid));out.append({'index':row['index'],'sink':sink_index,**identity})
    require_owned(root,process);return out

def private_devices(sinks,sources):
    if len(sinks)!=1 or len(sources)!=1:raise Refused('One private null sink and monitor only')
    sink,source=sinks[0],sources[0]
    if sink.get('name')!=SINK or sink.get('driver')!='module-null-sink.c'or source.get('name')!=MONITOR:raise Refused('Private null sink/monitor identity required')
    if source.get('monitor_of_sink')!=sink.get('index'):raise Refused('Monitor must belong to exact null sink')
    return sink['index'],source['index']

def recorder_binding(outputs,monitor_index,recorder,process):
    require_owned(recorder,process)
    if len(outputs)!=1:raise Refused('Exactly one own monitor recorder required')
    row=outputs[0];pid=(row.get('properties')or{}).get('application.process.id')
    if pid!=str(recorder['pid'])or row.get('source')!=monitor_index:raise Refused('Recorder must read only own monitor')
    return {'index':row['index'],'source':monitor_index,'pid':recorder['pid'],'startTicks':str(recorder['startTicks'])}

def future_emulator_args(original,help_text):
    # No backend value guessed: remove only an actual documented audio-disable switch.
    for flag in ['-no-audio','-noaudio']:
        if flag in original and not re.search(r'(?m)^\s*'+re.escape(flag)+r'(?:\s|$)',help_text):raise Refused('Disable switch absent from actual help')
    if '-allow-host-audio'in original or '-allow_host_audio'in original:raise Refused('No host input permission')
    if '-audio'in original:raise Refused('Backend selection needs exact current runtime proof, not guessed driver name')
    if sum(x in ['-no-audio','-noaudio']for x in original)!=1:raise Refused('Exactly one original audio-disable switch required')
    return [x for x in original if x not in ['-no-audio','-noaudio']]

def remote_private(boot,env=None,process=proc_record):
    env=os.environ if env is None else env
    if env.get('GITHUB_ACTIONS')!='true'or env.get('RUNNER_OS')!='Linux'or env.get('RUNNER_ARCH')!='X64':raise Refused('Hosted Linux x86_64 only')
    row=boot.get('privatePulseRuntime')or{};path=pathlib.Path(row.get('path',''))
    if not re.fullmatch(r'/tmp/v15pa-[A-Za-z0-9_]+',str(path)):raise Refused('Original short private Pulse runtime required')
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode)or not stat.S_ISDIR(info.st_mode)or info.st_uid!=os.getuid()or stat.S_IMODE(info.st_mode)!=0o700:raise Refused('Current own0700 private directory required')
    server='unix:'+str(path/'native')
    if env.get('PULSE_SERVER')!=server or env.get('PULSE_SINK')!=SINK or env.get('PULSE_SOURCE')!=MONITOR or env.get('XDG_RUNTIME_DIR')!=str(path):raise Refused('Exact original private Pulse environment required')
    socket=(path/'native').lstat()
    if not stat.S_ISSOCK(socket.st_mode)or socket.st_uid!=os.getuid():raise Refused('Current original private Unix socket required')
    rows=[r for r in boot.get('children',[])if r.get('kind')=='pulse']
    if len(rows)!=1:raise Refused('One original owned private daemon required')
    require_owned(rows[0],process);return rows[0]
