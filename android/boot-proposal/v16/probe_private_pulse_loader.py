"""Owned30s emulator loader/socket observation; no UI/Chrome/collector/audio verdict."""
from pathlib import Path
import hashlib,importlib.util,json,os,re,shutil,signal,sys,tempfile,time
PINS={'android/boot-proposal/v16/boot_browser_audio.py': 'aa5d28bbbcf62956ddf9803e585badc425478e567aa15bddf8029cbd613db414', 'android/boot-proposal/v16/browser_audio_acquire.py': '1ca9653b8393c0d86c590f01371c1351f03a19c763b9f28647818b6a22b72709', 'android/boot-proposal/v16/audio_route_gate.py': '470f16165976a0d08f571dc52be3b728a5bf2c23fa452b546a0ea4fdc4bebcb7', 'audio/native-pulse/routing.py': '9f1a25697b1c145dde14419da577b199c59712feadb191e6d671a75bbc482b59'}
FLAG='--explicit-private-pulse-loader-observation'
PINS.update({'android/boot-proposal/v16/owned_audio_command.py':'d0742eca9f3fd2e743225cf27a02e19f4457c153f44bb913ae644a587333a01b','android/boot-proposal/v16/boot.py':'7be62ba21b1c2ac4dc1f153e37f901ae31ce95bb5f6ac96b822a2d689f4d73c6'})
ENV_KEYS=('PULSE_SERVER','PULSE_SINK','PULSE_SOURCE','XDG_RUNTIME_DIR')
class Refused(ValueError):pass
def need(ok,reason):
 if not ok:raise Refused(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def dependencies(repo):
 for relative,digest in PINS.items():need(sha((repo/relative).read_bytes())==digest,'EXACT_OWNERSHIP_AND_ROUTING_SOURCE_REQUIRED')
def selected_env(raw,expected):
 need(len(raw)<=262144,'BOUNDED_OWNED_ENVIRONMENT_REQUIRED')
 values={}
 for item in raw.split(b'\0'):
  key,sep,value=item.partition(b'=')
  if sep and key.decode('ascii',errors='ignore')in ENV_KEYS:
   name=key.decode();need(name not in values,'DUPLICATE_SELECTED_ENVIRONMENT_KEY');values[name]=value
 return {k:{'present':k in values,'matchesExpected':values.get(k)==expected[k].encode(),'bytes':len(values[k])if k in values else 0,'sha256':sha(values[k])if k in values else None}for k in ENV_KEYS}
def debug_args(command,help_text):
 need(re.search(r'(?m)^\s*audio\s+audio sub-system\s*$',help_text)and re.search(r'(?m)^\s*audioout\s+audio output backend\s*$',help_text),'ACTUAL_DOCUMENTED_AUDIO_DEBUG_TAGS_REQUIRED')
 need('-no-window'in command and not any(x in command for x in ['-debug','-allow-host-audio','-allow_host_audio','-audio','-no-audio','-noaudio']),'ORIGINAL_AUDIO_ONLY_HEADLESS_ARGUMENTS_REQUIRED')
 return command+['-debug','audio,audioout']
def pulse_library_paths(raw):
 need(len(raw)<=524288,'BOUNDED_OWNED_LIBRARY_MAP_REQUIRED')
 paths=[]
 for line in raw.decode(errors='replace').splitlines():
  fields=line.split(maxsplit=5)
  if len(fields)==6 and re.fullmatch(r'/[^\s]+/libpulse(?:common)?(?:-[^\s/]+)?\.so(?:\.[^\s/]+)?(?: \(deleted\))?',fields[5]):paths.append(fields[5])
 return sorted(set(paths))
def env_snapshot(b,emu,expected):
 row=next(x for x in b.STATE['children']if x['kind']=='emulator')
 need(b.process_ticks(emu.pid)==row['startTicks'],'OWNED_EMULATOR_LEADER_IDENTITY_REQUIRED')
 snapshot=b.group_snapshot(emu.pid);need(snapshot['complete']and snapshot['members'],'OWNED_CURRENT_GROUP_SNAPSHOT_REQUIRED')
 result=[]
 for member in snapshot['members']:
  need(member['uid']==os.getuid()and member['sid']==emu.pid and member['pgid']==emu.pid,'UNKNOWN_GROUP_MEMBER_REFUSED')
  before=b.group_member(member['pid']);need(b.same_group_identity(before,member),'OWNED_GROUP_MEMBER_CHANGED')
  if before['state']in ['Z','X','x']:
   result.append({'pid':member['pid'],'startTicks':member['startTicks'],'state':before['state'],'environmentRead':'NOT_READ_INERT_PROCESS'});continue
  with Path('/proc/'+str(member['pid'])+'/environ').open('rb')as f:raw=f.read(262145)
  selected=selected_env(raw,expected)
  with Path('/proc/'+str(member['pid'])+'/maps').open('rb')as f:maps=f.read(524289)
  libraries=pulse_library_paths(maps)
  executable=os.readlink('/proc/'+str(member['pid'])+'/exe')
  after=b.group_member(member['pid']);need(b.same_group_identity(before,after),'OWNED_PROCESS_CHANGED_DURING_ENV_READ')
  result.append({'pid':member['pid'],'startTicks':member['startTicks'],'stateBefore':before['state'],'stateAfter':after['state'],'processBecameInert':after['state']in ['Z','X','x'],'actualExecutable':executable,'selectedPrivateEnvironment':selected,'pulseLibraryPaths':libraries})
 return result
def retain_startup_log(b,kind):
 path=b.OUT/(kind+'-private.raw');size=path.stat().st_size
 with path.open('rb')as f:
  first=f.read(32768);offset=max(0,size-32768);f.seek(offset);last=f.read(32768)
 for part,raw in [('first',first),('last',last)]:
  text=raw.decode('utf-8',errors='replace');text='\n'.join('[TOKEN_LINE_REDACTED]'if re.search(r'token|authorization|password|cookie',line,re.I)else line for line in text.splitlines());(b.OUT/(kind+'-startup-'+part+'.log')).write_text(text)
 return {'sampledWhileOwnedProcessMayWrite':True,'sizeAtRead':size,'firstBytes':len(first),'tailOffset':offset,'tailBytes':len(last),'sanitized':True}
def retain_available_startup_logs(b):
 result={}
 for kind in ['emulator','pulse']:
  path=b.OUT/(kind+'-private.raw')
  try:
   if not path.exists():result[kind]={'status':'ABSENT'};continue
   need(path.is_file()and not path.is_symlink(),'REGULAR_OWNED_STARTUP_LOG_REQUIRED')
   result[kind]={'status':'SANITIZED_SLICES_RETAINED',**retain_startup_log(b,kind)}
  except (OSError,ValueError,UnicodeError)as error:
   result[kind]={'status':'LOG_RETENTION_UNAVAILABLE','errorClass':type(error).__name__}
 return result
def hosted():
 need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_OS')=='Linux' and os.environ.get('RUNNER_ARCH')=='X64' and os.uname().sysname=='Linux' and os.uname().machine=='x86_64','OWNED_HOSTED_LINUX_X64_ONLY')
def install_trace_deps(repo):
 hosted();need(os.getuid()==0 and os.geteuid()==0,'FIXED_DEPENDENCY_SUBREAPER_MUST_BE_ROOT');dependencies(repo)
 sys.path.insert(0,str(Path(__file__).resolve().parent))
 import owned_audio_command as owner
 out=Path('evidence/android-loader-deps');out.mkdir(parents=True,exist_ok=False)
 command=['env','DEBIAN_FRONTEND=noninteractive','apt-get','-y','--no-install-recommends','install','strace']
 result=owner.run_owned(command,out/'install.log',90);result.update(dependencyOwnerUID=os.getuid(),dependencyMode='FIXED_ROOT_STRACE_ONLY')
 (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n');return 0 if result['ok'] else 2
def trace_command(command,help_text,trace_path):
 need('--kill-on-exit' in help_text and 'trace=' in help_text,'ACTUAL_STRACE_FORK_TRACE_AND_EXITKILL_REQUIRED')
 need(command and Path(command[0]).name=='emulator' and command.count('-no-window')==1,'EXACT_OWNED_EMULATOR_LAUNCH_ONLY')
 need(not any(x in command for x in ['-p','--attach','-daemonize','-D']),'ATTACH_OR_DETACHED_TRACE_REFUSED')
 return ['strace','--kill-on-exit','-f','-ttt','-s','256','-e','trace=openat,connect','-o',str(trace_path),'--']+command
def pulse_trace_record(line,private_socket):
 # Keep original bounded syscall line only if it names a Pulse library or
 # a Pulse UNIX socket. No file contents, network payloads or environment.
 if len(line.encode())>4096 or re.search(r'token|authorization|password|cookie',line,re.I):return None
 library=r'"(?:[^"\n]*/)?libpulse(?:common)?(?:-[^/"\n]+)?\.so(?:\.[^/"\n]+)?"'
 is_open='openat(' in line and re.search(library,line)
 unix='connect(' in line and 'AF_UNIX' in line
 socket_match=unix and (('"'+private_socket+'"') in line or re.search(r'sun_path="[^"\n]*/pulse/native"',line))
 if not (is_open or socket_match):return None
 return {'kind':'PULSE_LIBRARY_OPEN' if is_open else 'PULSE_UNIX_CONNECT','originalLine':line}
def retain_loader_trace(path,private_socket,limit=8388608):
 if not path.exists():return {'status':'ABSENT','records':[]}
 need(path.is_file() and not path.is_symlink() and path.stat().st_uid==os.getuid(),'REGULAR_OWNED_LOADER_TRACE_REQUIRED')
 digest=hashlib.sha256();rows=[];total=0;selected=0;discarded=0;oversize=0;offset=0;pending=set();call_counts={'openat':0,'connect':0};pids=set()
 with path.open('rb') as stream:
  # Process a bounded prefix, retaining exact source offsets. Incomplete lines
  # and unfinished syscalls are preserved if selected, never called success.
  while total<limit:
   raw=stream.readline(min(16385,limit-total));
   if not raw:break
   digest.update(raw);total+=len(raw)
   if len(raw)>16384 or not raw.endswith(b'\n'):
    oversize+=1;discarded+=1;offset+=len(raw);continue
   text=raw.decode('utf-8',errors='strict').rstrip('\n');record=pulse_trace_record(text,private_socket)
   prefix=re.match(r'^\s*(?:\[pid\s+)?(\d+)\]?\s+\d+\.\d+\s+',text)
   if prefix:
    pids.add(int(prefix[1]))
    for call in call_counts:
     if call+'(' in text:call_counts[call]+=1
   resumed=re.search(r'<\.\.\. (openat|connect) resumed>',text)
   if resumed and prefix and (prefix[1],resumed[1]) in pending and len(text.encode())<=4096 and not re.search(r'token|authorization|password|cookie',text,re.I):
    pending.remove((prefix[1],resumed[1]));record={'kind':'PULSE_RELEVANT_SYSCALL_RESUMED','originalLine':text}
   if record and '<unfinished ...>' in text and prefix:
    call='openat' if record['kind']=='PULSE_LIBRARY_OPEN' else 'connect';pending.add((prefix[1],call))
   if record:
    selected+=1
    if len(rows)<1024:rows.append({'byteOffset':offset,**record})
   else:discarded+=1
   offset+=len(raw)
  more=bool(stream.read(1))
 return {'status':'FILTERED_ORIGINAL_SYSCALL_ROWS','rawBytesProcessed':total,'prefixSHA256':digest.hexdigest(),'rawFileBytes':path.stat().st_size,'prefixTruncated':more,'oversizeOrPartialLinesOmitted':oversize,'selectedRows':selected,'selectedRowsTruncated':selected>len(rows),'nonmatchingRowsOmitted':discarded,'incompleteRelevantSyscalls':len(pending),'selectedTraceCallCounts':call_counts,'tracePIDs':sorted(pids),'records':rows,'absenceDoesNotProveNoUnselectedConnect':True}
def library_inventory(b):
 sdk=(b.SDK/'emulator').resolve();candidates=[]
 for root,pattern in [(Path('/usr/lib/x86_64-linux-gnu'),'libpulse*.so*'),(Path('/usr/lib/x86_64-linux-gnu/pulseaudio'),'libpulse*.so*'),(sdk/'lib64','libpulse*.so*')]:
  candidates.extend(sorted(root.glob(pattern)))
 need(len(candidates)<=64,'BOUNDED_PULSE_LIBRARY_INVENTORY_REQUIRED')
 candidates+=[sdk/'emulator',sdk/'qemu/linux-x86_64/qemu-system-x86_64-headless',Path(shutil.which('strace')or'/MISSING-STRACE'),Path(shutil.which('readelf')or'/MISSING-READELF')]
 result=[];seen=set();total=0
 for path in candidates:
  b.remaining(1)
  if not path.exists():result.append({'path':str(path),'status':'ABSENT'});continue
  target=path.resolve();need(target.is_file() and any(target.is_relative_to(root) for root in [sdk,Path('/usr/lib'),Path('/usr/bin')]),'KNOWN_PUBLIC_TOOL_OR_LIBRARY_PATH_REQUIRED')
  if target in seen:result.append({'path':str(path),'resolvedPath':str(target),'status':'SAME_PREVIOUS_TARGET'});continue
  seen.add(target);before=target.stat();entry={'path':str(path),'resolvedPath':str(target),'status':'HASH_SKIPPED_SIZE_BOUND','bytes':before.st_size,'sha256':None}
  if before.st_size<=536870912 and total+before.st_size<=1073741824:
   digest=hashlib.sha256();count=0
   with target.open('rb') as stream:
    while True:
     b.remaining(1);chunk=stream.read(1048576)
     if not chunk:break
     digest.update(chunk);count+=len(chunk)
   need(count==before.st_size,'TOOL_OR_LIBRARY_CHANGED_DURING_IDENTITY_READ');total+=count;entry.update(status='HASHED_ORIGINAL_FILE',sha256=digest.hexdigest())
  after=target.stat();need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'TOOL_OR_LIBRARY_CHANGED_DURING_IDENTITY_READ')
  # readelf reads the exact file. No execution/loading, user flags or path search.
  raw,_,cut=b.run(['readelf','--dynamic','--wide',str(target)],'loader-elf-'+str(len(result)),timeout=3,limit=65536)
  need(not cut,'BOUNDED_FULL_DYNAMIC_SECTION_REQUIRED')
  entry['dynamicNeeded'] = re.findall(r'\(NEEDED\).*Shared library: \[([^\]\n]+)\]',raw.decode())
  entry['dynamicRPath'] = re.findall(r'\((?:RUNPATH|RPATH)\).*\[([^\]\n]+)\]',raw.decode())
  result.append(entry)
 return {'status':'READ_ONLY_FILE_IDENTITIES_NOT_RUNTIME_BINDING','entries':result,'uniqueHashedBytes':total}
def retain_loader_observation(b,path,socket):
 try:
  result=retain_loader_trace(path,str(socket))
 except (OSError,ValueError,UnicodeError) as error:result={'status':'LOADER_TRACE_RETENTION_UNAVAILABLE','errorClass':type(error).__name__}
 (b.OUT/'loader-observation.json').write_text(json.dumps(result,indent=2)+'\n');return result

def main(argv=None):
 argv=sys.argv[1:]if argv is None else argv
 repo=Path(__file__).resolve().parents[3]
 if argv==['--install-trace-deps-root']:return install_trace_deps(repo)
 need(argv==[FLAG],'EXACT_DIAGNOSTIC_OPT_IN_REQUIRED')
 need(os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('RUNNER_OS')=='Linux'and os.environ.get('RUNNER_ARCH')=='X64'and os.uname().sysname=='Linux'and os.uname().machine=='x86_64','OWNED_HOSTED_LINUX_X64_ONLY')
 repo=Path(__file__).resolve().parents[3];dependencies(repo);sys.path.insert(0,str(Path(__file__).resolve().parent))
 spec=importlib.util.spec_from_file_location('owned_pulse_startup_boot',repo/'android/boot-proposal/v16/boot_browser_audio.py');b=importlib.util.module_from_spec(spec);sys.modules[spec.name]=b;spec.loader.exec_module(b)
 b.OUT=Path('evidence/android-pulse-loader');b.OUT.mkdir(parents=True,exist_ok=False);b.CAP=180;b.AUDIO_CLEANUP_RESERVE=45;b.START=time.monotonic()
 b.STATE.update(schema='owned-private-pulse-emulator-loader-diagnostic-v1',status='STARTING_DIAGNOSTIC',UIInputCommands=0,acquisitionMode='LOADER_ONLY_NO_BROWSER',functionalPassClaimed=False,audioMeasured=False,PWAVerified=False)
 private=None;avd_home=None;loader_trace=None;socket=None;code=2
 for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,lambda *_:(_ for _ in()).throw(b.Refused('OWN_PROCESS_INTERRUPTED')))
 try:
  installed=json.loads(Path('evidence/android-stable-setup/post-install.json').read_text());need(installed.get('status')=='PASS_INSTALLED_EXACT_STABLE_BINDINGS','EXISTING_APPROVED_STABLE_SDK_REQUIRED')
  b.enable_owned_subreaper();help_raw,_,cut=b.run([str(b.SDK/'emulator/emulator'),'-help-all'],'emulator_help',timeout=20,limit=2097152);need(not cut,'FULL_ACTUAL_EMULATOR_HELP_REQUIRED');help_text=help_raw.decode();audio_flag=b.verified_flags(help_text)
  pulse_help,_,cut=b.run(['pulseaudio','--help'],'pulse_help',timeout=5);need(not cut and b'--log-level'in pulse_help,'ACTUAL_SUPPORTED_PULSE_LOG_LEVEL_REQUIRED')
  need(shutil.which('strace') and shutil.which('readelf'),'EXISTING_REVIEWED_TRACER_AND_READELF_REQUIRED')
  trace_help,_,cut=b.run(['strace','--help'],'strace_help',timeout=5,limit=65536);need(not cut,'FULL_ACTUAL_STRACE_HELP_REQUIRED')
  b.run(['strace','--version'],'strace_version',timeout=5);b.run(['readelf','--version'],'readelf_version',timeout=5)
  packages,_,cut=b.run(['dpkg-query','--show','--showformat=${binary:Package}\t${Version}\n','libpulse0','libpulse-dev','strace','binutils'],'loader_packages',timeout=5,limit=65536);need(not cut,'FULL_SELECTED_PACKAGE_VERSIONS_REQUIRED')
  for package in ['libpulse0','libpulse-dev']:
   need(re.search(r'(?m)^'+package+r'(?::amd64)?\t1:16\.1\+dfsg1-2ubuntu10\.1$',packages.decode()),'ORIGINAL_FULL_RUN_PULSE_RUNTIME_AND_DEV_VERSIONS_REQUIRED')
  b.STATE['loaderReadOnlyInventory']=library_inventory(b);b.save()
  acl,_,_=b.run(['getfacl','--absolute-names','/dev/kvm'],'kvm_acl_before');(b.OUT/'kvm-original.acl').write_bytes(acl);b.STATE['KVMACLRestoreArmed']=True;b.save();b.run(['sudo','-n','setfacl','-m','u:'+str(os.getuid())+':rw','/dev/kvm'],'kvm_uid_acl');b.STATE['KVMACLChanged']=True;b.save();need(os.access('/dev/kvm',os.R_OK|os.W_OK),'OWNED_KVM_ACCESS_REQUIRED')
  private=Path(tempfile.mkdtemp(prefix='v15pa-',dir='/tmp'));private.chmod(0o700);socket=private/'native';need(len(os.fsencode(socket))<108,'PRIVATE_SOCKET_LENGTH');config=private/'only-null.pa';config.write_text('.fail\nload-module module-native-protocol-unix socket='+str(socket)+' auth-anonymous=1\nload-module module-null-sink sink_name=ci_silent rate=48000 channels=2\nset-default-sink ci_silent\nset-default-source ci_silent.monitor\n')
  b.STATE['privatePulseRuntime']={'path':str(private),'uid':private.stat().st_uid,'mode':private.stat().st_mode&0o777,'socketBytes':len(os.fsencode(socket))};env=os.environ.copy();env.update(XDG_RUNTIME_DIR=str(private),PULSE_SERVER='unix:'+str(socket),PULSE_SINK='ci_silent',PULSE_SOURCE='ci_silent.monitor')
  pulse=b.own_process(['pulseaudio','-n','--daemonize=no','--exit-idle-time=-1','--log-level=debug','--file='+str(config.resolve())],'pulse',env=env);deadline=time.monotonic()+10
  while not socket.exists()and pulse.poll()is None and time.monotonic()<deadline:time.sleep(.1)
  need(socket.exists(),'PRIVATE_PULSE_NOT_READY');routing=b.audio_acquire.native('routing.py')
  def graph(label):
   routing.remote_private(b.STATE,env,routing.proc_record);rows={k:b.audio_acquire.json_command(b,env,k,label+'-'+k)for k in ['sinks','sources','sink-inputs','source-outputs']};routing.private_devices(rows['sinks'],rows['sources']);return rows
  b.STATE['prelaunchGraph']=graph('prelaunch')
  ports,_,_=b.run(['ss','-ltn'],'control_ports_before');need(not any(re.search(r':(?:5037|5554|5555|8554)\s',line)for line in ports.decode().splitlines()),'PREEXISTING_CONTROL_LISTENER_REFUSED');b.run([b.ADB,'start-server'],'start_owned_adb_server');b.STATE['ownedADBServerStarted']=True;b.save();devices,_,_=b.run([b.ADB,'devices'],'adb_devices_before');need(not any(x.strip()for x in devices.decode().splitlines()[1:]),'EXISTING_ADB_DEVICE_REFUSED')
  name='ci_pulse_probe_'+str(os.getpid());avd_home=Path(tempfile.mkdtemp(prefix='v16avd-',dir='/tmp'));avd_home.chmod(0o700);env['ANDROID_AVD_HOME']=str(avd_home);b.STATE.update(ownedAVD=name,ownedAVDHome=str(avd_home));b.save()
  b.run([str(b.SDK/'cmdline-tools/latest/bin/avdmanager'),'create','avd','--name',name,'--package','system-images;android-35;google_apis_playstore;x86_64','--device','pixel_6'],'create_owned_avd',timeout=30,env=env);need((avd_home/(name+'.ini')).is_file(),'OWNED_AVD_DISCOVERY_INI_REQUIRED');listed,_,_=b.run([str(b.SDK/'emulator/emulator'),'-list-avds'],'owned_avd_list',env=env);need(listed.decode().splitlines()==[name],'OWNED_AVD_DISCOVERY_REQUIRED')
  original=[str(b.SDK/'emulator/emulator'),'-avd',name,'-no-window','-no-snapshot','-accel','on','-camera-back','none','-camera-front','none','-port','5554',audio_flag];command=debug_args(routing.future_emulator_args(original,help_text),help_text)
  routing.remote_private(b.STATE,env,routing.proc_record);b.STATE['diagnosticEmulatorArgs']=command;loader_trace=b.OUT/'loader.private';need(not loader_trace.exists(),'FRESH_OWNED_TRACE_REQUIRED');command=trace_command(command,trace_help.decode(),loader_trace);b.STATE['diagnosticTracerArgs']=command;b.STATE['diagnosticWindowSeconds']=30;b.save();emu=b.own_process(command,'emulator',env=env);began=time.monotonic();deadline=began+30;observations=[]
  while emu.poll()is None and time.monotonic()<deadline:
   b.remaining(1)
   if not observations and time.monotonic()-began>=3:
    observations.append({'atBootSeconds':time.monotonic()-b.START,'processes':env_snapshot(b,emu,env)})
   time.sleep(.1)
  need(emu.poll() is None and observations,'OWNED_TRACED_STARTUP_WINDOW_REQUIRED')
  b.STATE.update(selectedEnvironmentReadbacks=observations,startupElapsedSeconds=time.monotonic()-began,emulatorEarlyExitCode=emu.poll(),postStartupGraph=graph('post-startup'),status='DIAGNOSTIC_ACQUIRED_NOT_AUDIO_ACCEPTANCE');b.save();code=0
 except (b.Refused,Refused,ValueError,KeyError,OSError)as error:b.STATE.update(status='REFUSED_DIAGNOSTIC',errorClass=type(error).__name__,reason=str(error));code=2
 finally:
  # Retain startup diagnostics even if optional owned-process observation refused.
  # Log I/O never replaces the original refusal or bypasses owned cleanup.
  try:
   b.STATE['startupLogSlicesBeforeCleanup']=retain_available_startup_logs(b)
  finally:
   try:b.cleanup()
   finally:
    try:
     b.STATE['startupLogSlicesAfterCleanup']=retain_available_startup_logs(b)
     if loader_trace is not None:
      observation=retain_loader_observation(b,loader_trace,socket);b.STATE['loaderObservation']=observation
      if observation.get('status')!='FILTERED_ORIGINAL_SYSCALL_ROWS' or not observation.get('selectedTraceCallCounts',{}).get('openat',0):
       code=2;b.STATE['status']='REFUSED_DIAGNOSTIC';b.STATE.setdefault('reason','ACTUAL_OWNED_SYSCALL_OBSERVATION_REQUIRED')
    except (OSError,ValueError,UnicodeError) as error:
     code=2;b.STATE['loaderRetentionErrorClass']=type(error).__name__;b.STATE.setdefault('reason','LOADER_OBSERVATION_RETENTION_FAILED');b.STATE['status']='REFUSED_DIAGNOSTIC'
    finally:
     try:
      if loader_trace is not None and loader_trace.exists():
       need(loader_trace.is_file() and not loader_trace.is_symlink() and loader_trace.stat().st_uid==os.getuid(),'OWNED_RAW_TRACE_CLEANUP_REQUIRED');loader_trace.unlink()
      b.STATE['diagnosticRawTraceRemoved']=loader_trace is None or not loader_trace.exists()
     except (OSError,ValueError) as error:
      code=2;b.STATE['diagnosticRawTraceRemoved']=False;b.STATE['loaderRawCleanupErrorClass']=type(error).__name__
     b.save()
  if b.STATE.get('ownedChildCleanupVerified')is not True:code=2
  else:
   for directory in [avd_home,private]:
    if directory is not None:
     info=directory.lstat();need(not directory.is_symlink()and info.st_uid==os.getuid()and info.st_mode&0o777==0o700,'OWNED_PRIVATE_DIRECTORY_CLEANUP_REQUIRED');shutil.rmtree(directory)
   b.STATE['ownedPrivateDirectoriesRemoved']=True
  b.save()
 return code
if __name__=='__main__':raise SystemExit(main())
