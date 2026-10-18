"""Explicit hosted30s emulator/Pulse startup diagnostic. No Chrome, UI or audio protocol."""
from pathlib import Path
import hashlib,importlib.util,json,os,re,shutil,signal,sys,tempfile,time
PINS={'android/boot-proposal/v16/boot_browser_audio.py': 'aa5d28bbbcf62956ddf9803e585badc425478e567aa15bddf8029cbd613db414', 'android/boot-proposal/v16/browser_audio_acquire.py': '1ca9653b8393c0d86c590f01371c1351f03a19c763b9f28647818b6a22b72709', 'android/boot-proposal/v16/audio_route_gate.py': '470f16165976a0d08f571dc52be3b728a5bf2c23fa452b546a0ea4fdc4bebcb7', 'audio/native-pulse/routing.py': '9f1a25697b1c145dde14419da577b199c59712feadb191e6d671a75bbc482b59'}
FLAG='--explicit-private-pulse-startup-debug'
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
  after=b.group_member(member['pid']);need(b.same_group_identity(before,after),'OWNED_PROCESS_CHANGED_DURING_ENV_READ')
  result.append({'pid':member['pid'],'startTicks':member['startTicks'],'stateBefore':before['state'],'stateAfter':after['state'],'processBecameInert':after['state']in ['Z','X','x'],'selectedPrivateEnvironment':selected,'pulseLibraryPaths':libraries})
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
def main(argv=None):
 argv=sys.argv[1:]if argv is None else argv
 need(argv==[FLAG],'EXACT_DIAGNOSTIC_OPT_IN_REQUIRED')
 need(os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('RUNNER_OS')=='Linux'and os.environ.get('RUNNER_ARCH')=='X64'and os.uname().sysname=='Linux'and os.uname().machine=='x86_64','OWNED_HOSTED_LINUX_X64_ONLY')
 repo=Path(__file__).resolve().parents[3];dependencies(repo);sys.path.insert(0,str(Path(__file__).resolve().parent))
 spec=importlib.util.spec_from_file_location('owned_pulse_startup_boot',repo/'android/boot-proposal/v16/boot_browser_audio.py');b=importlib.util.module_from_spec(spec);sys.modules[spec.name]=b;spec.loader.exec_module(b)
 b.OUT=Path('evidence/android-pulse-startup');b.OUT.mkdir(parents=True,exist_ok=False);b.CAP=180;b.AUDIO_CLEANUP_RESERVE=45;b.START=time.monotonic()
 b.STATE.update(schema='owned-private-pulse-emulator-startup-diagnostic-v1',status='STARTING_DIAGNOSTIC',UIInputCommands=0,acquisitionMode='STARTUP_ONLY_NO_BROWSER',functionalPassClaimed=False,audioMeasured=False,PWAVerified=False)
 private=None;avd_home=None;code=2
 for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,lambda *_:(_ for _ in()).throw(b.Refused('OWN_PROCESS_INTERRUPTED')))
 try:
  installed=json.loads(Path('evidence/android-stable-setup/post-install.json').read_text());need(installed.get('status')=='PASS_INSTALLED_EXACT_STABLE_BINDINGS','EXISTING_APPROVED_STABLE_SDK_REQUIRED')
  b.enable_owned_subreaper();help_raw,_,cut=b.run([str(b.SDK/'emulator/emulator'),'-help-all'],'emulator_help',timeout=20,limit=2097152);need(not cut,'FULL_ACTUAL_EMULATOR_HELP_REQUIRED');help_text=help_raw.decode();audio_flag=b.verified_flags(help_text)
  pulse_help,_,cut=b.run(['pulseaudio','--help'],'pulse_help',timeout=5);need(not cut and b'--log-level'in pulse_help,'ACTUAL_SUPPORTED_PULSE_LOG_LEVEL_REQUIRED')
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
  routing.remote_private(b.STATE,env,routing.proc_record);b.STATE['diagnosticEmulatorArgs']=command;b.STATE['diagnosticWindowSeconds']=30;b.save();emu=b.own_process(command,'emulator',env=env);began=time.monotonic();deadline=began+30;observations=[]
  while emu.poll()is None and time.monotonic()<deadline:
   b.remaining(1)
   if not observations and time.monotonic()-began>=3:
    observations.append({'atBootSeconds':time.monotonic()-b.START,'processes':env_snapshot(b,emu,env)})
   time.sleep(.1)
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
    b.STATE['startupLogSlicesAfterCleanup']=retain_available_startup_logs(b)
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
