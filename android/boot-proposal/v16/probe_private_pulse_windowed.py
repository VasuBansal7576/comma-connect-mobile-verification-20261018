"""Owned remote30s Xvfb windowed-backend probe; no input/Chrome/collector/audio verdict."""
from pathlib import Path
import hashlib,importlib.util,json,os,re,shutil,signal,sys,tempfile,time
PINS={'android/boot-proposal/v16/boot_browser_audio.py': 'aa5d28bbbcf62956ddf9803e585badc425478e567aa15bddf8029cbd613db414', 'android/boot-proposal/v16/browser_audio_acquire.py': '1ca9653b8393c0d86c590f01371c1351f03a19c763b9f28647818b6a22b72709', 'android/boot-proposal/v16/audio_route_gate.py': '470f16165976a0d08f571dc52be3b728a5bf2c23fa452b546a0ea4fdc4bebcb7', 'audio/native-pulse/routing.py': '9f1a25697b1c145dde14419da577b199c59712feadb191e6d671a75bbc482b59'}
FLAG='--explicit-private-pulse-windowed-probe'
PINS.update({'android/boot-proposal/v16/owned_audio_command.py':'48366b081d0a2e6faf8053a3f49a8293fa81d98280dc96afad0ff59446bee20f','android/boot-proposal/v16/boot.py':'efcdfbbd7d0155f8d0e1488dda6137eb670190ccc7c2d063b544c6031fa39226'})
ENV_KEYS=('PULSE_SERVER','PULSE_SINK','PULSE_SOURCE','XDG_RUNTIME_DIR','DISPLAY','XAUTHORITY')
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
 for kind in ['emulator','pulse','xvfb']:
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
 out=Path('evidence/android-windowed-deps');out.mkdir(parents=True,exist_ok=False)
 command=['env','DEBIAN_FRONTEND=noninteractive','apt-get','-y','--no-install-recommends','install','strace','xvfb','xauth','x11-utils']
 result=owner.run_owned(command,out/'install.log',90);result.update(dependencyOwnerUID=os.getuid(),dependencyMode='FIXED_ROOT_STRACE_XVFB_XAUTH_QUERY_ONLY')
 (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n');return 0 if result['ok'] else 2
def trace_command(command,help_text,trace_path):
 need('--kill-on-exit' in help_text and 'trace=' in help_text,'ACTUAL_STRACE_FORK_TRACE_AND_EXITKILL_REQUIRED')
 need(command and Path(command[0]).name=='emulator' and command.count('-no-window')==0 and '-no-qt' not in command,'EXACT_OWNED_EMULATOR_LAUNCH_ONLY')
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
 candidates+=[sdk/'emulator',sdk/'qemu/linux-x86_64/qemu-system-x86_64-headless',sdk/'qemu/linux-x86_64/qemu-system-x86_64']+[Path(shutil.which(name)or'/MISSING-'+name)for name in ['strace','readelf','objdump','Xvfb','xauth','xdpyinfo']]
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

def windowed_emulator_args(command,help_text):
 need(command.count('-no-window')==1 and re.search(r'(?m)^\s*-no-window\s+disable graphical window display\s*$',help_text),'ACTUAL_DOCUMENTED_HEADLESS_SWITCH_REQUIRED')
 need(not any(x in command for x in ['-no-qt','-qt-hide-window','-allow-host-audio','-allow_host_audio','-audio','-noaudio','-no-audio']),'UNREVIEWED_AUDIO_OR_GRAPHICS_OVERRIDE')
 after=[x for x in command if x!='-no-window'];need(after==command[:command.index('-no-window')]+command[command.index('-no-window')+1:],'ONLY_HEADLESS_SWITCH_REMOVAL_REQUIRED');return after
def selected_unix_sockets(number,raw=None):
 target='/tmp/.X11-unix/X'+str(number)
 if raw is None:
  with Path('/proc/net/unix').open('rb')as stream:raw=stream.read(2097153)
 need(len(raw)<=2097152,'BOUNDED_UNIX_SOCKET_TABLE_REQUIRED');rows=[]
 for line in raw.decode(errors='replace').splitlines()[1:]:
  fields=line.split(maxsplit=7)
  if fields and fields[-1]in[target,'@'+target]:
   need(len(fields)==8 and fields[6].isdigit(),'SELECTED_DISPLAY_SOCKET_SCHEMA_REQUIRED');rows.append({'inode':int(fields[6]),'path':fields[7]})
 return rows
def selected_tcp_listener(number):
 for name in ['tcp','tcp6']:
  with Path('/proc/net/'+name).open('rb')as stream:raw=stream.read(2097153)
  need(len(raw)<=2097152,'BOUNDED_TCP_LISTENER_TABLE_REQUIRED')
  for line in raw.decode().splitlines()[1:]:
   fields=line.split()
   if len(fields)>3 and fields[3]=='0A'and int(fields[1].rsplit(':',1)[1],16)==6000+number:return True
 return False
def display_paths(number):return [Path('/tmp/.X11-unix/X'+str(number)),Path('/tmp/.X'+str(number)+'-lock')]
def refuse_existing_display(number):
 need(type(number)is int and 200<=number<1200,'OWNED_BOUNDED_DISPLAY_NUMBER_REQUIRED')
 need(not any(p.exists()or p.is_symlink()for p in display_paths(number))and not selected_unix_sockets(number)and not selected_tcp_listener(number),'PREEXISTING_DISPLAY_REFUSED_NO_CONNECT')
def display_file_identity(path):
 s=path.lstat();return {'path':str(path),'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'mode':s.st_mode}
def verify_owned_display(b,server,number):
 import stat
 row=next(x for x in b.STATE['children']if x['kind']=='xvfb');before=b.group_member(server.pid)
 need(server.poll()is None and before and before['pid']==server.pid and before['startTicks']==row['startTicks']and before['uid']==os.getuid()and before['sid']==server.pid and before['pgid']==server.pid,'LIVE_OWNED_XVFB_IDENTITY_REQUIRED')
 socket_path,lock=display_paths(number);need(not socket_path.is_symlink()and stat.S_ISSOCK(socket_path.lstat().st_mode)and socket_path.lstat().st_uid==os.getuid(),'OWNED_DISPLAY_SOCKET_REQUIRED')
 need(not lock.is_symlink()and lock.is_file()and lock.stat().st_uid==os.getuid()and lock.stat().st_size<=32,'OWNED_DISPLAY_LOCK_REQUIRED')
 need(lock.read_text().strip()==str(server.pid),'OWNED_DISPLAY_LOCK_PID_REQUIRED')
 rows=selected_unix_sockets(number);need(rows and any(r['path']==str(socket_path)for r in rows),'OWNED_DISPLAY_UNIX_LISTENER_REQUIRED')
 fds=list(Path('/proc/'+str(server.pid)+'/fd').iterdir());need(len(fds)<=1024,'BOUNDED_OWNED_XVFB_FDS_REQUIRED');inodes=set()
 for fd in fds:
  try:link=os.readlink(fd)
  except FileNotFoundError:continue
  match=re.fullmatch(r'socket:\[(\d+)\]',link)
  if match:inodes.add(int(match[1]))
 after=b.group_member(server.pid);need(b.same_group_identity(before,after),'OWNED_XVFB_CHANGED_DURING_SOCKET_READ')
 need(all(r['inode']in inodes for r in rows)and not selected_tcp_listener(number),'DISPLAY_SOCKET_NOT_EXACT_OWNED_XVFB_OR_TCP_LISTENER')
 return {'number':number,'display':':'+str(number),'pid':server.pid,'startTicks':row['startTicks'],'uid':os.getuid(),'UNIXOnly':True,'nativeSocketRows':rows,'files':[display_file_identity(p)for p in display_paths(number)],'authentication':'PRIVATE_0600_MIT_COOKIE_NO_VALUE_RETAINED'}
def start_private_xvfb(b,private,env):
 need(all(not env.get(k)for k in ['WAYLAND_DISPLAY','QT_QPA_PLATFORM','QT_PLUGIN_PATH']),'UNREVIEWED_QT_PLATFORM_OVERRIDE_REFUSED')
 b.STATE['graphicalEnvironmentChildOnlyOverride']={'DISPLAYWasPresent':bool(env.get('DISPLAY')),'XAUTHORITYWasPresent':bool(env.get('XAUTHORITY')),'originalProcessEnvironmentUnchanged':True}
 number=200+os.getpid()%1000;refuse_existing_display(number)
 b.STATE['privateDisplayReservation']={'number':number,'preexistingPathsAndUNIXAndTCPAbsent':True};b.save()
 raw,_,cut=b.run(['Xvfb','-help'],'xvfb_help',timeout=5,limit=65536);trace=b.STATE['trace'][-1];need(not cut and trace['stdoutBytes']+trace['stderrBytes']<=65536,'FULL_ACTUAL_XVFB_HELP_REQUIRED');text=(b.OUT/'xvfb_help.log').read_text()
 need(all(x in text for x in ['-screen','-auth','-nolisten','-noreset']),'ACTUAL_DOCUMENTED_PRIVATE_XVFB_OPTIONS_REQUIRED')
 auth=private/'Xauthority';script=private/'xauth-source.private';fd=os.open(script,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as stream:stream.write('add :'+str(number)+' MIT-MAGIC-COOKIE-1 '+os.urandom(16).hex()+'\n')
 try:b.run(['xauth','-q','-f',str(auth),'source',str(script)],'configure_private_xauth',timeout=5)
 finally:script.unlink()
 need(auth.is_file()and not auth.is_symlink()and 0<auth.stat().st_size<=4096 and auth.stat().st_uid==os.getuid(),'PRIVATE_XAUTHORITY_REQUIRED');auth.chmod(0o600)
 env.update(DISPLAY=':'+str(number),XAUTHORITY=str(auth));command=['Xvfb',':'+str(number),'-screen','0','1080x2400x24','-nolisten','tcp','-auth',str(auth),'-noreset']
 b.STATE['privateDisplayCommand']=command;b.save();server=b.own_process(command,'xvfb',env=env);deadline=time.monotonic()+10
 while time.monotonic()<deadline and server.poll()is None:
  b.remaining(1)
  if all(p.exists()for p in display_paths(number)):break
  time.sleep(.1)
 proof=verify_owned_display(b,server,number);b.STATE['privateDisplay']=proof;b.save()
 # Read-only negative/positive authentication queries after socket ownership.
 denied=private/'empty.Xauthority';fd=os.open(denied,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd);without_auth=dict(env);without_auth['XAUTHORITY']=str(denied)
 _,denied_code,_=b.run(['xdpyinfo','-display',env['DISPLAY']],'private_display_info_denied',timeout=5,limit=65536,env=without_auth,allowed_failure=True)
 need(denied_code!=0,'PRIVATE_DISPLAY_ACCEPTED_NO_COOKIE_NO_EMULATOR_LAUNCH');b.STATE['privateDisplayAuthentication']={'unauthenticatedReadExitCode':denied_code,'cookieValueNeverRetained':True};b.save()
 b.run(['xdpyinfo','-display',env['DISPLAY']],'private_display_info',timeout=5,limit=65536,env=env)
 b.STATE['privateDisplayAuthentication']['authenticatedReadExitCode']=0;b.save()
 need(auth.stat().st_mode&0o777==0o600,'PRIVATE_XAUTHORITY_MODE_REQUIRED');return server
def cleanup_private_display(b):
 reservation=b.STATE.get('privateDisplayReservation')
 if not reservation:return {'status':'NOT_STARTED','verified':True}
 number=reservation['number'];need(b.STATE.get('ownedChildCleanupVerified')is True,'DISPLAY_CLEANUP_REQUIRES_OWNED_PROCESS_GROUP_ABSENCE')
 need(not selected_unix_sockets(number)and not selected_tcp_listener(number),'DISPLAY_LISTENER_STILL_PRESENT_NO_PATH_REMOVAL')
 proof=b.STATE.get('privateDisplay',{});prior={v['path']:v for v in proof.get('files',[])};removed=[]
 for path in display_paths(number):
  if not path.exists()and not path.is_symlink():continue
  need(not path.is_symlink()and str(path)in prior and display_file_identity(path)==prior[str(path)]and path.lstat().st_uid==os.getuid(),'DISPLAY_PATH_IDENTITY_CHANGED_NO_REMOVAL')
  if path.name.endswith('-lock'):need(path.stat().st_size<=32 and path.read_text().strip()==str(proof['pid']),'DISPLAY_LOCK_CONTENT_CHANGED_NO_REMOVAL')
  path.unlink();removed.append(str(path))
 return {'status':'OWNED_DISPLAY_EXIT_SOCKETS_AND_LOCK_ABSENT','verified':True,'number':number,'removedExactBoundResidue':removed,'sharedX11DirectoryNeverRemoved':True}
def backend_binary_evidence(b):
 root=(b.SDK/'emulator/qemu/linux-x86_64').resolve();facts=[]
 for name in ['qemu-system-x86_64-headless','qemu-system-x86_64']:
  path=root/name;need(path.is_file()and not path.is_symlink(),'ACTUAL_BOTH_SDK_BACKEND_BINARIES_REQUIRED');before=path.stat();size=before.st_size;offset=0;tail=b'';hits=[];needle=b'Using headless implementation'
  with path.open('rb')as stream:
   while True:
    b.remaining(1);chunk=stream.read(1048576)
    if not chunk:break
    data=tail+chunk;at=0
    while True:
     index=data.find(needle,at)
     if index<0:break
     position=offset-len(tail)+index
     if position not in hits:hits.append(position)
     need(len(hits)<=64,'BOUNDED_HEADLESS_LITERAL_MATCHES_REQUIRED');at=index+1
    tail=data[-(len(needle)-1):];offset+=len(chunk)
  after=path.stat();need(offset==size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'SDK_BINARY_CHANGED_DURING_LITERAL_READ');row={'path':str(path),'bytes':size,'headlessStubLiteralOffsets':hits,'symbolDisassembly':[]}
  for symbol in ['pa_threaded_mainloop_new','pa_context_new']:
   raw,_,cut=b.run(['objdump','--disassemble='+symbol,str(path)],'backend-symbol-'+name+'-'+symbol,timeout=4,limit=65536);row['symbolDisassembly'].append({'symbol':symbol,'truncated':cut,'namedSymbolObserved':('<'+symbol+'>:').encode()in raw})
  facts.append(row)
 return facts
def private_connect_observed(observation,private_socket):
 pending=set()
 for row in observation.get('records',[]):
  line=row.get('originalLine','');prefix=re.match(r'^\s*(?:\[pid\s+)?(\d+)\]?\s+\d+\.\d+\s+',line)
  if not prefix:continue
  pid=prefix[1]
  if row.get('kind')=='PULSE_UNIX_CONNECT' and ('sun_path="'+private_socket+'"')in line:
   if re.search(r'=\s*0\s*$',line):return True
   if '<unfinished ...>'in line:pending.add(pid)
  elif row.get('kind')=='PULSE_RELEVANT_SYSCALL_RESUMED' and '<... connect resumed>'in line and pid in pending:
   pending.remove(pid)
   if re.search(r'=\s*0\s*$',line):return True
 return False
def windowed_backend_facts(b,observation,private_socket):
 expected=str((b.SDK/'emulator/qemu/linux-x86_64/qemu-system-x86_64').resolve())
 processes={r['pid']:r for sample in b.STATE.get('selectedEnvironmentReadbacks',[])for r in sample.get('processes',[])if r.get('actualExecutable')==expected}
 unique=len(processes)==1;pid=next(iter(processes))if unique else None;process=processes.get(pid,{})
 clients=b.STATE.get('postStartupClients',[])
 client_match=any(isinstance(c,dict)and isinstance(c.get('properties'),dict)and c['properties'].get('application.process.id')==str(pid)for c in clients)if unique and isinstance(clients,list)else False
 mapped=any(re.search(r'/libpulse\.so(?:\.|$)',p)for p in process.get('pulseLibraryPaths',[]))
 inventory=next((r for r in b.STATE.get('loaderReadOnlyInventory',{}).get('entries',[])if r.get('resolvedPath')==expected and r.get('status')=='HASHED_ORIGINAL_FILE'),{})
 env=process.get('selectedPrivateEnvironment',{});environment=bool(env)and all(v.get('present')is True and v.get('matchesExpected')is True for v in env.values())
 needed=any(name.startswith('libpulse.so')for name in inventory.get('dynamicNeeded',[]));connected=private_connect_observed(observation,private_socket)
 proved=all([unique,client_match,mapped,environment,needed,connected,bool(inventory.get('sha256'))])
 return {'schema':'bounded-windowed-private-pulse-backend-observation-v1','diagnosticOnly':True,'audioAcceptance':False,'proved':proved,'oneOwnedHeadfulProcess':unique,'actualHeadfulPID':pid,'headfulOriginalBinarySHA256':inventory.get('sha256'),'headfulELFNeedsPulse':needed,'realPulseLibraryMapped':mapped,'privateEnvironmentMatched':environment,'privateDaemonClientPIDMatchesHeadful':client_match,'ownTracePrivateSocketConnectReturnedZero':connected,'scope':'Native backend/private connection only; no app/media/collector/audio correctness.'}

def main(argv=None):
 argv=sys.argv[1:]if argv is None else argv
 repo=Path(__file__).resolve().parents[3]
 if argv==['--install-windowed-deps-root']:return install_trace_deps(repo)
 need(argv==[FLAG],'EXACT_DIAGNOSTIC_OPT_IN_REQUIRED')
 need(os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('RUNNER_OS')=='Linux'and os.environ.get('RUNNER_ARCH')=='X64'and os.uname().sysname=='Linux'and os.uname().machine=='x86_64','OWNED_HOSTED_LINUX_X64_ONLY')
 repo=Path(__file__).resolve().parents[3];dependencies(repo);sys.path.insert(0,str(Path(__file__).resolve().parent))
 spec=importlib.util.spec_from_file_location('owned_pulse_startup_boot',repo/'android/boot-proposal/v16/boot_browser_audio.py');b=importlib.util.module_from_spec(spec);sys.modules[spec.name]=b;spec.loader.exec_module(b)
 b.OUT=Path('evidence/android-pulse-windowed');b.OUT.mkdir(parents=True,exist_ok=False);b.CAP=180;b.AUDIO_CLEANUP_RESERVE=45;b.START=time.monotonic()
 b.STATE.update(schema='owned-private-pulse-emulator-windowed-diagnostic-v1',status='STARTING_DIAGNOSTIC',UIInputCommands=0,acquisitionMode='WINDOWED_XVFB_ONLY_NO_BROWSER',functionalPassClaimed=False,audioMeasured=False,PWAVerified=False)
 private=None;avd_home=None;loader_trace=None;socket=None;xvfb=None;code=2
 for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,lambda *_:(_ for _ in()).throw(b.Refused('OWN_PROCESS_INTERRUPTED')))
 try:
  installed=json.loads(Path('evidence/android-stable-setup/post-install.json').read_text());need(installed.get('status')=='PASS_INSTALLED_EXACT_STABLE_BINDINGS','EXISTING_APPROVED_STABLE_SDK_REQUIRED')
  b.enable_owned_subreaper();help_raw,_,cut=b.run([str(b.SDK/'emulator/emulator'),'-help-all'],'emulator_help',timeout=20,limit=2097152);need(not cut,'FULL_ACTUAL_EMULATOR_HELP_REQUIRED');help_text=help_raw.decode();audio_flag=b.verified_flags(help_text)
  pulse_help,_,cut=b.run(['pulseaudio','--help'],'pulse_help',timeout=5);need(not cut and b'--log-level'in pulse_help,'ACTUAL_SUPPORTED_PULSE_LOG_LEVEL_REQUIRED')
  need(all(shutil.which(name)for name in ['strace','readelf','objdump','Xvfb','xauth','xdpyinfo']),'EXISTING_REVIEWED_TRACER_ELF_AND_PRIVATE_XVFB_TOOLS_REQUIRED')
  trace_help,_,cut=b.run(['strace','--help'],'strace_help',timeout=5,limit=65536);need(not cut,'FULL_ACTUAL_STRACE_HELP_REQUIRED')
  b.run(['strace','--version'],'strace_version',timeout=5);b.run(['readelf','--version'],'readelf_version',timeout=5)
  packages,_,cut=b.run(['dpkg-query','--show','--showformat=${binary:Package}\t${Version}\n','libpulse0','libpulse-dev','strace','binutils'],'loader_packages',timeout=5,limit=65536);need(not cut,'FULL_SELECTED_PACKAGE_VERSIONS_REQUIRED')
  for package in ['libpulse0','libpulse-dev']:
   need(re.search(r'(?m)^'+package+r'(?::amd64)?\t1:16\.1\+dfsg1-2ubuntu10\.1$',packages.decode()),'ORIGINAL_FULL_RUN_PULSE_RUNTIME_AND_DEV_VERSIONS_REQUIRED')
  b.STATE['loaderReadOnlyInventory']=library_inventory(b);headless=next((r for r in b.STATE['loaderReadOnlyInventory']['entries']if r.get('resolvedPath','').endswith('/qemu-system-x86_64-headless')and r.get('status')=='HASHED_ORIGINAL_FILE'),{});need(headless.get('sha256')=='23b788a3b87b3228558924de4cb5477e2818b3b9415d6ce27d6438cf3e462b98','EXACT_ACTUAL_391307_HEADLESS_BACKEND_REQUIRED');b.STATE['originalBackendBinaryEvidence']=backend_binary_evidence(b);b.save()
  acl,_,_=b.run(['getfacl','--absolute-names','/dev/kvm'],'kvm_acl_before');(b.OUT/'kvm-original.acl').write_bytes(acl);b.STATE['KVMACLRestoreArmed']=True;b.save();b.run(['sudo','-n','setfacl','-m','u:'+str(os.getuid())+':rw','/dev/kvm'],'kvm_uid_acl');b.STATE['KVMACLChanged']=True;b.save();need(os.access('/dev/kvm',os.R_OK|os.W_OK),'OWNED_KVM_ACCESS_REQUIRED')
  private=Path(tempfile.mkdtemp(prefix='v15pa-',dir='/tmp'));private.chmod(0o700);socket=private/'native';need(len(os.fsencode(socket))<108,'PRIVATE_SOCKET_LENGTH');config=private/'only-null.pa';config.write_text('.fail\nload-module module-native-protocol-unix socket='+str(socket)+' auth-anonymous=1\nload-module module-null-sink sink_name=ci_silent rate=48000 channels=2\nset-default-sink ci_silent\nset-default-source ci_silent.monitor\n')
  b.STATE['privatePulseRuntime']={'path':str(private),'uid':private.stat().st_uid,'mode':private.stat().st_mode&0o777,'socketBytes':len(os.fsencode(socket))};env=os.environ.copy();env.update(XDG_RUNTIME_DIR=str(private),PULSE_SERVER='unix:'+str(socket),PULSE_SINK='ci_silent',PULSE_SOURCE='ci_silent.monitor')
  pulse=b.own_process(['pulseaudio','-n','--daemonize=no','--exit-idle-time=-1','--log-level=debug','--file='+str(config.resolve())],'pulse',env=env);deadline=time.monotonic()+10
  while not socket.exists()and pulse.poll()is None and time.monotonic()<deadline:time.sleep(.1)
  need(socket.exists(),'PRIVATE_PULSE_NOT_READY');routing=b.audio_acquire.native('routing.py')
  def graph(label):
   routing.remote_private(b.STATE,env,routing.proc_record);rows={k:b.audio_acquire.json_command(b,env,k,label+'-'+k)for k in ['sinks','sources','sink-inputs','source-outputs']};routing.private_devices(rows['sinks'],rows['sources']);return rows
  b.STATE['prelaunchGraph']=graph('prelaunch');xvfb=start_private_xvfb(b,private,env)
  ports,_,_=b.run(['ss','-ltn'],'control_ports_before');need(not any(re.search(r':(?:5037|5554|5555|8554)\s',line)for line in ports.decode().splitlines()),'PREEXISTING_CONTROL_LISTENER_REFUSED');b.run([b.ADB,'start-server'],'start_owned_adb_server');b.STATE['ownedADBServerStarted']=True;b.save();devices,_,_=b.run([b.ADB,'devices'],'adb_devices_before');need(not any(x.strip()for x in devices.decode().splitlines()[1:]),'EXISTING_ADB_DEVICE_REFUSED')
  name='ci_pulse_probe_'+str(os.getpid());avd_home=Path(tempfile.mkdtemp(prefix='v16avd-',dir='/tmp'));avd_home.chmod(0o700);env['ANDROID_AVD_HOME']=str(avd_home);b.STATE.update(ownedAVD=name,ownedAVDHome=str(avd_home));b.save()
  b.run([str(b.SDK/'cmdline-tools/latest/bin/avdmanager'),'create','avd','--name',name,'--package','system-images;android-35;google_apis_playstore;x86_64','--device','pixel_6'],'create_owned_avd',timeout=30,env=env);need((avd_home/(name+'.ini')).is_file(),'OWNED_AVD_DISCOVERY_INI_REQUIRED');listed,_,_=b.run([str(b.SDK/'emulator/emulator'),'-list-avds'],'owned_avd_list',env=env);need(listed.decode().splitlines()==[name],'OWNED_AVD_DISCOVERY_REQUIRED')
  original=[str(b.SDK/'emulator/emulator'),'-avd',name,'-no-window','-no-snapshot','-accel','on','-camera-back','none','-camera-front','none','-port','5554',audio_flag];command=debug_args(routing.future_emulator_args(original,help_text),help_text)
  routing.remote_private(b.STATE,env,routing.proc_record);b.STATE['headlessComparisonEmulatorArgs']=command;command=windowed_emulator_args(command,help_text);b.STATE['diagnosticEmulatorArgs']=command;loader_trace=b.OUT/'loader.private';need(not loader_trace.exists(),'FRESH_OWNED_TRACE_REQUIRED');command=trace_command(command,trace_help.decode(),loader_trace);b.STATE['diagnosticTracerArgs']=command;b.STATE['diagnosticWindowSeconds']=30;b.save();emu=b.own_process(command,'emulator',env=env);began=time.monotonic();deadline=began+30;observations=[]
  while emu.poll()is None and time.monotonic()<deadline:
   b.remaining(1)
   if not observations and time.monotonic()-began>=3:
    observations.append({'atBootSeconds':time.monotonic()-b.START,'processes':env_snapshot(b,emu,env)})
   time.sleep(.1)
  need(emu.poll() is None and observations,'OWNED_TRACED_STARTUP_WINDOW_REQUIRED');observations.append({'atBootSeconds':time.monotonic()-b.START,'processes':env_snapshot(b,emu,env)});b.STATE['privateDisplayPostStartup']=verify_owned_display(b,xvfb,b.STATE['privateDisplay']['number']);b.STATE['postStartupClients']=b.audio_acquire.json_command(b,env,'clients','post-startup-clients')
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
      observation=retain_loader_observation(b,loader_trace,socket);b.STATE['loaderObservation']=observation;b.STATE['windowedBackendObservation']=windowed_backend_facts(b,observation,str(socket))
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
     try:b.STATE['privateDisplayCleanup']=cleanup_private_display(b)
     except (OSError,ValueError)as error:
      code=2;b.STATE['privateDisplayCleanup']={'verified':False,'errorClass':type(error).__name__};b.STATE.setdefault('reason','PRIVATE_DISPLAY_CLEANUP_UNVERIFIED')
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
