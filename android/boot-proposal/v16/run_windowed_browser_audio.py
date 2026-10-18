"""Explicit hosted windowed browser audio. Only owned emulator/display lifecycle hooks."""
from pathlib import Path
import hashlib,importlib.util,json,os,re,stat,sys
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
PINS={'android/boot-proposal/guard.py': 'cbcf76b8548ccaf80cf0a04b2ae751cf2185e0f5d14d5b22a60c481828599001', 'android/boot-proposal/license-probe/probe.py': '931badff8250857d3bcba8beefe912bb58627be55f3eaaecafb988f25c5805bf', 'android/boot-proposal/run-bounded.py': 'a30fdc2bf9e9da3b51be0a9e37c62c3b338ff8b506f237b9c2d67f01213d0660', 'android/boot-proposal/verify-installed.py': '2ad6734573e686bb40399558c0681fea71b71543bd798049d33a03919272faa3', 'android/boot-proposal/v16/boot.py': '7be62ba21b1c2ac4dc1f153e37f901ae31ce95bb5f6ac96b822a2d689f4d73c6', 'android/boot-proposal/v16/owned_audio_command.py': 'd0742eca9f3fd2e743225cf27a02e19f4457c153f44bb913ae644a587333a01b', 'android/boot-proposal/v16/linux_subreaper_probe.py': 'e4c5769f6dfa3581cd879d6b7703c62085787397901ee6fee296fa3d5e9a5644', 'android/boot-proposal/v16/node_readonly_preflight.py': '594b2e0490fba8c100c3210d4457b272cef7d8e56fbf453b16eb18a51d13be12', 'android/boot-proposal/v16/boot_browser_audio.py': 'aa5d28bbbcf62956ddf9803e585badc425478e567aa15bddf8029cbd613db414', 'android/boot-proposal/v16/browser_audio_acquire.py': '1ca9653b8393c0d86c590f01371c1351f03a19c763b9f28647818b6a22b72709', 'android/boot-proposal/v16/audio_route_gate.py': '470f16165976a0d08f571dc52be3b728a5bf2c23fa452b546a0ea4fdc4bebcb7', 'android/boot-proposal/v16/native_audio_input.py': '0b679a4904910b4c949ad3d7a7a900bc86f5b5301f281e5e6f268dd40a4b4dcc', 'android/boot-proposal/v16/read_audio_state_v16.mjs': '97c33a4411666182c5989abd9dff3500ec792a60bc77d201b106ccd4f1b6af0c', 'android/boot-proposal/v16/readonly_browser_audio_bridge_v16.py': 'b3a6fd4fd5dafd6ac323a3b2b0d09e48fa16b3923378098d371b7ab71c9a2e9d', 'android/boot-proposal/v16/unpack_android_browser_carrier.py': 'd21f529a60cbe0246314e87a9e2f57af71a0bf15d8134546f49f3db0b2cf9110', 'android/boot-proposal/v16/assess_browser_audio_acquisition.py': '1f430eeea617847c0a88fd7be3d67da41b295c75021768263ba27502c660c646', 'android/boot-proposal/v16/scalarize_pulse_pcm.cjs': '8d38d3c1f87b5208016a18e4fde533d5370aa48ee1386f5951b33d2ed4aa4fb2', 'android/boot-proposal/v16/assess_android_browser_pulse.py': 'd5ab0d75f906cafc4b93c37a2438cf6887868f0df6c12e399d74dba1c0e5694a', 'android/boot-proposal/v16/audit_pulse_short.py': '621eca36b3314e9d3e6726367f13fac4e235275876ea16a3df582c1c4f62943f', 'android/boot-proposal/v16/probe_private_pulse_windowed.py': 'c915ebb21ddea45ef8c20cfb133d1cc8f9ff42148dffeec6f97adb7f795ce753', 'android/boot-proposal/v16/numeric/ACQUISITION.json': '4434abf8f06598c318f074bcfa22ee43139ebd207dec203c7290144a3d400ad3', 'android/boot-proposal/v16/numeric/assess-os-recording.py': 'e64a563f3c8ac61045eb8dbd17c25cf5b16714c1324f90f71e2c2b599f6aa923', 'android/boot-proposal/v16/numeric/audit_pcm_zeros.py': 'c45f76908b6cdbfd6eae8d723db270ac261cdb28b7bead1ec3ee696217bb52c7', 'android/boot-proposal/v16/numeric/joint_tones.py': '4a569028fc306798f30612aedb690b2e53bee53db2da928aec15bcec35b32a7a', 'android/boot-proposal/v16/numeric/scalar-core-180.js': '1adaa533a0ff7c709e15c967d39c8d6bd5bdcfbb2dcc8d3d9946b3e7c0061636', 'audio/native-pulse/capture_monitor.c': 'e7a2a0388df1a2f85272e0f2b03e84f8c537174c994ef766e3e8e826907a0509', 'audio/native-pulse/routing.py': '9f1a25697b1c145dde14419da577b199c59712feadb191e6d671a75bbc482b59', 'audio/native-pulse/validate_native.py': '5b2732b81c187de3976f3dabfbac1f3115c5f272c4ae039e40cc056523da2c5a', 'android/boot-proposal/v16/boot_windowed_browser_audio.py': '51456a002ca76fe8ceab9a2953974f4638eebd1f2b0f66a69dcec093615b0102', 'android/boot-proposal/v16/windowed_browser_audio_acquire.py': '9f33beaa5f5824461f7c4d25206e49de559770bb11c3d6518edc717a27ecc373', 'android/boot-proposal/v16/windowed_pulse_recorder.py': '78b88d40054eab9103bdd1b717908bb55e38770aaee3f502f711e7ea67b9d83b'}
FLAG='--explicit-v16-windowed-browser-audio'
ORIGINAL_FLAGS=['--explicit-v16-browser-audio','--approve-chrome-124-terms-without-account','--continue-owned-v16-lab-after-privacy-notice']
HEADFUL_SHA='2924da89cef31402e0379b643a73e4d60097239323095730fc8a78aa55b082f6'
class Refused(ValueError):pass
def need(ok,reason):
 if not ok:raise Refused(reason)
def source_closure(repo=REPO):
 for rel,digest in PINS.items():
  p=repo/rel;need(p.is_file()and not p.is_symlink()and hashlib.sha256(p.read_bytes()).hexdigest()==digest,'EXACT_WINDOWED_BROWSER_DEPENDENCY_REQUIRED:'+rel)
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
def authority_identity(p):
 info=p.lstat();need(stat.S_ISREG(info.st_mode)and not p.is_symlink()and info.st_uid==os.getuid()and info.st_mode&0o777==0o600,'EXACT_PRIVATE_AUTHORITY_FILE_REQUIRED')
 return {'path':str(p),'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,'mode':info.st_mode,'size':info.st_size,'mtimeNs':info.st_mtime_ns}
def remove_authority_files(b):
 need(b.STATE.get('ownedChildCleanupVerified')is True and b.STATE.get('privateDisplayCleanup',{}).get('verified')is True,'AUTHORITY_CLEANUP_REQUIRES_GROUPS_AND_DISPLAY_ABSENT')
 for record in b.STATE.get('windowedAuthorityFiles',[]):
  p=Path(record['path'])
  if not p.exists()and not p.is_symlink():continue
  need(authority_identity(p)==record,'PRIVATE_AUTHORITY_CHANGED_NO_REMOVAL');p.unlink()
 return {'verified':True,'cookieValuesNeverRetained':True,'boundFilesAbsent':True}
class Lifecycle:
 def __init__(self,b,display):
  self.b=b;self.display=display;self.server=None;self.env=None;self.headful=None
  self.original_before=b.audio_acquire.before_emulator_launch
  self.original_guard=b.listener_guard
  self.original_cleanup=b.cleanup
 def headful_identity(self):
  b=self.b;p=(b.SDK/'emulator/qemu/linux-x86_64/qemu-system-x86_64').resolve()
  need(p.is_file()and not p.is_symlink(),'ORIGINAL_HEADFUL_BINARY_REQUIRED');before=p.stat();digest=hashlib.sha256();count=0
  with p.open('rb')as stream:
   while True:
    b.remaining(1);chunk=stream.read(1048576)
    if not chunk:break
    digest.update(chunk);count+=len(chunk)
  after=p.stat();need(count==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)and digest.hexdigest()==HEADFUL_SHA,'EXACT_MEASURED_HEADFUL_BINARY_REQUIRED')
  raw,_,cut=b.run(['readelf','--dynamic','--wide',str(p)],'windowed_headful_dynamic',timeout=4,limit=65536)
  need(not cut and re.search(rb'\(NEEDED\).*Shared library: \[libpulse\.so[^\]]*\]',raw),'ORIGINAL_HEADFUL_PULSE_DEPENDENCY_REQUIRED')
  return {'path':str(p),'sha256':digest.hexdigest(),'bytes':count,'ELFNeedsPulse':True}
 def before_launch(self,b,original,actual_help,env):
  try:return self._before_launch(b,original,actual_help,env)
  except (Refused,self.display.Refused)as error:raise b.Refused(str(error))from error
 def _before_launch(self,b,original,actual_help,env):
  need(b is self.b and self.server is None,'ONE_ORIGINAL_WINDOWED_EMULATOR_LAUNCH_REQUIRED')
  # Original private-sink proof and removal of the documented audio-disable flag happen first.
  audio=self.original_before(b,original,actual_help,env)
  self.headful=self.headful_identity();private=Path(b.STATE['privatePulseRuntime']['path'])
  need(private.is_dir()and not private.is_symlink()and private.stat().st_uid==os.getuid()and private.stat().st_mode&0o777==0o700,'ORIGINAL_PRIVATE_PULSE_DIRECTORY_REQUIRED')
  auth=[private/'Xauthority',private/'empty.Xauthority']
  need(not any(p.exists()or p.is_symlink()for p in auth),'NEW_PRIVATE_AUTHORITY_FILES_REQUIRED')
  self.env=env
  try:self.server=self.display.start_private_xvfb(b,private,env)
  finally:
   b.STATE['windowedAuthorityFiles']=[authority_identity(p)for p in auth if p.exists()or p.is_symlink()];b.save()
  command=self.display.windowed_emulator_args(audio,actual_help)
  b.STATE['windowedBrowserLifecycle']={'mode':'BROWSER_WINDOWED_PRIVATE_XVFB','originalBrowserFlagsPreserved':True,'onlyGraphicsChange':'Remove documented -no-window after original private audio-route proof','headfulBinary':self.headful,'actualEmulatorArgs':command,'PWAVerified':False,'sourceProtocolModified':False};b.save();return command
 def before_native_inputs(self):
  try:return self._before_native_inputs()
  except (Refused,self.display.Refused)as error:raise self.b.Refused(str(error))from error
 def _before_native_inputs(self):
  self.original_guard();b=self.b
  need(self.server is not None and self.env is not None and self.headful is not None,'WINDOWED_DISPLAY_MUST_PRECEDE_NATIVE_INPUT')
  proof=self.display.verify_owned_display(b,self.server,b.STATE['privateDisplay']['number'])
  rows=[r for r in b.STATE['children']if r.get('kind')=='emulator'];need(len(rows)==1,'ONE_OWNED_EMULATOR_GROUP_REQUIRED')
  processes=[p for p,_ in b.CHILDREN if p.pid==rows[0]['pid']];need(len(processes)==1,'CURRENT_ORIGINAL_EMULATOR_OBJECT_REQUIRED')
  observed=self.display.env_snapshot(b,processes[0],self.env)
  headful=[r for r in observed if r.get('actualExecutable')==self.headful['path']];need(len(headful)==1,'ONE_ACTUAL_OWNED_HEADFUL_PROCESS_REQUIRED');process=headful[0]
  selected=process.get('selectedPrivateEnvironment',{})
  need(set(selected)==set(self.display.ENV_KEYS)and all(v.get('present')is True and v.get('matchesExpected')is True for v in selected.values()),'ACTUAL_HEADFUL_PRIVATE_ENVIRONMENT_REQUIRED')
  need(any(re.search(r'/libpulse\.so(?:\.|$)',p)for p in process.get('pulseLibraryPaths',[])),'ACTUAL_HEADFUL_PULSE_LIBRARY_MAPPING_REQUIRED')
  clients=b.audio_acquire.json_command(b,self.env,'clients','windowed-actual-clients')
  need(isinstance(clients,list)and any(isinstance(c,dict)and isinstance(c.get('properties'),dict)and c['properties'].get('application.process.id')==str(process['pid'])for c in clients),'ACTUAL_PRIVATE_DAEMON_HEADFUL_CLIENT_REQUIRED')
  current=b.group_member(process['pid'])
  need(current and current['pid']==process['pid']and current['startTicks']==process['startTicks']and current['uid']==os.getuid()and current['sid']==rows[0]['pid']and current['pgid']==rows[0]['pid']and current['state']not in ['Z','X','x'],'CURRENT_OWNED_HEADFUL_IDENTITY_REQUIRED')
  b.STATE['windowedSourceBackend']={'verifiedBeforeNativeChromeInput':True,'headfulPID':process['pid'],'headfulStartTicks':process['startTicks'],'currentHeadfulIdentity':current,'headfulBinary':self.headful,'processes':observed,'privateDisplay':proof,'privateDaemonClientPIDMatched':True,'originalCaptureGraphStillRequired':True,'priorDiagnosticTraceIsNotCurrentTrace':True,'audioAcceptance':False};b.save()
 def cleanup(self):
  b=self.b
  try:self.original_cleanup()
  finally:
   try:
    b.STATE['privateDisplayCleanup']=self.display.cleanup_private_display(b)
    b.STATE['windowedAuthorityCleanup']=remove_authority_files(b)
   except (OSError,ValueError)as error:
    b.STATE['windowedAuthorityCleanup']={'verified':False,'errorClass':type(error).__name__};raise
   finally:b.save()
 def install(self):
  # These three host-owned lifecycle seams never change Driver, native inputs, source or measurement APIs.
  self.b.audio_acquire.before_emulator_launch=self.before_launch
  self.b.listener_guard=self.before_native_inputs
  self.b.cleanup=self.cleanup

def main(argv=None):
 args=sys.argv[1:]if argv is None else argv
 need(args in [['--verify-source-only'],['--cleanup'],[FLAG]+ORIGINAL_FLAGS[1:]],'EXACT_EXPLICIT_WINDOWED_BROWSER_FLAGS_REQUIRED')
 source_closure()
 if args==['--verify-source-only']:return 0
 need(os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('RUNNER_OS')=='Linux'and os.environ.get('RUNNER_ARCH')=='X64'and os.uname().sysname=='Linux'and os.uname().machine=='x86_64','OWNED_HOSTED_LINUX_X64_REQUIRED')
 sys.path.insert(0,str(HERE))
 display=load('windowed_display_lifecycle',HERE/'probe_private_pulse_windowed.py')
 b=load('owned_windowed_browser_boot',HERE/'boot_windowed_browser_audio.py')
 if args==['--cleanup']:
  receipt=b.OUT/'receipt.json';need(receipt.is_file()and not receipt.is_symlink()and receipt.stat().st_size<=4194304,'ORIGINAL_WINDOWED_ACQUISITION_RECEIPT_REQUIRED')
  value=json.loads(receipt.read_text());need(value.get('windowedRequested')is True,'ORIGINAL_WINDOWED_MODE_RECEIPT_REQUIRED')
 lifecycle=Lifecycle(b,display);lifecycle.install()
 b.STATE.update(windowedRequested=True,windowedAcquisitionScope='Hosted Chrome browser output; original capture/nonce/phase/short gates required; no installed-PWA or physicalPhone claim.')
 previous=sys.argv
 try:
  sys.argv=[str(HERE/'boot_windowed_browser_audio.py')]+(['--cleanup']if args==['--cleanup']else ORIGINAL_FLAGS)
  result=b.main()
 finally:sys.argv=previous
 if args==['--cleanup']:
  need(b.STATE.get('ownedChildCleanupVerified')is True and b.STATE.get('privateDisplayCleanup',{}).get('verified')is True and b.STATE.get('windowedAuthorityCleanup',{}).get('verified')is True,'WINDOWED_OWNED_CLEANUP_UNVERIFIED');return result
 need(result==0 and b.STATE.get('windowedSourceBackend',{}).get('verifiedBeforeNativeChromeInput')is True and b.STATE.get('audioRawAndCarrierAcquired')is True and b.STATE.get('acquisitionMode')=='browser'and b.STATE.get('PWAVerified')is not True and b.STATE.get('privateDisplayCleanup',{}).get('verified')is True and b.STATE.get('windowedAuthorityCleanup',{}).get('verified')is True,'ORIGINAL_WINDOWED_BROWSER_SOURCE_CAPTURE_INCOMPLETE')
 return result
if __name__=='__main__':raise SystemExit(main())
