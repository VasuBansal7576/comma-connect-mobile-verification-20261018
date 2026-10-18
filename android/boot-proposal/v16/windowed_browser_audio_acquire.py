"""Explicit hosted Android OS-mix acquisition. Own native inputs; fixed read-only CDP only."""
import hashlib,importlib.util,json,os,shlex,shutil,sys,time
from pathlib import Path
import audio_route_gate as gate
import native_audio_input as ui
import readonly_browser_audio_bridge_v16 as bridge
import unpack_android_browser_carrier as unpack
import windowed_pulse_recorder
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
PINS={'capture_monitor.c':'e7a2a0388df1a2f85272e0f2b03e84f8c537174c994ef766e3e8e826907a0509','routing.py':'9f1a25697b1c145dde14419da577b199c59712feadb191e6d671a75bbc482b59','validate_native.py':'5b2732b81c187de3976f3dabfbac1f3115c5f272c4ae039e40cc056523da2c5a'}
def sha(data):return hashlib.sha256(data).hexdigest()
def native(name):
 p=REPO/'audio/native-pulse'/name
 if sha(p.read_bytes())!=PINS[name]:raise ValueError('Exact original native helper required: '+name)
 spec=importlib.util.spec_from_file_location('v16_audio_'+p.stem,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def private_env(b):
 p=Path(b.STATE['privatePulseRuntime']['path']);env=os.environ.copy();env.update(XDG_RUNTIME_DIR=str(p),PULSE_SERVER='unix:'+str(p/'native'),PULSE_SINK='ci_silent',PULSE_SOURCE='ci_silent.monitor');return env

def json_command(b,env,kind,label):
 sequence=b.STATE.get('audioPulseCommandSequence',0)+1;b.STATE['audioPulseCommandSequence']=sequence
 data,_,cut=b.run(['pactl','--format=json','list',kind],label+'-'+str(sequence),timeout=4,limit=2*1024*1024,env=env)
 if cut:raise b.Refused('PULSE_GRAPH_TRUNCATED')
 (b.OUT/('audio-pulse-'+str(sequence)+'.json')).write_bytes(data)
 return json.loads(data)

def before_emulator_launch(b,original,actual_help,env):
 if '--explicit-v16-browser-audio'not in sys.argv or b.CAP!=900:raise b.Refused('EXPLICIT_AUDIO900_ONLY')
 r=native('routing.py');s=json_command(b,env,'sinks','audio-prelaunch-sinks');m=json_command(b,env,'sources','audio-prelaunch-sources')
 args=gate.audio_arguments(original,actual_help,b.STATE,s,m,env,r.proc_record,r,explicit_audio_mode=True)
 b.STATE['explicitAudioBeforeEmulator']={'documentedDisableFlagOnlyRemoved':True,'originalArgs':original,'audioArgs':args,'nativeRoutingSHA256':PINS['routing.py'],'privateDirectoryPrefix':'v15pa-'};b.save();return args

class Driver:
 def __init__(self,b):
  self.b=b;self.seq=ui.Sequence();self.env=private_env(b);self.r=native('routing.py');self.out=b.OUT/'audio';self.out.mkdir(exist_ok=False);self.n=0;self.origin=None;self.active_deadline=None;self.collector=None;self.recorder=None;self.graph_receipts=[];self.actions=[];self.capture_wait=False;self.capture_began=None;self.start_confirmed=False;self.failure=None
  self.emulators=[x for x in b.STATE['children']if x.get('kind')=='emulator']
  if len(self.emulators)!=1:raise b.Refused('ONE_ORIGINAL_EMULATOR_REQUIRED')
  self.emulator=self.emulators[0];self.r.require_owned(self.emulator,self.r.proc_record)
 def check(self):
  self.b.remaining(1)
  if self.seq.cancelled:raise self.b.Refused('AUDIO_ACQUISITION_CANCELLED')
  if self.active_deadline is not None and time.monotonic()>=self.active_deadline:raise self.b.Refused('ORIGINAL_ACTIVE130_DEADLINE')
  self.r.require_owned(self.emulator,self.r.proc_record)
  if self.collector is not None and not self.capture_wait and self.collector.poll()is not None:raise self.b.Refused('COLLECTOR_ENDED_DURING_SOURCE_PHASE')
 def observe(self,carrier=False):
  self.check();self.n+=1;extra=[];b=self.b
  def adb(args):
   self.check();data,_,cut=b.run([b.ADB]+args,'audio-readonly-adb-'+str(self.n),timeout=5,limit=1024*1024,retain_stdout=False)
   if cut:raise b.Refused('AUDIO_READONLY_ADB_TRUNCATED')
   return data
  def evaluate(endpoint):
   self.check();node=shutil.which('node')
   if not node:raise b.Refused('EXISTING_NODE_REQUIRED')
   data,_,cut=b.run([node,str(HERE/'read_audio_state_v16.mjs'),endpoint],'audio-fixed-readonly-'+str(self.n),timeout=12,limit=32*1024*1024,retain_stdout=False)
   if cut:raise b.Refused('AUDIO_DOM_TRUNCATED')
   values=bridge.decode_json(data)
   if not isinstance(values,list)or len(values)!=14:raise b.Refused('FIXED_AUDIO_DOM_SCHEMA')
   no_product,close_count,status,quick=values[10:]
   if type(no_product)is not bool or type(close_count)is not int or close_count<0 or any(x is not None and not isinstance(x,str)for x in [status,quick]):raise b.Refused('ACTUAL_DOM_AUDIO_FIELDS_REQUIRED')
   extra.append({'productAbsent':no_product,'closeCount':close_count,'osStatus':status or'','quickStatus':quick or'','frozenStatus':values[9] or'','packedStatus':values[8] or''});return json.dumps(values[:10]).encode()
  target=self.out/('readonly-'+str(self.n));result=bridge.observe_owned_pwa(adb,bridge.local_http_get,evaluate,target,owned_vm_guard=True,require_carrier=carrier,allow_closed_device=self.start_confirmed)
  self.check()
  if result['status']not in ['CURRENT_DOCUMENT_OBSERVATION_RETAINED_NO_CARRIER','ORIGINAL_READONLY_CARRIER_RETAINED_NOT_VALIDATED']or not result['cleanupVerified']or len(extra)!=1:raise b.Refused('ACTUAL_BROWSER_READONLY_OBSERVATION_REFUSED')
  current=result['observation']['timeOrigin']
  if self.origin is None:self.origin=current
  if current!=self.origin:raise b.Refused('AUDIO_CURRENT_DOCUMENT_CHANGED')
  result['fixedAudioFacts']=extra[0];(target/'audio-facts.json').write_text(json.dumps(result,indent=2)+'\n');return extra[0],target,result
 def tap(self,label):
  self.seq.allow(label);self.observe();b=self.b
  for scroll in range(4):
   self.check();fresh,xml,png=b.retained_fresh_input('audio-'+str(self.n)+'-'+str(scroll));target=ui.resolve(xml,png,label);age=b.input_age(fresh);self.check()
   action={'label':label,'target':target,'xmlSHA256':sha(xml),'pngSHA256':sha(png),'nativeSnapshotLabel':fresh['label'],'ageSeconds':age,'atBootSeconds':time.monotonic()-b.START,'sourceInputIsNative':True,'dispatched':False};self.actions.append(action)
   if target['kind']=='scroll':
    if scroll>=3:raise b.Refused('THREE_NATIVE_SCROLLS_EXHAUSTED')
    b.STATE['UIInputCommands']+=1;b.save();b.run([b.ADB,'-s',b.SERIAL,'shell','input','swipe',str(target['x']),str(target['fromY']),str(target['x']),str(target['toY']),'300'],'audio-known-scroll',timeout=5);action['dispatched']=True;continue
   self.seq.dispatched_once(label) # Reserve before command: no retries even if dispatch outcome is unknown.
   b.STATE['UIInputCommands']+=1;b.save();b.run([b.ADB,'-s',b.SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'audio-native-tap',timeout=5);action['dispatched']=True;self.save();return
  raise b.Refused('NATIVE_AUDIO_LABEL_NOT_ACQUIRED')
 def save(self):
  (self.out/'acquisition.json').write_text(json.dumps({'schema':'actual-v16-android-browser-pulse-acquisition-v1','acquisitionMode':'browser','documentTimeOrigin':self.origin,'actions':self.actions,'graphReceipts':self.graph_receipts,'orderedActions':self.seq.dispatched,'cancelled':self.seq.cancelled,'failure':self.failure,'captureACK':self.seq.ack,'productCloseObserved':self.seq.closed,'sourceCleanupObserved':self.seq.clean,'PWAVerified':False,'functionalPassClaimed':False},indent=2)+'\n')
 def graph(self,require_output):
  self.check();rows={k:json_command(self.b,self.env,k,'audio-graph-'+k)for k in ['sinks','sources','sink-inputs','source-outputs']}
  self.r.remote_private(self.b.STATE,self.env,self.r.proc_record);si,mo=self.r.private_devices(rows['sinks'],rows['sources'])
  inputs=self.r.input_bindings(rows['sink-inputs'],si,self.emulator,self.r.proc_record,require_nonempty=require_output)
  recorder,classification=windowed_pulse_recorder.bind(rows['source-outputs'],mo,self.recorder,self.r,b=self.b,emulator=self.emulator)
  receipt={'sourceOutputClassification':classification,'hostMonotonic':time.monotonic(),'sinkIndex':si,'monitorIndex':mo,'emulatorOutputs':inputs,'nativeRecorder':recorder,'rows':rows};self.graph_receipts.append(receipt);self.save();return receipt
 def wait(self,predicate,limit,graph=False):
  end=time.monotonic()+limit
  while True:
   self.check()
   if graph:self.graph(False)
   facts,path,receipt=self.observe()
   if time.monotonic()>=end:raise self.b.Refused('ACTUAL_AUDIO_READINESS_TIMEOUT')
   if predicate(facts):return facts,path,receipt
   time.sleep(.2)
 def compile(self):
  b=self.b;source=REPO/'audio/native-pulse/capture_monitor.c'
  if sha(source.read_bytes())!=PINS['capture_monitor.c']:raise b.Refused('ORIGINAL_COLLECTOR_PIN')
  flags,_,cut=b.run(['pkg-config','--cflags','--libs','libpulse'],'audio-pkg-config',timeout=5,limit=8192)
  if cut:raise b.Refused('LIBPULSE_FLAGS_TRUNCATED')
  binary=self.out/'capture_monitor';b.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(binary)]+shlex.split(flags.decode())+['-lm'],'audio-compile',timeout=30)
  b.STATE['audioCollectorBuild']={'sourceSHA256':sha(source.read_bytes()),'binarySHA256':sha(binary.read_bytes())};b.save();return binary.resolve()
 def start_capture(self,binary):
  self.check();b=self.b
  if b.remaining(220)<220:raise b.Refused('INSUFFICIENT_ORIGINAL_WORK_BUDGET_BEFORE_CAPTURE')
  self.capture_began=time.monotonic()
  self.collector=b.own_process([str(binary),'protocol',str(self.out/'system.f32'),str(self.out/'native-journal.jsonl'),str(self.out/'native-summary.json')],'audio-collector',env=self.env)
  self.recorder=self.r.proc_record(self.collector.pid);deadline=time.monotonic()+8
  while True:
   self.check();log=b.OUT/'audio-collector-private.raw'
   if log.exists()and b'CAPTURE_DATA_READY\n'in log.read_bytes():break
   if time.monotonic()>=deadline:raise b.Refused('NO_ACTUAL_NATIVE_DATA_READY')
   time.sleep(.05)
  self.pre_graph=self.graph(True);self.seq.ack=True;self.active_deadline=time.monotonic()+130;self.save()
 def ensure_result(self,label,disclosure):
  self.observe();fresh,xml,png=self.b.retained_fresh_input('audio-result-'+str(self.n))
  try:ui.resolve(xml,png,label)
  except ui.Refused as error:
   if str(error)!='CURRENT_NATIVE_LABEL_ABSENT':raise
   # One state-aware native disclosure tap, only when the actual child is absent.
   self.tap(disclosure)
 def run(self):
  binary=self.compile();facts,_,_=self.observe()
  if facts['closeCount']!=1 or facts['productAbsent']:raise self.b.Refused('CURRENT_PRODUCT_CLOSE_NOT_OBSERVED')
  # Existence of child in actual fresh XML controls expansion; avoid blindly toggling an open dock.
  try:
   fresh,xml,png=self.b.retained_fresh_input('audio-quick-open-check');ui.resolve(xml,png,'Pin actual playlist')
  except ui.Refused as e:
   if str(e)!='CURRENT_NATIVE_LABEL_ABSENT':raise
   self.tap('V16 verification controls')
  self.tap('Pin actual playlist');self.wait(lambda f:'playlist=PINNED assets=6 'in f['osStatus'],20)
  self.tap('Prepare playback');self.wait(lambda f:f['quickStatus'].startswith('READY: native playing and unmuted.'),12)
  self.start_capture(binary);self.tap('Start pilot and run');self.wait(lambda f:f['quickStatus']=='RUNNING: original pilot and product phases armed once.',8,True);self.start_confirmed=True
  self.wait(lambda f:f['productAbsent']and f['closeCount']==0,48,True);self.seq.closed=True
  self.tap('Start bare native');self.wait(lambda f:'bare-native source=LIVE 'in f['osStatus'],8,True)
  self.wait(lambda f:'bare-native source=stopped 'in f['osStatus']and'cleanup=true'in f['osStatus'],25,True);self.seq.clean=True
  self.tap('Export all');self.tap('Freeze');self.wait(lambda f:f['frozenStatus'].startswith('Frozen '),15)
  self.ensure_result('Pack frozen witness','Evidence export');self.tap('Pack frozen witness');self.wait(lambda f:f['packedStatus'].startswith('Packed '),20);_,path,result=self.observe(carrier=True)
  raw=(path/'original-carrier.txt').read_bytes();original,integrity=unpack.unpack(raw,result['observation']['packStatus']);(self.out/'source-frozen.json').write_bytes(original);(self.out/'integrity.json').write_text(json.dumps(integrity,indent=2)+'\n')
  self.active_deadline=None # Native DONE after full source carrier. The original150s collector keeps its own deadline.
  self.capture_wait=True
  end=self.capture_began+175
  while self.collector.poll()is None:
   self.b.remaining(1)
   if time.monotonic()>=end:raise self.b.Refused('NATIVE_COLLECTOR_INDEPENDENT_DEADLINE')
   # Source stopped, but any present output must still belong to the same emulator.
   self.r.remote_private(self.b.STATE,self.env,self.r.proc_record)
   sinks=json_command(self.b,self.env,'sinks','audio-tail-sinks');sources=json_command(self.b,self.env,'sources','audio-tail-sources');si,_=self.r.private_devices(sinks,sources)
   self.r.input_bindings(json_command(self.b,self.env,'sink-inputs','audio-tail-inputs'),si,self.emulator,self.r.proc_record,require_nonempty=False);time.sleep(.5)
  if self.collector.returncode!=0:raise self.b.Refused('NATIVE_COLLECTOR_FAILED')
  summary=json.loads((self.out/'native-summary.json').read_bytes());gate.bind_completed_summary(self.pre_graph,summary)
  v=native('validate_native.py');validation=v.validate((self.out/'system.f32').read_bytes(),summary,[json.loads(x)for x in(self.out/'native-journal.jsonl').read_text().splitlines()])
  (self.out/'native-validation.json').write_text(json.dumps(validation,indent=2)+'\n')
  if not validation['nativeCaptureChecksPass']:raise self.b.Refused('NATIVE_RAW_CALLBACK_PROVENANCE_FAILED')
  self.b.STATE['audioRawAndCarrierAcquired']=True;self.b.STATE['status']='ACTUAL_AUDIO_RAW_CARRIER_ACQUIRED_NUMERIC_AND_CLEANUP_PENDING';self.save();self.b.save()

def acquire(b):
 if b.STATE.get('browserNativeContextObserved')is not True or b.STATE.get('UIInputCommands')!=3 or b.STATE.get('installedPWAStandaloneObserved')is True:raise b.Refused('STOP_NO_ACTUAL_ORIGINAL_CHROME_BROWSER_CONTEXT')
 d=Driver(b)
 try:d.run()
 except BaseException as error:
  d.seq.cancelled=True;d.failure={'name':type(error).__name__,'message':str(error)[:1024]};d.save()
  if isinstance(error,(ui.Refused,bridge.Refused,ValueError)):raise b.Refused(str(error))from error
  raise
 finally:d.save() # Original boot finally handles only its owned groups, ADB and KVM restoration.
