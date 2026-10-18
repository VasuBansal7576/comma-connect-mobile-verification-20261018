"""Explicit post-install native functional acquisition; no executable boot entrypoint.
Only own native ADB taps/swipes change state. CDP has a sealed read-only expression.
"""
import hashlib,json,shutil,sys,time,xml.etree.ElementTree as ET
from pathlib import Path
import native_functional_input as ui
import readonly_functional_bridge as bridge
import installed_target_selector_v16_measurement as selection
import functional_contracts as contract
HERE=Path(__file__).resolve().parent
INSTALLED_SELECTION_PINS={'installed_target_selector_v16_measurement.py': '7a0987ea22b49a0ccf0d7b610d856e1ebcd00251d6332754ca26ecd945b07c1a', 'read_installed_identity_v16.mjs': '4aa8ff0c57feb24bbec01735bd3f19542586f353e1455af64653d3b43096708a', 'readonly_functional_bridge.py': '098f061dfa5875687c726409f11fcb4a7287031c39aba8e0d9e704d62c50ad5b'}
MODES={'url','eof','failure'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def installed_document_origin(state):
 r=state.get('readonlyInstalledObservation',{});o=r.get('observation',{})
 contract.need(state.get('installedPWAStandaloneObserved')is True and r.get('cleanupVerified')is True and r.get('status')=='CURRENT_DOCUMENT_OBSERVATION_RETAINED_NO_CARRIER','ORIGINAL_INSTALLED_READONLY_RECEIPT_REQUIRED')
 contract.need(o.get('standaloneNavigator')is False and o.get('standaloneDisplay')is True and o.get('href')==bridge.URL and o.get('entry')==bridge.ENTRY and o.get('badge')==bridge.BADGE,'ORIGINAL_INSTALLED_CURRENT_PINS_REQUIRED')
 origin=contract.number(o.get('timeOrigin'));contract.need(0<origin<1e15,'FINITE_POSITIVE_INSTALLED_DOCUMENT_ORIGIN');return origin
class Driver:
 def __init__(self,b,mode):
  if mode not in MODES or '--explicit-v16-functional-'+mode not in sys.argv:raise b.Refused('EXPLICIT_FUNCTIONAL_MODE_REQUIRED')
  if b.STATE.get('installedPWAStandaloneObserved')is not True:raise b.Refused('ACTUAL_INSTALLED_STANDALONE_REQUIRED')
  b.verified_current_icon_launch()
  if b.remaining(360)<360:raise b.Refused('FUNCTIONAL360_WORK_RESERVE_REQUIRED')
  self.b=b;self.mode=mode;self.out=b.OUT/('functional-'+mode);self.out.mkdir(exist_ok=False);self.phase_limit=480 if mode=='url'else 300;self.deadline=min(time.monotonic()+self.phase_limit,b.START+b.CAP-80);self.n=0;self.origin=installed_document_origin(b.STATE);self.actions=[];self.snapshots={};self.claim=None;self.failure=None
  self.emulators=[r for r in b.STATE.get('children',[])if r.get('kind')=='emulator'and r.get('startTicks')and b.process_ticks(r['pid'])==r['startTicks']]
  if len(self.emulators)!=1 or not b.STATE.get('ownedADBServerStarted'):raise b.Refused('CURRENT_OWN_VM_ADB_REQUIRED')
 def check(self):
  self.b.remaining(1)
  if time.monotonic()>=self.deadline:raise self.b.Refused('FUNCTIONAL_ABSOLUTE_PHASE_DEADLINE')
  e=self.emulators[0]
  if self.b.process_ticks(e['pid'])!=e['startTicks']:raise self.b.Refused('ORIGINAL_OWN_EMULATOR_CHANGED')
 def save(self):
  (self.out/'acquisition.json').write_text(json.dumps({'schema':'v16-android-native-functional-acquisition-v1','mode':self.mode,'phaseOperationalLimitSeconds':self.phase_limit,'actions':self.actions,'snapshots':self.snapshots,'claim':self.claim,'failure':self.failure,'functionalPassClaimed':False,'audioMeasured':False,'physicalPhoneEquivalent':False},indent=2)+'\n')
 def observe(self,carrier=False,require_same_document=True):
  self.check();self.n+=1;extra=[];b=self.b
  for name,digest in INSTALLED_SELECTION_PINS.items():
   if sha((HERE/name).read_bytes())!=digest:raise b.Refused('EXACT_INSTALLED_MEASUREMENT_SELECTOR_REQUIRED')
  def adb(args):
   self.check();data,_,cut=b.run([b.ADB]+args,'functional-readonly-adb-'+str(self.n),timeout=5,limit=1024*1024,retain_stdout=False)
   if cut:raise b.Refused('FUNCTIONAL_ADB_TRUNCATED')
   return data
  def evaluate(endpoint,seconds=12):
   self.check();node=shutil.which('node')
   if not node:raise b.Refused('EXISTING_NODE_REQUIRED')
   data,_,cut=b.run([node,str(HERE/'read_functional_state.mjs'),endpoint],'functional-fixed-readonly-'+str(self.n),timeout=min(12,seconds),limit=32*1024*1024,retain_stdout=False)
   if cut:raise b.Refused('FUNCTIONAL_DOM_TRUNCATED')
   values=bridge.decode_json(data)
   if not isinstance(values,list)or len(values)!=13 or any(v is not None and not isinstance(v,str)for v in values[10:]):raise b.Refused('FIXED_FUNCTIONAL_DOM_SCHEMA')
   extra.append({'nativeReportText':values[10],'nativeFreezeStatus':values[11],'nativeRestoreStatus':values[12]});return json.dumps(values[:10]).encode()
  identity_count=[0]
  def identity_evaluate(endpoint,seconds):
   self.check();node=shutil.which('node')
   if not node:raise b.Refused('EXISTING_NODE_REQUIRED')
   identity_count[0]+=1
   data,_,cut=b.run([node,str(HERE/'read_installed_identity_v16.mjs'),endpoint],'functional-target-identity-'+str(self.n)+'-'+str(identity_count[0]),timeout=min(10,seconds),limit=1024*1024,retain_stdout=False)
   if cut:raise b.Refused('INSTALLED_MEASUREMENT_IDENTITY_TRUNCATED')
   return data
  def select_installed(version,targets,port,evidence):
   def list_targets(seconds):
    self.check();return bridge.decode_json(bridge.local_http_get(port,'/json/list',min(3,seconds)),1024*1024)
   try:
    return selection.select(version,targets,port,read_identity=identity_evaluate,read_full=evaluate,list_targets=list_targets,decode=bridge.decode_json,validate_target=lambda v,rows,p:bridge.browser_and_target(v,rows,p,False),validate_full=lambda value:bridge.validate_observation(value,carrier,False),evidence=evidence,allow_distinct_owned_urls=True,source_profile='functional')
   except selection.Refused as error:raise bridge.Refused(str(error))
  target=self.out/('readonly-'+str(self.n));r=bridge.observe_owned_pwa(adb,bridge.local_http_get,evaluate,target,owned_vm_guard=True,require_carrier=carrier,installed_selector=select_installed)
  self.check()
  if r['status']not in ['CURRENT_DOCUMENT_OBSERVATION_RETAINED_NO_CARRIER','ORIGINAL_READONLY_CARRIER_RETAINED_NOT_VALIDATED']or r['cleanupVerified']is not True or len(extra)!=1:raise b.Refused('ACTUAL_FUNCTIONAL_READONLY_REFUSED')
  o=r['observation']
  if require_same_document and self.origin is not None and o['timeOrigin']!=self.origin:raise b.Refused('FUNCTIONAL_DOCUMENT_CHANGED')
  self.origin=o['timeOrigin'];o.update(extra[0]);(target/'functional-facts.json').write_text(json.dumps(o,indent=2)+'\n');return o,target
 def wait(self,predicate,seconds=20,new_document=False):
  deadline=min(time.monotonic()+seconds,self.deadline);last=None
  while time.monotonic()<deadline:
   last=self.observe(require_same_document=not new_document)
   if time.monotonic()>=deadline:raise self.b.Refused('FUNCTIONAL_READINESS_NOT_ACQUIRED')
   if predicate(last[0]):return last
   time.sleep(.2)
  raise self.b.Refused('FUNCTIONAL_READINESS_NOT_ACQUIRED')
 def tap(self,label,new_document=False):
  if label=='Download':raise self.b.Refused('EVIDENCE_CHILD_IS_PRESENCE_ONLY_NEVER_DOWNLOAD')
  self.observe();b=self.b
  for scroll in range(4):
   self.check()
   if scroll:self.observe()
   fresh,xml,png=b.retained_fresh_input('functional-'+str(self.n)+'-'+str(len(self.actions)))
   try:target=ui.resolve(xml,png,label)
   except ui.Refused as error:
    if label!='Menu'or str(error)!='NATIVE_CLICKABLE_ANCESTOR_REQUIRED':raise
    target=ui.offscreen_menu_reveal(xml,png)
   age=b.input_age(fresh);self.check()
   action={'label':label,'target':target,'nativeSnapshotLabel':fresh['label'],'xmlSHA256':sha(xml),'pngSHA256':sha(png),'captureStartMonotonic':fresh['captureStartMonotonic'],'ageSeconds':age,'documentTimeOriginBefore':self.origin,'inputOrdinal':b.STATE.get('UIInputCommands',0)+1,'attempts':1,'nativeInput':True,'commandCompleted':False};self.actions.append(action);self.save()
   if target['kind']=='scroll':
    if scroll>=3:raise b.Refused('THREE_FUNCTIONAL_NATIVE_SCROLLS_EXHAUSTED')
    b.STATE['UIInputCommands']+=1;b.save();b.input_age(fresh);self.check();b.run([b.ADB,'-s',b.SERIAL,'shell','input','swipe',str(target['x']),str(target['fromY']),str(target['x']),str(target['toY']),'300'],'functional-known-scroll',timeout=5);action['commandCompleted']=True;self.save();continue
   # Reserve before dispatch. No input retry if outcome is unknown.
   b.STATE['UIInputCommands']+=1;b.save();b.input_age(fresh);self.check();b.run([b.ADB,'-s',b.SERIAL,'shell','input','tap',str(target['x']),str(target['y'])],'functional-native-tap',timeout=5);action['commandCompleted']=True;self.save()
   return self.observe(require_same_document=not new_document)
  raise b.Refused('FUNCTIONAL_NATIVE_TARGET_UNACQUIRED')
 def present(self,label):
  self.observe();fresh,xml,png=self.b.retained_fresh_input('functional-presence-'+str(self.n))
  self.b.input_age(fresh);self.check();return ui.observed_label_presence(xml,png,label)
 def ensure(self,label,disclosure):
  if not self.present(label):self.tap(disclosure)
 def export_panel(self):
  self.ensure('Evidence export','V16 verification controls')
  # Quick Freeze AND Pack can be outside Evidence; original Download stays inside it.
  self.ensure('Download','Evidence export')
  if not self.present('Download'):raise self.b.Refused('ACTUAL_EVIDENCE_CHILD_NOT_ACQUIRED')
 def compact_export(self):
  self.ensure('Evidence export','V16 verification controls')
  if self.present('Download'):self.tap('Evidence export')
  if self.present('Download'):raise self.b.Refused('EVIDENCE_MUST_BE_NATIVE_CLOSED_FOR_FREEZE')
  if not self.present('Freeze')or not self.present('Pack frozen witness'):raise self.b.Refused('ORIGINAL_COMPACT_EXPORT_CONTROLS_UNACQUIRED')
 def close_declared_navigation_if_open(self):
  if self.present('Browser Back'):
   self.tap('Declared browser navigation')
   if self.present('Browser Back'):raise self.b.Refused('DECLARED_NAVIGATION_STILL_EXPOSED')
 def current_menu(self,o):
  if o['href']!=bridge.ORIGIN+'/r?candidate=v16'or o['entry']is not None or o['badge']!=bridge.BADGE:return False
  fresh,xml,png=self.b.retained_fresh_input('functional-current-menu-'+str(self.n));context=ui.menu_context(xml,png);self.b.input_age(fresh)
  (self.out/('current-menu-'+str(self.n)+'.json')).write_text(json.dumps({'nativeSnapshotLabel':fresh['label'],'xmlSHA256':sha(xml),'pngSHA256':sha(png),'timeOrigin':o['timeOrigin'],'context':context},indent=2)+'\n');return True
 def menu(self):
  o,_=self.observe()
  if self.current_menu(o):return
  self.close_declared_navigation_if_open();self.export_panel();self.tap('Menu',new_document=True);o,_=self.wait(lambda o:o['href']==bridge.ORIGIN+'/r?candidate=v16',20,new_document=True)
  if not self.current_menu(o):raise self.b.Refused('CURRENT_REVIEWED_MENU_UNACQUIRED')
 def snapshot(self,phase):
  self.compact_export();prior,_=self.observe();self.tap('Freeze');o,_=self.wait(lambda o:(o['exportStatus']or'').startswith('Frozen ')and o['exportStatus']!=prior['exportStatus'],15);frozen=o['exportStatus']
  previous_pack=o['packStatus'];self.tap('Pack frozen witness');self.wait(lambda o:(o['packStatus']or'').startswith('Packed ')and o['packStatus']!=previous_pack,20);o,folder=self.observe(carrier=True)
  raw=(folder/'original-carrier.txt').read_bytes();data,x=contract.unpack(raw,o['packStatus'],frozen,o['timeOrigin']);(self.out/(phase+'-carrier.txt')).write_bytes(raw);(self.out/(phase+'-frozen.json')).write_bytes(data)
  self.snapshots[phase]={'timeOrigin':o['timeOrigin'],'document':x['state']['documentInstance'],'carrierSHA256':sha(raw),'frozenSHA256':sha(data),'readonlyFolder':folder.name};self.save()
  self.tap('V16 verification controls');return x
 def native_freeze(self,count):
  self.ensure('Native failure input controls','V16 verification controls');self.ensure('Freeze actual native witness','Native failure input controls');self.tap('Freeze actual native witness');o,_=self.wait(lambda o:o['nativeFreezeStatus']=='Frozen '+str(count)+' complete',15);report=bridge.decode_json((o['nativeReportText']or'').encode());contract.latest(report,count);(self.out/('nf-'+str(count)+'.json')).write_text(json.dumps(report,indent=2)+'\n');self.tap('V16 verification controls');return report
 def native_text(self,*labels):
  # Native contextual evidence for settings-open state only. No DOM state inference.
  fresh,xml,png=self.b.retained_fresh_input('functional-context-'+str(self.n));tree=ET.fromstring(xml);self.b.input_age(fresh)
  text='\n'.join(e.get('text','')+' '+e.get('content-desc','')for e in tree.iter())
  if not all(label in text for label in labels):raise self.b.Refused('NATIVE_CONTEXT_TEXT_NOT_ACQUIRED')
  self.save();return fresh
 def history(self,label,new_document=False):
  self.ensure(label,'Declared browser navigation');return self.tap(label,new_document)
 def run_url(self):
  self.menu();self.tap('V16 referrals alias controls',True);self.wait(lambda o:'/referrals/?candidate=v16&keep=native#position'in o['href'],20,new_document=True)
  rows={'referrals-initial':self.snapshot('referrals-initial')};self.tap('referrals');rows['referrals-closed']=self.snapshot('referrals-closed')
  for action,name in [('Browser Back','referrals-back'),('Browser Forward','referrals-forward'),('Browser Back','referrals-before-reload')]:self.history(action);rows[name]=self.snapshot(name)
  before_reload=self.origin;self.history('Reload document',True);self.wait(lambda o:'/referrals/'in o['href']and o['timeOrigin']!=before_reload,30,new_document=True);rows['referrals-reloaded']=self.snapshot('referrals-reloaded')
  self.menu();self.tap('V16 URL/state controls',True);self.wait(lambda o:'/acced23acced2301' in o['href'],20,new_document=True);self.native_text('Device settings','acced23acced2302');self.tap('Close');rows['settings-closed']=self.snapshot('settings-closed');self.history('Browser Back');self.native_text('Device settings','acced23acced2302');self.tap('Close');rows['settings-closed-again']=self.snapshot('settings-closed-again');self.claim=contract.url_sequence(rows)
 def run_eof(self):
  self.menu();self.tap('V16 natural EOF 20-second request',True);self.wait(lambda o:'/1.001/20?candidate=v16&experiment=ng'in o['href'],30,new_document=True);time.sleep(3);first=self.native_freeze(1);p=contract.latest(first,1);loop=p['media']['loop'];contract.need(loop['startTime']==1001 and loop['duration']==18999,'WIDE_EOF_REQUEST_REQUIRED');
  try:contract.transport(p)
  except contract.Refused:self.snapshot('EOF-transport-unqualified');raise
  time.sleep(38);final=self.native_freeze(2);self.claim=contract.eof(final);self.snapshot('natural-eof-complete')
 def run_failure(self):
  self.menu();self.tap('Native MediaError and ordinary Play /nf',True);self.wait(lambda o:'experiment=nf'in o['href'],30,new_document=True);time.sleep(5);first=self.native_freeze(1);p=contract.latest(first,1)
  # Always preserve actual branch/global SDK records before selecting the recovery acceptance.
  global_first=self.snapshot('failure-initial');branch=contract.transport(p);classification=contract.failure_initial(first,global_first)
  if classification['status']!='ACTUAL_FAILURE_SHAPE_QUALIFIED':self.claim=classification;return
  self.tap('Jump forward 10 seconds');latest=self.native_freeze(2);self.ensure('Restore generated bytes only','V16 verification controls');self.tap('Restore generated bytes only');self.wait(lambda o:o['nativeRestoreStatus']=='HTTP restored; native/player untouched; press actual product Play.',15);restored=self.native_freeze(3);self.tap('Unpause');time.sleep(4);recovered=self.native_freeze(4);global_final=self.snapshot('failure-recovery-complete');self.claim=contract.failure_recovery(first,latest,restored,recovered,global_first,global_final,branch)
 def run(self):
  self.observe();{'url':self.run_url,'eof':self.run_eof,'failure':self.run_failure}[self.mode]();self.save()
def acquire(b,mode):
 d=Driver(b,mode)
 try:d.run()
 except BaseException as e:
  d.failure={'class':type(e).__name__,'code':str(e)[:256]};d.save();raise
 finally:d.save()
 return d.claim
